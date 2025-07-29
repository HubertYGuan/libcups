//
// TLS support code for CUPS using OpenSSL/LibreSSL.
//
// Note: This file is included from tls.c
//
// Copyright © 2020-2025 by OpenPrinting
// Copyright © 2007-2019 by Apple Inc.
// Copyright © 1997-2007 by Easy Software Products, all rights reserved.
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_crt_private.h>
#include <psa/crypto.h>
#include <mbedtls/ssl.h>
#include <mbedtls/pem.h>
#include <mbedtls/oid.h>
#include <string.h>
#include <time.h>

#define MAX_CREDS_STR_LEN 32767
#define MAX_DN_STR_LEN 1023

//
// Define OIDs
//

#define MBEDTLS_OID_X520_COUNTRY_NAME "2.5.4.6"
#define MBEDTLS_OID_X520_ORGANIZATION_NAME "2.5.4.10"
#define MBEDTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME "2.5.4.11"
#define MBEDTLS_OID_X520_COMMON_NAME "2.5.4.3"
#define MBEDTLS_OID_X520_LOCALITY_NAME "2.5.4.7"
#define MBEDTLS_OID_X520_STATE_OR_PROVINCE_NAME "2.5.4.8"
#define MBEDTLS_OID_PKCS9_EMAIL "1.2.840.113549.1.9.1"

#define SET_OID(x, oid) \
  do { x.len = MBEDTLS_OID_SIZE(oid); x.p = (unsigned char *) oid; } while (0)

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"

//
// Local globals...
//

static mbedtls_x509_crl tls_crl = {0};// Certificate revocation list

static psa_status_t mbedtls_create_key(psa_key_attributes_t *attributes, psa_key_id_t *key, cups_credtype_t type);
static int mbedtls_x509write_csr_set_ext_key_usage(mbedtls_x509write_csr *req, const mbedtls_asn1_sequence *exts);
static void mbedtls_x509_time_t(mbedtls_x509_time *in, time_t *tt);
static void time_to_str(time_t *raw, char *buf, size_t buf_size)
{
  struct tm *raw_tm = localtime(raw);
  strftime(buf, buf_size, "%Y%m%d%H%M%S", raw_tm);
}
static int mbedtls_http_read(void *ctx, unsigned char *buf, size_t len);
static int mbedtls_http_write(void *ctx, unsigned char *buf, size_t len);
static void mbedtls_load_crl(void);

//
// 'cupsAreCredentialsValidForName()' - Return whether the credentials are valid for the given name.
//

bool					// O - `true` if valid, `false` otherwise
cupsAreCredentialsValidForName(
    const char *common_name,		// I - Name to check
    const char *credentials)		// I - Credentials
{
  bool			result = false;	// Result
  mbedtls_x509_crt	chain; // Linked list of certs (no max #)
  uint32_t flags = 0;
  int ret = -1;

  // Range check input...
  if (!common_name || !*common_name || !credentials || !*credentials)
    return (false);

  // Init list and parse credentials
  mbedtls_x509_crt_init(&chain);

  uint32_t creds_len = strnlen(credentials, MAX_CREDS_STR_LEN) + 1;
  ret = mbedtls_x509_crt_parse(&chain, credentials, creds_len);
  // Actually, only ret < 0 is an error, ret > 0 means not all certificates read
  if (ret)
  {
    result = false;
    goto exit;
  }

  mbedtls_x509_crt_verify_name(&chain, common_name, &flags);
  if (flags)
  {
    result = false;
    DEBUG_printf("mbedtls_x509_crt_verify_name exited with flags: %u", flags);
    goto exit;
  }

  if (tls_crl == NULL)
  {
    result = true;
    goto exit;
  }
  mbedtls_x509_crl *cur = &tls_crl;

  cupsMutexLock(&tls_mutex);

  result = true;
  while (cur)
  {
    if (mbedtls_x509_crt_is_revoked(&chain, cur))
    {
      result = false;
      break;
    }
    cur = cur->next;
  }

  cupsMutexUnlock(&tls_mutex);

  exit:

  mbedtls_x509_crt_free(&chain);

  return (result);
}

//
// 'cupsCreateCredentials()' - Make an X.509 certificate and private key pair.
//
// This function creates an X.509 certificate and private key pair.  The
// certificate and key are stored in the directory "path" or, if "path" is
// `NULL`, in a per-user or system-wide (when running as root) certificate/key
// store.  The generated certificate is signed by the named root certificate or,
// if "root_name" is `NULL`, a site-wide default root certificate.  When
// "root_name" is `NULL` and there is no site-wide default root certificate, a
// self-signed certificate is generated instead.
//
// The "ca_cert" argument specifies whether a CA certificate should be created.
//
// The "purpose" argument specifies the purpose(s) used for the credentials as a
// bitwise OR of the following constants:
//
// - `CUPS_CREDPURPOSE_SERVER_AUTH` for validating TLS servers,
// - `CUPS_CREDPURPOSE_CLIENT_AUTH` for validating TLS clients,
// - `CUPS_CREDPURPOSE_CODE_SIGNING` for validating compiled code,
// - `CUPS_CREDPURPOSE_EMAIL_PROTECTION` for validating email messages,
// - `CUPS_CREDPURPOSE_TIME_STAMPING` for signing timestamps to objects, and/or
// - `CUPS_CREDPURPOSE_OCSP_SIGNING` for Online Certificate Status Protocol
//   message signing.
//
// The "type" argument specifies the type of credentials using one of the
// following constants:
//
// - `CUPS_CREDTYPE_DEFAULT`: default type (RSA-3072 or P-384),
// - `CUPS_CREDTYPE_RSA_2048_SHA256`: RSA with 2048-bit keys and SHA-256 hash,
// - `CUPS_CREDTYPE_RSA_3072_SHA256`: RSA with 3072-bit keys and SHA-256 hash,
// - `CUPS_CREDTYPE_RSA_4096_SHA256`: RSA with 4096-bit keys and SHA-256 hash,
// - `CUPS_CREDTYPE_ECDSA_P256_SHA256`: ECDSA using the P-256 curve with SHA-256 hash,
// - `CUPS_CREDTYPE_ECDSA_P384_SHA256`: ECDSA using the P-384 curve with SHA-256 hash, or
// - `CUPS_CREDTYPE_ECDSA_P521_SHA256`: ECDSA using the P-521 curve with SHA-256 hash.
//
// The "usage" argument specifies the usage(s) for the credentials as a bitwise
// OR of the following constants:
//
// - `CUPS_CREDUSAGE_DIGITAL_SIGNATURE`: digital signatures,
// - `CUPS_CREDUSAGE_NON_REPUDIATION`: non-repudiation/content commitment,
// - `CUPS_CREDUSAGE_KEY_ENCIPHERMENT`: key encipherment,
// - `CUPS_CREDUSAGE_DATA_ENCIPHERMENT`: data encipherment,
// - `CUPS_CREDUSAGE_KEY_AGREEMENT`: key agreement,
// - `CUPS_CREDUSAGE_KEY_CERT_SIGN`: key certicate signing,
// - `CUPS_CREDUSAGE_CRL_SIGN`: certificate revocation list signing,
// - `CUPS_CREDUSAGE_ENCIPHER_ONLY`: encipherment only,
// - `CUPS_CREDUSAGE_DECIPHER_ONLY`: decipherment only,
// - `CUPS_CREDUSAGE_DEFAULT_CA`: defaults for CA certificates,
// - `CUPS_CREDUSAGE_DEFAULT_TLS`: defaults for TLS certificates, and/or
// - `CUPS_CREDUSAGE_ALL`: all usages.
//
// The "organization", "org_unit", "locality", "state_province", and "country"
// arguments specify information about the identity and geolocation of the
// issuer.
//
// The "common_name" argument specifies the common name and the "num_alt_names"
// and "alt_names" arguments specify a list of DNS hostnames for the
// certificate.
//
// The "expiration_date" argument specifies the expiration date and time as a
// Unix `time_t` value in seconds.
//

bool					// O - `true` on success, `false` on error
cupsCreateCredentials(
    const char         *path,		// I - Directory path for certificate/key store or `NULL` for default
    bool               ca_cert,		// I - `true` to create a CA certificate, `false` for a client/server certificate
    cups_credpurpose_t purpose,		// I - Credential purposes (extended key usage)
    cups_credtype_t    type,		// I - Credential type
    cups_credusage_t   usage,		// I - Credential usages
    const char         *organization,	// I - Organization or `NULL` to use common name
    const char         *org_unit,	// I - Organizational unit or `NULL` for none
    const char         *locality,	// I - City/town or `NULL` for "Unknown"
    const char         *state_province,	// I - State/province or `NULL` for "Unknown"
    const char         *country,	// I - Country or `NULL` for locale-based default
    const char         *common_name,	// I - Common name
    const char         *email,		// I - Email address or `NULL` for none
    size_t             num_alt_names,	// I - Number of subject alternate names
    const char * const *alt_names,	// I - Subject Alternate Names
    const char         *root_name,	// I - Root certificate/domain name or `NULL` for site/self-signed
    time_t             expiration_date)	// I - Expiration date
{
  bool			ret = false;	// Return value
  mbedtls_x509write_cert ctx = {0};  // New context for certificate
  mbedtls_pk_context pkctx = {0};  // pk context for new key
  bool pkctx_is_init = false;  // If pkctx has been initiated
  mbedtls_x509_san_list *san_list_head, *san_list_cur = NULL; // Subject alt name list structs
  mbedtls_asn1_sequence *ext_key_usage_head = NULL;  // List of extended key usage items
  mbedtls_entropy_context entropy;  // Entropy and ctr drbg contexts are needed for pseudo-rng
  mbedtls_ctr_drbg_context ctr_drbg;  // These will be deprecated in Mbed TLS 4.0.0
  psa_key_id_t	key = 0;	// Encryption private/public key pair id
  psa_key_attributes_t key_atts = {0};  // Key attributes
  mbedtls_x509_crt	root_crt = {0};  // Root certificate
  mbedtls_pk_context	root_key_ctx = {0};  // Root private key context
  char			defpath[1024],	// Default path
 			crtfile[1024],	// Certificate filename
			keyfile[1024],	// Private key filename
			pubfile[1024],	// Public key filename
 			*root_crtdata,	// Root certificate data
			*root_keydata;	// Root private key data
  unsigned		mbedtls_usage = 0;  // keyUsage bits
  cups_file_t		*fp;		// Key/cert file
  unsigned char		buffer[32768];	// Buffer for x509 data
  size_t		bytes;		// Number of bytes of data
  unsigned char		serial[8];	// Serial number buffer
  time_t		curtime;	// Current time
  int			err;		// Result of mbedtls calls (int is same as psa_status_t)
  char error_str[256];  // Error code mbedtls_strerror
  *error_str = '\0';


  DEBUG_printf("cupsCreateCredentials(path=\"%s\", ca_cert=%s, purpose=0x%x, type=%d, usage=0x%x, organization=\"%s\", org_unit=\"%s\", locality=\"%s\", state_province=\"%s\", country=\"%s\", common_name=\"%s\", num_alt_names=%u, alt_names=%p, root_name=\"%s\", expiration_date=%ld)", path, ca_cert ? "true" : "false", purpose, type, usage, organization, org_unit, locality, state_province, country, common_name, (unsigned)num_alt_names, alt_names, root_name, (long)expiration_date);

  // Filenames...
  if (!path)
    path = http_default_path(defpath, sizeof(defpath));

  if (!path || !common_name)
  {
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, strerror(EINVAL), 0);
    goto done;
  }

  http_make_path(crtfile, sizeof(crtfile), path, common_name, "crt");
  http_make_path(keyfile, sizeof(keyfile), path, common_name, "key");
  http_make_path(pubfile, sizeof(pubfile), path, common_name, "pub");

  err = psa_crypto_init();
  if (err)
  {
    DEBUG_puts("Failed to init psa crypto.\n");
    return false;
  }

  // Seed the PRNG
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)
  if (err)
  {
    DEBUG_puts("Failed to seed PRNG\n");
    goto done;
  }

  // Create the encryption key...
  DEBUG_puts("1cupsCreateCredentials: Creating key pair.");

  // Generate and store keys in memory, do not use mbedtls' persistence
  err = mbedtls_create_key(&key_atts, &key, type);
  if (err != 0)
  {
    goto done;
  }

  DEBUG_puts("1cupsCreateCredentials: Key pair created.");

  // Save it...
  bytes = sizeof(buffer);

  if ((err = psa_export_key(key, buffer, bytes, &bytes)) != 0)
  {
    mbedtls_strerror(err, error_str, sizeof(error_str));
    DEBUG_printf("1cupsCreateCredentials: Unable to export key pair: %s", error_str);
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, error_str, 0);
    goto done;
  }
  else if ((fp = cupsFileOpen(keyfile, "w")) != NULL)
  {
    DEBUG_printf("1cupsCreateCredentials: Writing key pair to \"%s\".", keyfile);
    cupsFileWrite(fp, (char *)buffer, bytes);
    cupsFileClose(fp);
  }
  else
  {
    DEBUG_printf("1cupsCreateCredentials: Unable to create key pair file \"%s\": %s", keyfile, strerror(errno));
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, strerror(errno), 0);
    goto done;
  }

  // Create the certificate...
  DEBUG_puts("1cupsCreateCredentials: Generating X.509 certificate.");

  curtime   = time(NULL);
  serial[0] = (unsigned char)(curtime >> 56);
  serial[1] = (unsigned char)(curtime >> 48);
  serial[2] = (unsigned char)(curtime >> 40);
  serial[3] = (unsigned char)(curtime >> 32);
  serial[4] = (unsigned char)(curtime >> 24);
  serial[5] = (unsigned char)(curtime >> 16);
  serial[6] = (unsigned char)(curtime >> 8);
  serial[7] = (unsigned char)(curtime);

  if (!organization)
    organization = common_name;
  if (!org_unit)
    org_unit = "";
  if (!locality)
    locality = "Unknown";
  if (!state_province)
    state_province = "Unknown";
  if (!country)
    country = "US";

  mbedtls_x509write_crt_init(&ctx);

  // Issuer key set later when root cert loaded
  mbedtls_pk_init(&pkctx);
  pkctx_is_init = true;
  err = mbedtls_pk_setup_opaque(&pkctx, key);
  if (err)
  {
    DEBUG_puts("Failed to setup pk context\n");
    goto done;
  }
  mbedtls_x509write_crt_set_subject_key(&ctx, &pkctx);

  // Set dn
  char dn[MAX_DN_STR_LEN + 1];
  err = snprintf(dn, sizeof(dn), "%s=%s,%s=%s,%s=%s,%s=%s,%s=%s,%s=%s",
           MBEDTLS_OID_X520_COUNTRY_NAME, country,
           MBEDTLS_OID_X520_ORGANIZATION_NAME, organization,
           MBEDTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, org_unit,
           MBEDTLS_OID_X520_COMMON_NAME, common_name,
           MBEDTLS_OID_X520_LOCALITY_NAME, locality,
           MBEDTLS_OID_X520_STATE_OR_PROVINCE_NAME, state_province);

  if (err > MAX_DN_STR_LEN)
  {
    DEBUG_puts("DN too long, exiting\n");
    goto done;
  }

  if (email && *email)
  {
    char toappend[sizeof(email) + strlen(MBEDTLS_OID_PKCS9_EMAIL) + 2 + 1];
    snprintf(toappend, sizeof(toappend), ",%s=%s", MBEDTLS_OID_PKCS9_EMAIL, email);
    if ((err = strlen(toappend) + strlen(dn)) > MAX_DN_STR_LEN)
    {
      DEBUG_puts("DN too long to fit email, exiting\n");
      goto done;
    }
    strncat(dn, toappend, strlen(toappend));
  }

  err = mbedtls_x509write_crt_set_subject_name(&ctx, dn);
  if (err)
  {
    DEBUG_puts("Failed to set subject name\n");
    goto done;
  }

  err = mbedtls_x509write_crt_set_serial_raw(&ctx, serial, sizeof(serial));
  if (err)
  {
    DEBUG_puts("Failed to set serial\n");
    goto done;
  }

  char curtime_str[strlen("YYYYMMDDhhmmss")+1];
  time_to_str(&curtime, curtime_str, sizeof(curtime_str));
  char expiration_str[strlen("YYYYMMDDhhmmss")+1];
  time_to_str(&expiration_date, expiration_str, sizeof(expiration_str));

  err = mbedtls_x509write_crt_set_validity(&ctx, curtime_str, expiration_str);
  if (err)
  {
    DEBUG_puts("Failed to set validity period\n");
    goto done;
  }

  // Allows for unlimited length cert chains below this
  err = mbedtls_x509write_crt_set_basic_constraints(&ctx, ca_cert ? 1 : 0, -1);
  if (err)
  {
    DEBUG_puts("Failed to set ca cert status\n");
    goto done;
  }

  san_list_head = mbedtls_calloc(1, sizeof(mbedtls_x509_san_list));
  if (!san_list_head)
  {
    DEBUG_puts("Failed to allocate memory for subject alt name list\n");
    goto done;
  }
  san_list_cur = san_list_head;
  san_list_cur->next = NULL;

  san_list_cur->node.type = MBEDTLS_X509_SAN_DNS_NAME;
  san_list_cur->node.san.unstructured_name.p = "localhost"; // Read-only
  san_list_cur->node.san.unstructured_name.len = strlen("localhost");

  char *localname = NULL;
  if (!strchr(common_name, '.'))
  {
    // Add common_name.local to the list, too...
    localname = (char *)mbedtls_malloc(256);  // hostname.local
    if (!localname)
    {
      DEBUG_puts("Failed to allocate memory for subject alt name localname\n");
      goto done;
    }
    snprintf(localname, 256, "%s.local", common_name);
    san_list_cur->next = mbedtls_calloc(1, sizeof(mbedtls_x509_san_list));
    if (!san_list_cur->next)
    {
      DEBUG_puts("Failed to allocate memory for subject alt name list\n");
      goto done;
    }
    san_list_cur = san_list_cur->next;
    san_list_cur->next = NULL;

    san_list_cur->node.type = MBEDTLS_X509_SAN_DNS_NAME;
    san_list_cur->node.san.unstructured_name.p = localname;
    san_list_cur->node.san.unstructured_name.len = strlen(localname);
  }

  if (num_alt_names > 0)
  {
    size_t i;				// Looping var

    for (i = 0; i < num_alt_names; i ++)
    {
      if (strcmp(alt_names[i], "localhost"))
      {
        san_list_cur->next = mbedtls_calloc(1, sizeof(mbedtls_x509_san_list));
        if (!san_list_cur->next)
        {
          DEBUG_puts("Failed to allocate memory for subject alt name list\n");
          goto done;
        }
        san_list_cur = san_list_cur->next;
        san_list_cur->next = NULL;

        san_list_cur->node.type = MBEDTLS_X509_SAN_DNS_NAME;
        san_list_cur->node.san.unstructured_name.p = alt_names[i];
        san_list_cur->node.san.unstructured_name.len = strlen(alt_names[i]);
      }
    }
  }

  err = mbedtls_x509write_crt_set_subject_alternative_name(&ctx, &san_list_head);
  if (err)
  {
    DEBUG_puts("Failed to set subject alt name\n");
    goto done;
  }

  ext_key_usage_head = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
  if (!ext_key_usage_head)
  {
    DEBUG_puts("Failed to allocate memory for ext_key_usage list\n");
    goto done;
  }
  ext_key_usage_head->next = NULL;
  ext_key_usage_head->buf.tag = MBEDTLS_ASN1_OID;
  mbedtls_asn1_sequence *ext_key_usage_tail = ext_key_usage_head;

  if (purpose & CUPS_CREDPURPOSE_SERVER_AUTH)
  {
    SET_OID(ext_key_usage_head->buf, MBEDTLS_OID_SERVER_AUTH);
    ext_key_usage_tail->next = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
    if (!ext_key_usage_tail)
    {
      DEBUG_puts("Failed to allocate memory for ext_key_usage list\n");
      goto done;
    }
    ext_key_usage_tail = ext_key_usage_tail->next;
    ext_key_usage_tail->next = NULL;
    ext_key_usage_tail->buf.tag = MBEDTLS_ASN1_OID;
  }
  if (purpose & CUPS_CREDPURPOSE_CLIENT_AUTH)
  {
    SET_OID(ext_key_usage_head->buf, MBEDTLS_OID_CLIENT_AUTH);
    ext_key_usage_tail->next = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
    if (!ext_key_usage_tail)
    {
      DEBUG_puts("Failed to allocate memory for ext_key_usage list\n");
      goto done;
    }
    ext_key_usage_tail = ext_key_usage_tail->next;
    ext_key_usage_tail->next = NULL;
    ext_key_usage_tail->buf.tag = MBEDTLS_ASN1_OID;
  }
  if (purpose & CUPS_CREDPURPOSE_CODE_SIGNING)
  {
    SET_OID(ext_key_usage_head->buf, MBEDTLS_OID_CODE_SIGNING);
    ext_key_usage_tail->next = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
    if (!ext_key_usage_tail)
    {
      DEBUG_puts("Failed to allocate memory for ext_key_usage list\n");
      goto done;
    }
    ext_key_usage_tail = ext_key_usage_tail->next;
    ext_key_usage_tail->next = NULL;
    ext_key_usage_tail->buf.tag = MBEDTLS_ASN1_OID;
  }
  if (purpose & CUPS_CREDPURPOSE_EMAIL_PROTECTION)
  {
    SET_OID(ext_key_usage_head->buf, MBEDTLS_OID_EMAIL_PROTECTION);
    ext_key_usage_tail->next = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
    if (!ext_key_usage_tail)
    {
      DEBUG_puts("Failed to allocate memory for ext_key_usage list\n");
      goto done;
    }
    ext_key_usage_tail = ext_key_usage_tail->next;
    ext_key_usage_tail->next = NULL;
    ext_key_usage_tail->buf.tag = MBEDTLS_ASN1_OID;
  }
  // TIME_STAMPING was originally not included
  if (purpose & CUPS_CREDPURPOSE_OCSP_SIGNING)
  {
    SET_OID(ext_key_usage_head->buf, MBEDTLS_OID_OCSP_SIGNING);
    ext_key_usage_tail->next = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
    if (!ext_key_usage_tail)
    {
      DEBUG_puts("Failed to allocate memory for ext_key_usage list\n");
      goto done;
    }
    ext_key_usage_tail = ext_key_usage_tail->next;
    ext_key_usage_tail->next = NULL;
    ext_key_usage_tail->buf.tag = MBEDTLS_ASN1_OID;
  }

  err = mbedtls_x509write_crt_set_ext_key_usage(&ctx, ext_key_usage_head);
  if (err)
  {
    DEBUG_puts("Failed to set extended key usage\n");
    goto done;
  }

  if (usage & CUPS_CREDUSAGE_DIGITAL_SIGNATURE)
    mbedtls_usage |= MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
  if (usage & CUPS_CREDUSAGE_NON_REPUDIATION)
    mbedtls_usage |= MBEDTLS_X509_KU_NON_REPUDIATION;
  if (usage & CUPS_CREDUSAGE_KEY_ENCIPHERMENT)
    mbedtls_usage |= MBEDTLS_X509_KU_KEY_ENCIPHERMENT;
  if (usage & CUPS_CREDUSAGE_DATA_ENCIPHERMENT)
    mbedtls_usage |= MBEDTLS_X509_KU_DATA_ENCIPHERMENT;
  if (usage & CUPS_CREDUSAGE_KEY_AGREEMENT)
    mbedtls_usage |= MBEDTLS_X509_KU_KEY_AGREEMENT;
  if (usage & CUPS_CREDUSAGE_KEY_CERT_SIGN)
    mbedtls_usage |= MBEDTLS_X509_KU_KEY_CERT_SIGN;
  if (usage & CUPS_CREDUSAGE_CRL_SIGN)
    mbedtls_usage |= MBEDTLS_X509_KU_CRL_SIGN;
  if (usage & CUPS_CREDUSAGE_ENCIPHER_ONLY)
    mbedtls_usage |= MBEDTLS_X509_KU_ENCIPHER_ONLY;
  if (usage & CUPS_CREDUSAGE_DECIPHER_ONLY)
    mbedtls_usage |= MBEDTLS_X509_KU_DECIPHER_ONLY;

  err = mbedtls_x509write_crt_set_key_usage(&ctx, mbedtls_usage);
  if (err)
  {
    DEBUG_puts("Failed to set key usage\n");
    goto done;
  }
  err = mbedtls_x509write_crt_set_version(&ctx, MBEDTLS_X509_CRT_VERSION_3);
  if (err)
  {
    DEBUG_puts("Failed to set version\n");
    goto done;
  }

  err = mbedtls_x509write_crt_set_subject_key_identifier(&ctx);
  if (err)
  {
    DEBUG_puts("Failed to set subject key identifier\n");
    goto done;
  }

  err = mbedtls_x509write_crt_set_md_alg(&ctx, MBEDTLS_MD_SHA256);
  if (err)
  {
    DEBUG_puts("Failed to set message digest algorithm\n");
    goto done;
  }

  // Try loading a root certificate...
  if (!ca_cert)
  {
    root_crtdata = cupsCopyCredentials(path, root_name ? root_name : "_site_");
    root_keydata = cupsCopyCredentialsKey(path, root_name ? root_name : "_site_");

    if (root_crtdata && root_keydata)
    {
      // Load root certificate...
      mbedtls_x509_crt_init(&root_crt);
      uint32_t creds_len = strnlen(root_crtdata, MAX_CREDS_STR_LEN) + 1;
      err = mbedtls_x509_crt_parse(&root_crt, root_crtdata, creds_len);
      if (err)
      {
        DEBUG_puts("Failed to parse root cert\n");
        mbedtls_x509_crt_free(&root_crt);
        memset(&root_crt, sizeof(root_crt), 0);
      }
      else
      {
        // Load key pair
        mbedtls_pk_init(&root_key_ctx);
        err = mbedtls_pk_parse_key(&root_key_ctx, root_keydata, strlen(root_keydata) + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
        if (err)
        {
          DEBUG_puts("Failed to parse root key pair\n");
          mbedtls_x509_crt_free(&root_crt);
          memset(&root_crt, sizeof(root_crt), 0);
          mbedtls_pk_free(&root_key_ctx);
          memset(&root_key_ctx, sizeof(root_key_ctx), 0);
        }
      }
    }
    free(root_crtdata);
    free(root_keydata);
  }

  if (root_crt.serial.p && root_key_ctx.priv_id != 0)
  {
    // Set issuer key and name
    char issuer_name[256];
    err = mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name), &root_crt.subject);
    if (err)
    {
      DEBUG_puts("Failed to parse certificate dn\n");
      mbedtls_x509_crt_free(&root_crt);
      mbedtls_pk_free(&root_key_ctx);
      goto done;
    }

    err = mbedtls_x509write_crt_set_issuer_name(&ctx, issuer_name);
    if (err)
    {
      DEBUG_puts("Failed to set issuer name\n");
      mbedtls_x509_crt_free(&root_crt);
      mbedtls_pk_free(&root_key_ctx);
      goto done;
    }

    // No check for if the issuer key and key of issuer cert match
    err = mbedtls_x509write_crt_set_issuer_key(&ctx, &root_key_ctx);
    if (err)
    {
      DEBUG_puts("Failed to set issuer name\n");
      mbedtls_x509_crt_free(&root_crt);
      mbedtls_pk_free(&root_key_ctx);
      goto done;
    }
  }
  else
  {
    // Self-sign
    err = mbedtls_x509write_crt_set_issuer_name(&ctx, dn);
    if (err)
    {
      DEBUG_puts("Failed to set self-signed issuer name\n");
      goto done;
    }

    err = mbedtls_x509write_crt_set_issuer_key(&ctx, &pkctx);
    if (err)
    {
      DEBUG_puts("Failed to set self-signed issuer key\n");
      goto done;
    }
  }

  err = mbedtls_x509write_crt_set_authority_key_identifier(&ctx);
  if (err)
  {
    DEBUG_puts("Failed to set authority key identifier\n");
    goto done;
  }

  // Save it... (Using PEM format)
  bytes = 0;
  err = mbedtls_x509write_crt_pem(&ctx, buffer, sizeof(buffer), mbedtls_ctr_drbg_random, &ctr_drbg);
  bytes = strlen((charr *)buffer);
  if (err)
  {
    mbedtls_strerror(err, error_str, sizeof(error_str));
    DEBUG_printf("1cupsCreateCredentials: Unable to export public key and X.509 certificate: %s", error_str);
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, error_str, 0);
    goto done;
  }
  else if ((fp = cupsFileOpen(crtfile, "w")) != NULL)
  {
    DEBUG_printf("1cupsCreateCredentials: Writing public key and X.509 certificate to \"%s\".", crtfile);
    cupsFileWrite(fp, (char *)buffer, bytes);
    cupsFileClose(fp);
  }
  else
  {
    DEBUG_printf("1cupsCreateCredentials: Unable to create public key and X.509 certificate file \"%s\": %s", crtfile, strerror(errno));
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, strerror(errno), 0);
    goto done;
  }

  DEBUG_puts("1cupsCreateCredentials: Successfully created credentials.");

  bytes = sizeof(buffer);

  if ((err = psa_export_public_key(key, buffer, bytes, &bytes)) < 0)
  {
    mbedtls_strerror(err, error_str, sizeof(error_str));
    DEBUG_printf("1cupsCreateCredentials: Unable to export public key: %s", error_str);
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, error_str, 0);
    goto done;
  }
  else if ((fp = cupsFileOpen(pubfile, "w")) != NULL)
  {
    DEBUG_printf("1cupsCreateCredentials: Writing public key to \"%s\".", keyfile);
    cupsFileWrite(fp, (char *)buffer, bytes);
    cupsFileClose(fp);
  }
  else
  {
    DEBUG_printf("1cupsCreateCredentials: Unable to create public key file \"%s\": %s", keyfile, strerror(errno));
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, strerror(errno), 0);
    goto done;
  }

  ret = true;

  // Cleanup...
  done:

  mbedtls_psa_crypto_free();
  mbedtls_x509write_crt_free(&ctx);
  if (key)
    psa_destroy_key(key);
  if (pkctx_is_init)
    mbedtls_pk_free(&pkctx);
  if (localname)
    mbedtls_free(localname);
  if (san_list_head)
  {
    san_list_cur = san_list_head;
    while (san_list_cur)
    {
      mbedtls_x509_san_list *next = san_list_cur->next;
      /* Note: mbedtls_x509_free_subject_alt_name() is not what we want here.
        * It's the right thing for entries that were parsed from a certificate,
        * where pointers are to the raw certificate, but here all the
        * pointers were allocated while parsing from a user-provided string. */
      if (cur->node.type == MBEDTLS_X509_SAN_DIRECTORY_NAME) {
        mbedtls_x509_name *dn = &cur->node.san.directory_name;
        mbedtls_free(dn->oid.p);
        mbedtls_free(dn->val.p);
        mbedtls_asn1_free_named_data_list(&dn->next);
      }
      mbedtls_free(cur);
      san_list_cur = next;
    }
  }
  mbedtls_asn1_sequence_free(ext_key_usage_head);

  if (err)
  {
    mbedtls_strerror(err, error_str, sizeof(error_str));
    DEBUG_printf("1cupsCreateCredentials: Error: %s", error_str);
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, error_str, 0);
  }

  return (ret);
}


//
// 'cupsCreateCredentialsRequest()' - Make an X.509 Certificate Signing Request.
//
// This function creates an X.509 certificate signing request (CSR) and
// associated private key.  The CSR and key are stored in the directory "path"
// or, if "path" is `NULL`, in a per-user or system-wide (when running as root)
// certificate/key store.
//
// The "purpose" argument specifies the purpose(s) used for the credentials as a
// bitwise OR of the following constants:
//
// - `CUPS_CREDPURPOSE_SERVER_AUTH` for validating TLS servers,
// - `CUPS_CREDPURPOSE_CLIENT_AUTH` for validating TLS clients,
// - `CUPS_CREDPURPOSE_CODE_SIGNING` for validating compiled code,
// - `CUPS_CREDPURPOSE_EMAIL_PROTECTION` for validating email messages,
// - `CUPS_CREDPURPOSE_TIME_STAMPING` for signing timestamps to objects, and/or
// - `CUPS_CREDPURPOSE_OCSP_SIGNING` for Online Certificate Status Protocol
//   message signing.
//
// The "type" argument specifies the type of credentials using one of the
// following constants:
//
// - `CUPS_CREDTYPE_DEFAULT`: default type (RSA-3072 or P-384),
// - `CUPS_CREDTYPE_RSA_2048_SHA256`: RSA with 2048-bit keys and SHA-256 hash,
// - `CUPS_CREDTYPE_RSA_3072_SHA256`: RSA with 3072-bit keys and SHA-256 hash,
// - `CUPS_CREDTYPE_RSA_4096_SHA256`: RSA with 4096-bit keys and SHA-256 hash,
// - `CUPS_CREDTYPE_ECDSA_P256_SHA256`: ECDSA using the P-256 curve with SHA-256 hash,
// - `CUPS_CREDTYPE_ECDSA_P384_SHA256`: ECDSA using the P-384 curve with SHA-256 hash, or
// - `CUPS_CREDTYPE_ECDSA_P521_SHA256`: ECDSA using the P-521 curve with SHA-256 hash.
//
// The "usage" argument specifies the usage(s) for the credentials as a bitwise
// OR of the following constants:
//
// - `CUPS_CREDUSAGE_DIGITAL_SIGNATURE`: digital signatures,
// - `CUPS_CREDUSAGE_NON_REPUDIATION`: non-repudiation/content commitment,
// - `CUPS_CREDUSAGE_KEY_ENCIPHERMENT`: key encipherment,
// - `CUPS_CREDUSAGE_DATA_ENCIPHERMENT`: data encipherment,
// - `CUPS_CREDUSAGE_KEY_AGREEMENT`: key agreement,
// - `CUPS_CREDUSAGE_KEY_CERT_SIGN`: key certicate signing,
// - `CUPS_CREDUSAGE_CRL_SIGN`: certificate revocation list signing,
// - `CUPS_CREDUSAGE_ENCIPHER_ONLY`: encipherment only,
// - `CUPS_CREDUSAGE_DECIPHER_ONLY`: decipherment only,
// - `CUPS_CREDUSAGE_DEFAULT_CA`: defaults for CA certificates,
// - `CUPS_CREDUSAGE_DEFAULT_TLS`: defaults for TLS certificates, and/or
// - `CUPS_CREDUSAGE_ALL`: all usages.
//
// The "organization", "org_unit", "locality", "state_province", and "country"
// arguments specify information about the identity and geolocation of the
// issuer.
//
// The "common_name" argument specifies the common name and the "num_alt_names"
// and "alt_names" arguments specify a list of DNS hostnames for the
// certificate.
//

bool					// O - `true` on success, `false` on error
cupsCreateCredentialsRequest(
    const char         *path,		// I - Directory path for certificate/key store or `NULL` for default
    cups_credpurpose_t purpose,		// I - Credential purposes (extended key usage)
    cups_credtype_t    type,		// I - Credential type
    cups_credusage_t   usage,		// I - Credential usages
    const char         *organization,	// I - Organization or `NULL` to use common name
    const char         *org_unit,	// I - Organizational unit or `NULL` for none
    const char         *locality,	// I - City/town or `NULL` for "Unknown"
    const char         *state_province,	// I - State/province or `NULL` for "Unknown"
    const char         *country,	// I - Country or `NULL` for locale-based default
    const char         *common_name,	// I - Common name
    const char         *email,		// I - Email address or `NULL` for none
    size_t             num_alt_names,	// I - Number of subject alternate names
    const char * const *alt_names)	// I - Subject Alternate Names
{
  bool			ret = false;	// Return value
  mbedtls_x509write_csr req = {0};	// Certificate request
  psa_key_id_t key = 0;	 // Private/public key pair
  psa_key_attributes  key_atts = {0};  // Key attributes
  mbedtls_pk_context pkctx = {0}; // PK context for key
  mbedtls_x509_san_list *san_list_head, *san_list_cur = NULL; // Subject alt name list structs
  mbedtls_asn1_sequence *ext_key_usage_head = NULL;  // List of extended key usage items
  mbedtls_entropy_context entropy;  // Entropy and ctr drbg contexts are needed for pseudo-rng
  mbedtls_ctr_drbg_context ctr_drbg;  // These will be deprecated in Mbed TLS 4.0.0
  char			defpath[1024],	// Default path
 			csrfile[1024],	// Certificate signing request filename
			keyfile[1024],	// Private key filename
			pubfile[1024];	// Public key filename
  unsigned		mbedtls_usage = 0;// Mbed TLS keyUsage bits
  cups_file_t		*fp;		// Key/cert file
  unsigned char		buffer[8192];	// Buffer for key/cert data
  size_t		bytes;		// Number of bytes of data
  int			err;		// Mbed TLS status
  char error_str[256];
  *error_str = '\0';


  DEBUG_printf("cupsCreateCredentialsRequest(path=\"%s\", purpose=0x%x, type=%d, usage=0x%x, organization=\"%s\", org_unit=\"%s\", locality=\"%s\", state_province=\"%s\", country=\"%s\", common_name=\"%s\", num_alt_names=%u, alt_names=%p)", path, purpose, type, usage, organization, org_unit, locality, state_province, country, common_name, (unsigned)num_alt_names, alt_names);

  // Filenames...
  if (!path)
    path = http_default_path(defpath, sizeof(defpath));

  if (!path || !common_name)
  {
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, strerror(EINVAL), 0);
    goto done;
  }

  http_make_path(csrfile, sizeof(csrfile), path, common_name, "csr");
  http_make_path(keyfile, sizeof(keyfile), path, common_name, "ktm");
  http_make_path(pubfile, sizeof(pubfile), path, common_name, "pub");

  err = psa_crypto_init();
  if (err)
  {
    DEBUG_puts("Failed to init psa crypto.\n");
    return false;
  }

  // Seed the PRNG
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)
  if (err)
  {
    DEBUG_puts("Failed to seed PRNG\n");
    goto done;
  }

  // Create the encryption key...
  DEBUG_puts("1cupsCreateCredentialsRequest: Creating key pair.");

  // Generate and store keys in memory, do not use mbedtls' persistence
  err = mbedtls_create_key(&key_atts, &key, type);
  if (err != 0)
  {
    goto done;
  }

  DEBUG_puts("1cupsCreateCredentialsRequest: Key pair created.");

  // Save it...
  bytes = sizeof(buffer);

  if ((err = psa_export_key(key, buffer, bytes, &bytes)) != 0)
  {
    mbedtls_strerror(err, error_str, sizeof(error_str));
    DEBUG_printf("1cupsCreateCredentialsRequest: Unable to export key pair: %s", error_str);
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, error_str, 0);
    goto done;
  }
  else if ((fp = cupsFileOpen(keyfile, "w")) != NULL)
  {
    DEBUG_printf("1cupsCreateCredentialsRequest: Writing key pair to \"%s\".", keyfile);
    cupsFileWrite(fp, (char *)buffer, bytes);
    cupsFileClose(fp);
  }
  else
  {
    DEBUG_printf("1cupsCreateCredentialsRequest: Unable to create key pair file \"%s\": %s", keyfile, strerror(errno));
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, strerror(errno), 0);
    goto done;
  }

  // Create the certificate signing request...
  DEBUG_puts("1cupsCreateCredentialsRequest: Generating X.509 certificate request.");

  if (!organization)
    organization = common_name;
  if (!org_unit)
    org_unit = "";
  if (!locality)
    locality = "Unknown";
  if (!state_province)
    state_province = "Unknown";
  if (!country)
    country = "US";

  mbedtls_x509write_csr_init(&req);

  // Set key
  mbedtls_pk_init(&pkctx);
  pkctx_is_init = true;
  err = mbedtls_pk_setup_opaque(&pkctx, key);
  if (err)
  {
    DEBUG_puts("Failed to setup pk context\n");
    goto done;
  }
  mbedtls_x509write_csr_set_key(&req, &pkctx);

  // Set dn
  char dn[MAX_DN_STR_LEN + 1];
  err = snprintf(dn, sizeof(dn), "%s=%s,%s=%s,%s=%s,%s=%s,%s=%s,%s=%s",
           MBEDTLS_OID_X520_COUNTRY_NAME, country,
           MBEDTLS_OID_X520_ORGANIZATION_NAME, organization,
           MBEDTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, org_unit,
           MBEDTLS_OID_X520_COMMON_NAME, common_name,
           MBEDTLS_OID_X520_LOCALITY_NAME, locality,
           MBEDTLS_OID_X520_STATE_OR_PROVINCE_NAME, state_province);

  if (err > MAX_DN_STR_LEN)
  {
    DEBUG_puts("DN too long, exiting\n");
    goto done;
  }

  if (email && *email)
  {
    char toappend[sizeof(email) + strlen(MBEDTLS_OID_PKCS9_EMAIL) + 2 + 1];
    snprintf(toappend, sizeof(toappend), ",%s=%s", MBEDTLS_OID_PKCS9_EMAIL, email);
    if ((err = strlen(toappend) + strlen(dn)) > MAX_DN_STR_LEN)
    {
      DEBUG_puts("DN too long to fit email, exiting\n");
      goto done;
    }
    strncat(dn, toappend, strlen(toappend));
  }

  err = mbedtls_x509write_csr_set_subject_name(&req, dn);
  if (err)
  {
    DEBUG_puts("Failed to set subject name\n");
    goto done;
  }

  san_list_head = mbedtls_calloc(1, sizeof(mbedtls_x509_san_list));
  if (!san_list_head)
  {
    DEBUG_puts("Failed to allocate memory for subject alt name list\n");
    goto done;
  }
  san_list_cur = san_list_head;
  san_list_cur->next = NULL;

  san_list_cur->node.type = MBEDTLS_X509_SAN_DNS_NAME;
  san_list_cur->node.san.unstructured_name.p = "localhost"; // Read-only
  san_list_cur->node.san.unstructured_name.len = strlen("localhost");

  char *localname = NULL;
  if (!strchr(common_name, '.'))
  {
    // Add common_name.local to the list, too...
    localname = (char *)mbedtls_malloc(256);  // hostname.local
    if (!localname)
    {
      DEBUG_puts("Failed to allocate memory for subject alt name localname\n");
      goto done;
    }
    snprintf(localname, 256, "%s.local", common_name);
    san_list_cur->next = mbedtls_calloc(1, sizeof(mbedtls_x509_san_list));
    if (!san_list_cur->next)
    {
      DEBUG_puts("Failed to allocate memory for subject alt name list\n");
      goto done;
    }
    san_list_cur = san_list_cur->next;
    san_list_cur->next = NULL;

    san_list_cur->node.type = MBEDTLS_X509_SAN_DNS_NAME;
    san_list_cur->node.san.unstructured_name.p = localname;
    san_list_cur->node.san.unstructured_name.len = strlen(localname);
  }

  if (num_alt_names > 0)
  {
    size_t i;				// Looping var

    for (i = 0; i < num_alt_names; i ++)
    {
      if (strcmp(alt_names[i], "localhost"))
      {
        san_list_cur->next = mbedtls_calloc(1, sizeof(mbedtls_x509_san_list));
        if (!san_list_cur->next)
        {
          DEBUG_puts("Failed to allocate memory for subject alt name list\n");
          goto done;
        }
        san_list_cur = san_list_cur->next;
        san_list_cur->next = NULL;

        san_list_cur->node.type = MBEDTLS_X509_SAN_DNS_NAME;
        san_list_cur->node.san.unstructured_name.p = alt_names[i];
        san_list_cur->node.san.unstructured_name.len = strlen(alt_names[i]);
      }
    }
  }

  err = mbedtls_x509write_csr_set_subject_alternative_name(&ctx, &san_list_head);
  if (err)
  {
    DEBUG_puts("Failed to set subject alt name\n");
    goto done;
  }

  ext_key_usage_head = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
  if (!ext_key_usage_head)
  {
    DEBUG_puts("Failed to allocate memory for ext_key_usage list\n");
    goto done;
  }
  ext_key_usage_head->next = NULL;
  ext_key_usage_head->buf.tag = MBEDTLS_ASN1_OID;
  mbedtls_asn1_sequence *ext_key_usage_tail = ext_key_usage_head;

  if (purpose & CUPS_CREDPURPOSE_SERVER_AUTH)
  {
    SET_OID(ext_key_usage_head->buf, MBEDTLS_OID_SERVER_AUTH);
    ext_key_usage_tail->next = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
    if (!ext_key_usage_tail)
    {
      DEBUG_puts("Failed to allocate memory for ext_key_usage list\n");
      goto done;
    }
    ext_key_usage_tail = ext_key_usage_tail->next;
    ext_key_usage_tail->next = NULL;
    ext_key_usage_tail->buf.tag = MBEDTLS_ASN1_OID;
  }
  if (purpose & CUPS_CREDPURPOSE_CLIENT_AUTH)
  {
    SET_OID(ext_key_usage_head->buf, MBEDTLS_OID_CLIENT_AUTH);
    ext_key_usage_tail->next = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
    if (!ext_key_usage_tail)
    {
      DEBUG_puts("Failed to allocate memory for ext_key_usage list\n");
      goto done;
    }
    ext_key_usage_tail = ext_key_usage_tail->next;
    ext_key_usage_tail->next = NULL;
    ext_key_usage_tail->buf.tag = MBEDTLS_ASN1_OID;
  }
  if (purpose & CUPS_CREDPURPOSE_CODE_SIGNING)
  {
    SET_OID(ext_key_usage_head->buf, MBEDTLS_OID_CODE_SIGNING);
    ext_key_usage_tail->next = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
    if (!ext_key_usage_tail)
    {
      DEBUG_puts("Failed to allocate memory for ext_key_usage list\n");
      goto done;
    }
    ext_key_usage_tail = ext_key_usage_tail->next;
    ext_key_usage_tail->next = NULL;
    ext_key_usage_tail->buf.tag = MBEDTLS_ASN1_OID;
  }
  if (purpose & CUPS_CREDPURPOSE_EMAIL_PROTECTION)
  {
    SET_OID(ext_key_usage_head->buf, MBEDTLS_OID_EMAIL_PROTECTION);
    ext_key_usage_tail->next = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
    if (!ext_key_usage_tail)
    {
      DEBUG_puts("Failed to allocate memory for ext_key_usage list\n");
      goto done;
    }
    ext_key_usage_tail = ext_key_usage_tail->next;
    ext_key_usage_tail->next = NULL;
    ext_key_usage_tail->buf.tag = MBEDTLS_ASN1_OID;
  }
  // TIME_STAMPING was originally not included
  if (purpose & CUPS_CREDPURPOSE_OCSP_SIGNING)
  {
    SET_OID(ext_key_usage_head->buf, MBEDTLS_OID_OCSP_SIGNING);
    ext_key_usage_tail->next = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
    if (!ext_key_usage_tail)
    {
      DEBUG_puts("Failed to allocate memory for ext_key_usage list\n");
      goto done;
    }
    ext_key_usage_tail = ext_key_usage_tail->next;
    ext_key_usage_tail->next = NULL;
    ext_key_usage_tail->buf.tag = MBEDTLS_ASN1_OID;
  }

  err = mbedtls_x509write_csr_set_ext_key_usage(&ctx, ext_key_usage_head);
  if (err)
  {
    DEBUG_puts("Failed to set extended key usage\n");
    goto done;
  }

  if (usage & CUPS_CREDUSAGE_DIGITAL_SIGNATURE)
    mbedtls_usage |= MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
  if (usage & CUPS_CREDUSAGE_NON_REPUDIATION)
    mbedtls_usage |= MBEDTLS_X509_KU_NON_REPUDIATION;
  if (usage & CUPS_CREDUSAGE_KEY_ENCIPHERMENT)
    mbedtls_usage |= MBEDTLS_X509_KU_KEY_ENCIPHERMENT;
  if (usage & CUPS_CREDUSAGE_DATA_ENCIPHERMENT)
    mbedtls_usage |= MBEDTLS_X509_KU_DATA_ENCIPHERMENT;
  if (usage & CUPS_CREDUSAGE_KEY_AGREEMENT)
    mbedtls_usage |= MBEDTLS_X509_KU_KEY_AGREEMENT;
  if (usage & CUPS_CREDUSAGE_KEY_CERT_SIGN)
    mbedtls_usage |= MBEDTLS_X509_KU_KEY_CERT_SIGN;
  if (usage & CUPS_CREDUSAGE_CRL_SIGN)
    mbedtls_usage |= MBEDTLS_X509_KU_CRL_SIGN;
  if (usage & CUPS_CREDUSAGE_ENCIPHER_ONLY)
    mbedtls_usage |= MBEDTLS_X509_KU_ENCIPHER_ONLY;
  if (usage & CUPS_CREDUSAGE_DECIPHER_ONLY)
    mbedtls_usage |= MBEDTLS_X509_KU_DECIPHER_ONLY;

  err = mbedtls_x509write_csr_set_key_usage(&ctx, mbedtls_usage);
  if (err)
  {
    DEBUG_puts("Failed to set key usage\n");
    goto done;
  }

  err = mbedtls_x509write_csr_set_md_alg(&ctx, MBEDTLS_MD_SHA256);
  if (err)
  {
    DEBUG_puts("Failed to set message digest algorithm\n");
    goto done;
  }

  // Seems there is no way to set the version

  // Save it... (Using PEM format)
  bytes = 0;
  err = mbedtls_x509write_csr_pem(&req, buffer, sizeof(buffer), mbedtls_ctr_drbg_random, &ctr_drbg);
  bytes = strlen((charr *)buffer);
  if (err)
  {
    DEBUG_printf("1cupsCreateCredentialsRequest: Unable to export public key and X.509 certificate request: %s", mbedtls_strerror(err));
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, mbedtls_strerror(err), 0);
    goto done;
  }
  else if ((fp = cupsFileOpen(csrfile, "w")) != NULL)
  {
    DEBUG_printf("1cupsCreateCredentialsRequest: Writing public key and X.509 certificate request to \"%s\".", csrfile);
    cupsFileWrite(fp, (char *)buffer, bytes);
    cupsFileClose(fp);
  }
  else
  {
    DEBUG_printf("1cupsCreateCredentialsRequest: Unable to create public key and X.509 certificate request file \"%s\": %s", csrfile, strerror(errno));
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, strerror(errno), 0);
    goto done;
  }

  DEBUG_puts("1cupsCreateCredentialsRequest: Successfully created credentials request.");

  bytes = sizeof(buffer);

  if ((err = psa_export_public_key(key, buffer, bytes, &bytes)) < 0)
  {
    DEBUG_printf("1cupsCreateCredentials: Unable to export public key: %s", mbedtls_strerror(err));
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, mbedtls_strerror(err), 0);
    goto done;
  }
  else if ((fp = cupsFileOpen(pubfile, "w")) != NULL)
  {
    DEBUG_printf("1cupsCreateCredentials: Writing public key to \"%s\".", keyfile);
    cupsFileWrite(fp, (char *)buffer, bytes);
    cupsFileClose(fp);
  }
  else
  {
    DEBUG_printf("1cupsCreateCredentials: Unable to create public key file \"%s\": %s", keyfile, strerror(errno));
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, strerror(errno), 0);
    goto done;
  }

  ret = true;

  // Cleanup...
  done:

  mbedtls_psa_crypto_free();
  mbedtls_x509write_csr_free(&req);
  if (key)
    psa_destroy_key(key);
  if (pkctx_is_init)
    mbedtls_pk_free(&pkctx);
  if (localname)
    mbedtls_free(localname);
  if (san_list_head)
  {
    san_list_cur = san_list_head;
    while (san_list_cur)
    {
      mbedtls_x509_san_list *next = san_list_cur->next;
      /* Note: mbedtls_x509_free_subject_alt_name() is not what we want here.
        * It's the right thing for entries that were parsed from a certificate,
        * where pointers are to the raw certificate, but here all the
        * pointers were allocated while parsing from a user-provided string. */
      if (cur->node.type == MBEDTLS_X509_SAN_DIRECTORY_NAME) {
        mbedtls_x509_name *dn = &cur->node.san.directory_name;
        mbedtls_free(dn->oid.p);
        mbedtls_free(dn->val.p);
        mbedtls_asn1_free_named_data_list(&dn->next);
      }
      mbedtls_free(cur);
      san_list_cur = next;
    }
  }
  mbedtls_asn1_sequence_free(ext_key_usage_head);

  if (err)
  {
    mbedtls_strerror(err, error_str, sizeof(error_str));
    DEBUG_printf("1cupsCreateCredentialsRequest: Error: %s", error_str);
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, error_str, 0);
  }
  return (ret);
}


//
// 'cupsGetCredentialsExpiration()' - Return the expiration date of the credentials.
//

time_t					// O - Expiration date of credentials
cupsGetCredentialsExpiration(
    const char *credentials)		// I - Credentials
{
  time_t		result = 0;	// Result
  mbedtls_x509_crt chain = {0};	// Certificates chain

  mbedtls_x509_crt_init(&chain);

  uint32_t creds_len = strnlen(credentials, MAX_CREDS_STR_LEN) + 1;
  if (mbedtls_x509_crt_parse(&chain, credentials, creds_len) >= 0)
  {
    mbedtls_x509_time_t(&chain.valid_to, &result);
    if (result == -1)
      result = 0;
  }

  mbedtls_x509_crt_free(&chain);

  return (result);
}


//
// 'cupsGetCredentialsInfo()' - Return a string describing the credentials.
//

char *					// O - Credential description string
cupsGetCredentialsInfo(
    const char *credentials,		// I - Credentials
    char       *buffer,			// I - Buffer
    size_t     bufsize)			// I - Size of buffer
{
  mbedtls_x509_crt	chain;	// Certificates chain

  DEBUG_printf("httpCredentialsString(credentials=%p, buffer=%p, bufsize=" CUPS_LLFMT ")", credentials, buffer, CUPS_LLCAST bufsize);

  if (buffer)
    *buffer = '\0';


  if (!credentials || !buffer || bufsize < 32)
  {
    DEBUG_puts("1cupsGetCredentialsInfo: Returning NULL.");
    return (NULL);
  }

  mbedtls_x509_crt_init(&chain);

  uint32_t creds_len = strnlen(credentials, MAX_CREDS_STR_LEN) + 1;
  if (mbedtls_x509_crt_parse(&chain, credentials, creds_len) >= 0)
  {
    char		name[256],	// Common name associated with cert
			issuer[256];	// Issuer associated with cert
    size_t		len;		// Length of string
    char    sigalg[256];  // Signature algorithm as string
    time_t		expiration;	// Expiration date of cert
    char		expstr[256];	// Expiration date as string */
    unsigned char	md5_digest[16];	// MD5 result

    *name = '\0';
    len = sizeof(name) - 1;
    const mbedtls_x509_name *cur_name;
    for (cur_name = &chain.subject; cur_name != NULL; cur_name = cur_name->next)
    {
      if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &cur_name->oid) == 0)
      {
        cupsCopyString(name, (char *)cur_name->val.p, sizeof(name));
        name[len] = '\0';
        break;
      }
    }
    if (*name == '\0')
      cupsCopyString(name, "unknown", sizeof(name));

    *issuer = '\0';
    len = sizeof(issuer) - 1;
    for (cur_name = &chain.issuer; cur_name != NULL; cur_name = cur_name->next)
    {
      if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &cur_name->oid) == 0)
      {
        cupsCopyString(issuer, (char *)cur_name->val.p, sizeof(issuer));
        issuer[len] = '\0';
        break;
      }
    }
    if (*issuer == '\0')
      cupsCopyString(name, "unknown", sizeof(name));

    if (mbedtls_oid_get_sig_alg_desc(&chain.sig_oid, &sigalg))
      cupsCopyString(sigalg, "unknown", sizeof(sigalg));

    mbedtls_x509_time_t(&chain.valid_to, &expiration);
    if (expiration == -1)
      expiration = 0;

    cupsHashData("md5", credentials, strlen(credentials), md5_digest, sizeof(md5_digest));

    snprintf(buffer, bufsize, "%s (issued by %s) / %s / %s / %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", name, issuer, httpGetDateString(expiration, expstr, sizeof(expstr)), sigalg, md5_digest[0], md5_digest[1], md5_digest[2], md5_digest[3], md5_digest[4], md5_digest[5], md5_digest[6], md5_digest[7], md5_digest[8], md5_digest[9], md5_digest[10], md5_digest[11], md5_digest[12], md5_digest[13], md5_digest[14], md5_digest[15]);
  }
  mbedtls_x509_crt_free(&chain);

  DEBUG_printf("1cupsGetCredentialsInfo: Returning \"%s\".", buffer);

  return (buffer);
}


//
// 'cupsGetCredentialsTrust()' - Return the trust of credentials.
//
// This function determines the level of trust for the supplied credentials.
// The "path" parameter specifies the certificate/key store for known
// credentials and certificate authorities.  The "common_name" parameter
// specifies the FQDN of the service being accessed such as
// "printer.example.com".  The "credentials" parameter provides the credentials
// being evaluated, which are usually obtained with the
// @link httpCopyPeerCredentials@ function.  The "require_ca" parameter
// specifies whether a CA-signed certificate is required for trust.
//
// The `AllowAnyRoot`, `AllowExpiredCerts`, `TrustOnFirstUse`, and
// `ValidateCerts` options in the "client.conf" file (or corresponding
// preferences file on macOS) control the trust policy, which defaults to
// AllowAnyRoot=Yes, AllowExpiredCerts=No, TrustOnFirstUse=Yes, and
// ValidateCerts=No.  When the "require_ca" parameter is `true` the AllowAnyRoot
// and TrustOnFirstUse policies are turned off ("No").
//
// The returned trust value can be one of the following:
//
// - `HTTP_TRUST_OK`: Credentials are OK/trusted
// - `HTTP_TRUST_INVALID`: Credentials are invalid
// - `HTTP_TRUST_EXPIRED`: Credentials are expired
// - `HTTP_TRUST_RENEWED`: Credentials have been renewed
// - `HTTP_TRUST_UNKNOWN`: Credentials are unknown/new
//

http_trust_t				// O - Level of trust
cupsGetCredentialsTrust(
    const char *path,	        	// I - Directory path for certificate/key store or `NULL` for default
    const char *common_name,		// I - Common name for trust lookup
    const char *credentials,		// I - Credentials
    bool       require_ca)		// I - Require a CA-signed certificate?
{
  http_trust_t		trust = HTTP_TRUST_OK;
					// Trusted?
  char			defpath[1024],	// Default path
 			*tcreds = NULL;	// Trusted credentials
  mbedtls_x509_crt chain;	// Certificates chain
  _cups_globals_t	*cg = _cupsGlobals();
					// Per-thread globals


  // Range check input...
  if (!path)
    path = http_default_path(defpath, sizeof(defpath));

  if (!path || !credentials || !common_name)
  {
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, strerror(EINVAL), false);
    return (HTTP_TRUST_UNKNOWN);
  }

  mbedtls_x509_crt_init(&chain);
  // Load the credentials...
  uint32_t creds_len = strnlen(credentials, MAX_CREDS_STR_LEN) + 1;
  if (mbedtls_x509_crt_parse(&chain, credentials, creds_len) < 0)
  {
    _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, _("Unable to import credentials."), true);
    return (HTTP_TRUST_UNKNOWN);
  }

  if (!cg->client_conf_loaded)
  {
    _cupsSetDefaults();
    mbedtls_load_crl();
  }

  // Look this common name up in the default keychains...
  if (chain.next == NULL && (tcreds = cupsCopyCredentials(path, common_name)) != NULL)
  {
    char	credentials_str[1024],	// String for incoming credentials
		tcreds_str[1024];	// String for saved credentials

    cupsGetCredentialsInfo(credentials, credentials_str, sizeof(credentials_str));
    cupsGetCredentialsInfo(tcreds, tcreds_str, sizeof(tcreds_str));

    if (strcmp(credentials_str, tcreds_str))
    {
      // Credentials don't match, let's look at the expiration date of the new
      // credentials and allow if the new ones have a later expiration...
      if (!cg->trust_first || require_ca)
      {
        // Do not trust certificates on first use...
        _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, _("Trust on first use is disabled."), true);

        trust = HTTP_TRUST_INVALID;
      }
      else if (cupsGetCredentialsExpiration(credentials) <= cupsGetCredentialsExpiration(tcreds))
      {
        // The new credentials are not newly issued...
        _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, _("New credentials are older than stored credentials."), true);

        trust = HTTP_TRUST_INVALID;
      }
      else if (!cupsAreCredentialsValidForName(common_name, credentials))
      {
        // The common name does not match the issued certificate...
        _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, _("New credentials are not valid for name."), true);

        trust = HTTP_TRUST_INVALID;
      }
      else if (cupsGetCredentialsExpiration(tcreds) < time(NULL))
      {
        // Save the renewed credentials...
	trust = HTTP_TRUST_RENEWED;

        cupsSaveCredentials(path, common_name, credentials, /*key*/NULL);
      }
    }

    free(tcreds);
  }
  else if ((cg->validate_certs || require_ca) && !cupsAreCredentialsValidForName(common_name, credentials))
  {
    _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, _("No stored credentials, not valid for name."), true);
    trust = HTTP_TRUST_INVALID;
  }
  else if (chain.next)
  {
    if (!http_check_roots(credentials))
    {
      // See if we have a site CA certificate we can compare...
      if ((tcreds = cupsCopyCredentials(path, "_site_")) != NULL)
      {
	size_t	credslen,		// Length of credentials
		  tcredslen;		// Length of trust root


	// Do a tail comparison of the root...
	credslen  = strlen(credentials);
	tcredslen = strlen(tcreds);
	if (credslen <= tcredslen || strcmp(credentials + (credslen - tcredslen), tcreds))
	{
	  // Certificate isn't directly generated from the CA cert...
	  trust = HTTP_TRUST_INVALID;
	}

	if (trust != HTTP_TRUST_OK)
	  _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, _("Credentials do not validate against site CA certificate."), true);

	free(tcreds);
      }
    }
  }
  else if (require_ca)
  {
    _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, _("Credentials are not CA-signed."), true);
    trust = HTTP_TRUST_INVALID;
  }
  else if (!cg->trust_first)
  {
    _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, _("Trust on first use is disabled."), true);
    trust = HTTP_TRUST_INVALID;
  }
  else if (!cg->any_root || require_ca)
  {
    _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, _("Self-signed credentials are blocked."), true);
    trust = HTTP_TRUST_INVALID;
  }

  if (trust == HTTP_TRUST_OK && !cg->expired_certs)
  {
    time_t	curtime;		// Current date/time
    time_t  activation;
    time_t  expiration;

    time(&curtime);
    mbedtls_x509_time_t(&chain.valid_to, &expiration);
    mbedtls_x509_time_t(&chain.valid_from, &activation);
    if (curtime < activation || curtime > expiration)
    {
      _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, _("Credentials have expired."), true);
      trust = HTTP_TRUST_EXPIRED;
    }
  }

  mbedtls_x509_crt_free(&chain);

  return (trust);
}


//
// 'cupsSignCredentialsRequest()' - Sign an X.509 certificate signing request to produce an X.509 certificate chain.
//
// This function creates an X.509 certificate from a signing request.  The
// certificate is stored in the directory "path" or, if "path" is `NULL`, in a
// per-user or system-wide (when running as root) certificate/key store.  The
// generated certificate is signed by the named root certificate or, if
// "root_name" is `NULL`, a site-wide default root certificate.  When
// "root_name" is `NULL` and there is no site-wide default root certificate, a
// self-signed certificate is generated instead.
//
// The "allowed_purpose" argument specifies the allowed purpose(s) used for the
// credentials as a bitwise OR of the following constants:
//
// - `CUPS_CREDPURPOSE_SERVER_AUTH` for validating TLS servers,
// - `CUPS_CREDPURPOSE_CLIENT_AUTH` for validating TLS clients,
// - `CUPS_CREDPURPOSE_CODE_SIGNING` for validating compiled code,
// - `CUPS_CREDPURPOSE_EMAIL_PROTECTION` for validating email messages,
// - `CUPS_CREDPURPOSE_TIME_STAMPING` for signing timestamps to objects, and/or
// - `CUPS_CREDPURPOSE_OCSP_SIGNING` for Online Certificate Status Protocol
//   message signing.
//
// The "allowed_usage" argument specifies the allowed usage(s) for the
// credentials as a bitwise OR of the following constants:
//
// - `CUPS_CREDUSAGE_DIGITAL_SIGNATURE`: digital signatures,
// - `CUPS_CREDUSAGE_NON_REPUDIATION`: non-repudiation/content commitment,
// - `CUPS_CREDUSAGE_KEY_ENCIPHERMENT`: key encipherment,
// - `CUPS_CREDUSAGE_DATA_ENCIPHERMENT`: data encipherment,
// - `CUPS_CREDUSAGE_KEY_AGREEMENT`: key agreement,
// - `CUPS_CREDUSAGE_KEY_CERT_SIGN`: key certicate signing,
// - `CUPS_CREDUSAGE_CRL_SIGN`: certificate revocation list signing,
// - `CUPS_CREDUSAGE_ENCIPHER_ONLY`: encipherment only,
// - `CUPS_CREDUSAGE_DECIPHER_ONLY`: decipherment only,
// - `CUPS_CREDUSAGE_DEFAULT_CA`: defaults for CA certificates,
// - `CUPS_CREDUSAGE_DEFAULT_TLS`: defaults for TLS certificates, and/or
// - `CUPS_CREDUSAGE_ALL`: all usages.
//
// The "cb" and "cb_data" arguments specify a function and its data that are
// used to validate any subjectAltName values in the signing request:
//
// ```
// bool san_cb(const char *common_name, const char *alt_name, void *cb_data) {
//   ... return true if OK and false if not ...
// }
// ```
//
// If `NULL`, a default validation function is used that allows "localhost" and
// variations of the common name.
//
// The "expiration_date" argument specifies the expiration date and time as a
// Unix `time_t` value in seconds.
//
// WIP Since mbedtls seems like it doesn't support ext key usage extension (purpose) for CSRs
bool					// O - `true` on success, `false` on failure
cupsSignCredentialsRequest(
    const char         *path,		// I - Directory path for certificate/key store or `NULL` for default
    const char         *common_name,	// I - Common name to use
    const char         *request,	// I - PEM-encoded CSR
    const char         *root_name,	// I - Root certificate
    cups_credpurpose_t allowed_purpose,	// I - Allowed credential purpose(s)
    cups_credusage_t   allowed_usage,	// I - Allowed credential usage(s)
    cups_cert_san_cb_t cb,		// I - subjectAltName callback or `NULL` to allow just .local
    void               *cb_data,	// I - Callback data
    time_t             expiration_date)	// I - Certificate expiration date
{
  bool			ret = false;	// Return value
  int			i,		// Looping var
			err;		// Mbed TLS error code, if any
  mbedtls_x509_csr	csr = {0};	// Certificate request
  mbedtls_x509write_cert	crt = {0};	// Certificate
  mbedtls_x509_crt	root_crt = {0};// Root certificate
  mbedtls_pk_context	root_key_ctx = {0}; // Root key pair PK context
  mbedtls_x509_san_list *san_list_head, *san_list_cur = NULL; // Subject alt name list structs
  char			defpath[1024],	// Default path
			temp[1024],	// Temporary string
 			crtfile[1024],	// Certificate filename
 			*root_crtdata,	// Root certificate data
			*root_keydata;	// Root private key data
  size_t		tempsize;	// Size of temporary string
  cups_credpurpose_t	purpose;	// Credential purpose(s)
  unsigned		mbedtls_usage;	// GNU TLS keyUsage bits
  cups_credusage_t	usage;		// Credential usage(s)
  cups_file_t		*fp;		// Key/cert file
  unsigned char		buffer[32768];	// Buffer for x509 data
  size_t		bytes;		// Number of bytes of data
  unsigned char		serial[8];	// Serial number buffer
  time_t		curtime;	// Current time
  char error_str[256];
  *error_str = '\0';


  DEBUG_printf("cupsSignCredentialsRequest(path=\"%s\", common_name=\"%s\", request=\"%s\", root_name=\"%s\", allowed_purpose=0x%x, allowed_usage=0x%x, cb=%p, cb_data=%p, expiration_date=%ld)", path, common_name, request, root_name, allowed_purpose, allowed_usage, cb, cb_data, (long)expiration_date);

  // Filenames...
  if (!path)
    path = http_default_path(defpath, sizeof(defpath));

  if (!path || !common_name || !request)
  {
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, strerror(EINVAL), 0);
    goto done;
  }

  if (!cb)
    cb = http_default_san_cb;

  // Import the request...
  mbedtls_x509_csr_init(&csr);

  uint32_t request_len = strnlen(request, MAX_CREDS_STR_LEN) + 1;
  if ((err = mbedtls_x509_csr_import(&csr, request, request_len)) != 0)
  {
    mbedtls_strerror(err, error_str, sizeof(error_str));
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, error_str, 0);
    goto done;
  }

  // Create the certificate...
  DEBUG_puts("1cupsSignCredentialsRequest: Generating X.509 certificate.");

  curtime   = time(NULL);
  serial[0] = (unsigned char)(curtime >> 56);
  serial[1] = (unsigned char)(curtime >> 48);
  serial[2] = (unsigned char)(curtime >> 40);
  serial[3] = (unsigned char)(curtime >> 32);
  serial[4] = (unsigned char)(curtime >> 24);
  serial[5] = (unsigned char)(curtime >> 16);
  serial[6] = (unsigned char)(curtime >> 8);
  serial[7] = (unsigned char)(curtime);

  mbedtls_x509write_crt_init(&crt);

  mbedtls_x509_dn_gets(buffer, sizeof(buffer), &csr.subject);
  if (!strstr(buffer, MBEDTLS_OID_X520_COUNTRY_NAME) && !strstr(buffer, "C="))
  {
    if (strlen(buffer))
    {
      cupsConcatString(buffer, ",C=US");
    }
    else
    {
      cupsConcatString(buffer, "C=US");
    }
  }
  char *common_name_pos = NULL;
  if ((common_name_pos = strstr(buffer, MBEDTLS_OID_X520_COMMON_NAME)) != NULL)
  {
    char *end_pos = strchr(common_name_pos, ',');
    if (end_pos)
    {
      char temp[256];
      cupsCopyString(temp, end_pos, sizeof(temp));
      char toappend[256];
      snprintf(toappend, sizeof(toappend), "CN=%s", common_name);
      cupsCopyString(common_name_pos, toappend, sizeof(buffer) - (size_t)(common_name_pos - buffer));
      cupsCopyString(common_name_pos + strlen(toappend), temp, \
                     sizeof(buffer) - (size_t)(common_name_pos - buffer - strlen(toappend)));
    }
    else
    {
      char toappend[256];
      snprintf(toappend, sizeof(toappend), ",CN=%s", common_name);
      cupsCopyString(common_name_pos, toappend, sizeof(buffer) - (size_t)(common_name_pos - buffer));
    }
  }
  else if ((common_name_pos = strstr(buffer, MBEDTLS_OID_X520_COMMON_NAME)) != NULL)
  {
    char *end_pos = strchr(common_name_pos, ',');
    if (end_pos)
    {
      char temp[256];
      cupsCopyString(temp, end_pos, sizeof(temp));
      char toappend[256];
      snprintf(toappend, sizeof(toappend), "CN=%s", common_name);
      cupsCopyString(common_name_pos, toappend, sizeof(buffer) - (size_t)(common_name_pos - buffer));
      cupsCopyString(common_name_pos + strlen(toappend), temp, \
                     sizeof(buffer) - (size_t)(common_name_pos - buffer - strlen(toappend)));
    }
    else
    {
      char toappend[256];
      snprintf(toappend, sizeof(toappend), ",CN=%s", common_name);
      cupsCopyString(common_name_pos, toappend, sizeof(buffer) - (size_t)(common_name_pos - buffer));
    }
  }
  else
  {
    if (strlen(buffer))
    {
      char toappend[256];
      snprintf(toappend, sizeof(toappend), ",CN=%s", common_name);
      cupsConcatString(buffer, toappend);
    }
    else
    {
      char toappend[256];
      snprintf(toappend, sizeof(toappend), "CN=%s", common_name);
      cupsConcatString(buffer, toappend);
    }
  }

  if (!strstr(buffer, MBEDTLS_OID_X520_STATE_OR_PROVINCE_NAME) && !strstr(buffer, "ST="))
  {
    if (strlen(buffer))
    {
      cupsConcatString(buffer, ",ST=Unknown");
    }
    else
    {
      cupsConcatString(buffer, "ST=Unknown");
    }
  }

  if (!strstr(buffer, MBEDTLS_OID_X520_LOCALITY_NAME) && !strstr(buffer, "L="))
  {
    if (strlen(buffer))
    {
      cupsConcatString(buffer, ",L=Unknown");
    }
    else
    {
      cupsConcatString(buffer, "L=Unknown");
    }
  }

  err = mbedtls_x509write_crt_set_subject_name(&crt, buffer);
  if (err)
  {
    DEBUG_puts("Failed to set dn\n");
    goto done;
  }
  memset(buffer, 0, sizeof(buffer));

  err = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
  if (err)
  {
    DEBUG_puts("Failed to set serial\n");
    goto done;
  }
  
  char curtime_str[strlen("YYYYMMDDhhmmss")+1];
  time_to_str(&curtime, curtime_str, sizeof(curtime_str));
  char expiration_str[strlen("YYYYMMDDhhmmss")+1];
  time_to_str(&expiration_date, expiration_str, sizeof(expiration_str));
  err = mbedtls_x509write_crt_set_validity(&crt, curtime_str, expiration_str);
  if (err)
  {
    DEBUG_puts("Failed to set validity period\n");
    goto done;
  }

  err = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, 0);
  if (err)
  {
    DEBUG_puts("Failed to set basic constraints\n");
    goto done;
  }

  mbedtls_x509_sequence *csr_cur = &csr.subject_alt_names;
  san_list_head = mbedtls_calloc(1, sizeof(mbedtls_x509_san_list));
  if (!san_list_head)
  {
    DEBUG_puts("Failed to allocate memory for subject alt name list\n");
    goto done;
  }
  san_list_cur = san_list_head;
  san_list_cur->next = NULL;
  err = mbedtls_x509_parse_subject_alt_name(&csr_cur->buf, &san_list_cur->node);
  if (err)
  {
    DEBUG_puts("Failed to parse san from csr\n");
    goto done;
  }
  // Validate
  DEBUG_printf("1cupsSignCredentialsRequest: SAN %s", san_list_cur->node.san.unstructured_name.p);

  if (san_list_cur->node.type != MBEDTLS_X509_SAN_DNS_NAME || (cb)(common_name, \
      san_list_cur->node.san.unstructured_name.p, cb_data))
  {
    // Good subjectAltName
  }
  else
  {
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, _("Validation of subjectAltName in X.509 certificate request failed."), true);
    goto done;
  }

  csr_cur = csr_cur->next;
  
  while (csr_cur)
    {
      san_list_cur->next = mbedtls_calloc(1, sizeof(mbedtls_x509_san_list));
      if (!san_list_cur->next)
      {
        DEBUG_puts("Failed to allocate memory for subject alt name list\n");
        goto done;
      }
      san_list_cur = san_list_cur->next;
      san_list_cur->next = NULL;

      err = mbedtls_x509_parse_subject_alt_name(&csr_cur->buf, &san_list_cur->node);
      if (err)
      {
        DEBUG_puts("Failed to parse san from csr\n");
        goto done;
      }
      DEBUG_printf("1cupsSignCredentialsRequest: SAN %s", san_list_cur->node.san.unstructured_name.p);

      if (san_list_cur->node.type != MBEDTLS_X509_SAN_DNS_NAME || (cb)(common_name, \
          san_list_cur->node.san.unstructured_name.p, cb_data))
      {
        // Good subjectAltName
      }
      else
      {
        _cupsSetError(IPP_STATUS_ERROR_INTERNAL, _("Validation of subjectAltName in X.509 certificate request failed."), true);
        goto done;
      }
      
      csr_cur = csr_cur->next;
    }

  for (i = 0; i < 100; i ++)
  {
    unsigned type;			// Name type

    tempsize = sizeof(temp) - 1;
    if (mbedtls_x509_csr_get_subject_alt_name(csr, i, temp, &tempsize, &type, NULL) < 0)
      break;

    temp[tempsize] = '\0';

    DEBUG_printf("1cupsSignCredentialsRequest: SAN %s", temp);

    if (type != mbedtls_SAN_DNSNAME || (cb)(common_name, temp, cb_data))
    {
      // Good subjectAltName
//      mbedtls_x509_crt_set_subject_alt_name(crt, type, temp, (unsigned)strlen(temp), i ? mbedtls_FSAN_APPEND : mbedtls_FSAN_SET);
    }
    else
    {
      _cupsSetError(IPP_STATUS_ERROR_INTERNAL, _("Validation of subjectAltName in X.509 certificate request failed."), true);
      goto done;
    }
  }

  for (purpose = 0, i = 0; i < 100; i ++)
  {
    tempsize = sizeof(temp) - 1;
    if (mbedtls_x509_csr_get_key_purpose_oid(csr, i, temp, &tempsize, NULL) < 0)
      break;
    temp[tempsize] = '\0';

    if (!strcmp(temp, mbedtls_KP_TLS_WWW_SERVER))
      purpose |= CUPS_CREDPURPOSE_SERVER_AUTH;
    if (!strcmp(temp, mbedtls_KP_TLS_WWW_CLIENT))
      purpose |= CUPS_CREDPURPOSE_CLIENT_AUTH;
    if (!strcmp(temp, mbedtls_KP_CODE_SIGNING))
      purpose |= CUPS_CREDPURPOSE_CODE_SIGNING;
    if (!strcmp(temp, mbedtls_KP_EMAIL_PROTECTION))
      purpose |= CUPS_CREDPURPOSE_EMAIL_PROTECTION;
    if (!strcmp(temp, mbedtls_KP_OCSP_SIGNING))
      purpose |= CUPS_CREDPURPOSE_OCSP_SIGNING;
  }
  DEBUG_printf("1cupsSignCredentialsRequest: purpose=0x%04x", purpose);

  if (purpose & ~allowed_purpose)
  {
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, _("Bad keyUsage extension in X.509 certificate request."), true);
    goto done;
  }

#if 0
  if (purpose == 0 || (purpose & CUPS_CREDPURPOSE_SERVER_AUTH))
    mbedtls_x509_crt_set_key_purpose_oid(crt, mbedtls_KP_TLS_WWW_SERVER, 0);
  if (purpose & CUPS_CREDPURPOSE_CLIENT_AUTH)
    mbedtls_x509_crt_set_key_purpose_oid(crt, mbedtls_KP_TLS_WWW_CLIENT, 0);
  if (purpose & CUPS_CREDPURPOSE_CODE_SIGNING)
    mbedtls_x509_crt_set_key_purpose_oid(crt, mbedtls_KP_CODE_SIGNING, 0);
  if (purpose & CUPS_CREDPURPOSE_EMAIL_PROTECTION)
    mbedtls_x509_crt_set_key_purpose_oid(crt, mbedtls_KP_EMAIL_PROTECTION, 0);
  if (purpose & CUPS_CREDPURPOSE_OCSP_SIGNING)
    mbedtls_x509_crt_set_key_purpose_oid(crt, mbedtls_KP_OCSP_SIGNING, 0);
#endif // 0

  if (mbedtls_x509_csr_get_key_usage(csr, &mbedtls_usage, NULL) < 0)
  {
    // No keyUsage, use default for TLS...
    mbedtls_usage = mbedtls_KEY_DIGITAL_SIGNATURE | mbedtls_KEY_KEY_ENCIPHERMENT;
  }
  else
  {
    // Got keyUsage, convert to CUPS bitfield
    usage = 0;
    if (mbedtls_usage & mbedtls_KEY_DIGITAL_SIGNATURE)
      usage |= CUPS_CREDUSAGE_DIGITAL_SIGNATURE;
    if (mbedtls_usage & mbedtls_KEY_NON_REPUDIATION)
      usage |= CUPS_CREDUSAGE_NON_REPUDIATION;
    if (mbedtls_usage & mbedtls_KEY_KEY_ENCIPHERMENT)
      usage |= CUPS_CREDUSAGE_KEY_ENCIPHERMENT;
    if (mbedtls_usage & mbedtls_KEY_DATA_ENCIPHERMENT)
      usage |= CUPS_CREDUSAGE_DATA_ENCIPHERMENT;
    if (mbedtls_usage & mbedtls_KEY_KEY_AGREEMENT)
      usage |= CUPS_CREDUSAGE_KEY_AGREEMENT;
    if (mbedtls_usage & mbedtls_KEY_KEY_CERT_SIGN)
      usage |= CUPS_CREDUSAGE_KEY_CERT_SIGN;
    if (mbedtls_usage & mbedtls_KEY_CRL_SIGN)
      usage |= CUPS_CREDUSAGE_CRL_SIGN;
    if (mbedtls_usage & mbedtls_KEY_ENCIPHER_ONLY)
      usage |= CUPS_CREDUSAGE_ENCIPHER_ONLY;
    if (mbedtls_usage & mbedtls_KEY_DECIPHER_ONLY)
      usage |= CUPS_CREDUSAGE_DECIPHER_ONLY;

    DEBUG_printf("1cupsSignCredentialsRequest: usage=0x%04x", usage);

    if (usage & ~allowed_usage)
    {
      _cupsSetError(IPP_STATUS_ERROR_INTERNAL, _("Bad extKeyUsage extension in X.509 certificate request."), true);
      goto done;
    }
  }
//  mbedtls_x509_crt_set_key_usage(crt, mbedtls_usage);

  mbedtls_x509_crt_set_version(crt, 3);

  bytes = sizeof(buffer);
  if (mbedtls_x509_crt_get_key_id(crt, 0, buffer, &bytes) >= 0)
    mbedtls_x509_crt_set_subject_key_id(crt, buffer, bytes);

  // Try loading a root certificate...
  root_crtdata = cupsCopyCredentials(path, root_name ? root_name : "_site_");
  root_keydata = cupsCopyCredentialsKey(path, root_name ? root_name : "_site_");

  if (root_crtdata && root_keydata)
  {
    // Load root certificate...
    datum.data = (unsigned char *)root_crtdata;
    datum.size = strlen(root_crtdata);

    mbedtls_x509_crt_init(&root_crt);
    if (mbedtls_x509_crt_import(root_crt, &datum, mbedtls_X509_FMT_PEM) < 0)
    {
      // No good, clear it...
      mbedtls_x509_crt_deinit(root_crt);
      root_crt = NULL;
    }
    else
    {
      // Load root private key...
      datum.data = (unsigned char *)root_keydata;
      datum.size = strlen(root_keydata);

      mbedtls_x509_privkey_init(&root_key);
      if (mbedtls_x509_privkey_import(root_key, &datum, mbedtls_X509_FMT_PEM) < 0)
      {
        // No food, clear them...
        mbedtls_x509_privkey_deinit(root_key);
        root_key = NULL;

        mbedtls_x509_crt_deinit(root_crt);
        root_crt = NULL;
      }
    }
  }

  free(root_crtdata);
  free(root_keydata);

  if (!root_crt || !root_key)
  {
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, _("Unable to load X.509 CA certificate and private key."), true);
    goto done;
  }

  mbedtls_x509_crt_sign(crt, root_crt, root_key);

  // Save it...
  http_make_path(crtfile, sizeof(crtfile), path, common_name, "crt");

  bytes = sizeof(buffer);
  if ((err = mbedtls_x509_crt_export(crt, mbedtls_X509_FMT_PEM, buffer, &bytes)) < 0)
  {
    DEBUG_printf("1cupsSignCredentialsRequest: Unable to export public key and X.509 certificate: %s", mbedtls_strerror(err));
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, mbedtls_strerror(err), 0);
    goto done;
  }
  else if ((fp = cupsFileOpen(crtfile, "w")) != NULL)
  {
    DEBUG_printf("1cupsSignCredentialsRequest: Writing public key and X.509 certificate to \"%s\".", crtfile);
    cupsFileWrite(fp, (char *)buffer, bytes);
    cupsFileClose(fp);
  }
  else
  {
    DEBUG_printf("1cupsSignCredentialsRequest: Unable to create public key and X.509 certificate file \"%s\": %s", crtfile, strerror(errno));
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, strerror(errno), 0);
    goto done;
  }

  DEBUG_puts("1cupsSignCredentialsRequest: Successfully created credentials.");

  ret = true;

  // Cleanup...
  done:

  if (csr)
    mbedtls_x509_csr_deinit(csr);
  if (crt)
    mbedtls_x509_crt_deinit(crt);
  if (root_crt)
    mbedtls_x509_crt_deinit(root_crt);
  if (root_key)
    mbedtls_x509_privkey_deinit(root_key);

  return (ret);
}

//
// 'httpCopyPeerCredentials()' - Copy the credentials associated with the peer in an encrypted connection.
//

char *					// O - Credentials string
httpCopyPeerCredentials(http_t *http)	// I - HTTP connection
{
  char		*credentials = NULL;	// Return value
  size_t	alloc_creds = 0;	// Allocated size
  const mbedtls_x509_crt *crt = NULL;		// Certificates
  int err;    // Error code
  char error_str[256];
  *error_str = '\0';

  DEBUG_printf("httpCopyPeerCredentials(http=%p)", http);

  if (http && http->tls)
  {
    // Get the list of peer certificates...
    crt = mbedtls_ssl_get_peer_cert(http->tls);

    DEBUG_printf("1httpCopyPeerCredentials: crt=%p", crt);

    if (crt)
    {
      // Add them to the credentials string...
      mbedtls_x509_crt *cur = crt;
      while (cur)
      {
        // Expand credentials string...
        char *pem = NULL;    // PEM-encoded certificate
        size_t	pemsize = 0;		// Length of PEM-encoded certificate
        size_t  pemsize2 = 0;    // For checking if we actually wrote pemsize bytes

        err = mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT, crt->raw.p, crt->raw.len, NULL, 0, &pemsize);
        if (err)
        {
          mbedtls_strerror(err, error_str, sizeof(error_str));
          DEBUG_printf("Failed to calculate PEM buffer size: %s\n", error_str);
          if (credentials)
            free(credentials);
          return NULL;
        }
        pem = malloc(pemsize);
        if (!pem)
        {
          DEBUG_puts("Failed to allocate PEM buffer\n");
          if (credentials)
            free(credentials);
          return NULL;
        }
        err = mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT, crt->raw.p, crt->raw.len, pem, pemsize, &pemsize2);
        if (err)
        {
          mbedtls_strerror(err, error_str, sizeof(error_str));
          DEBUG_printf("Failed to write PEM buffer: %s\n", error_str);
          if (credentials)
            free(credentials);
          free(pem);
          return NULL;
        }
        if (pemsize != pemsize2)
        {
          DEBUG_printf("Calculated size does not match written size: Calc: %ul Written: %ul\n", pemsize, pemsize2);
          if (credentials)
            free(credentials);
          free(pem);
          return NULL;
        }

        if (pem && (credentials = realloc(credentials, alloc_creds + (pemsize = strlen(pem)) + 1)) != NULL)
        {
          // Copy PEM-encoded data...
          memcpy(credentials + alloc_creds, pem, pemsize);
          credentials[alloc_creds + pemsize] = '\0';
          alloc_creds += pemsize;
        }

        free(pem);
        cur = cur->next;
      }
    }
  }

  DEBUG_printf("1httpCopyPeerCredentials: Returning %p.", credentials);

  return (credentials);
}


//
// '_httpCreateCredentials()' - Create credentials in the internal format.
//

_http_tls_credentials_t *		// O - Internal credentials
_httpCreateCredentials(
    const char *credentials,		// I - Credentials string
    const char *key)			// I - Private key string
{
  int			err;		// Result from Mbed TLS
  char error_str[256];
  *error_str = '\0';
  _http_tls_credentials_t *hcreds;	// Credentials
  mbedtls_entropy_context entropy;  // Entropy and ctr drbg contexts are needed for pseudo-rng
  mbedtls_ctr_drbg_context ctr_drbg;  // These will be deprecated in Mbed TLS 4.0.0

  DEBUG_printf("_httpCreateCredentials(credentials=\"%s\", key=\"%s\")", credentials, key);

  if ((hcreds = calloc(1, sizeof(_http_tls_credentials_t))) == NULL)
    return (NULL);

  mbedtls_x509_crt_init(&hcreds->crt);
  mbedtls_pk_init(&hcreds->pkctx);
  err = psa_crypto_init();
  if (err)
  {
    mbedtls_strerror(err, error_str, sizeof(error_str));
    DEBUG_printf("Failed to init psa crypto: %s\n", error_str);
  }

  // Seed the PRNG
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)
  if (err)
  {
    mbedtls_strerror(err, error_str, sizeof(error_str));
    DEBUG_printf("Failed to seed PRNG: %s\n", error_str);
    goto done;
  }

  hcreds->use  = 1;

  if (credentials && *credentials && key && *key)
  {
    uint32_t creds_len = strnlen(credentials, MAX_CREDS_STR_LEN) + 1;
    err = mbedtls_x509_crt_parse(&hcreds->crt, credentials, creds_len);
    if (err)
    {
      mbedtls_strerror(err, error_str, sizeof(error_str));
      DEBUG_printf("Failed to parse credentials: %s\n", error_str);
    }

    err = mbedtls_pk_parse_key(&hcreds->pkctx, (unsigned char *)key, strlen(key) + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (err)
    {
      mbedtls_strerror(err, error_str, sizeof(error_str));
      DEBUG_printf("Failed to parse key: %s\n", error_str);
    }
  }

  DEBUG_printf("1_httpCreateCredentials: Returning %p.", hcreds);

  return (hcreds);
}


//
// '_httpFreeCredentials()' - Free internal credentials.
//

void
_httpFreeCredentials(
    _http_tls_credentials_t *hcreds)	// I - Internal credentials
{
  if (!hcreds)
    return;

  if (hcreds->use)
    hcreds->use --;

  if (hcreds->use)
    return;

  mbedtls_x509_crt_free(&hcreds->crt);
  mbedtls_pk_free(&hcreds->pkctx);
  free(hcreds);
}


//
// 'httpGetSecurity()' - Get the TLS version and cipher suite used by a connection.
//
// This function gets the TLS version and cipher suite being used by a
// connection, if any.  The string is copied to "buffer" and is of the form
// "TLS/major.minor CipherSuite".  If not encrypted, the buffer is cleared to
// the empty string.
//

const char *				// O - Security information or `NULL` if not encrypted
httpGetSecurity(http_t *http,		// I - HTTP connection
                char   *buffer,		// I - String buffer
                size_t bufsize)		// I - Size of buffer
{
  const char	*cipherName;		// Cipher suite name


  // Range check input...
  if (buffer)
    *buffer = '\0';

  if (!http || !http->tls || !buffer || bufsize < 16)
    return (NULL);

  // Record the TLS version and cipher suite...
  cipherName = mbedtls_ssl_get_ciphersuite_name(mbedtls_ssl_session_get_ciphersuite_id(&http->tls->session));

  switch (mbedtls_ssl_get_version_number(http->tls))
  {
    default :
        snprintf(buffer, bufsize, "TLS/?.? %s", cipherName);
        break;

    case MBEDTLS_SSL_VERSION_TLS1_2 :
        snprintf(buffer, bufsize, "TLS/1.2 %s", cipherName);
        break;

    case MBEDTLS_SSL_VERSION_TLS1_3 :
        snprintf(buffer, bufsize, "TLS/1.3 %s", cipherName);
        break;
  }

  return (buffer);
}


//
// '_httpTLSInitialize()' - Initialize the TLS stack.
//

void
_httpTLSInitialize(void)
{
  // Mbed TLS does not require global TLS initialization
}


//
// '_httpTLSPending()' - Return the number of pending TLS-encrypted bytes.
//

size_t					// O - Bytes available
_httpTLSPending(http_t *http)		// I - HTTP connection
{
  return (mbedtls_ssl_get_bytes_avail(http->tls));
}


//
// '_httpTLSRead()' - Read from a SSL/TLS connection.
//

int					// O - Bytes read
_httpTLSRead(http_t *http,		// I - Connection to server
	     char   *buf,		// I - Buffer to store data
	     int    len)		// I - Length of buffer
{
  ssize_t	result;			// Return value

  result = mbedtls_ssl_read(http->tls, buf, (size_t)len);

  if (result < 0)
  {
    // Convert Mbed TLS error to errno value...
    switch (result)
    {
      case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS :
      case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS :
      case MBEDTLS_ERR_SSL_WANT_READ :
      case MBEDTLS_ERR_SSL_WANT_WRITE :
        errno = EAGAIN;
        break;
      case MBEDTLS_ERR_SSL_CLIENT_RECONNECT :
      case MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA : // early data not supported
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY :
      default :
          errno = EPIPE;
          break;
    }

    result = -1;
  }

  return ((int)result);
}


//
// '_httpTLSStart()' - Set up SSL/TLS support on a connection.
//

bool					// O - `true` on success, `false` on failure
_httpTLSStart(http_t *http)		// I - Connection to server
{
  const char		*keypath;	// Certificate store path
  char			hostname[256],	// Hostname
			*hostptr;	// Pointer into hostname
  int			status;		// Status of handshake
  _http_tls_credentials_t *credentials = NULL;
					// TLS credentials
  char			priority_string[2048];
					// Priority string
  int			version;	// Current version
  double		old_timeout;	// Old timeout value
  http_timeout_cb_t	old_cb;		// Old timeout callback
  void			*old_data;	// Old timeout data
  _cups_globals_t	*cg = _cupsGlobals();
					// Per-thread globals
  static const int const versions[] =// SSL/TLS versions
  {
    MBEDTLS_SSL_VERSION_UNKNOWN,
    MBEDTLS_SSL_VERSION_TLS1_2,
    MBEDTLS_SSL_VERSION_TLS1_3
  };
  mbedtls_ssl_config conf;  // SSL Config
  char error_str[256];
  *error_str = '\0';
  mbedtls_entropy_context entropy;  // Entropy and ctr drbg contexts are needed for pseudo-rng
  mbedtls_ctr_drbg_context ctr_drbg;  // These will be deprecated in Mbed TLS 4.0.0

  DEBUG_printf("3_httpTLSStart(http=%p)", http);

  if (!cg->client_conf_loaded)
  {
    DEBUG_puts("4_httpTLSStart: Setting defaults.");
    _cupsSetDefaults();
    DEBUG_printf("4_httpTLSStart: tls_options=%x", tls_options);
  }

  cupsMutexLock(&tls_mutex);
  keypath = tls_keypath;
  cupsMutexUnlock(&tls_mutex);

  if (http->mode == _HTTP_MODE_SERVER && !keypath)
  {
    DEBUG_puts("4_httpTLSStart: cupsSetServerCredentials not called.");
    http->error  = errno = EINVAL;
    http->status = HTTP_STATUS_ERROR;
    _cupsSetError(IPP_STATUS_ERROR_INTERNAL, _("Server credentials not set."), true);

    return (false);
  }

  status = psa_crypto_init;

  // Seed the PRNG
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  status = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
  if (status)
  {
    mbedtls_strerror(status, error_str, sizeof(error_str));
    DEBUG_printf("Failed to seed PRNG: %s\n", error_str);
    return false;
  }
  status = psa_crypto_init();
  if (status)
  {
    mbedtls_strerror(status, error_str, sizeof(error_str));
    DEBUG_printf("Failed to init PSA crypto: %s\n", error_str);
    return false;
  }
  
  mbedtls_ssl_init(http->tls);
  mbedtls_ssl_config_init(&conf);
  status = mbedtls_ssl_config_defaults(&conf, http->mode == _HTTP_MODE_CLIENT ? \
  MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if (!status)
  {
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  }

  if (status)
  {
    http->error  = EIO;
    http->status = HTTP_STATUS_ERROR;

    mbedtls_strerror(status, error_str, sizeof(error_str));
    DEBUG_printf("4_httpTLSStart: Unable to initialize common TLS parameters: %s", error_str);
    _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, error_str, 0);

    mbedtls_ssl_free(http->tls);
    mbedtls_ssl_config_free(conf);
    http->tls = NULL;

    return (false);
  }

  if (http->mode == _HTTP_MODE_CLIENT)
  {
    // Client: get the hostname to use for TLS...
    if (httpAddrIsLocalhost(http->hostaddr))
    {
      cupsCopyString(hostname, "localhost", sizeof(hostname));
    }
    else
    {
      // Otherwise make sure the hostname we have does not end in a trailing dot.
      cupsCopyString(hostname, http->hostname, sizeof(hostname));
      if ((hostptr = hostname + strlen(hostname) - 1) >= hostname && *hostptr == '.')
	*hostptr = '\0';
    }

    if (!status && (credentials = _httpUseCredentials(cg->credentials)) == NULL)
    {
      if ((credentials = _httpCreateCredentials(NULL, NULL)) == NULL)
        status = -1;
    }
  }
  else
  {
    // Server: get certificate and private key...
    char	crtfile[1024],		// Certificate file
		keyfile[1024];		// Private key file
    const char	*cn = NULL,		// Common name to lookup
		*cnptr;			// Pointer into common name
    bool	have_creds = false;	// Have credentials?

    cupsMutexLock(&tls_mutex);

    if (!tls_common_name)
    {
      cupsMutexUnlock(&tls_mutex);

      if (http->fields[HTTP_FIELD_HOST])
      {
	// Use hostname for TLS upgrade...
	cupsCopyString(hostname, http->fields[HTTP_FIELD_HOST], sizeof(hostname));
      }
      else
      {
	// Resolve hostname from connection address...
	http_addr_t	addr;		// Connection address
	socklen_t	addrlen;	// Length of address

	addrlen = sizeof(addr);
	if (getsockname(http->fd, (struct sockaddr *)&addr, &addrlen))
	{
	  DEBUG_printf("4_httpTLSStart: Unable to get socket address: %s", strerror(errno));
	  hostname[0] = '\0';
	}
	else if (httpAddrIsLocalhost(&addr))
	{
	  hostname[0] = '\0';
	}
	else
	{
	  httpAddrLookup(&addr, hostname, sizeof(hostname));
	  DEBUG_printf("4_httpTLSStart: Resolved socket address to \"%s\".", hostname);
	}
      }

      if (isdigit(hostname[0] & 255) || hostname[0] == '[')
	hostname[0] = '\0';		// Don't allow numeric addresses

      if (hostname[0])
	cn = hostname;

      cupsMutexLock(&tls_mutex);
    }

    if (!cn)
      cn = tls_common_name;

    DEBUG_printf("4_httpTLSStart: Using common name \"%s\"...", cn);

    if (cn)
    {
      // First look in the CUPS keystore...
      http_make_path(crtfile, sizeof(crtfile), tls_keypath, cn, "crt");
      http_make_path(keyfile, sizeof(keyfile), tls_keypath, cn, "key");

      if (access(crtfile, R_OK) || access(keyfile, R_OK))
      {
        // No CUPS-managed certs, look for CA certs...
        char cacrtfile[1024], cakeyfile[1024];	// CA cert files

        // change these paths
        snprintf(cacrtfile, sizeof(cacrtfile), "/etc/letsencrypt/live/%s/fullchain.pem", cn);
        snprintf(cakeyfile, sizeof(cakeyfile), "/etc/letsencrypt/live/%s/privkey.pem", cn);

        if ((access(cacrtfile, R_OK) || access(cakeyfile, R_OK)) && (cnptr = strchr(cn, '.')) != NULL)
        {
          // Try just domain name...
          cnptr ++;
          if (strchr(cnptr, '.'))
          {
            snprintf(cacrtfile, sizeof(cacrtfile), "/etc/letsencrypt/live/%s/fullchain.pem", cnptr);
            snprintf(cakeyfile, sizeof(cakeyfile), "/etc/letsencrypt/live/%s/privkey.pem", cnptr);
          }
        }

        if (!access(cacrtfile, R_OK) && !access(cakeyfile, R_OK))
        {
          // Use the CA certs...
          cupsCopyString(crtfile, cacrtfile, sizeof(crtfile));
          cupsCopyString(keyfile, cakeyfile, sizeof(keyfile));
        }
      }

      have_creds = !access(crtfile, R_OK) && !access(keyfile, R_OK);
    }

    if (!have_creds && tls_auto_create && cn)
    {
      DEBUG_printf("4_httpTLSStart: Auto-create credentials for \"%s\".", cn);

      if (!cupsCreateCredentials(tls_keypath, false, CUPS_CREDPURPOSE_SERVER_AUTH, CUPS_CREDTYPE_DEFAULT, CUPS_CREDUSAGE_DEFAULT_TLS, NULL, NULL, NULL, NULL, NULL, cn, /*email*/NULL, 0, NULL, NULL, time(NULL) + 3650 * 86400))
      {
	DEBUG_puts("4_httpTLSStart: cupsCreateCredentials failed.");
	http->error  = errno = EINVAL;
	http->status = HTTP_STATUS_ERROR;
	_cupsSetError(IPP_STATUS_ERROR_INTERNAL, _("Unable to create server credentials."), true);
	cupsMutexUnlock(&tls_mutex);

  mbedtls_ssl_free(http->tls);
  mbedtls_ssl_config_free(conf);
  http->tls = NULL;
	return (false);
      }
    }

    cupsMutexUnlock(&tls_mutex);

    DEBUG_printf("4_httpTLSStart: Using certificate \"%s\" and private key \"%s\".", crtfile, keyfile);

    if ((credentials = calloc(1, sizeof(_http_tls_credentials_t))) == NULL)
    {
      DEBUG_puts("4_httpTLSStart: cupsCreateCredentials failed.");
      http->error  = errno = EINVAL;
      http->status = HTTP_STATUS_ERROR;
      _cupsSetError(IPP_STATUS_ERROR_INTERNAL, _("Unable to create server credentials."), true);
      cupsMutexUnlock(&tls_mutex);
      mbedtls_ssl_free(http->tls);
      mbedtls_ssl_config_free(conf);
      http->tls = NULL;
      return (false);
    }

    credentials->use = 1;
    mbedtls_x509_crt_init(&credentials->crt);
    mbedtls_pk_init(&credentials->pkctx);
    status = mbedtls_pk_parse_keyfile(&credentials->pkctx, keyfile, NULL, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (!status)
      status = mbedtls_x509_crt_parse_file(&credentials->crt, crtfile);
  }

  if (!status && credentials)
      status = mbedtls_ssl_conf_own_cert(&conf, &credentials->crt, &credentials->pkctx);

  if (status)
  {
    http->error  = EIO;
    http->status = HTTP_STATUS_ERROR;

    mbedtls_strerror(status, error_str, sizeof(error_str));
    DEBUG_printf("4_httpTLSStart: Unable to complete client/server setup: %s", error_str);
    _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, error_str, 0);

    mbedtls_ssl_free(http->tls);
    mbedtls_ssl_config_free(&conf);
    _httpFreeCredentials(credentials);
    http->tls = NULL;

    return (false);
  }

  switch (tls_min_version)
  {
  default:
  case _HTTP_TLS_1_2:
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    break;
  case _HTTP_TLS_1_3:
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
    break;
  }

  switch (tls_max_version)
  {
  case _HTTP_TLS_1_2:
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    break;
  default:
  case _HTTP_TLS_1_3:
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
    break;
  }


  if (tls_options & _HTTP_TLS_DENY_CBC)
    // mbedtls does not have a blacklist for ciphersuites

  // Finish setup
  status = mbedtls_ssl_setup(http->tls, &conf);
  if (status)
  {
    mbedtls_strerror(status, error_str, sizeof(error_str));
    DEBUG_printf("Failed ssl setup: %s\n", error_str);
    goto 
  }
  status = mbedtls_ssl_set_hostname(http->tls, hostname);
  if (status)
  {
    mbedtls_strerror(status, error_str, sizeof(error_str));
    DEBUG_printf("Failed to set hostname: %s\n", error_str);
  }

  // TODO: look into using httpWait as recv_timeout
  mbedtls_ssl_set_bio(http->tls, (void *)http, mbedtls_http_write, mbedtls_http_read, NULL);

  // Enforce a minimum timeout of 10 seconds for the TLS handshake...
  old_timeout  = http->timeout_value;
  old_cb       = http->timeout_cb;
  old_data     = http->timeout_data;

  if (!old_cb || old_timeout < 10.0)
  {
    DEBUG_puts("4_httpTLSStart: Setting timeout to 10 seconds.");
    httpSetTimeout(http, 10.0, NULL, NULL);
  }

  // Do the TLS handshake...

  while ((status = mbedtls_ssl_handshake(http->tls)) != 0)
  {

    mbedtls_strerror(status, error_str, sizeof(error_str));
    DEBUG_printf("5_httpStartTLS: mbedtls_ssl_handshake returned %d (%s)", status, error_str);

    if (status != MBEDTLS_ERR_SSL_WANT_READ && status != MBEDTLS_ERR_SSL_WANT_WRITE && \
        status != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS && status != MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS)
    {
      http->error  = EIO;
      http->status = HTTP_STATUS_ERROR;
      _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, gnutls_strerror(status), 0);

      mbedtls_ssl_free(http->tls);
      mbedtls_ssl_config_free(&conf);
      _httpFreeCredentials(credentials);
      http->tls = NULL;

      httpSetTimeout(http, old_timeout, old_cb, old_data);
      return false;
    }
  }

  // Restore the previous timeout settings...
  httpSetTimeout(http, old_timeout, old_cb, old_data);

  http->tls_credentials = credentials;

  return (true);
}


//
// '_httpTLSStop()' - Shut down SSL/TLS on a connection.
//

void
_httpTLSStop(http_t *http)		// I - Connection to server
{
  int	error;				// Error code
  char error_str[256];
  *error_str = '\0';

  while ((error = mbedtls_ssl_close_notify(http->tls)) < 0)
  {
    if (error != MBEDTLS_ERR_SSL_WANT_READ &&
        error != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
      mbedtls_strerror(error, error_str, sizeof(error_str));
      DEBUG_printf("SSL close notify returned: %s\n", error_str);
      _cupsSetError(IPP_STATUS_ERROR_INTERNAL, error_str, 0);
    }
  }

  mbedtls_ssl_config_free(http->tls->conf);
  mbedtls_ssl_free(http->tls);
  http->tls = NULL;

  if (http->tls_credentials)
  {
    _httpFreeCredentials(http->tls_credentials);
    http->tls_credentials = NULL;
  }
}


//
// '_httpTLSWrite()' - Write to a SSL/TLS connection.
//

int					// O - Bytes written
_httpTLSWrite(http_t     *http,		// I - Connection to server
	      const char *buf,		// I - Buffer holding data
	      int        len)		// I - Length of buffer
{
  ssize_t	result;			// Return value


  DEBUG_printf("5_httpTLSWrite(http=%p, buf=%p, len=%d)", http, buf, len);

  result = mbedtls_ssl_write(http->tls, buf, (size_t)len);

  if (result < 0)
  {
    // Convert Mbed TLS error to errno value...
    switch (result)
    {
      case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS :
      case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS :
      case MBEDTLS_ERR_SSL_WANT_READ :
      case MBEDTLS_ERR_SSL_WANT_WRITE :
        errno = EAGAIN;
        break;
      case MBEDTLS_ERR_SSL_CLIENT_RECONNECT :
      case MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA : // early data not supported
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY :
      default :
        errno = EPIPE;
        break;
    }

    result = -1;
  }

  DEBUG_printf("5_httpTLSWrite: Returning %d.", (int)result);

  return ((int)result);
}


//
// '_httpUseCredentials()' - Increment the use count for internal credentials.
//

_http_tls_credentials_t *		// O - Internal credentials
_httpUseCredentials(
    _http_tls_credentials_t *hcreds)	// I - Internal credentials
{
  if (hcreds)
    hcreds->use ++;

  return (hcreds);
}


//
// 'mbedtls_create_key()' - Create a PSA key pair for exporting, assumes psa_crypto_init() has been called
//

static psa_status_t		// O - Status
mbedtls_create_key(psa_key_attributes_t *key_atts, // I - Key attributes
                   psa_key_id_t *key, // O - Key id
                   cups_credtype_t type) // I - Type of key
{
  int ret = PSA_ERROR_CORRUPTION_DETECTED;
  psa_usage_t usage_flags = PSA_KEY_USAGE_EXPORT;

  switch (type)
  {
    case CUPS_CREDTYPE_ECDSA_P256_SHA256 :
  psa_set_key_type(key_atts, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
  psa_set_key_algorithm(key_atts, PSA_ALG_ECDSA(PSA_ALG_SHA256));
  psa_set_key_bits(key_atts, 256);
	break;

    case CUPS_CREDTYPE_ECDSA_P384_SHA256 :
  psa_set_key_type(key_atts, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
  psa_set_key_algorithm(key_atts, PSA_ALG_ECDSA(PSA_ALG_SHA256));
  psa_set_key_bits(key_atts, 384);
	break;

    case CUPS_CREDTYPE_ECDSA_P521_SHA256 :
	psa_set_key_type(key_atts, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
  psa_set_key_algorithm(key_atts, PSA_ALG_ECDSA(PSA_ALG_SHA256));
  psa_set_key_bits(key_atts, 521);
	break;

    case CUPS_CREDTYPE_RSA_2048_SHA256 :
	psa_set_key_type(key_atts, PSA_KEY_TYPE_RSA_KEY_PAIR);
  psa_set_key_algorithm(key_atts, PSA_ALG_PKCS1V15(PSA_ALG_SHA256));
  psa_set_key_bits(key_atts, 2048);
	break;

    default :
    case CUPS_CREDTYPE_RSA_3072_SHA256 :
	psa_set_key_type(key_atts, PSA_KEY_TYPE_RSA_KEY_PAIR);
  psa_set_key_algorithm(key_atts, PSA_ALG_PKCS1V15(PSA_ALG_SHA256));
  psa_set_key_bits(key_atts, 3072);
	break;

    case CUPS_CREDTYPE_RSA_4096_SHA256 :
	psa_set_key_type(key_atts, PSA_KEY_TYPE_RSA_KEY_PAIR);
  psa_set_key_algorithm(key_atts, PSA_ALG_PKCS1V15(PSA_ALG_SHA256));
  psa_set_key_bits(key_atts, 4096);
	break;
  }

  ret = psa_generate_key(key_atts, key);
  if (ret != 0)
  {
    DEBUG_puts("Failed to generate key\n");
  }

  return ret;
}


//
// 'mbedtls_x509write_csr_set_ext_key_usage()' - Write an asn1 sequence of extended key usage
//                                               values to the extended key usage extension
//

int mbedtls_x509write_csr_set_ext_key_usage(mbedtls_x509write_csr *reqs,
                                            const mbedtls_asn1_sequence *exts)
{
    unsigned char buf[256];
    unsigned char *c = buf + sizeof(buf);
    int ret;
    size_t len = 0;
    const mbedtls_asn1_sequence *last_ext = NULL;
    const mbedtls_asn1_sequence *ext;

    memset(buf, 0, sizeof(buf));

    /* We need at least one extension: SEQUENCE SIZE (1..MAX) OF KeyPurposeId */
    if (exts == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    /* Iterate over exts backwards, so we write them out in the requested order */
    while (last_ext != exts) {
        for (ext = exts; ext->next != last_ext; ext = ext->next) {
        }
        if (ext->buf.tag != MBEDTLS_ASN1_OID) {
            return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        }
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf, ext->buf.p, ext->buf.len));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, ext->buf.len));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_OID));
        last_ext = ext;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(&c, buf,
                                                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return mbedtls_x509write_csr_set_extension(ctx,
                                               MBEDTLS_OID_EXTENDED_KEY_USAGE,
                                               MBEDTLS_OID_SIZE(MBEDTLS_OID_EXTENDED_KEY_USAGE),
                                               1, c, len);
}

void mbedtls_x509_time_t(mbedtls_x509_time *in, time_t *tt)
{
  // Assume non-null ptrs
  struct tm tm;
  tm.tm_year = in->year - 1900;
  tm.tm_mon = in->mon - 1;
  tm.tm_mday = in->day;
  tm.tm_hour = in->hour;
  tm.tm_min = now->min;
  tm.tm_sec = in->sec;
  tm.tm_isdst = -1;
  *tt = mktime(&tm);
}


int mbedtls_http_read(void *ctx, unsigned char *buf, size_t len)
{
  http_t	*http;			// HTTP connection
  ssize_t	bytes;			// Bytes read

  DEBUG_printf("5mbedtls_http_read(ptr=%p, data=%p, length=%d)", ptr, data, (int)length);

  http = (http_t *)ctx;

  if (!http->blocking || http->timeout_value > 0.0)
  {
    // Make sure we have data before we read...
    while (!_httpWait(http, http->wait_value, 0))
    {
      if (http->timeout_cb && (*http->timeout_cb)(http, http->timeout_data))
	continue;

      http->error = ETIMEDOUT;
      return MBEDTLS_ERR_SSL_TIMEOUT;
    }
  }

  bytes = recv(http->fd, data, length, 0);
  DEBUG_printf("5mbedtls_http_read: bytes=%d", (int)bytes);

  if (bytes >= 0)
    return bytes;

  switch (errno)
  {
    case EAGAIN:
      return MBEDTLS_ERR_SSL_WANT_READ;
    case ETIMEDOUT:
      return MBEDTLS_ERR_SSL_TIMEOUT;
    case EOPNOTSUPP:
      return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    case ENOBUFS:
      return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    case ENOMEM:
      return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    default:
      return -1; 
  }
}

int mbedtls_http_write(void *ctx, unsigned char *buf, size_t len)
{
  ssize_t bytes;			// Bytes written

  DEBUG_printf("5mbedtls_http_write(ptr=%p, data=%p, length=%d)", ptr, data, (int)length);
  bytes = send(((http_t *)ctx)->fd, data, length, 0);
  DEBUG_printf("5mbedtls_http_write: bytes=%d", (int)bytes);

  if (bytes >= 0)
    return (bytes);

  switch (errno)
  {
    case EAGAIN:
      return MBEDTLS_ERR_SSL_WANT_READ;
    case ETIMEDOUT:
      return MBEDTLS_ERR_SSL_TIMEOUT;
    case EOPNOTSUPP:
      return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    case ENOBUFS:
      return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    case ENOMEM:
      return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    default:
      return -1; 
  }
}

//
// 'mbedtls_load_crl()' - Load the certificate revocation list, if any.
//

static void
mbedtls_load_crl(void)
{
  cupsMutexLock(&tls_mutex);

  mbedtls_x509_crl_init(&tls_crl);

  cups_file_t		*fp;		// CRL file
  char		filename[1024],	// site.crl
    line[256];	// Base64-encoded line
  unsigned char	*data = NULL;	// Buffer for cert data
  size_t		alloc_data = 0,	// Bytes allocated
    num_data = 0;	// Bytes used
  size_t		decoded;	// Bytes decoded
  mbedtls_datum_t	datum;		// Data record


  http_make_path(filename, sizeof(filename), CUPS_SERVERROOT, "site", "crl");

  if ((int err = mbedtls_x509_crl_parse_file(&tls_crl, filename)) != 0)
  {
    char error_str[256];
    *error_str = '\0';
    mbedtls_strerror(err, error_str, sizeof(error_str));
    DEBUG_printf("Unable to load crl: %s", error_str);
  }

  cupsMutexUnlock(&tls_mutex);
}