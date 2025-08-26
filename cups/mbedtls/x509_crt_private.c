/*
 *  X.509 certificate parsing and verification
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 *  [SIRO] https://cabforum.org/wp-content/uploads/Chunghwatelecom201503cabforumV4.pdf
 */

#include "x509_crt_private.h"

/*
 * Like memcmp, but case-insensitive and always returns -1 if different
 */
static int x509_memcasecmp(const void *s1, const void *s2, size_t len)
{
    size_t i;
    unsigned char diff;
    const unsigned char *n1 = s1, *n2 = s2;

    for (i = 0; i < len; i++) {
        diff = n1[i] ^ n2[i];

        if (diff == 0) {
            continue;
        }

        if (diff == 32 &&
            ((n1[i] >= 'a' && n1[i] <= 'z') ||
             (n1[i] >= 'A' && n1[i] <= 'Z'))) {
            continue;
        }

        return -1;
    }

    return 0;
}

/*
 * Return 0 if name matches wildcard, -1 otherwise
 */
static int x509_check_wildcard(const char *cn, const mbedtls_x509_buf *name)
{
    size_t i;
    size_t cn_idx = 0, cn_len = strlen(cn);

    /* We can't have a match if there is no wildcard to match */
    if (name->len < 3 || name->p[0] != '*' || name->p[1] != '.') {
        return -1;
    }

    for (i = 0; i < cn_len; ++i) {
        if (cn[i] == '.') {
            cn_idx = i;
            break;
        }
    }

    if (cn_idx == 0) {
        return -1;
    }

    if (cn_len - cn_idx == name->len - 1 &&
        x509_memcasecmp(name->p + 1, cn + cn_idx, name->len - 1) == 0) {
        return 0;
    }

    return -1;
}

/*
 * Check for CN match
 */
static int x509_crt_check_cn(const mbedtls_x509_buf *name,
                             const char *cn, size_t cn_len)
{
    /* try exact match */
    if (name->len == cn_len &&
        x509_memcasecmp(cn, name->p, cn_len) == 0) {
        return 0;
    }

    /* try wildcard match */
    if (x509_check_wildcard(cn, name) == 0) {
        return 0;
    }

    return -1;
}

static int x509_crt_check_san_ip(const mbedtls_x509_sequence *san,
                                 const char *cn, size_t cn_len)
{
    uint32_t ip[4];
    cn_len = mbedtls_x509_crt_parse_cn_inet_pton(cn, ip);
    if (cn_len == 0) {
        return -1;
    }

    for (const mbedtls_x509_sequence *cur = san; cur != NULL; cur = cur->next) {
        const unsigned char san_type = (unsigned char) cur->buf.tag &
                                       MBEDTLS_ASN1_TAG_VALUE_MASK;
        if (san_type == MBEDTLS_X509_SAN_IP_ADDRESS &&
            cur->buf.len == cn_len && memcmp(cur->buf.p, ip, cn_len) == 0) {
            return 0;
        }
    }

    return -1;
}

static int x509_crt_check_san_uri(const mbedtls_x509_sequence *san,
                                  const char *cn, size_t cn_len)
{
    for (const mbedtls_x509_sequence *cur = san; cur != NULL; cur = cur->next) {
        const unsigned char san_type = (unsigned char) cur->buf.tag &
                                       MBEDTLS_ASN1_TAG_VALUE_MASK;
        if (san_type == MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER &&
            cur->buf.len == cn_len && memcmp(cur->buf.p, cn, cn_len) == 0) {
            return 0;
        }
    }

    return -1;
}

/*
 * Check for SAN match, see RFC 5280 Section 4.2.1.6
 */
static int x509_crt_check_san(const mbedtls_x509_sequence *san,
                              const char *cn, size_t cn_len)
{
    int san_ip = 0;
    int san_uri = 0;
    /* Prioritize DNS name over other subtypes due to popularity */
    for (const mbedtls_x509_sequence *cur = san; cur != NULL; cur = cur->next) {
        switch ((unsigned char) cur->buf.tag & MBEDTLS_ASN1_TAG_VALUE_MASK) {
            case MBEDTLS_X509_SAN_DNS_NAME:
                if (x509_crt_check_cn(&cur->buf, cn, cn_len) == 0) {
                    return 0;
                }
                break;
            case MBEDTLS_X509_SAN_IP_ADDRESS:
                san_ip = 1;
                break;
            case MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER:
                san_uri = 1;
                break;
            /* (We may handle other types here later.) */
            default: /* Unrecognized type */
                break;
        }
    }
    if (san_ip) {
        if (x509_crt_check_san_ip(san, cn, cn_len) == 0) {
            return 0;
        }
    }
    if (san_uri) {
        if (x509_crt_check_san_uri(san, cn, cn_len) == 0) {
            return 0;
        }
    }

    return -1;
}

/*
 * Verify the requested CN - only call this if cn is not NULL!
 */
void x509_crt_verify_name(const mbedtls_x509_crt *crt,
                          const char *cn,
                          uint32_t *flags)
{
    const mbedtls_x509_name *name;
    size_t cn_len = strlen(cn);

    if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
        if (x509_crt_check_san(&crt->subject_alt_names, cn, cn_len) == 0) {
            return;
        }
    } else {
        for (name = &crt->subject; name != NULL; name = name->next) {
            if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0 &&
                x509_crt_check_cn(&name->val, cn, cn_len) == 0) {
                return;
            }
        }

    }

    *flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
}