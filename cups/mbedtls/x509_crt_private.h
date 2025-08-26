/**
 * \file x509_crt_private.h
 *
 * \brief X.509 certificate parsing and writing private functions
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_X509_CRT_PRIVATE_H
#define MBEDTLS_X509_CRT_PRIVATE_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

#ifdef __cplusplus
extern "C" {
#endif

void x509_crt_verify_name(const mbedtls_x509_crt *crt,
                          const char *cn,
                          uint32_t *flags);
#ifdef __cplusplus
}
#endif

#endif // !MBEDTLS_X509_CRT_PRIVATE_H