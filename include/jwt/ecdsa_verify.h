//
// Created by Henryk Hruszka on 10/10/2025.
//

#ifndef ECDSA_VERIFY_H
#define ECDSA_VERIFY_H
#include <glib.h>

// Verify ES256 signature (secp256r1 / P-256)
int ecdsa_verify_es256(gchar *data,
                       const char *signature_b64url,
                       const char *public_key_pem);

// Verify ES384 signature (secp384r1 / P-384)
int ecdsa_verify_es384(gchar *data,
                       const char *signature_b64url,
                       const char *public_key_pem);

// Verify ES512 signature (secp521r1 / P-521)
int ecdsa_verify_es512(gchar *data,
                       const char *signature_b64url,
                       const char *public_key_pem);

#endif //ECDSA_VERIFY_H
