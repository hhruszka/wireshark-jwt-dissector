//
// Created by Henryk Hruszka on 10/10/2025.
//

#ifndef RSA_VERIFY_H
#define RSA_VERIFY_H
#include <glib.h>

// Verify RS256 signature
int rsa_verify_rs256(gchar *data,
                     const char *signature_b64url,
                     const char *public_key_pem);

#endif //RSA_VERIFY_H
