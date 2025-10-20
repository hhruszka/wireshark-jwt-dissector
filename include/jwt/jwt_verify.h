//
// Created by Henryk Hruszka on 10/10/2025.
//

#ifndef JWT_VERIFY_H
#define JWT_VERIFY_H

#include <jwt/jwt_export.h>

typedef enum {
    JWT_ALG_RS256,
    JWT_ALG_ES256,
    JWT_ALG_ES384,
    JWT_ALG_ES512,
    JWT_ALG_UNKNOWN
} jwt_algorithm_t;

// Main verification function
JWT_API int jwt_verify(const char *token, const char *public_key_pem, const char *alg_name);

// Parse algorithm string
jwt_algorithm_t jwt_parse_algorithm(const char *alg_name);

#endif //JWT_VERIFY_H
