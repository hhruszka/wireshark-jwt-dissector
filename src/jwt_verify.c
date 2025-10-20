//
// Created by Henryk Hruszka on 10/10/2025.
//
#include "jwt_verify.h"
#include "rsa_verify.h"
#include "ecdsa_verify.h"
#include <glib.h>

jwt_algorithm_t jwt_parse_algorithm(const char *alg_name) {
    jwt_algorithm_t algorithm = JWT_ALG_UNKNOWN;
    GString * alg_name_upper = g_string_ascii_up(g_string_new(alg_name));
    if (g_strcmp0(alg_name_upper, "RS256") == 0) algorithm = JWT_ALG_RS256;
    if (g_strcmp0(alg_name_upper, "ES256") == 0) algorithm = JWT_ALG_ES256;
    if (g_strcmp0(alg_name_upper, "ES384") == 0) algorithm = JWT_ALG_ES384;
    if (g_strcmp0(alg_name_upper, "ES512") == 0) algorithm = JWT_ALG_ES512;
    g_string_free(alg_name_upper, TRUE);
    return algorithm;
}

int jwt_verify(const char *token, const char *public_key_pem, const char *alg_name) {
    // Split token
    gchar **parts = g_strsplit(token, ".", 3);
    if (g_strv_length(parts) != 3) {
        g_strfreev(parts);
        return 0;
    }

    // Build header.payload
    gchar *header_payload = g_strdup_printf("%s.%s", parts[0], parts[1]);
    jwt_algorithm_t alg = jwt_parse_algorithm(alg_name);

    int verified = 0;
    switch (alg) {
        case JWT_ALG_RS256:
            verified = rsa_verify_rs256(header_payload, parts[2], public_key_pem);
        break;
        case JWT_ALG_ES256:
            verified = ecdsa_verify_es256(header_payload, parts[2], public_key_pem);
        break;
        case JWT_ALG_ES384:
            verified = ecdsa_verify_es384(header_payload, parts[2], public_key_pem);
        break;
        case JWT_ALG_ES512:
            verified = ecdsa_verify_es512(header_payload, parts[2], public_key_pem);
        break;
        default:
            break;
    }

    g_free(header_payload);
    g_strfreev(parts);
    return verified;
}