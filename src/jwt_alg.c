//
// Created by Henryk Hruszka on 20/10/2025.
//
#include <stdlib.h>
#include <jwt/base64.h>
#include "jwt/cJSON.h"

char* get_jwt_algorithm(const char* jwt_token) {
    // Find first dot (separator between header and payload)
    char* first_dot = strchr(jwt_token, '.');
    if (!first_dot) {
        return NULL;
    }

    // Extract header portion
    ptrdiff_t header_len = first_dot - jwt_token;
    if (header_len <= 0) {
        return NULL;
    }

    char* header_b64 = strndup(jwt_token, (size_t)header_len);
    if (!header_b64) {
        return NULL;
    }

    // Decode base64url header
    size_t decoded_len;
    char* decoded_header = base64url_decode(header_b64, &decoded_len);
    free(header_b64);

    if (!decoded_header) {
        return NULL;
    }

    // Parse JSON header
    cJSON* header_json = cJSON_ParseWithLength(decoded_header, decoded_len);
    free(decoded_header);

    if (!header_json) {
        return NULL;
    }

    // Extract "alg" field
    cJSON* alg_item = cJSON_GetObjectItemCaseSensitive(header_json, "alg");
    char* algorithm = NULL;

    if (cJSON_IsString(alg_item) && alg_item->valuestring) {
        algorithm = strdup(alg_item->valuestring);
    }

    cJSON_Delete(header_json);
    return algorithm;
}