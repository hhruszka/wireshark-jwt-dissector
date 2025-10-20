//
// Created by Henryk Hruszka on 10/10/2025.
//
#ifndef BASE64_H
#define BASE64_H
#include <glib.h>
#include <jwt/jwt_export.h>

typedef enum {
    BASE64_STANDARD,
    BASE64_STANDARD_WITH_PADDING,
    BASE64_URL,
    BASE64_URL_WITH_PADDING,
    BASE64_UNKNOWN
} Base64Type;

JWT_API guchar* base64url_decode(const char *input, gsize *out_len);
Base64Type detect_base64_type(const gchar *str);

#endif //BASE64_H
