//
// Created by Henryk Hruszka on 10/10/2025.
//
#ifndef BASE64_H
#define BASE64_H
#include <glib.h>

typedef enum {
    BASE64_STANDARD,
    BASE64_URL,
    BASE64_UNKNOWN
} Base64Type;

guchar* base64url_decode(const char *input, gsize *out_len);
#endif //BASE64_H
