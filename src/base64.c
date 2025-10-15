#include "base64.h"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <lauxlib.h>
#include <lua.h>
#include <glib.h>

Base64Type detect_base64_type(const gchar *str) {
    gboolean has_plus = strchr(str, '+') != NULL;
    gboolean has_slash = strchr(str, '/') != NULL;
    gboolean has_dash = strchr(str, '-') != NULL;
    gboolean has_underscore = strchr(str, '_') != NULL;
    gboolean has_padding = strchr(str, '=') != NULL;


    if ((has_plus || has_slash) && (has_dash || has_underscore)) {
        return BASE64_UNKNOWN;  // Mixed - invalid
    }

    if (has_padding && (has_plus || has_slash)) {
        return BASE64_STANDARD_WITH_PADDING;
    }

    if (has_plus || has_slash) {
        return BASE64_STANDARD;
    }

    if ((has_dash || has_underscore) && has_padding) {
        return BASE64_URL_WITH_PADDING;
    }

    // No special characters - could be either
    // In JWT context, assume base64url
    return BASE64_URL;
}

// Helper: Base64url decode (JWT uses base64url, not standard base64)
guchar* base64url_decode(const char *input, gsize *out_len) {
    // Replace - with + and _ with /
    gchar *modified = g_strdup(input);
    for (int i = 0; modified[i]; i++) {
        if (modified[i] == '-') modified[i] = '+';
        else if (modified[i] == '_') modified[i] = '/';
    }
    
    // Add padding if needed
    int padding = (4 - (strlen(modified) % 4)) % 4;
    gchar *padded = g_strdup_printf("%s%.*s", modified, padding, "===");
    
    guchar *result = g_base64_decode(padded, out_len);
    g_free(modified);
    g_free(padded);
    return result;
}

static int l_decode_base64(lua_State *L) {
    const char *input = luaL_checkstring(L, 1);
    gsize out_len;
    guchar *decoded = g_base64_decode(input, &out_len);
    lua_pushlstring(L, (const char*)decoded, out_len);
    g_free(decoded);
    return 1;
}
