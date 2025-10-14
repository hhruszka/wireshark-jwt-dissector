// #include <epan/packet.h>
// #include <epan/wslua/wslua.h>
#include <lauxlib.h>
#include <lua.h>

#include "jwt_utils.h"
#include "jwt_verify.h"
#include "base64.h"
#include "json.h"
#include "jwt_export.h"

// Lua: base64url_decode(string) -> string
static int l_base64url_decode(lua_State *L) {
    size_t len;
    const char *input = luaL_checklstring(L, 1, &len);

    gsize out_len;
    guchar *decoded = base64url_decode(input, &out_len);

    if (decoded) {
        lua_pushlstring(L, (const char*)decoded, out_len);
        g_free(decoded);
        return 1;
    }

    lua_pushnil(L);
    return 0;
}

// Lua: verify_jwt(token, public_key, algorithm) -> boolean
static int l_verify_jwt(lua_State *L) {
    const char *token = luaL_checkstring(L, 1);
    const char *public_key = luaL_checkstring(L, 2);
    const char *alg = luaL_optstring(L, 3, "RS256");

    int result = jwt_verify(token, public_key, alg);
    lua_pushboolean(L, result);
    return 1;
}

// Lua: get_version() -> string
static int l_get_version(lua_State *L) {
    lua_pushstring(L, JWT_UTILS_VERSION);
    return 1;
}

// Register functions
static const luaL_Reg jwt_utils_funcs[] = {
    {"base64url_decode", l_base64url_decode},
    {"verify_jwt", l_verify_jwt},
    {"json_unmarshall",l_json_decode},
    {"base64_json_unmarshall",l_json_decode_base64},
    {"version", l_get_version},
    {NULL, NULL}
};

// Module initialize

JWT_API int luaopen_jwt_utils(lua_State *L) {
    luaL_newlib(L, jwt_utils_funcs);
    return 1;
}

#ifdef _WIN32
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}
#endif
