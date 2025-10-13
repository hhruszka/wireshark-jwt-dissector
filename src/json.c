#include <epan/wslua/wslua.h>
#include <lua/lauxlib.h>
#include <lua/lua.h>
#include "base64.h"
#include "cJSON.h"
#include "json.h"

void l_cjson_to_lua(lua_State *L, cJSON *json) {
    if (json == NULL) {
        lua_pushnil(L);
        return;
    }

    switch (json->type) {
        case cJSON_NULL:
            lua_pushnil(L);
        break;
        case cJSON_False:
            lua_pushboolean(L, 0);
        break;
        case cJSON_True:
            lua_pushboolean(L, 1);
        break;
        case cJSON_Number:
            lua_pushnumber(L, json->valuedouble);
        break;
        case cJSON_String:
            lua_pushstring(L, json->valuestring);
        break;
        case cJSON_Array: {
            lua_newtable(L);
            int i = 1;
            cJSON *item = json->child;
            while (item) {
                l_cjson_to_lua(L, item);
                lua_rawseti(L, -2, i++);
                item = item->next;
            }
            break;
        }
        case cJSON_Object: {
            lua_newtable(L);
            cJSON *item = json->child;
            while (item) {
                lua_pushstring(L, item->string);
                l_cjson_to_lua(L, item);
                lua_settable(L, -3);
                item = item->next;
            }
            break;
        }
    }
}

int l_json_decode(lua_State *L) {
    const char *json_str = luaL_checkstring(L, 1);
    cJSON *json = cJSON_Parse(json_str);

    if (json == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "JSON parse error");
        return 2;
    }

    l_cjson_to_lua(L, json);
    cJSON_Delete(json);
    return 1;
}

int l_json_decode_base64(lua_State *L) {
    const char *base64_string = luaL_checkstring(L, 1);


    gsize out_len;
    guchar *json_str = base64url_decode(base64_string, &out_len);
    if (json_str == NULL) {
        g_free(json_str);
        lua_pushnil(L);
        lua_pushstring(L, "base64 decode error");
        return 2;
    }

    cJSON *json = cJSON_ParseWithLength((const char *)json_str,out_len);

    if (json == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "JSON parse error");
        g_free(json_str);
        return 2;
    }

    l_cjson_to_lua(L, json);
    cJSON_Delete(json);
    g_free(json_str);
    return 1;
}