//
// Created by Henryk Hruszka on 12/10/2025.
//

#ifndef JSON_H
#define JSON_H

#include <lua/lua.h>

int l_json_decode(lua_State *L);
int l_json_decode_base64(lua_State *L);

#endif //JSON_H
