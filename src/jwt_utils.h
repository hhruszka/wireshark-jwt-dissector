//
// Created by Henryk Hruszka on 10/10/2025.
//

#ifndef JWT_UTILS_H
#define JWT_UTILS_H

#include <lua.h>

// Plugin version
#define JWT_UTILS_VERSION "1.0.0"

// Initialize the plugin
int luaopen_jwt_utils(lua_State *L);

#endif //JWT_UTILS_H
