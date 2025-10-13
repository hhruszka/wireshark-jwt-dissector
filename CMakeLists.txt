# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(jwt 1 0 0 0)

# Required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED openssl)
#pkg_check_modules(GLIB REQUIRED glib-2.0)
pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0)
# Find Lua (use pkg-config or fallback if needed)
find_package(Lua REQUIRED)
# Add these lines to find OpenSSL libraries, if not already present
find_package(OpenSSL REQUIRED)
#find_package(Glib REQUIRED)

# Source files
set(SOURCES
        src/cJSON.c
        src/json.c
        src/jwt_utils.c
        src/jwt_verify.c
        src/base64.c
        src/rsa_verify.c
        src/ecdsa_verify.c
)
#
set(PLUGIN_FILES
        ${SOURCES}
)

# Lua script for installation
set(LUA_SCRIPTS
        lua/jwt_postdissector.lua
)

# Add the Wireshark plugin library
# Use utility-specific naming here
add_wireshark_plugin_library(jwt epan ${PLUGIN_FILES})

# Include directories
target_include_directories(jwt PRIVATE
#        ${GLIB_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIRS}
        ${LUA_INCLUDE_DIR}
)

# Link Wireshark libraries and external dependencies
target_link_libraries(jwt PRIVATE
        epan                    # Wireshark's core library (adjust if necessary)
#        ${GLIB_LIBRARIES}
        PkgConfig::GLIB # Use the modern imported target
        ${OPENSSL_LIBRARIES}
        ${LUA_LIBRARIES}
)

# Set output name (no lib prefix)
set_target_properties(jwt PROPERTIES
        PREFIX ""
        OUTPUT_NAME "jwt"
)

# Install plugin library (adjust destination if needed)
install_plugin(jwt epan)

# Install Lua scripts
install(FILES ${LUA_SCRIPTS} DESTINATION share/wireshark/lua)

# Optional: Check for coding standards compliance
CHECKAPI(
        NAME
        jwt
        SWITCHES
        --group dissectors-prohibited
        --group dissectors-restricted
        SOURCES
        ${SOURCES}
)