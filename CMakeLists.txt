# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
#cmake_minimum_required(VERSION 3.10)
#project(jwt C)
#find_package(Wireshark REQUIRED)
include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(jwt 1 0 0 0)

find_package(PkgConfig REQUIRED)
#pkg_check_modules(GLIB2 REQUIRED IMPORTED_TARGET glib-2.0)
find_package(GLIB2 REQUIRED)
find_package(Lua REQUIRED)
find_package(OpenSSL REQUIRED)


# Debug: Print what was found
message(STATUS "***** OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "***** OpenSSL libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "***** Lua include dir: ${LUA_INCLUDE_DIRS}")
message(STATUS "***** Lua libraries: ${LUA_LIBRARIES}")
message(STATUS "***** GLib includes: ${GLIB2_INCLUDE_DIRS}")
message(STATUS "***** GLib libraries: ${GLIB2_LIBRARIES}")

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

#add_library(jwt MODULE ${SOURCES})
add_library(jwt MODULE ${SOURCES})

# Include directories
target_include_directories(jwt PRIVATE
        ${LUA_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${GLIB2_INCLUDE_DIRS}
)
#
## Link Wireshark libraries and external dependencies
target_link_libraries(jwt PRIVATE
        ${OPENSSL_LIBRARIES}
        ${LUA_LIBRARIES}
        ${GLIB2_LIBRARIES}
)

if (WIN32)
    # Set output name (no lib prefix)
    set_target_properties(jwt PROPERTIES
            PREFIX ""
            OUTPUT_NAME "jwt"
            SUFFIX ".dll"
    )
endif ()

#message(STATUS "Checking install path: [${WIRESHARK_PERSONAL_PLUGINS_DIR}]")
# Install plugin library (adjust destination if needed)
#install(TARGETS jwt
#        LIBRARY DESTINATION ${WIRESHARK_PERSONAL_PLUGINS_DIR}
#)
#install_plugin(jwt epan)
install(TARGETS jwt
        LIBRARY DESTINATION C:/Users/hhruszka/Development/jwt
)