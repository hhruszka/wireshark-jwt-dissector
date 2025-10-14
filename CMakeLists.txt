# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
cmake_minimum_required(VERSION 3.10)
project(jwt C)

#set(WIRESHARK_BUILD_DIR "C:/Users/hhruszka/Development/wireshark/wsbuild-x64")
set(WIRESHARK_LIBS_DIR "C:/Users/hhruszka/Development/wireshark/wireshark-x64-libs-4.6")

# Important: Point to the vcpkg export directory where packages actually are
set(VCPKG_ROOT "${WIRESHARK_LIBS_DIR}/vcpkg-export-2025.07.25-x64-windows-ws/installed/x64-windows")
set(LUA_ROOT "${WIRESHARK_LIBS_DIR}/lua-5.4.6-unicode-win64-vc14")

find_package(OpenSSL REQUIRED)

set(GLIB_INCLUDE_DIRS
        "${VCPKG_ROOT}/include/glib-2.0"
        "${VCPKG_ROOT}/lib/glib-2.0/include"
)
set(GLIB_LIBRARIES "${VCPKG_ROOT}/lib/glib-2.0.lib")

set(LUA_INCLUDE_DIRS
        "${LUA_ROOT}/include"
)
set(LUA_LIBRARIES "${LUA_ROOT}/lua54.lib")

# Debug: Print what was found
message(STATUS "***** OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "***** OpenSSL libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "***** Lua include dir: ${LUA_INCLUDE_DIRS}")
message(STATUS "***** Lua libraries: ${LUA_LIBRARIES}")
message(STATUS "***** GLib includes: ${GLIB_INCLUDE_DIRS}")
message(STATUS "***** GLib libraries: ${GLIB_LIBRARIES}")

# Source files
set(SOURCES
        src/cJSON.c
        src/json.c
        src/jwt_utils.c
        src/jwt_verify.c
        src/base64.c
        src/rsa_verify.c
        src/ecdsa_verify.c
        src/jwt_export.h
)

#add_library(jwt MODULE ${SOURCES})
add_library(jwt SHARED ${SOURCES})
target_compile_definitions(jwt PRIVATE BUILDING_JWT_DLL)

# For GCC/Clang visibility
if(NOT WIN32)
    target_compile_options(jwt PRIVATE -fvisibility=hidden)
endif()

# Include directories
target_include_directories(jwt PRIVATE
        ${LUA_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${GLIB_INCLUDE_DIRS}
)

## Link Wireshark libraries and external dependencies
target_link_libraries(jwt PRIVATE
        ${OPENSSL_LIBRARIES}
        ${LUA_LIBRARIES}
        ${GLIB_LIBRARIES}
)

if (WIN32)
    # Set output name (no lib prefix)
    set_target_properties(jwt PROPERTIES
            PREFIX ""
            OUTPUT_NAME "jwt"
            SUFFIX ".dll"
    )
endif ()

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR})
set_target_properties(jwt PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/targets"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/targets"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/targets"
)
