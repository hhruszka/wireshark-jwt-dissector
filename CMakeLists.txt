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
if (WIN32)
    set(WIRESHARK_LIBS_DIR "C:/Users/hhruszka/Development/wireshark/wireshark-x64-libs-4.6")
    # Important: Point to the vcpkg export directory where packages actually are
    set(VCPKG_ROOT "${WIRESHARK_LIBS_DIR}/vcpkg-export-2025.07.25-x64-windows-ws/installed/x64-windows")
    set(LUA_ROOT "${WIRESHARK_LIBS_DIR}/lua-5.4.6-unicode-win64-vc14")
    set(GNUTLS_ROOT "${WIRESHARK_LIBS_DIR}/gnutls-3.8.10-1-x64-mingw-dynamic-ws")
endif ()

if (APPLE)
    #    set(WIRESHARK_LIBS_DIR "/Development/wireshark/wireshark-x64-libs-4.6")
    message(STATUS "***** MACOS checking required packages")
    # First, find the PackageConfig module
    find_package(PkgConfig REQUIRED)

    pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0)
    pkg_check_modules(GNUTLS REQUIRED IMPORTED_TARGET gnutls)
    pkg_check_modules(LUA REQUIRED IMPORTED_TARGET lua)
endif ()


# Option to choose crypto library
option(USE_GNUTLS "Use GnuTLS instead of OpenSSL" ON)

if (USE_GNUTLS)
    #    find_package(GnuTLS REQUIRED)
    message(STATUS "***** Using GnuTLS for cryptography")
    if (WIN32)
        set(GNUTLS_INCLUDE_DIRS "${GNUTLS_ROOT}/include")
        set(GNUTLS_LIBRARIES "${GNUTLS_ROOT}/lib/libgnutls-30.lib")
    endif ()
else ()
    find_package(OpenSSL REQUIRED)
    message(STATUS "***** Using OpenSSL for cryptography")
endif ()

if (WIN32)
    set(GLIB_INCLUDE_DIRS
            "${VCPKG_ROOT}/include/glib-2.0"
            "${VCPKG_ROOT}/lib/glib-2.0/include"
    )
    set(GLIB_LIBRARIES "${VCPKG_ROOT}/lib/glib-2.0.lib")

    set(LUA_INCLUDE_DIRS
            "${LUA_ROOT}/include"
    )
    set(LUA_LIBRARIES "${LUA_ROOT}/lua54.lib")
endif ()

# Debug: Print what was found
if (USE_GNUTLS)
    message(STATUS "***** GnuTLS include dir: ${GNUTLS_INCLUDE_DIRS}")
    message(STATUS "***** GnuTLS libraries: ${GNUTLS_LIBRARY_DIRS}")
    message(STATUS "***** GnuTLS libraries: ${GNUTLS_LIBRARIES}")
else ()
    message(STATUS "***** OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "***** OpenSSL libraries: ${OPENSSL_LIBRARIES}")
endif ()
message(STATUS "***** Lua include dir: ${LUA_INCLUDE_DIRS}")
message(STATUS "***** Lua libraries: ${LUA_LIBRARY_DIRS}")
message(STATUS "***** Lua libraries: ${LUA_LIBRARIES}")
message(STATUS "***** GLib includes: ${GLIB_INCLUDE_DIRS}")
message(STATUS "***** GLib libraries: ${GLIB_LIBRARY_DIRS}")
message(STATUS "***** GLib libraries: ${GLIB_LIBRARIES}")

# Common source files
set(COMMON_SOURCES
        src/cJSON.c
        src/json.c
        src/jwt_utils.c
        src/jwt_verify.c
        src/base64.c
        src/jwt_export.h
)

# Crypto-specific source files
if (USE_GNUTLS)
    set(CRYPTO_SOURCES
            src/rsa_verify_gnutls.c
            src/ecdsa_verify_gnutls.c
    )
else ()
    set(CRYPTO_SOURCES
            src/rsa_verify_openssl.c
            src/ecdsa_verify_openssl.c
    )
endif ()

# Combine all sources
set(SOURCES ${COMMON_SOURCES} ${CRYPTO_SOURCES})

#add_library(jwt MODULE ${SOURCES})
add_library(jwt SHARED ${SOURCES})
if (WIN32)
    target_compile_definitions(jwt PRIVATE BUILDING_JWT_DLL)
endif ()
# For GCC/Clang visibility
if (NOT WIN32)
    target_compile_options(jwt PRIVATE -fvisibility=hidden)
endif ()

# Include directories
if (USE_GNUTLS)
    target_include_directories(jwt PRIVATE
            ${LUA_INCLUDE_DIRS}
            ${GNUTLS_INCLUDE_DIRS}
            ${GLIB2_INCLUDE_DIRS}
    )
else ()
    target_include_directories(jwt PRIVATE
            ${LUA_INCLUDE_DIRS}
            ${OPENSSL_INCLUDE_DIRS}
            ${GLIB2_INCLUDE_DIRS}
    )
endif ()

## Link Wireshark libraries and external dependencies
if (USE_GNUTLS)
    if (APPLE)
        target_link_libraries(jwt PRIVATE
                PkgConfig::GNUTLS
                PkgConfig::LUA
                PkgConfig::GLIB
        )
    else()
        target_link_libraries(jwt PRIVATE
                ${GNUTLS_LIBRARIES}
                ${LUA_LIBRARIES}
                ${GLIB_LIBRARIES}
        )
    endif()
else ()
    if (APPLE)
        target_link_libraries(jwt PRIVATE
                ${OPENSSL_LIBRARIES}
                PkgConfig::LUA
                PkgConfig::GLIB
        )
    else()
        target_link_libraries(jwt PRIVATE
                ${OPENSSL_LIBRARIES}
                ${LUA_LIBRARIES}
                ${GLIB2_LIBRARIES}
        )
    endif()
endif ()

if (WIN32)
    # Set output name (no lib prefix)
    set_target_properties(jwt PROPERTIES
            PREFIX ""
            OUTPUT_NAME "jwt"
            SUFFIX ".dll"
    )
endif ()

if (APPLE)
    # Set output name (no lib prefix)
    set_target_properties(jwt PROPERTIES
            PREFIX ""
            OUTPUT_NAME "jwt"
            SUFFIX ".dylib"
    )
endif ()

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR})
set_target_properties(jwt PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/targets"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/targets"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/targets"
)
