//
// Created by hhruszka on 10/14/2025.
//

#ifndef JWT_JWT_EXPORT_H
#define JWT_JWT_EXPORT_H

#if defined(_WIN32) || defined(__CYGWIN__)
    #ifdef BUILDING_JWT_DLL
        #define JWT_API __declspec(dllexport)
    #else
        #define JWT_API __declspec(dllimport)
    #endif
#else
    #if __GNUC__ >= 4
        #define JWT_API __attribute__((visibility("default")))
    #else
        #define JWT_API
    #endif
#endif

#endif //JWT_JWT_EXPORT_H