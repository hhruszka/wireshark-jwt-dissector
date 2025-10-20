//
// Created by Henryk Hruszka on 20/10/2025.
//

#ifndef JWT_ALG_H
#define JWT_ALG_H
#include <jwt/jwt_export.h>

char *get_jwt_algorithm_name_from_header(const char *header);
JWT_API char* get_jwt_algorithm(const char* jwt_token);

#endif //JWT_ALG_H
