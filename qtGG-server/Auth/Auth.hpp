#pragma once
#include "../common.hpp"
#include "../config.hpp"
#include <crow.h>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <string_view>

namespace Auth {
    bool registerUser(QSqlDatabase &db, std::string_view username, std::string_view email, std::string_view password);

    std::string loginUser(QSqlDatabase &db, std::string_view user, std::string_view password);

    std::string generateJwt(std::string_view payload);

    /// @brief verifies json web token and read its payload.
    /// @return json string with payload. If verification failed will return an empty string.
    std::string readJwt(std::string_view token);

    bool doesPasswordMeetsRequirements(std::string_view password);
}
