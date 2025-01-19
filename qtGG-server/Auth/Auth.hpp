#pragma once
#include <crow.h>
#include <QSqlDatabase>
#include <string_view>

namespace Auth {
    // <user_id, time_issued>
    extern std::unordered_map<uint64_t, int64_t> g_issuedTokens;

    constexpr uint USER_FIELD_LEN = 30;
    constexpr uint EMAIL_FIELD_LEN = 80;

    bool registerUser(QSqlDatabase &db, std::string_view username, std::string_view email, std::string_view password);

    std::string loginUser(QSqlDatabase &db, std::string_view user, std::string_view password);

    std::string generateJwt(std::string_view payload);

    /// @brief verifies json web token and read its payload.
    /// @return json string with payload. If verification failed will return an empty string.
    crow::json::rvalue validateAndReadJWT(std::string_view token);

    crow::json::rvalue validateAndReadJWT(const crow::request &req);

    /// @brief read and validate JWT token. In case it's invalid. sends response with HTTP_UNAUTHORIZED code.
    /// @return true if token is valid, so function shall continue. false otherwise
    bool handleAuthorizationHeader(crow::json::rvalue &out_jwt, const crow::request &req, crow::response &res);

    // Validation
    bool validatePassword(std::string_view password);
    bool validateUsername(std::string_view username);
    bool validateEmail(std::string_view email);

}
