#pragma once
#include <random>
#include <crow.h>
#include <QString>
#include <QUuid>
#include "config.hpp"

inline constexpr int HTTP_CODE_BAD_REQUEST = 400;
inline constexpr int HTTP_CODE_UNAUTHORIZED = 401;
inline constexpr int HTTP_CODE_FORBIDDEN = 403;
inline constexpr int HTTP_CODE_INTERNAL_SERVER_ERROR = 500;


inline bool connectToDatabase(QSqlDatabase &db) {
    QString connectionName = QUuid::createUuid().toString();
    db = QSqlDatabase::addDatabase("QPSQL", connectionName);

    db.setHostName(config::DATABASE_ADDR);
    db.setDatabaseName(config::DATABASE_NAME);
    db.setUserName(config::DATABASE_USER);
    db.setPassword(config::DATABASE_PASSWORD);
    bool connected = db.open();
    if (!connected) {
        CROW_LOG_CRITICAL << "Connection to database failed.";
    }
    return connected;
}

inline std::string jsonWrite(const crow::json::wvalue::object &json) {
    crow::json::wvalue wvalue(json);
    return wvalue.dump();
}

template <typename T>
T getRandInt(T min, T max) {
    static_assert(std::is_integral_v<T>);

    static std::random_device rd;
    static std::mt19937 generator(rd());
    std::uniform_int_distribution<T> dist(min, max);

    return dist(generator);
}

inline std::string base64UrlEncode(const unsigned char* data, size_t len) {
    std::string b64 = crow::utility::base64encode_urlsafe(data, len);
    while (b64.at(b64.size() - 1) == '=') {
        b64 = b64.substr(0, b64.size() - 1);
    }
    return b64;
}

inline std::string base64UrlEncode(const char* data, size_t len) {
    return base64UrlEncode(reinterpret_cast<const unsigned char *>(data), len);
}

inline std::string base64UrlEncode(std::string_view data) {
    return base64UrlEncode(reinterpret_cast<const unsigned char *>(data.data()), data.length());
}

inline std::string base64UrlDecode(std::string_view msg) {
    auto decoded = crow::utility::base64decode(msg.data(), msg.size());
    return decoded;
}

inline QString toQString(std::string_view str) {
    return QString::fromStdString({str.data(), str.size()});
}

inline std::string_view toStringView(const crow::json::detail::r_string& str) {
    return {str.begin(), str.end()};
}
