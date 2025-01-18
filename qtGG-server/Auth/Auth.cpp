#include "Auth.hpp"
#include "../Crypt/Crypt.hpp"
#include <QSqlError>
#include "../common.hpp"
#include "../config.hpp"
#include <QSqlQuery>

namespace Auth {

    bool registerUser(QSqlDatabase &db, std::string_view username, std::string_view email, std::string_view password) {
        // Check if user already exists
        QSqlQuery query(db);
        query.prepare("SELECT 1 FROM users WHERE username=? OR email=?");
        query.addBindValue(toQString(username));
        query.addBindValue(toQString(email));
        bool result = query.exec();

        if (!result)
            throw std::exception();

        if (query.next())
            return false;

        // Hash password
        auto salt = Crypt::generateSalt();
        auto hash = Crypt::passwordHashSha512(password, salt, config::SECRET_PEPPER);

        // Add user to the database
        query.prepare("INSERT INTO users(username, email, pass_hash) VALUES (?, ?, ?)");
        query.addBindValue(toQString(username));
        query.addBindValue(toQString(email));
        query.addBindValue(QString::fromStdString(hash));
        result = query.exec();
        if (!result)
            CROW_LOG_ERROR << query.lastError().text().toStdString();

        return result;
    }

    std::string loginUser(QSqlDatabase &db, std::string_view user, std::string_view password) {
        QSqlQuery query(db);
        query.prepare("SELECT id, pass_hash FROM users WHERE username=? OR email=?");
        query.addBindValue(toQString(user));
        query.addBindValue(toQString(user));
        bool result = query.exec();
        if (!result) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return R"({"error":"database query failed"})";
        }


        if (!query.next())
            return R"({"error":"user not found"})";

        // Verify password
        auto dbHashStr = query.value(1).toString();
        auto salt = dbHashStr.mid(1, dbHashStr.indexOf("$", 1) - 1);
        auto passHash = Crypt::passwordHashSha512(password, salt.toStdString(), config::SECRET_PEPPER);

        if (passHash != dbHashStr.toStdString())
            return R"({"error":"invalid password"})";

        // Make jwt
        crow::json::wvalue jwtPayload({
            {"id", query.value(0).toString().toStdString()},
        });

        return generateJwt(jwtPayload.dump());
    }

    std::string generateJwt(std::string_view payload) {
        crow::json::wvalue header({
            {"alg", "HS256"},
            {"typ", "jwt"}
        });
        std::string headerStr = header.dump();
        auto encHeader = base64UrlEncode(headerStr);
        auto encBody = base64UrlEncode(payload.data(), payload.size());

        std::string out = encHeader + '.' + encBody;
        return out + '.' + Crypt::hmacSha256Base64(out, config::SECRET_HMAC_KEY);
    }

    static bool verifyJwt(std::string_view jwt) {
        auto sigPos = jwt.find_last_of('.');

        if (sigPos == std::string_view::npos || sigPos == jwt.size() - 1)
            return false;

        auto signature = jwt.substr(sigPos + 1);
        auto rest = jwt.substr(0, sigPos);

        auto computedHash = Crypt::hmacSha256Base64(rest, config::SECRET_HMAC_KEY);

        return computedHash == signature;
    }

    crow::json::rvalue validateAndReadJWT(std::string_view token) {
        if (!verifyJwt(token))
            return {};

        // Slice token to extract a payload
        // if jwt has been verified we can assume that dot will be found
        auto payloadPos = token.find_first_of('.') + 1;
        token = token.substr(payloadPos);
        token = token.substr(0, token.find_first_of('.'));

        return crow::json::load(base64UrlDecode(token));
    }

    crow::json::rvalue validateAndReadJWT(const crow::request &req) {
        auto auth = req.get_header_value("Authorization");
        if (auth.starts_with("Bearer ") || auth.starts_with("bearer ")) {
            auth = auth.substr(7);
        }
        return validateAndReadJWT(auth);
    }

    bool handleAuthorizationHeader(crow::json::rvalue &out_jwt, const crow::request &req, crow::response &res) {
        out_jwt = Auth::validateAndReadJWT(req);
        if (out_jwt.size() <= 2) {
            res.code = HTTP_CODE_UNAUTHORIZED;
            res.end();
            return false;
        }
        return true;
    }

    bool validatePassword(std::string_view password) {
        if (password.length() < config::PASS_MIN_LEN) return false;
        if (password.length() > config::PASS_MAX_LEN) return false;
        return true;
    }

    bool validateUsername(std::string_view username) {
        if (username.empty()) return false;
        if (username.length() > USER_FIELD_LEN) return false;
        for (auto c: username) {
            if (!isalnum(c)) return false;
        }
        return true;
    }

    bool validateEmail(std::string_view email) {
        bool atFound = false;
        if (email.length() > EMAIL_FIELD_LEN) return false;
        for (auto c: email) {
            if (c == '@' && !atFound) {
                atFound = true;
                continue;
            }
            if (!isalnum(c) && c != '.') return false;
        }
        if (!atFound) return false;
        if (email[email.length() - 1] == '@') return false;
        return true;
    }
}
