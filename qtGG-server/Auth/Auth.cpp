#include "Auth.hpp"
#include <QSqlError>
#include <QSqlQuery>
#include <chrono>
#include "../Crypt/Crypt.hpp"
#include "../common.hpp"
#include "../config.hpp"

namespace Auth {
    std::unordered_map<uint64_t, int64_t> g_issuedTokens{};
    std::timed_mutex g_issuedTokensMutex{};

    bool isUserActive(QSqlDatabase &db, uint64_t userId) {
        QSqlQuery query(db);
        query.prepare("SELECT 1 FROM users WHERE id=? AND active=true");
        query.addBindValue(quint64(userId));
        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            throw std::runtime_error("database error");
        }
        return query.next();
    }

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

        auto userId = static_cast<uint64_t>(query.value(0).toULongLong());
        // Make jwt
        crow::json::wvalue jwtPayload({
            {"id", userId}
        });

        if (g_issuedTokensMutex.try_lock_for(std::chrono::milliseconds(200))) {
            if (g_issuedTokens.contains(userId) && g_issuedTokens.at(userId) == 0) {
                g_issuedTokens.erase(userId);
            }
            g_issuedTokensMutex.unlock();
        }
        return generateJwt(jwtPayload.dump());
    }

    std::string generateJwt(std::string_view payload) {
        // add issued field to the payload
        auto jsonPayload = crow::json::load(payload.data(), payload.size());
        auto userId = jsonPayload["id"].u();
        bool failed = false;
        crow::json::wvalue newPayload(jsonPayload);

        // mutex lock
        if (g_issuedTokensMutex.try_lock_for(std::chrono::milliseconds(200))) {
            if (!g_issuedTokens.contains(userId)) {
                g_issuedTokens[userId] = time(nullptr);
            }
            auto serverVal = g_issuedTokens.at(userId);
            if (serverVal == 0) {
                // JWT has been revoked meanwhile
                failed = true;
            } else {
                newPayload["issued"] = g_issuedTokens.at(userId);
            }
            g_issuedTokensMutex.unlock();
        } else {
            CROW_LOG_WARNING << "Mutex try_lock_for timeout.";
            newPayload["issued"] = time(nullptr);
        }
        // mutex unlocked

        if (failed) return "";
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

    static bool verifyJwtHash(std::string_view jwt) {
        // check hash
        auto sigPos = jwt.find_last_of('.');

        if (sigPos == std::string_view::npos || sigPos == jwt.size() - 1)
            return false;

        auto signature = jwt.substr(sigPos + 1);
        auto rest = jwt.substr(0, sigPos);

        auto computedHash = Crypt::hmacSha256Base64(rest, config::SECRET_HMAC_KEY);

        return computedHash == signature;
    }

    crow::json::rvalue readJWTAndVerifyHash(std::string_view token) {
        if (!verifyJwtHash(token))
            return {};

        // Slice token to extract a payload
        // if jwt hash has been verified we can assume that dot will be found
        auto payloadPos = token.find_first_of('.') + 1;
        token = token.substr(payloadPos);
        token = token.substr(0, token.find_first_of('.'));

        auto payload = crow::json::load(base64UrlDecode(token));
        return payload;
    }

    crow::json::rvalue readJWTAndVerifyHash(const crow::request &req) {
        auto auth = req.get_header_value("Authorization");
        if (auth.starts_with("Bearer ") || auth.starts_with("bearer ")) {
            auth = auth.substr(7);
        }
        return readJWTAndVerifyHash(auth);
    }

    bool handleAuthorizationHeader(QSqlDatabase &db, crow::json::rvalue &out_jwt, const crow::request &req,
                                   crow::response &res) {
        out_jwt = Auth::readJWTAndVerifyHash(req);

        if (out_jwt.size() <= 2) {
            res.code = HTTP_CODE_UNAUTHORIZED;
            return false;
        }
        // check if verification is needed
        auto userId = out_jwt["id"].u();
        bool needsVerification = true;

        // mutex lock
        if (g_issuedTokensMutex.try_lock_for(std::chrono::milliseconds(200))) {
            if (g_issuedTokens.contains(userId) && g_issuedTokens.at(userId) == out_jwt["issued"].u())
                needsVerification = false;
            g_issuedTokensMutex.unlock();
        }
        // mutex unlocked

        if (!needsVerification)
            return true;

        // TODO: More validations, especially for permissions
        if (!isUserActive(db, userId)) {
            res.code = HTTP_CODE_UNAUTHORIZED;
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
