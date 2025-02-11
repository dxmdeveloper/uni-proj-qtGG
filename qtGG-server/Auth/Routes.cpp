#include "Routes.hpp"

#include "Auth.hpp"
#include "../common.hpp"
#include "../config.hpp"

namespace Auth::routes {
    void createRoutes(crow::SimpleApp &app) {
        CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::POST)([&](const crow::request &req) {
            QSqlDatabase db;
            connectToDatabase(db);

            auto result = login(db, req);

            db.close();
            return result;
        });
        CROW_ROUTE(app, "/register").methods(crow::HTTPMethod::POST)([&](const crow::request &req) {
            QSqlDatabase db;
            connectToDatabase(db);

            auto result = register_(db, req);

            db.close();
            return result;
        });
    }

    std::string login(std::reference_wrapper<QSqlDatabase> db, const crow::request &req) {
        auto reqBody = crow::json::load(req.body);

        auto loginResult = loginUser(db, reqBody["user"].s().begin(), reqBody["pass"].s().begin());
        if (loginResult.empty() || loginResult[0] == '{')
            return loginResult;

        return R"({"jwt":")" + loginResult + "\"}";
    }

    std::string register_(std::reference_wrapper<QSqlDatabase> db, const crow::request &req) {
        auto reqBody = crow::json::load(req.body);
        auto pass = toStringView(reqBody["pass"].s());
        auto user = toStringView(reqBody["user"].s());
        auto email = toStringView(reqBody["email"].s());
        bool result{false};

        // Validate
        if (!validatePassword(pass))
            return std::format(R"({{"error":"Password doesn't meet requirements. "
                           "Password length must be {}-{} characters long."}})",
                               config::PASS_MIN_LEN,
                               config::PASS_MAX_LEN);

        if (!validateEmail(email)) {
            if (email.length() > EMAIL_FIELD_LEN)
                return std::format(R"({{"error":"Email address is too long (limit: {})."}})", EMAIL_FIELD_LEN);
            return R"({"error":"Email address is invalid"})";
        }

        if (!validateUsername(user)) {
            return R"({"error":"Invalid username format or is too long"})";
        }

        // Try to register the user
        try {
            result = Auth::registerUser(db, user, email, pass);
        } catch (const std::exception &e) {
            return R"({"error":"Internal server error."})";
        }
        if (!result)
            return R"({"error":"The username or email address is already in use."})";

        return R"({"status":"success"})";
    }
}
