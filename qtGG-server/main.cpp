#include <iostream>
#include <crow.h>
#include <QSqlQuery>
#include <QSqlDatabase>
#include "config.hpp"
#include <QCoreApplication>

#include "common.hpp"
#include "Auth/Auth.hpp"

bool connectToDatabase(QSqlDatabase &db) {
    db.setHostName(DATABASE_ADDR);
    db.setDatabaseName(DATABASE_NAME);
    db.setUserName(DATABASE_USER);
    db.setPassword(DATABASE_PASSWORD);
    return db.open();
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    crow::SimpleApp serverApp;

    QSqlDatabase db = QSqlDatabase::addDatabase("QPSQL");
    bool connected = connectToDatabase(db);
    if (!connected) {
        CROW_LOG_CRITICAL << "Connection to database failed.";
    }

    // TEST
    bool registered = Auth::registerUser(db, "test3", "test3@local", "aoeuaoeu");
    CROW_LOG_INFO << "Registered user: " << registered;
    auto jwt = Auth::loginUser(db, "test3", "aoeuaoeu");
    CROW_LOG_INFO << "Login result: " << jwt;
    CROW_LOG_INFO << "JWT payload read: " << Auth::readJwt(jwt);

    CROW_ROUTE(serverApp, "/")([]() {
        return "HTTP Server is set up!";
    });

    // curl -d '{"user":"test3","pass":"aoeuaoeu"}' 127.0.0.1/login
    CROW_ROUTE(serverApp, "/login").methods(crow::HTTPMethod::Post)([&](const crow::request &req, crow::response &res) {
        auto reqBody = crow::json::load(req.body);

        auto loginResult = Auth::loginUser(db, reqBody["user"].s().begin(), reqBody["pass"].s().begin());
        if (loginResult.empty() || loginResult[0] == '{') {
            res.code = HTTP_CODE_UNAUTHORIZED;
            res.body = loginResult;
            res.end();
        } else {
            res.body = R"({"jwt":")" + loginResult + "\"}";
            res.end();
        }
    });

    CROW_ROUTE(serverApp, "/register").methods(crow::HTTPMethod::Post)([&](const crow::request &req) {
        auto reqBody = crow::json::load(req.body);
        auto pass = reqBody["pass"].s().begin();
        auto user = reqBody["user"].s().begin();
        auto email = reqBody["email"].s().begin();
        bool result{false};

        if (!Auth::doesPasswordMeetsRequirements(pass)) {
            return R"({"error":"Password doesn't meet requirements. Password length must be 8-64 characters long."})";
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
    });

    serverApp.port(80).multithreaded().run();
}
