#pragma once
#include <functional>
#include <QSqlDatabase>
#include <crow.h>


namespace Auth::routes {
    void createRoutes(crow::SimpleApp &app, QSqlDatabase &db);

    /// POST /login
    /// @params: user, pass
    std::string login(std::reference_wrapper<QSqlDatabase> db, const crow::request &req);

    /// POST /register
    /// @params: user, email, pass
    std::string register_(std::reference_wrapper<QSqlDatabase> db, const crow::request &req);
}
