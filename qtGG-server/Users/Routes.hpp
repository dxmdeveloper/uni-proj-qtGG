#pragma once
#include <QSqlDatabase>
#include <crow.h>

namespace Users::routes {
    void createRoutes(crow::SimpleApp &app, QSqlDatabase &db);

    /// GET /getUsersList
    /// @returns: [{"id":uint64, "username":string}...]
    void getUsersList(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res);
}


