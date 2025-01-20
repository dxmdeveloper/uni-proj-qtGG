#include "Routes.hpp"
#include "../Auth/Auth.hpp"
#include "Users.hpp"

namespace Users::routes {
    void createRoutes(crow::SimpleApp &app, QSqlDatabase &db) {
        CROW_ROUTE(app, "/getUsersList")([&](const crow::request &req, crow::response &res) {
            getUsersList(db, req, res);
            res.end();
        });
    }

    void getUsersList(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res) {
        crow::json::rvalue jwt{};
        if (!Auth::handleAuthorizationHeader(db, jwt, req, res)) return;

        auto list = Users::getUsersList(db);

        std::vector<crow::json::wvalue> jUsers;
        jUsers.reserve(list.size());
        for (const auto &user : list) {
            crow::json::wvalue jUser {
                {"id", user.id},
                {"username", user.username}
            };
            jUsers.push_back(jUser);
        }
        crow::json::wvalue json{jUsers};
        res.body = json.dump();
    };
}