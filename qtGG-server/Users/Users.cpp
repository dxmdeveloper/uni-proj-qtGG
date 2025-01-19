#include "Users.hpp"
#include <QSqlQuery>
#include <QSqlError>
#include <QSqlDriver>
#include <crow.h>

namespace Users {
    std::vector<UsersListEntry> getUsersList(QSqlDatabase &db) {
        QSqlQuery query(db);
        query.prepare("SELECT id, username FROM users WHERE active=1");
        if (query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            throw std::runtime_error("getUsersList() SQL Query failed");
        }
        std::vector<UsersListEntry> usersList;
        if (db.driver()->hasFeature(QSqlDriver::QuerySize)) {
            usersList.reserve(query.size());
        }
        while (query.next()) {
            UsersListEntry user{
                .id = static_cast<uint64_t>(query.value(0).toULongLong()),
                .username = query.value(1).toString().toStdString()
            };
            usersList.push_back(user);
        }
        return usersList;
    }
}
