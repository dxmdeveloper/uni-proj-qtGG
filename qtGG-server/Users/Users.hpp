#pragma once
#include <QSqlDatabase>
#include <vector>

namespace Users {

    struct UsersListEntry {
        uint64_t id;
        std::string username;
    };

    std::vector<UsersListEntry> getUsersList(QSqlDatabase& db);

}
