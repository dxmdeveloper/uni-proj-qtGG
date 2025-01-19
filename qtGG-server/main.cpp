#include <iostream>
// TODO: move it to documentation
/// TIP if crow doesn't compile rename function/method signals to getSignals in crow/app.h
#include <crow.h>
#include <QSqlQuery>
#include <QSqlDatabase>
#include "config.hpp"
#include <QCoreApplication>

#include "common.hpp"
#include "Auth/Routes.hpp"
#include "Users/Routes.hpp"
#include "Conversations/Routes.hpp"

bool connectToDatabase(QSqlDatabase &db) {
    db.setHostName(config::DATABASE_ADDR);
    db.setDatabaseName(config::DATABASE_NAME);
    db.setUserName(config::DATABASE_USER);
    db.setPassword(config::DATABASE_PASSWORD);
    return db.open();
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    crow::SimpleApp serverApp;

    QSqlDatabase db = QSqlDatabase::addDatabase("QPSQL");
    bool connected = connectToDatabase(db);
    if (!connected) {
        CROW_LOG_CRITICAL << "Connection to database failed.";
        return -1;
    }

    CROW_ROUTE(serverApp, "/")([]() {
        return "HTTP Server is set up!";
    });

    // curl -d '{"user":"test3","pass":"aoeuaoeu"}' 127.0.0.1/login
    // /login /register
    Auth::routes::createRoutes(serverApp, db);
    Users::routes::createRoutes(serverApp, db);
    Conversations::routes::createRoutes(serverApp, db);

    serverApp.port(80).multithreaded().run();
}
