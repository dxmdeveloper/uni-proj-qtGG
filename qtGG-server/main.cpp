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

#include <crypto.hpp>


int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    crow::SimpleApp serverApp;

    // test connection
    QSqlDatabase db = QSqlDatabase::addDatabase("QPSQL");
    bool connected = connectToDatabase(db);
    if (!connected) {
        return -1;


    // Demo / test routes
    CROW_ROUTE(serverApp, "/")([]() {
        return "HTTP Server is set up!";
    });

    CROW_ROUTE(serverApp, "/RSA2048")([]() {
        auto [prv, pub] = Crypt::generateRsaKeys(2048);
        return prv + "\n" + pub;
    });

    // curl -d '{"user":"test3","pass":"aoeuaoeu"}' 127.0.0.1/login
    // /login /register
    Auth::routes::createRoutes(serverApp, db);
    Users::routes::createRoutes(serverApp, db);
    Conversations::routes::createRoutes(serverApp, db);

    serverApp.port(80).multithreaded().run();
}
