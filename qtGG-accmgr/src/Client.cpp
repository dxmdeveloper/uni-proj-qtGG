#include "Client.hpp"
#include <nlohmann/json.hpp>

using namespace nlohmann;

Client::Client(QObject *parent)
    : QObject(parent),
      loginNetworkAccessManager{new QNetworkAccessManager(this)},
      registrationNetworkAccessManager(new QNetworkAccessManager(this)) {
    // Connect Network Access Managers to response handling slots
    connect(registrationNetworkAccessManager, SIGNAL(finished(QNetworkReply*)), this,
            SLOT(onRegisterReqFinished(QNetworkReply*)));
    connect(loginNetworkAccessManager, SIGNAL(finished(QNetworkReply*)), this,
            SLOT(onLoginReqFinished(QNetworkReply*)));
}

Client::Client(const QString &server, QObject *parent) : Client(parent) {
    setServer(server);
}

void Client::setServer(const QString &server) { this->server = "http://" + server; }

void Client::logIn(std::string_view user, std::string_view pass) {
    json obj({{"user", user}, {"pass", pass}});
    quickPost(loginNetworkAccessManager, obj, server + "/login");
}

void Client::registerUser(std::string_view user, std::string_view email, std::string_view password) {
    json obj({{"user", user}, {"email", email}, {"pass", password}});
    quickPost(registrationNetworkAccessManager, obj, server + "/register");
}


void Client::onLoginReqFinished(QNetworkReply *reply) {
    if (reply->error() != QNetworkReply::NoError) {
        loginError(reply->errorString().toStdString());
        return;
    }

    auto data = json::parse(reply->readAll().toStdString());

    if (data.contains("error")) {
        loginError(data["error"]);
        return;
    }
    if (data.contains("jwt")) {
        loginSuccess(data["jwt"]);
        return;
    }

    loginError("unknown error");
}

void Client::onRegisterReqFinished(QNetworkReply *reply) {
    if (reply->error() != QNetworkReply::NoError) {
        registrationError(reply->errorString().toStdString());
        return;
    }

    auto data = json::parse(reply->readAll().toStdString());

    if (data.contains("error")) {
        registrationError(data["error"]);
        return;
    }
    if (data.contains("status")) {
        registrationSuccess();
        return;
    }

    registrationError("unknown error");
}

void Client::quickPost(QNetworkAccessManager *mgr, const json &json, const QString &address) {
    QNetworkRequest request(address);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    auto data = json.dump();

    mgr->post(request, data.c_str());
}
