#include "Client.hpp"
#include <nlohmann/json.hpp>

using namespace nlohmann;

Client::Client(QObject *parent)
    : QObject(parent),
      networkAccessManager{new QNetworkAccessManager(this)} {
    connect(networkAccessManager, SIGNAL(finished(QNetworkReply*)), this, SLOT(onLoginReqFinished(QNetworkReply*)));
}

Client::Client(QObject *parent, const QString &server) : Client(parent) {
    setServer(server);
}

void Client::logIn(std::string_view user, std::string_view pass) {
    json obj({{"user", user}, {"pass", pass}});
    QNetworkRequest request(server + "/login");
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    auto data = obj.dump();

    this->networkAccessManager->post(request, data.c_str());
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
