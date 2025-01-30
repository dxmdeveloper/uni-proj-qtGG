#pragma once
#include <nlohmann/json.hpp>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkAccessManager>


class Client : public QObject {
    Q_OBJECT
public:
    explicit Client(QObject *parent = nullptr);
    Client(const QString &server, QObject *parent = nullptr);
    void setServer(const QString &server);

    /// @brief sends a request to the server. Generates loginSuccess or loginError signals
    void logIn(std::string_view user, std::string_view pass);

    void registerUser(std::string_view user, std::string_view email, std::string_view password);

signals:
    void loginSuccess(std::string jwt);
    void loginError(std::string error);

    void registrationSuccess();
    void registrationError(std::string error);

private slots:
    void onLoginReqFinished(QNetworkReply* reply);
    void onRegisterReqFinished(QNetworkReply* reply);

private:
    void quickPost(QNetworkAccessManager *mgr, const nlohmann::json &json, const QString &address);

private:
    QNetworkAccessManager *loginNetworkAccessManager;
    QNetworkAccessManager *registrationNetworkAccessManager;
    QString server;
};
