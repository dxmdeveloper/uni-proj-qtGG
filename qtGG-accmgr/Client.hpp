#pragma once
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkAccessManager>


class Client : public QObject {
    Q_OBJECT
public:
    Client(QObject *parent = nullptr);
    Client(QObject *parent, const QString &server);
    void setServer(const QString &server) {this->server = "http://" + server;}

    /// @brief sends a request to the server. Generates loginSuccess or loginError signals
    void logIn(std::string_view user, std::string_view pass);

signals:
    void loginSuccess(std::string jwt);
    void loginError(std::string error);

    void registrationSuccess();
    void registrationError(std::string error);

private slots:
    void onLoginReqFinished(QNetworkReply* reply);
    void onRegisterReqFinished(QNetworkReply* reply);

private:
    QNetworkAccessManager *networkAccessManager;
    QString server;
};
