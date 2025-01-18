#pragma once
#include <QLineEdit>
#include <QWidget>
#include <QPushButton>
#include <QMainWindow>
#include <QCheckBox>

#include "Client.hpp"
#include "RegistrationDialog.hpp"

namespace Ui {
    class LoginWindow : public QMainWindow {
        Q_OBJECT

    public:
        explicit LoginWindow(std::string *jwt, QWidget *parent = nullptr);


    private slots:
        void setServerHostname(const QString &hostname);

        void onLoginButtonClicked();

        static void onErrorResponse(const std::string &error);

        void onSuccessResponse(const std::string &jwt);

        void onRegisterButtonClicked();

    private:
        std::string *jwt;
        QLineEdit *serverInput;
        QLineEdit *userInput;
        QLineEdit *passInput;
        QCheckBox *rememberMeCheckBox;
        RegistrationDialog *registrationDialog;
        Client *client;
    };
}
