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
        LoginWindow(std::string *jwt, QWidget *parent = nullptr);

    public:
        std::string *jwt;

    private slots:
        void onLoginButtonClicked();

        static void onErrorResponse(const std::string &error);

        void onSuccessResponse(const std::string &jwt);

        void onRegisterButtonClicked();

    private:
        QLineEdit *serverInput;
        QLineEdit *userInput;
        QLineEdit *passInput;
        QCheckBox *rememberMeCheckBox;
        Client *client;
        RegistrationDialog *registrationDialog;
    };
}
