#pragma once
#include <QDialog>
#include <QLineEdit>
#include <QMetaType>

#include "Client.hpp"

namespace Ui {
    class RegistrationDialog : public QDialog {
        Q_OBJECT

    public:
        explicit RegistrationDialog(QWidget *parent = nullptr);
        explicit RegistrationDialog(Client *client, QWidget *parent = nullptr);

    signals:
        void serverHostnameEstablished(const QString& hostname);


    private slots:
        void onRegistrationSuccess();

        static void onRegistrationError(const std::string &error);

        void onSubmitClicked();

        void onInputChanged();

    private:
        Client *client;
        QLineEdit *userInput;
        QLineEdit *emailInput;
        QLineEdit *passInput;
        QLineEdit *repeatInput;
        QLineEdit *serverInput;
        QPushButton * registerButton;
    };
}
