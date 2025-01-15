#include "LoginWindow.hpp"

#include <QApplication>
#include <QVBoxLayout>
#include <QMessageBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include "internal_common.hpp"
#include "RegistrationDialog.hpp"

namespace Ui {
    LoginWindow::LoginWindow(std::string *jwt, QWidget *parent)
        : QMainWindow(parent),
          jwt(jwt),
          client(new Client(this)) {
        // Child Widgets
        registrationDialog = new RegistrationDialog(this);
        registrationDialog->setModal(true);

        // UI
        auto central = new QWidget(this);
        setCentralWidget(central);
        setWindowTitle("QtGG Login");

        auto layout = new QVBoxLayout(central);
        auto userLabel = new QLabel();
        auto passLabel = new QLabel();
        auto serverLabel = new QLabel();
        auto rememberMeLabel = new QLabel();
        userInput = new QLineEdit();
        passInput = new QLineEdit();
        rememberMeCheckBox = new QCheckBox();
        serverInput = new QLineEdit();
        auto loginButton = new QPushButton();

        userLabel->setText(tr("username or email address:"));
        passLabel->setText(tr("password:"));
        serverLabel->setText(tr("server:"));
        rememberMeLabel->setText(tr("remember me:"));
        loginButton->setText(tr("log in"));

        userLabel->setBuddy(userInput);
        passLabel->setBuddy(passInput);
        serverLabel->setBuddy(serverInput);
        rememberMeLabel->setBuddy(rememberMeCheckBox);

        passInput->setEchoMode(QLineEdit::Password);
        serverInput->setText(DEFAULT_SERVER);
        serverInput->setMaximumWidth(250);

        layout->addWidget(userLabel);
        layout->addWidget(userInput);
        layout->addSpacing(8);
        layout->addWidget(passLabel);
        layout->addWidget(passInput);
        layout->addSpacing(16);
        layout->addWidget(serverLabel);
        layout->addWidget(serverInput);

        auto rememberMeLayout = new QHBoxLayout();
        rememberMeLayout->addWidget(rememberMeLabel);
        rememberMeLayout->addWidget(rememberMeCheckBox);
        rememberMeLayout->addStretch();
        layout->addLayout(rememberMeLayout);

        layout->addWidget(loginButton);

        auto auxOptsLayout = new QHBoxLayout();
        auto registerButton = new QPushButton();
        registerButton->setText(tr("register"));
        auxOptsLayout->addWidget(registerButton);
        auxOptsLayout->addStretch();
        layout->addLayout(auxOptsLayout);

        layout->addStretch();
        central->setLayout(layout);

        resize(400, 0);

        // Connect slots with signals
        connect(client, SIGNAL(loginSuccess(std::string)), this, SLOT(onSuccessResponse(std::string)));
        connect(client, SIGNAL(loginError(std::string)), this, SLOT(onErrorResponse(std::string)));
        connect(loginButton, SIGNAL(clicked()), this, SLOT(onLoginButtonClicked()));
        connect(registerButton, SIGNAL(clicked()), this, SLOT(onRegisterButtonClicked()));
    }

    void LoginWindow::onLoginButtonClicked() {
        auto user = userInput->text();
        auto pass = passInput->text();
        bool rememberMe = rememberMeCheckBox->isChecked();
        // TODO: do something with remember me

        client->setServer(serverInput->text());
        client->logIn(user.toStdString(), pass.toStdString());
    }

    void LoginWindow::onErrorResponse(const std::string &error) {
        QMessageBox msgBox;
        msgBox.setIcon(QMessageBox::Critical);
        msgBox.setWindowTitle(tr("Login Error"));
        msgBox.setText(QString::fromStdString(error));
        msgBox.exec();
    }

    void LoginWindow::onSuccessResponse(const std::string &jwt) {
        *this->jwt = jwt;
        QApplication::quit();
    }

    void LoginWindow::onRegisterButtonClicked() {
        registrationDialog->show();
    }
}
