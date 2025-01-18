#include "RegistrationDialog.hpp"
#include <QBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>
#include "internal_common.hpp"

namespace Ui {
    RegistrationDialog::RegistrationDialog(QWidget *parent) : RegistrationDialog(new Client(this), parent) {
    }

    RegistrationDialog::RegistrationDialog(Client *client, QWidget *parent) : QDialog(parent), client(client) {
        auto *layout = new QVBoxLayout(this);
        auto *userLabel = new QLabel();
        auto *emailLabel = new QLabel();
        auto *passLabel = new QLabel();
        auto *repeatLabel = new QLabel();
        auto *serverLabel = new QLabel();
        userInput = new QLineEdit();
        emailInput = new QLineEdit();
        passInput = new QLineEdit();
        repeatInput = new QLineEdit();
        serverInput = new QLineEdit();
        registerButton = new QPushButton(tr("register"));

        userLabel->setText(tr("username:"));
        emailLabel->setText(tr("email:"));
        passLabel->setText(tr("password:"));
        repeatLabel->setText(tr("repeat password:"));
        serverLabel->setText(tr("server:"));

        userLabel->setBuddy(userInput);
        emailLabel->setBuddy(emailInput);
        passLabel->setBuddy(passInput);
        repeatLabel->setBuddy(repeatInput);
        serverLabel->setBuddy(serverInput);

        passInput->setEchoMode(QLineEdit::Password);
        repeatInput->setEchoMode(QLineEdit::Password);
        registerButton->setEnabled(false);

        serverInput->setText(DEFAULT_SERVER);

        layout->addWidget(userLabel);
        layout->addWidget(userInput);
        layout->addWidget(emailLabel);
        layout->addWidget(emailInput);
        layout->addWidget(passLabel);
        layout->addWidget(passInput);
        layout->addWidget(repeatLabel);
        layout->addWidget(repeatInput);
        layout->addWidget(serverLabel);
        layout->addWidget(serverInput);

        layout->addWidget(registerButton);
        layout->addStretch();
        this->setLayout(layout);

        resize(300, 0);
        setWindowTitle(tr("Registration"));

        // Connect slots and signals
        connect(userInput, SIGNAL(textChanged(QString)), this, SLOT(onInputChanged()));
        connect(emailInput, SIGNAL(textChanged(QString)), this, SLOT(onInputChanged()));
        connect(passInput, SIGNAL(textChanged(QString)), this, SLOT(onInputChanged()));
        connect(repeatInput, SIGNAL(textChanged(QString)), this, SLOT(onInputChanged()));
        connect(registerButton, SIGNAL(clicked()), this, SLOT(onSubmitClicked()));

        connect(client, SIGNAL(registrationSuccess()), this, SLOT(onRegistrationSuccess()));
        connect(client, SIGNAL(registrationError(std::string)), this, SLOT(onRegistrationError(std::string)));
    }

    void RegistrationDialog::onRegistrationSuccess() {
        serverHostnameEstablished(this->serverInput->text());

        QMessageBox msgBox;
        msgBox.setIcon(QMessageBox::Information);
        msgBox.setWindowTitle(tr("Registration success"));
        msgBox.setText(tr("Registration success"));
        msgBox.exec();

        this->close();
    }

    void RegistrationDialog::onRegistrationError(const std::string &error) {
        QMessageBox msgBox;
        msgBox.setIcon(QMessageBox::Critical);
        msgBox.setWindowTitle(tr("Registration Error"));
        msgBox.setText(QString::fromStdString(error));
        msgBox.exec();
    }

    void RegistrationDialog::onSubmitClicked() {
        auto user = userInput->text().toStdString();
        auto email = emailInput->text().toStdString();
        auto pass = passInput->text().toStdString();
        auto server = serverInput->text();
        client->setServer(server);
        client->registerUser(user, email, pass);
    }

    void RegistrationDialog::onInputChanged() {
        bool conditionsMatch = true;
        conditionsMatch &= (!userInput->text().isEmpty());
        conditionsMatch &= (!emailInput->text().isEmpty());
        conditionsMatch &= (!passInput->text().isEmpty());
        conditionsMatch &= (repeatInput->text() == passInput->text());
        conditionsMatch &= (!serverInput->text().isEmpty());

        registerButton->setEnabled(conditionsMatch);
    }
}
