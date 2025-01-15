#include "RegistrationDialog.hpp"
#include <QBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include "internal_common.hpp"

namespace Ui {
    RegistrationDialog::RegistrationDialog(QWidget *parent) : QDialog(parent) {
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
    }

    void RegistrationDialog::onRegistrationSuccess(const std::string &msg) {
    }

    void RegistrationDialog::onRegistrationError(const std::string &error) {
    }

    void RegistrationDialog::onSubmitClicked() {
    }

    void RegistrationDialog::onInputChanged() {
        bool conditionsMatch = true;
        conditionsMatch &= (userInput->text().isEmpty() == false);
        conditionsMatch &= (emailInput->text().isEmpty() == false);
        conditionsMatch &= (passInput->text().isEmpty() == false);
        conditionsMatch &= (repeatInput->text() == passInput->text());
        conditionsMatch &= (serverInput->text().isEmpty() == false);

        registerButton->setEnabled(conditionsMatch);
    }
}
