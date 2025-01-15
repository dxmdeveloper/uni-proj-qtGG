#pragma once
#include <QDialog>
#include <QLineEdit>

namespace Ui {
    class RegistrationDialog : public QDialog {
        Q_OBJECT

    public:
        RegistrationDialog(QWidget *parent = nullptr);

    private slots:
        void onRegistrationSuccess(const std::string &msg);

        void onRegistrationError(const std::string &error);

        void onSubmitClicked();

        void onInputChanged();

    private:
        QLineEdit *userInput;
        QLineEdit *emailInput;
        QLineEdit *passInput;
        QLineEdit *repeatInput;
        QLineEdit *serverInput;
        QPushButton * registerButton;
    };
}
