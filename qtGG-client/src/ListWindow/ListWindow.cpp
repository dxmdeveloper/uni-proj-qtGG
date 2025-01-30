#include "ListWindow.hpp"
#include <QPushButton>
#include <QMenuBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidget>
#include <QListWidget>
#include <crypto.hpp>
#include <QMessageBox>


#include "../common.hpp"
#include <nlohmann/json.hpp>
#include <QtNetwork/QNetworkReply>

namespace Ui {
    ListWindow::ListWindow(std::string_view server, QWidget *parent)
        : QMainWindow(parent)
           {
        setServer(server);
        chatWindow = new ChatWindow(qStrServer, this);

        // === Setup UI ===
        auto *central = new QWidget(this);
        auto *vLayout = new QVBoxLayout(central);

        // Username header
        auto *usernameWidget = new QWidget();
        auto *usernameLayout = new QHBoxLayout();
        usernameWidget->setFixedHeight(50);
        userLabel = new QLabel("{username}", central);
        userLabel->setFont(QFont("Arial", 16, QFont::Bold));
        JwtReader jwtReader(g_jwt);
        auto payload = jwtReader.getPayload();
        auto json = nlohmann::json::parse(payload);
        userLabel->setText(QString::fromStdString(json["user"].get<std::string>()));

        usernameLayout->addWidget(userLabel);
        usernameLayout->addStretch();
        usernameWidget->setLayout(usernameLayout);
        vLayout->addWidget(usernameWidget);

        // Contact list
        contactList = new QListWidget();
        vLayout->addWidget(contactList);

        // Finish Ui setup
        setCentralWidget(central);

        createMenuBar();
        resize(280, 600);

        // === Slots and signals ===
        manager = new QNetworkAccessManager(this);
        connect(manager, &QNetworkAccessManager::finished, this, &ListWindow::onUserListReceived);
        connect(contactList, &QListWidget::itemDoubleClicked, this, &ListWindow::onUserSelected);

        // === Request user list ===
        QNetworkRequest request;
        request.setUrl(QUrl(qStrServer + usersListUrl));
        request.setRawHeader("Authorization", g_jwt.c_str());
        manager->get(request);
    }

    void ListWindow::setServer(std::string_view server) {
        this->server = "http://"+std::string(server);
        this->qStrServer = QString::fromStdString(this->server);
    }

    void ListWindow::createMenuBar() {
        auto appMenu = menuBar()->addMenu(tr("&Application"));
        appMenu->addAction(tr("&Options"));
        appMenu->addAction(tr("&Log out"));
        appMenu->addAction(tr("&Quit"));

        auto aboutMenu = menuBar()->addAction(tr("&About"));
    }

    void ListWindow::onUserListReceived(QNetworkReply *reply) {
        if (reply->error()) {
            if (reply->error() == QNetworkReply::AuthenticationRequiredError) {
                // TODO: Log out
            }
            QMessageBox msgBox;
            msgBox.setWindowTitle("Failed to get user list");
            msgBox.setText(reply->errorString());
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.exec();
            return;
        }
        auto data = reply->readAll();
        auto json = nlohmann::json::parse(data.toStdString());
        for (auto &user : json) {
            auto username = QString::fromStdString(user["username"].get<std::string>());
            auto id = user["id"].get<quint64>();
            if (username == userLabel->text())
                continue;

            auto item = new QListWidgetItem(username);
            item->setData(Qt::UserRole, id);
            contactList->addItem(item);
        }
    }

    void ListWindow::onUserSelected(const QListWidgetItem *item) const {
        auto id = item->data(Qt::UserRole).toULongLong();
        auto username = item->text();
        chatWindow->setChat(id, username);
        chatWindow->show();
    }
}
