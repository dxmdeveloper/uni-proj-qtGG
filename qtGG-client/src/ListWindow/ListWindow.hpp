#pragma once
#include <QLabel>
#include <QListWidget>
#include <QMainWindow>
#include <QNetworkAccessManager>

#include "../ChatWindow/ChatWindow.hpp"

namespace Ui {
    class ListWindow : public QMainWindow {
        Q_OBJECT

    public:
        ListWindow(std::string_view server, QWidget *parent = nullptr);
        void setServer(std::string_view server);

    private:
        void createMenuBar();

    private slots:
        void onUserListReceived(QNetworkReply *reply);
        void onUserSelected(const QListWidgetItem *item) const;

    private:
        std::string server;
        QString qStrServer;
        QListWidget *contactList;
        QNetworkAccessManager *manager;
        QLabel *userLabel;
        ChatWindow *chatWindow;

        constexpr static char usersListUrl[] = "/getUsersList";
    };
}
