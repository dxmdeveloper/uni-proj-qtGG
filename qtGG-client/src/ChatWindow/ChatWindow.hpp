#pragma once
#include <QLabel>
#include <QMainWindow>
#include <QNetworkAccessManager>
#include <QPlainTextEdit>
#include <QRunnable>
#include <queue>
#include <mutex>

#include "../common.hpp"

namespace Ui {
    class ChatWindow : public QMainWindow {
        Q_OBJECT

    public:
        explicit ChatWindow(QString server, QWidget *parent = nullptr);

        ~ChatWindow();

        void setChat(quint64 userId, const QString &username);

    private slots:
        void onStartConvReply(QNetworkReply *reply);

        void onGetMsgReply(QNetworkReply *reply);

        void onSendMsgReply(QNetworkReply *reply);

        void onKeyReply(QNetworkReply *reply);

        void onPendingKeyExchReply(QNetworkReply *reply);

        void onSubmit();

    private:
        struct Message {
            quint64 id;
            quint64 sender;
            qint64 send_at;
            QString msg;
        };

        class MessageProcessingTask final : public QRunnable {
        public:
            MessageProcessingTask(ChatWindow *window, QNetworkReply *reply)
                : window(window), reply(reply) {
            }

            void run() override {
                window->messageProcessingThreadFunc(*reply);
            }

            ChatWindow *window;
            QNetworkReply *reply;
        };

    protected:
        void addMessageToChat(const Message &msg);

        void addAesKey(const AES256Key &key);

        static AES256Key generateAesKey();

        void messageProcessingThreadFunc(QNetworkReply &reply);

        void timerEvent(QTimerEvent *event) override;

        void killChatTimers();

    private:
        QString server;
        QNetworkAccessManager *getMsgNetAccessMgr = nullptr;
        QNetworkAccessManager *sendMsgNetAccessMgr = nullptr;
        QNetworkAccessManager *keyExchNetAccessMgr = nullptr;
        QNetworkAccessManager *startConvNetAccessMgr = nullptr;
        QNetworkAccessManager *bgKeyExchNetAccessMgr = nullptr;
        QTextEdit *chat;
        QPlainTextEdit *input;
        QLabel *chatUsername;
        time_t lastGetMsgTime = 0;
        uint64_t lastMsgId = 0;

        std::unordered_map<quint64, AES256Key> keys;
        std::queue<Message> receivedMsgQueue;
        std::timed_mutex receivedMsgQueueMutex;

        std::pair<std::string, std::string> rsaKeyPair;

        quint64 currentChatUserId = 0;
        quint64 currentChatId = 0;
        quint64 currentExchangeId = 0;
        QString currentChatUsername;

        bool isRequestingKeyExchange = false;

        // timer ids
        std::optional<int> getMsgTimerId{};
        std::optional<int> keyExchTimerId{};
        std::optional<int> printMsgTimerId{};
        int pendingKeyExchChkTimerId{};

        constexpr static char START_CONV_URL[] = "/startConversation";
        constexpr static char GET_MSG_URL[] = "/getMessages";
        constexpr static char SEND_MSG_URL[] = "/sendMessage";
        constexpr static char KEY_EXCHANGE_URL[] = "/exchangeKey";
        constexpr static char PENDING_KEY_EXCH_URL[] = "/keyExchangeRequests";

        constexpr static int PRINT_INTERVAL = 100;
        constexpr static int GET_MSG_INTERVAL = 1000;
        constexpr static int KEY_EXCH_CHECK_INTERVAL = 800;
        constexpr static int BG_KEY_EXCH_CHK_INTERVAL = 5000;
    };
}
