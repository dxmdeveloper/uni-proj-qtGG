#include "ChatWindow.hpp"

#include <QPushButton>
#include <QVBoxLayout>
#include <nlohmann/json.hpp>

#include <crypto.hpp>
#include <QMessageBox>
#include <QNetworkReply>
#include <QThreadPool>
#include <utility>

#include "../common.hpp"

namespace Ui {
    ChatWindow::ChatWindow(QString server, QWidget *parent)
        : QMainWindow(parent),
          server(std::move(server)) {
        auto *central = new QWidget();
        auto *vLayout = new QVBoxLayout();
        auto *chatPanelLayout = new QHBoxLayout();

        chatUsername = new QLabel("");
        chatUsername->setFont(QFont("Arial", 16, QFont::Bold));
        chatPanelLayout->addWidget(chatUsername);
        chatPanelLayout->addStretch();
        vLayout->addLayout(chatPanelLayout);

        auto *inputLayout = new QHBoxLayout();
        chat = new QTextEdit();
        input = new QPlainTextEdit();

        chat->setReadOnly(true);

        auto *sendButton = new QPushButton("Send");
        sendButton->setFixedWidth(50);

        input->setFixedHeight(40);
        input->setLineWrapMode(QPlainTextEdit::WidgetWidth);

        inputLayout->addWidget(input);
        inputLayout->addWidget(sendButton);

        vLayout->addWidget(chat);
        vLayout->addLayout(inputLayout);

        central->setLayout(vLayout);
        this->setCentralWidget(central);

        resize(600, 400);

        // signals
        connect(sendButton, &QPushButton::clicked, this, &ChatWindow::onSubmit);
    }

    ChatWindow::~ChatWindow() {
        killAllTimers();
    }

    void ChatWindow::setChat(quint64 userId, const QString &username) {
        // cleanup after previous chat
        chat->clear();
        lastMsgId = 0;
        killAllTimers();

        delete getMsgNetAccessMgr;
        delete sendMsgNetAccessMgr;
        delete keyExchNetAccessMgr;
        delete startConvNetAccessMgr;

        // setup new chat
        currentChatUserId = userId;
        currentChatUsername = username;
        chatUsername->setText(username);
        printMsgTimerId = startTimer(PRINT_INTERVAL);

        // create new access managers and connect them
        getMsgNetAccessMgr = new QNetworkAccessManager(this);
        sendMsgNetAccessMgr = new QNetworkAccessManager(this);
        keyExchNetAccessMgr = new QNetworkAccessManager(this);
        startConvNetAccessMgr = new QNetworkAccessManager(this);

        connect(getMsgNetAccessMgr, &QNetworkAccessManager::finished, this, &ChatWindow::onGetMsgReply);
        connect(sendMsgNetAccessMgr, &QNetworkAccessManager::finished, this, &ChatWindow::onSendMsgReply);
        connect(keyExchNetAccessMgr, &QNetworkAccessManager::finished, this, &ChatWindow::onKeyReply);
        connect(startConvNetAccessMgr, &QNetworkAccessManager::finished, this, &ChatWindow::onStartConvReply);

        QNetworkRequest request(QUrl(server + START_CONV_URL));
        request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        request.setRawHeader("Authorization", g_jwt.c_str());

        nlohmann::json json({
            {"user", userId}
        });

        auto data = json.dump();
        startConvNetAccessMgr->post(request, data.c_str());
    }

    void ChatWindow::onStartConvReply(QNetworkReply *reply) {
        if (reply->error()) {
            // TODO: repeat request
            QMessageBox msgBox;

            msgBox.setWindowTitle("Failed to start conversation.");
            msgBox.setText(reply->errorString());
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.exec();
            return;
        }
        auto replyData = reply->readAll();
        auto json = nlohmann::json::parse(replyData.toStdString());
        currentChatId = json["conversation_id"].get<uint64_t>();
        bool created = json["created"].get<bool>();

        if (created) {
            auto key = generateAesKey();
            addAesKey(key);
            getMsgTimerId = startTimer(GET_MSG_INTERVAL);
            return;
        }

        if (!keys.contains(currentChatId)) {
            isPendingKeyExchange = true;
            // Generate rsa keys
            rsaKeyPair = Crypt::generateRsaKeys(2048);
            nlohmann::json keyReqJson({
                {"step", 0},
                {"conversation_id", currentChatId},
                {"key", rsaKeyPair.second}
            });

            // Request key exchange
            QNetworkRequest request(QUrl(server + KEY_EXCHANGE_URL));
            request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
            request.setRawHeader("Authorization", g_jwt.c_str());
            keyExchNetAccessMgr->post(request, keyReqJson.dump().c_str());

            // give information to user
            chat->append("<b>Waiting for the other user to exchange an encryption key...</b>");
        }
    }

    void ChatWindow::onGetMsgReply(QNetworkReply *reply) {
        if (reply->error()) {
            QMessageBox msgBox;
            msgBox.setText("Failed to get messages.");
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.exec();
            return;
        }

        QThreadPool *pool = QThreadPool::globalInstance();
        auto *task = new MessageProcessingTask(this, reply);
        pool->start(task);
    }

    void ChatWindow::onSendMsgReply(QNetworkReply *reply) {
        // error handling
        nlohmann::json json;
        if (!reply->error())
            json = nlohmann::json::parse(reply->readAll().toStdString());

        if (reply->error() || json.contains("error")) {
            QMessageBox msgBox;
            msgBox.setText("Failed to send message.");
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.exec();
        }
    }

    void ChatWindow::onKeyReply(QNetworkReply *reply) {
        nlohmann::json json;
        if (!reply->error())
            json = nlohmann::json::parse(reply->readAll().toStdString());

        if (reply->error() || json.contains("error")) {
            QMessageBox msgBox;
            msgBox.setWindowTitle("Failed to exchange key.");
            msgBox.setText(reply->errorString());
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.exec();
            return;
        }

        if (json.contains("exchange_id")) {
            currentExchangeId = json["exchange_id"].get<quint64>();
            keyExchTimerId = startTimer(KEY_EXCH_CHECK_INTERVAL);
            return;
        }
        bool containsStep = json.contains("step");
        if (containsStep && json["step"].get<int>() == 1) {
            QNetworkRequest request(QUrl(
                QString("%1/%2/key")
                .arg(server + KEY_EXCHANGE_URL)
                .arg(currentChatId)));
            request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
            request.setRawHeader("Authorization", g_jwt.c_str());
            keyExchNetAccessMgr->get(request);
        }

        if (json.contains("key")) {
            auto aesKey = json["key"].get<std::string>();
            aesKey = Crypt::decryptRsaBase64(aesKey, rsaKeyPair.first);
            auto aesDecoded = Encoding::base64UrlDecodeBytes(aesKey);
            AES256Key key{};
            std::copy_n(aesDecoded.begin(), key.size(), key.begin());
            addAesKey(key);

            // timers
            killTimer(keyExchTimerId.value());
            keyExchTimerId.reset();
            getMsgTimerId = startTimer(GET_MSG_INTERVAL);
        }
    }

    void ChatWindow::onSubmit() {
        auto msg = input->toPlainText().toStdString();
        if (msg.empty()) return;

        // encrypt message
        assert(keys.contains(currentChatId));
        auto key = keys[currentChatId];
        msg = Crypt::encryptAes256Base64(msg, key);

        nlohmann::json json({
            {"msg", msg},
            {"conversation_id", currentChatId}
        });

        auto data = json.dump();
        QNetworkRequest request(QUrl(server + SEND_MSG_URL));
        request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        request.setRawHeader("Authorization", g_jwt.c_str());

        QByteArray postData = QByteArray::fromStdString(data);
        sendMsgNetAccessMgr->post(request, postData);

        input->clear();
    }

    void ChatWindow::addMessageToChat(const Message &msg) {
        // Format output
        auto formatted =
                "<br><b>"
                + (currentChatUserId != msg.sender ? "You: " : currentChatUsername + ": ")
                + "</b>"
                + msg.msg;
        chat->append(formatted);
    }

    void ChatWindow::addAesKey(const AES256Key &key) {
        // TODO: save key to a file/database
        keys[currentChatId] = key;
        isPendingKeyExchange = false;
    }

    AES256Key ChatWindow::generateAesKey() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<uint8_t> dist(0, 255);

        AES256Key key{};
        for (auto &i: key) {
            i = dist(gen);
        }
        return key;
    }

    void ChatWindow::messageProcessingThreadFunc(QNetworkReply &reply) {
        auto data = reply.readAll();
        auto json = nlohmann::json::parse(data.toStdString());

        assert(keys.contains(currentChatId));
        auto key = keys[currentChatId];

        for (auto &msg: json) {
            Message message{
                .id = msg["id"].get<quint64>(),
                .sender = msg["sender"].get<quint64>(),
                .send_at = msg["send_at"].get<qint64>(),
                .msg = QString::fromStdString(
                    Crypt::decryptAesBase64(msg["msg"].get<std::string>(), key))
                .toHtmlEscaped()
            };
            std::lock_guard lock(receivedMsgQueueMutex);
            receivedMsgQueue.push(message);
        }
    }

    void ChatWindow::timerEvent(QTimerEvent *event) {
        auto timer = event->timerId();

        if (printMsgTimerId.has_value() && timer == printMsgTimerId.value()) {
            int i = 0;
            Message msg;
            while (!receivedMsgQueue.empty() && i < 10) {
                {
                    std::lock_guard lock(receivedMsgQueueMutex);
                    msg = receivedMsgQueue.front();
                    receivedMsgQueue.pop();
                }
                if (msg.id <= lastMsgId) continue;
                addMessageToChat(msg);
                lastMsgId = msg.id;
                i++;
            }
            return;
        }
        if (getMsgTimerId.has_value() && timer == getMsgTimerId.value()) {
            QNetworkRequest request(QUrl(
                QString("%1/%2/%3")
                .arg(server + GET_MSG_URL)
                .arg(currentChatId)
                .arg(lastMsgId)));
            request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
            request.setRawHeader("Authorization", g_jwt.c_str());
            getMsgNetAccessMgr->get(request);
            return;
        }

        if (keyExchTimerId.has_value() && timer == keyExchTimerId.value()) {
            if (isPendingKeyExchange) {
                QNetworkRequest request(QUrl(QString("%1/%2/step")
                    .arg(server + KEY_EXCHANGE_URL)
                    .arg(currentChatId)));
                keyExchNetAccessMgr->get(request);
            }
            return;
        }

        assert(false && "uncovered timer id path");
    }

    void ChatWindow::killAllTimers() {
        if (getMsgTimerId.has_value())
            killTimer(getMsgTimerId.value());

        if (keyExchTimerId.has_value())
            killTimer(keyExchTimerId.value());

        if (printMsgTimerId.has_value())
            killTimer(printMsgTimerId.value());
    }
}
