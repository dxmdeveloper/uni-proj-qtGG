#include "ChatWindow.hpp"

#include <QPushButton>
#include <QVBoxLayout>
#include <QDebug>
#include <nlohmann/json.hpp>

#include <crypto.hpp>
#include <QMessageBox>
#include <QNetworkReply>
#include <QThreadPool>
#include <utility>
#include <random>

#include "../common.hpp"

namespace Ui {
    ChatWindow::ChatWindow(QString server, QWidget *parent)
        : QMainWindow(parent),
          server(std::move(server)),
          bgKeyExchNetAccessMgr(new QNetworkAccessManager(this)) {
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
        connect(bgKeyExchNetAccessMgr, &QNetworkAccessManager::finished, this, &ChatWindow::onPendingKeyExchReply);

        // background processing
        pendingKeyExchChkTimerId = startTimer(BG_KEY_EXCH_CHK_INTERVAL);
    }

    ChatWindow::~ChatWindow() {
        killChatTimers();
        killTimer(pendingKeyExchChkTimerId);
    }

    void ChatWindow::setChat(quint64 userId, const QString &username) {
        // cleanup after previous chat
        chat->clear();
        lastMsgId = 0;
        killChatTimers();

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
            isRequestingKeyExchange = true;
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
            chat->append("Failed to get messages.<br>");
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
        auto rawBody = reply->readAll().toStdString();
        if (!reply->error())
            json = nlohmann::json::parse(rawBody);

        if (reply->error() || json.contains("error")) {
            chat->append("Failed to exchange keys.<br>");
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
                .arg(currentExchangeId)));

            request.setRawHeader("Authorization", g_jwt.c_str());
            keyExchNetAccessMgr->get(request);
        }

        auto onSuccessSetTimersAndChat = [&]() {
            chat->clear();
            if (keyExchTimerId)
                killTimer(keyExchTimerId.value());
            keyExchTimerId.reset();
            getMsgTimerId = startTimer(GET_MSG_INTERVAL);
        };

        if (json.contains("key")) {
            auto aesEnc = json["key"].get<std::string>();
            if (aesEnc.empty()) return; // exchange is complete

            aesEnc = Crypt::decryptRsaBase64(aesEnc, rsaKeyPair.first);
            auto aesDecoded = Encoding::base64UrlDecodeBytes(aesEnc);

            AES256Key key{};
            if (aesDecoded.size() < key.size()) {
                qDebug() << "Invalid AES key.";
                return;
            }

            std::copy_n(aesDecoded.begin(), key.size(), key.begin());
            addAesKey(key);

            rsaKeyPair.first.clear();
            rsaKeyPair.second.clear();
            onSuccessSetTimersAndChat();
        }

        if (json.contains("success") && !json["success"].get<bool>()) {
            chat->clear();
            auto aesKey = generateAesKey();
            addAesKey(aesKey);
            isRequestingKeyExchange = false;
            onSuccessSetTimersAndChat();
        }
    }

    void ChatWindow::onPendingKeyExchReply(QNetworkReply *reply) {
        if (reply->error()) {
            qDebug() << "Failed to check for pending key exchange.";
            qDebug() << reply->errorString();
            return;
        }
        auto json = nlohmann::json::parse(reply->readAll().toStdString());
        if (json.empty()) return;

        // answer one request at a time
        for (auto &req: json) {
            auto convId = req["conversation_id"].get<quint64>();
            if (!keys.contains(convId)) continue;

            auto rsaKey = req["key"].get<std::string>();
            auto exchangeId = req["exchange_id"].get<quint64>();

            auto aesKey = keys.at(convId);
            auto encryptedAesKey = Crypt::encryptRsaBase64(
                Encoding::base64UrlEncode(aesKey.data(), aesKey.size()),
                rsaKey
                );

            QNetworkRequest request(QUrl(server + KEY_EXCHANGE_URL));
            request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
            request.setRawHeader("Authorization", g_jwt.c_str());

            nlohmann::json jData({
                {"step", 1},
                {"exchange_id", exchangeId},
                {"key", encryptedAesKey}
            });

            bgKeyExchNetAccessMgr->post(request, jData.dump().c_str());
            break; // no more than one request at a time
        }
    }

    void ChatWindow::onSubmit() {
        auto msg = input->toPlainText().toStdString();
        if (msg.empty()) return;

        // encrypt message
        if (!keys.contains(currentChatId)) {
            QMessageBox msgBox;
            msgBox.setWindowTitle("Error");
            msgBox.setText("Encryption key is not yet exchanged.");
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.exec();
            return;
        }
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
        isRequestingKeyExchange = false;
    }

    AES256Key ChatWindow::generateAesKey() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<int> dist(0, 255);

        AES256Key key{};
        for (auto &i: key) {
            i = (char)dist(gen);
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

        if (timer == pendingKeyExchChkTimerId) {
            QNetworkRequest request(QUrl(server + PENDING_KEY_EXCH_URL));
            request.setRawHeader("Authorization", g_jwt.c_str());
            bgKeyExchNetAccessMgr->get(request);
            return;
        }

        if (printMsgTimerId && timer == printMsgTimerId.value()) {
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
        if (getMsgTimerId && timer == getMsgTimerId.value()) {
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

        if (keyExchTimerId && timer == keyExchTimerId.value()) {
            if (isRequestingKeyExchange) {
                QNetworkRequest request(QUrl(QString("%1/%2/step")
                    .arg(server + KEY_EXCHANGE_URL)
                    .arg(currentExchangeId)));
                request.setRawHeader("Authorization", g_jwt.c_str());
                keyExchNetAccessMgr->get(request);
            }
            return;
        }

        assert(false && "uncovered timer id path");
    }

    void ChatWindow::killChatTimers() {
        if (getMsgTimerId)
            killTimer(getMsgTimerId.value());

        if (keyExchTimerId)
            killTimer(keyExchTimerId.value());

        if (printMsgTimerId)
            killTimer(printMsgTimerId.value());
    }
}
