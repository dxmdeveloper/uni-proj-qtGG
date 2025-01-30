#pragma once
#include <QSqlDatabase>
#include <chrono>
#include <vector>

namespace Conversations {
    struct Message {
        uint64_t id;
        uint64_t sender;
        std::time_t sendAt;
        std::string message;
    };

    bool sendMessage(QSqlDatabase &db, uint64_t conversationId, uint64_t senderId, std::string_view message);

    template<bool sinceIsLastMsgId>
    std::vector<Message> getMessages(QSqlDatabase &db, uint64_t conversationId, std::int64_t since, size_t limit);
}

