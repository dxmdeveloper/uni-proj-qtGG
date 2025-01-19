#pragma once
#include <cstdint>
#include <QSqlDatabase>

namespace Conversations {
    inline constexpr int KEY_FIELD_LEN = 5000;
    inline constexpr int MESSAGE_FIELD_LEN = 500;

    // === Conversations in general ===
    uint64_t findConversation(QSqlDatabase &db, uint64_t user1, uint64_t user2);
    bool isUserInConversation(QSqlDatabase &db, uint64_t conversationId, uint64_t user);
    //bool doesConversationExist(QSqlDatabase &db, uint64_t id);
    uint64_t createConversationIfNotExists(QSqlDatabase &db, uint64_t user1, uint64_t user2);
    bool dropConversation(QSqlDatabase &db, uint64_t id);



}
