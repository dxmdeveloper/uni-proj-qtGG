#pragma once
#include <cstdint>
#include <QSqlDatabase>

namespace Conversations {

    // === Encryption key exchange ===
    /// @return key_exchange.id on success,
    /// UINT64_MAX internal error, UINT64_MAX - 1 exchange failed (both users requesting)
    uint64_t startKeyExchange(QSqlDatabase &db, uint64_t conversationId, uint64_t reqUserId);
    bool offerAESKey(QSqlDatabase &db, uint64_t keyExchangeId, uint64_t keyOwnerId);
    bool sendRSAKey(QSqlDatabase &db, uint64_t keyExchangeId, std::string_view key);
    bool sendAESKey(QSqlDatabase &db, uint64_t keyExchangeId, std::string_view key);
    bool keyExchangeCleanup(QSqlDatabase &db, uint64_t keyExchangeId);

    bool isKeyOwnerInExchange(QSqlDatabase &db, uint64_t keyExchangeId, uint64_t keyOwnerId);
    bool isReqUserInKeyExchange(QSqlDatabase &db, uint64_t keyExchangeId, uint64_t reqUserId);

    bool handleFailedKeyExchange(QSqlDatabase &db, uint64_t conversationId);

}
