#include "KeyExchange.hpp"

#include <QSqlDriver>
#include <QSqlQuery>
#include <QSqlError>
#include <crow/logging.h>
#include "../common.hpp"

namespace Conversations {
    uint64_t startKeyExchange(QSqlDatabase &db, uint64_t conversationId, uint64_t reqUserId) {
        QSqlQuery query(db);
        // Check if the user has already requested
        query.prepare("SELECT id, step FROM key_exchange WHERE conversation=? AND req_user=?");
        query.addBindValue(quint64(conversationId));
        query.addBindValue(quint64(reqUserId));
        auto result = query.exec();
        if (!result) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return UINT64_MAX;
        }
        if (query.next()) {
            auto keyExchangeId = static_cast<uint64_t>(query.value(0).toULongLong());
            auto step = query.value(1).toInt();
            // user has already requested, can update the key
            if (step == 0)
                return keyExchangeId;
            // clean after a previous exchange
            keyExchangeCleanup(db, keyExchangeId);
        }

        // check if the second user has requested
        query.prepare("SELECT 1 FROM key_exchange WHERE conversation=?");
        query.addBindValue(quint64(conversationId));
        result = query.exec();
        if (!result) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return UINT64_MAX;
        }
        if (query.next()) {
            // exchange failed (both users requesting)
            return UINT64_MAX - 1;
        }
        // Start key exchange
        query.prepare("INSERT INTO key_exchange(step, req_user, conversation) VALUES (0, ?, ?)");
        query.addBindValue(quint64(reqUserId));
        query.addBindValue(quint64(conversationId));
        result = query.exec();
        auto lastId = query.lastInsertId();

        if (!result || !lastId.isValid()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return UINT64_MAX;
        }

        return static_cast<uint64_t>(lastId.toULongLong());
    }

    template<bool inc>
    bool sendKeyTmpl(QSqlDatabase &db, uint64_t keyExchangeId, std::string_view key) {
        QSqlQuery query(db);
        query.prepare("SELECT 1 FROM key_exchange WHERE step=0 AND id=?");
        query.addBindValue(quint64(keyExchangeId));

        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return false;
        }
        if (!query.next())
            return false;

        query.prepare("UPDATE key_exchange SET step=?, updated_at=CURRENT_TIMESTAMP, enc_key=? WHERE id=?");
        query.addBindValue(inc ? 1 : 0);
        query.addBindValue(toQString(key));
        query.addBindValue(quint64(keyExchangeId));

        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return false;
        }
        return true;
    }

    bool sendRSAKey(QSqlDatabase &db, uint64_t keyExchangeId, std::string_view key) {
        return sendKeyTmpl<false>(db, keyExchangeId, key);
    }

    bool sendAESKey(QSqlDatabase &db, uint64_t keyExchangeId, std::string_view key) {
        return sendKeyTmpl<true>(db, keyExchangeId, key);
    }

    bool keyExchangeCleanup(QSqlDatabase &db, uint64_t keyExchangeId) {
        QSqlQuery query(db);
        query.prepare("DELETE FROM key_exchange WHERE id=?");
        query.addBindValue(quint64(keyExchangeId));

        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return false;
        }
        return true;
    }

    std::string getExchangeKey(QSqlDatabase &db, uint64_t keyExchangeId, uint64_t user) {
        QSqlQuery query(db);
        query.prepare("SELECT enc_key FROM key_exchange WHERE id=? AND (req_user=? OR key_owner=?)");
        query.addBindValue(quint64(keyExchangeId));
        query.addBindValue(quint64(user));
        query.addBindValue(quint64(user));
        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            throw std::exception();
        }
        if (!query.next())
            return "";

        return query.value(0).toString().toStdString();
    }

    int getKeyExchangeCurrentStep(QSqlDatabase &db, uint64_t keyExchangeId) {
        QSqlQuery query(db);
        query.prepare("SELECT step FROM key_exchange WHERE id=?");
        query.addBindValue(quint64(keyExchangeId));
        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return -1;
        }
        if (!query.next())
            return -1;

        return query.value(0).toInt();
    }

    bool isAllowedToGiveKey(QSqlDatabase &db, uint64_t keyExchangeId, uint64_t userId) {
        QSqlQuery query(db);
        query.prepare("SELECT 1 FROM key_exchange k INNER JOIN conversations c ON k.conversation=c.id"
                      " WHERE k.id=? AND (c.user1=? OR c.user2=?)");
        query.addBindValue(quint64(keyExchangeId));
        query.addBindValue(quint64(userId));
        query.addBindValue(quint64(userId));
        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return false;
        }
        return query.next();
    }

    bool isKeyOwnerInExchange(QSqlDatabase &db, uint64_t keyExchangeId, uint64_t keyOwnerId) {
        QSqlQuery query(db);
        query.prepare("SELECT 1 FROM key_exchange WHERE id=? AND key_owner=?");
        query.addBindValue(quint64(keyExchangeId));
        query.addBindValue(quint64(keyOwnerId));
        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return false;
        }
        return query.next();
    }

    bool isReqUserInKeyExchange(QSqlDatabase &db, uint64_t keyExchangeId, uint64_t reqUserId) {
        QSqlQuery query(db);
        query.prepare("SELECT 1 FROM key_exchange WHERE id=? AND req_user=?");
        query.addBindValue(quint64(keyExchangeId));
        query.addBindValue(quint64(reqUserId));
        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return false;
        }
        return query.next();
    }

    bool handleFailedKeyExchange(QSqlDatabase &db, uint64_t conversationId) {
        // delete key exchange record
        QSqlQuery query(db);
        db.transaction();
        query.prepare("DELETE FROM key_exchange WHERE conversation=?");
        query.addBindValue(quint64(conversationId));
        auto result = query.exec();
        if (!result) {
            db.rollback();
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return false;
        }
        // remove all messages from conversation as it's encrypted and users have no keys
        query.prepare("DROP FROM messages WHERE conversation=?");
        query.addBindValue(quint64(conversationId));
        result = query.exec();
        if (!result) {
            db.rollback();
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return false;
        }
        db.commit();
        return true;
    }

    std::vector<PendingRequest> getPendingKeyExchanges(QSqlDatabase &db, uint64_t userId) {
        QSqlQuery query(db);
        query.prepare(
            "SELECT c.id, k.id, k.enc_key FROM key_exchange k"
            " INNER JOIN conversations c ON k.conversation=c.id"
            " WHERE (c.user1=:u OR c.user2=:u) AND k.step=0 AND k.req_user<>:u");
        query.bindValue(":u", quint64(userId));
        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return {};
        }
        std::vector<PendingRequest> result;
        if (db.driver()->hasFeature(QSqlDriver::QuerySize)) {
            result.reserve(query.size());
        }

        while (query.next()) {
            result.push_back(PendingRequest{
                .conversationId = static_cast<uint64_t>(query.value(0).toULongLong()),
                .exchangeId = static_cast<uint64_t>(query.value(1).toULongLong()),
                .key = query.value(2).toString().toStdString()
            });
        }

        return result;
    }
}
