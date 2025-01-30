#include "Conversation.hpp"
#include <QSqlQuery>
#include <QSqlError>
#include <crow/logging.h>

namespace Conversations {
    uint64_t findConversation(QSqlDatabase &db, uint64_t user1, uint64_t user2) {
        QSqlQuery query(db);
        query.prepare("SELECT id FROM conversations WHERE (user1=? AND user2=?) OR (user1=? AND user2=?)");
        query.addBindValue(quint64(user1));
        query.addBindValue(quint64(user2));
        query.addBindValue(quint64(user2));
        query.addBindValue(quint64(user1));

        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            throw std::exception();
        }

        if (!query.next())
            return UINT64_MAX;

        return static_cast<int64_t>(query.value(0).toLongLong());
    }

    bool isUserInConversation(QSqlDatabase &db, uint64_t conversationId, uint64_t user) {
        QSqlQuery query(db);
        query.prepare("SELECT 1 FROM conversations WHERE (user1=:u OR user2=:u) AND id=:c");
        query.bindValue(":u", quint64(user));
        query.bindValue(":c", quint64(conversationId));
        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return false;
        }
        return query.next();
    }

    uint64_t createConversationIfNotExists(QSqlDatabase &db, uint64_t user1, uint64_t user2, bool *out_created) {
        if (user1 == user2)
            return UINT64_MAX;

        // ensure there is no such conversation
        auto existing = findConversation(db, user1, user2);
        if (existing != UINT64_MAX) {
            if (out_created != nullptr)
                *out_created = false;
            return static_cast<uint64_t>(existing);
        }

        // sort user ids so user1 is always the smaller number
        if (user1 > user2)
            std::swap(user1, user2);

        // insertion query
        QSqlQuery query(db);
        query.prepare("INSERT INTO conversations (user1, user2) VALUES (?, ?)");
        query.addBindValue(quint64(user1));
        query.addBindValue(quint64(user2));
        auto result = query.exec();
        auto lastId = query.lastInsertId();

        if (!result || !lastId.isValid()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return UINT64_MAX;
        }
        if (out_created != nullptr)
            *out_created = true;
        return static_cast<uint64_t>(lastId.toLongLong());
    }

    bool dropConversation(QSqlDatabase &db, uint64_t id) {
        QSqlQuery query(db);
        query.prepare("DELETE FROM conversations WHERE id=?");
        query.addBindValue(quint64(id));
        auto result = query.exec();
        if (!result)
            CROW_LOG_ERROR << query.lastError().text().toStdString();
        return result;
    }
}
