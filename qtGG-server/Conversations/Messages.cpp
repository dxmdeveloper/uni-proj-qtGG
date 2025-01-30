#include "Messages.hpp"
#include <QSqlQuery>
#include <QSqlError>
#include <QSqlDriver>
#include <QTime>
#include <crow.h>
#include "../common.hpp"

namespace Conversations {
    bool sendMessage(QSqlDatabase &db, uint64_t conversationId, uint64_t senderId, std::string_view message) {
        QSqlQuery query(db);
        query.prepare("INSERT INTO messages (conversation, sender, message) VALUES (?, ?, ?)");
        query.addBindValue(quint64(conversationId));
        query.addBindValue(quint64(senderId));
        query.addBindValue(toQString(message));
        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            return false;
        }
        return true;
    }

    template<bool sinceIsLastMsgId>
    std::vector<Message> getMessages(QSqlDatabase &db, uint64_t conversationId, std::int64_t since, size_t limit) {
        std::vector<Message> messages{};
        QSqlQuery query(db);
        if constexpr (!sinceIsLastMsgId) {
            query.prepare(
                "SELECT * FROM ("
                "    SELECT id, sender, date_part('epoch', send_at) AS send_at, message "
                "    FROM messages "
                "    WHERE conversation = ? AND send_at >= to_timestamp(?) "
                "    ORDER BY send_at DESC "
                "    LIMIT ?"
                ") m "
                "ORDER BY send_at ASC"
            );
        } else {
            query.prepare(
                "SELECT * FROM ("
                "    SELECT id, sender, date_part('epoch', send_at) AS send_at, message "
                "    FROM messages "
                "    WHERE conversation = ? AND id > ? "
                "    ORDER BY send_at DESC "
                "    LIMIT ?"
                ") m "
                "ORDER BY send_at ASC"
            );
        }

        query.addBindValue(quint64(conversationId));
        query.addBindValue(qint64(since));
        query.addBindValue(quint64(limit));
        if (!query.exec()) {
            CROW_LOG_ERROR << query.lastError().text().toStdString();
            throw std::exception();
        }
        if (db.driver()->hasFeature(QSqlDriver::QuerySize))
            messages.reserve(query.size());

        while (query.next()) {
            auto id = static_cast<uint64_t>(query.value(0).toULongLong());
            auto sender = static_cast<uint64_t>(query.value(1).toULongLong());
            auto sendAt = static_cast<time_t>(query.value(2).toLongLong());
            auto message = query.value(3).toString().toStdString();

            messages.emplace_back(id, sender, sendAt, message);
        }

        return messages;
    }

    template std::vector<Message> getMessages<true>(QSqlDatabase &, uint64_t, std::int64_t, size_t);

    template std::vector<Message> getMessages<false>(QSqlDatabase &, uint64_t, std::int64_t, size_t);
}
