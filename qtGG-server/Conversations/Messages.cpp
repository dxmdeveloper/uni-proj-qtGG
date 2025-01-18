#include "Messages.hpp"
#include <QSqlQuery>
#include <QSqlError>
#include <QSqlDriver>
#include <QTime>
#include <crow.h>
#include "../common.hpp"

namespace Conversations {
    std::vector<Message> getMessages(QSqlDatabase &db, uint64_t conversationId, std::time_t since) {
        std::vector<Message> messages{};
        QSqlQuery query(db);
        query.prepare("SELECT id, sender, send_at, message FROM messages WHERE conversation=? AND send_at>=?");
        query.addBindValue(quint64(conversationId));
        query.addBindValue(qint64(since));
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
}
