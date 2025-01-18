#pragma once
#include <functional>
#include <QSqlDatabase>
#include <string>
#include <crow.h>

namespace Conversations::routes {

    /// POST /startConversation
    /// @params: user
    /// @return: conversation_id / error
    void startConversation(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res);

    /// POST /exchangeKey
    /// @params: step; step=0: conversation_id; step>0: exchange_id; step>1 key
    /// @return: success:bool / error; step=0: exchange_id
    void exchangeKey(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res);

    /// POST /sendMessage
    /// @params: conversation_id, msg
    /// @return: {} / error;
    std::string sendMessage(std::reference_wrapper<QSqlDatabase> db, uint64_t conversationId, time_t since);

    /// GET /getMessages/<conversation_id>?since=<since>
    /// @return [{"id":uint64,"sender":uint64,"send_at":int64,"msg":string}...]
    std::string getMessages(std::reference_wrapper<QSqlDatabase> db, const crow::request &req);
}
