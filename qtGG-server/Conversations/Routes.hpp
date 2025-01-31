#pragma once
#include <functional>
#include <QSqlDatabase>
#include <string>
#include <crow.h>


namespace Conversations::routes {
    void createRoutes(crow::SimpleApp &app);

    /// POST /startConversation
    /// @params: user
    /// @return: conversation_id / error
    void startConversation(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res);

    /// POST /exchangeKey
    /// @params: step, key; step=0: conversation_id; step>0: exchange_id;
    /// @return: success:bool / error; step=0: exchange_id if success=true
    /// example resp: {"success":true,"exchange_id":uint64} resp {"success":false}
    void exchangeKey(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res);

    // GET /exchangeKey/<exchange_id>/step
    void exchangeKeyGetStep(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res, uint64_t exchangeId);

    // GET /exchangeKey/<exchange_id>/key
    void exchangeKeyGetKey(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res, uint64_t exchangeId);

    /// POST /sendMessage
    /// @params: conversation_id, msg
    /// @return: {} / error;
    void sendMessage(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res);

    /// GET /getMessages/<conversation_id>/<last_message_id>
    /// @return [{"id":uint64,"sender":uint64,"send_at":int64,"msg":string}...]
    void getMessages(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res, uint64_t conv,
                     int64_t since);

    /// GET /keyExchangeRequests
    /// @return [{"exchange_id":uint64,"conversation_id":uint64,"key":string}...]
    void keyExchangeRequests(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res);
}
