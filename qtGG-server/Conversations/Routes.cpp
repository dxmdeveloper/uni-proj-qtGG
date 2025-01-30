#include "Routes.hpp"
#include "../Auth/Auth.hpp"
#include <crow.h>
#include "../common.hpp"
#include "Conversation.hpp"
#include "KeyExchange.hpp"
#include "Messages.hpp"

void logRequest(const crow::request& req) {
    CROW_LOG_INFO << "Request URL: " << req.url;
    CROW_LOG_INFO << "Request Method: " << crow::method_name(req.method);
    CROW_LOG_INFO << "Request Headers:";
    for (const auto& header : req.headers) {
        CROW_LOG_INFO << header.first << ": " << header.second;
    }
    CROW_LOG_INFO << "Request Body: " << req.body;
}


namespace Conversations::routes {
    void createRoutes(crow::SimpleApp &app, QSqlDatabase &db) {
        CROW_ROUTE(app, "/startConversation").methods(crow::HTTPMethod::POST)(
            [&](const crow::request &req, crow::response &res) {
                startConversation(db, req, res);
                res.end();
            });
        CROW_ROUTE(app, "/exchangeKey").methods(crow::HTTPMethod::POST)(
            [&](const crow::request &req, crow::response &res) {
                exchangeKey(db, req, res);
                res.end();
            });
        CROW_ROUTE(app, "/sendMessage").methods(crow::HTTPMethod::POST)(
            [&](const crow::request &req, crow::response &res) {
                sendMessage(db, req, res);
                res.end();
            });
        CROW_ROUTE(app, "/getMessages/<int>/<int>")(
            [&](const crow::request &req, crow::response &res, uint64_t c, int64_t s) {
                getMessages(db, req, res, c, s);
                res.end();
            });
        CROW_ROUTE(app, "/exchangeKey/<int>/step")(
            [&](const crow::request &req, crow::response &res, uint64_t e) {
                //logRequest(req);
                exchangeKeyGetStep(db, req, res, e);
                res.end();
            });
        CROW_ROUTE(app, "/exchangeKey/<int>/key")(
            [&](const crow::request &req, crow::response &res, uint64_t e) {
                exchangeKeyGetKey(db, req, res, e);
                res.end();
            });
        CROW_ROUTE(app, "/keyExchangeRequests")(
            [&](const crow::request &req, crow::response &res) {
                keyExchangeRequests(db, req, res);
                res.end();
            });
    }

    void startConversation(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res) {
        crow::json::rvalue jwt{};
        if (!Auth::handleAuthorizationHeader(db, jwt, req, res)) return;

        auto userId = jwt["id"].u();

        auto reqJson = crow::json::load(req.body);
        auto target = reqJson["user"].u();

        bool created = false;
        auto cId = createConversationIfNotExists(db, userId, target, &created);
        if (cId == UINT64_MAX) {
            res.code = HTTP_CODE_INTERNAL_SERVER_ERROR;
            return;
        }
        res.body = jsonWrite({
            {"conversation_id", cId},
            {"created", created}
        });
    }

    void exchangeKey(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res) {
        crow::json::rvalue jwt{};
        if (!Auth::handleAuthorizationHeader(db, jwt, req, res)) return;

        auto userId = jwt["id"].u();
        auto reqJson = crow::json::load(req.body);

        auto step = reqJson["step"].u();
        auto exchangeId = uint64_t{};
        bool authorized = false;

        auto actualExchange = [&](auto exchangeFunc, auto exId) -> bool {
            auto key = toStringView(reqJson["key"].s());
            if (key.size() > KEY_FIELD_LEN) {
                res.body = jsonWrite({{"error", "key is too long"}});
                return false;
            }

            return exchangeFunc(db, exId, key);
        };

        /// NOTE: reduced to 2 steps (from 4) that's why it's mad
        switch (step) {
            case 0: {
                auto convId = reqJson["conversation_id"].u();
                if (!isUserInConversation(db, convId, userId)) {
                    res.code = HTTP_CODE_FORBIDDEN;
                    return;
                }
                // Start key exchange
                exchangeId = startKeyExchange(db, convId, userId);

                if (exchangeId == UINT64_MAX) {
                    res.code = HTTP_CODE_INTERNAL_SERVER_ERROR;
                    return;
                }
                if (exchangeId == UINT64_MAX - 1) {
                    // Delete previous messages because both users have no keys to decrypt them
                    cleanConversation(db, convId);
                    res.body = jsonWrite({{"success", false}});
                    return;
                }
                // set key
                if (actualExchange(sendRSAKey, exchangeId))
                    res.body = jsonWrite({{"success", true}, {"exchange_id", exchangeId}});
                else
                    res.body = jsonWrite({{"error", "internal error"}});
            }
            break;
            case 1: {
                exchangeId = reqJson["exchange_id"].u();
                authorized = isAllowedToGiveKey(db, exchangeId, userId);
                if (!authorized) {
                    res.code = HTTP_CODE_FORBIDDEN;
                    return;
                }

                bool result = actualExchange(sendAESKey, exchangeId);
                if (result) res.body = "{}";
            }
            break;
            default:
                res.code = HTTP_CODE_BAD_REQUEST;
                break;
        }
    }

    void exchangeKeyGetStep(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res,
                            uint64_t exchangeId) {
        crow::json::rvalue jwt{};

        if (!Auth::handleAuthorizationHeader(db, jwt, req, res)) return;

        auto step = getKeyExchangeCurrentStep(db, exchangeId);
        if (step == -1) {
            res.code = HTTP_CODE_INTERNAL_SERVER_ERROR;
            return;
        }
        res.body = jsonWrite({{"step", step}});
    }

    void exchangeKeyGetKey(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res,
                           uint64_t exchangeId) {
        crow::json::rvalue jwt{};
        if (!Auth::handleAuthorizationHeader(db, jwt, req, res)) return;

        auto userId = jwt["id"].u();
        auto key = getExchangeKey(db, exchangeId, userId); // function checks if user is in exchange
        res.body = jsonWrite({{"key", key}});
    }

    void sendMessage(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res) {
        crow::json::rvalue jwt{};
        if (!Auth::handleAuthorizationHeader(db, jwt, req, res)) return;

        auto userId = jwt["id"].u();
        auto reqJson = crow::json::load(req.body);

        if (!reqJson.has("conversation_id") || !reqJson.has("msg")) {
            res.code = HTTP_CODE_BAD_REQUEST;
            return;
        }
        auto conv = reqJson["conversation_id"].u();

        if (!isUserInConversation(db, conv, userId)) {
            res.code = HTTP_CODE_FORBIDDEN;
            return;
        }

        auto msg = toStringView(reqJson["msg"].s());
        if (msg.size() == 0) {
            res.body = jsonWrite({{"error", "message is empty"}});
            return;
        }
        if (msg.size() > MESSAGE_FIELD_LEN) {
            res.body = jsonWrite({{"error", std::format("message is too long (limit: {})", MESSAGE_FIELD_LEN)}});
            return;
        }

        auto result = Conversations::sendMessage(db, conv, userId, msg);
        if (!result) {
            res.code = HTTP_CODE_INTERNAL_SERVER_ERROR;
            return;
        }
        res.body = "{}";
    }

    void getMessages(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res,
                     uint64_t conv, int64_t since) {
        crow::json::rvalue jwt{};
        if (!Auth::handleAuthorizationHeader(db, jwt, req, res)) return;

        auto userId = jwt["id"].u();
        auto reqJson = crow::json::load(req.body);

        if (!isUserInConversation(db, conv, userId)) {
            res.code = HTTP_CODE_FORBIDDEN;
            return;
        }

        auto messages = Conversations::getMessages<true>(db, conv, since, 512);
        std::vector<crow::json::wvalue> jMsgs;
        jMsgs.reserve(messages.size());

        for (const auto &msg: messages) {
            crow::json::wvalue obj{
                {"id", msg.id},
                {"sender", msg.sender},
                {"send_at", msg.sendAt},
                {"msg", msg.message}
            };
            jMsgs.push_back(obj);
        }
        crow::json::wvalue json(jMsgs);
        res.body = json.dump();
    }

    void keyExchangeRequests(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res) {
        crow::json::rvalue jwt{};
        if (!Auth::handleAuthorizationHeader(db, jwt, req, res)) return;

        auto userId = jwt["id"].u();

        auto pending = getPendingKeyExchanges(db, userId);
        std::vector<crow::json::wvalue> jPending;
        jPending.reserve(pending.size());
        for (auto &p: pending) {
            crow::json::wvalue obj{
                {"exchange_id", p.exchangeId},
                {"conversation_id", p.conversationId},
                {"key", p.key}
            };
            jPending.push_back(obj);
        }

        res.body = crow::json::wvalue(jPending).dump();
    }
}
