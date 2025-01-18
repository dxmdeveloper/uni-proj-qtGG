#include "Routes.hpp"
#include "../Auth/Auth.hpp"
#include <crow.h>
#include "../common.hpp"
#include "Conversation.hpp"
#include "KeyExchange.hpp"

namespace Conversations::routes {
    void startConversation(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res) {
        crow::json::rvalue jwt{};
        if (!Auth::handleAuthorizationHeader(jwt, req, res)) return;

        auto userId = jwt["id"].u();

        auto reqJson = crow::json::load(req.body);
        auto target = reqJson["user"].u();

        auto cId = createConversationIfNotExists(db, userId, target);
        if (cId == UINT64_MAX) {
            res.code = HTTP_CODE_INTERNAL_SERVER_ERROR;
            res.end();
            return;
        }
        res.body = jsonWrite({{"conversation_id", cId}});
        res.end();
    }

    void exchangeKey(std::reference_wrapper<QSqlDatabase> db, const crow::request &req, crow::response &res) {
        crow::json::rvalue jwt{};
        if (!Auth::handleAuthorizationHeader(jwt, req, res)) return;

        auto userId = jwt["id"].u();
        auto reqJson = crow::json::load(req.body);

        auto step = reqJson["step"].u();

        auto actualExchange = [&](auto authFunc, auto exchangeFunc) {
            auto exchangeId = reqJson["exchange_id"].u();
            auto key = toStringView(reqJson["key"].s());
            if (key.size() > KEY_FIELD_LEN) {
                res.body = jsonWrite({{"error", "key is too long"}});
                res.end();
                return;
            }
            bool authorized = authFunc(db, exchangeId, userId);
            if (!authorized) {
                res.code = HTTP_CODE_FORBIDDEN;
                res.end();
                return;
            }
            exchangeFunc(db, exchangeId, key);
        };

        switch (step) {
            case 0: {
                auto convId = reqJson["conversation_id"].u();
                if (!isUserInConversation(db, convId, userId)) {
                    res.code = HTTP_CODE_FORBIDDEN;
                    res.end();
                    return;
                }
                auto exchangeId = startKeyExchange(db, userId, reqJson["exchange_id"].u());
                if (exchangeId == UINT64_MAX) {
                    res.code = HTTP_CODE_INTERNAL_SERVER_ERROR;
                    res.end();
                    return;
                }

                res.body = jsonWrite({
                    {"success", (exchangeId != UINT64_MAX - 1)},
                    {"exchange_id", exchangeId}
                });
                res.end();
                return;
            }
            case 1: {
                auto exchangeId = reqJson["exchange_id"].u();
                bool success = offerAESKey(db, exchangeId, userId);
                if (!success) {
                    res.body = jsonWrite({{"error", "exchange not found"}});
                    res.end();
                    return;
                }
                res.body = "{}";
                res.end();
                return;
            }
            case 2: actualExchange(isReqUserInKeyExchange, sendRSAKey);
                break;
            case 3: actualExchange(isKeyOwnerInExchange, sendRSAKey);
                break;
            default:
                res.code = HTTP_CODE_BAD_REQUEST;
                res.end();
                break;
        }
    }
}
