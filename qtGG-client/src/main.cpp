#include <QApplication>
#include <QDebug>
#include "ChatWindow/ChatWindow.hpp" // For testing purposes it is included here
#include "ListWindow/ListWindow.hpp"
#include <accmgr.h>
#include <openssl/rand.h> // for tests

#include "common.hpp"
#include "../../qtGG-crypto/include/crypto/Crypt.hpp"
#include "../../qtGG-crypto/include/crypto/Encoding.hpp"

std::string g_jwt{};

int main(int argc, char *argv[]) {
    auto accmgrOut = AccMgr_runAndReturnJWT();
    if (!accmgrOut.jwt || !accmgrOut.server)
        return -1;
    g_jwt = {accmgrOut.jwt};
    std::string server(accmgrOut.server);

    AccMgr_Output_free(&accmgrOut);

    QApplication app(argc, argv);
    QString testStr("");
    Ui::ChatWindow chatWindow(testStr);
    Ui::ListWindow listWindow(server);
    chatWindow.show();
    listWindow.show();

    return app.exec();
}