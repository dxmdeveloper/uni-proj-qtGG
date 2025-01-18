#define BUILD_LIBRARY 1
#include "accmgr.h"

#include <QApplication>
#include "LoginWindow.hpp"
#include "RegistrationDialog.hpp"

std::tuple<int, char **> createFakeArgs() {
    static char arg1[] = "qtGG-accmgr";
    static char arg2[] = "";
    static char *argv[2] = {arg1, arg2};
    return {1, argv};
}

 int main() {
    // AccMgr_Output output = AccMgr_runAndReturnJWT();
    // int exitCode = output.error;
    // return exitCode;
 }


AccMgr_Output AccMgr_runAndReturnJWT() {
    // TODO: load saved user
    return AccMgr_openLoginDialog();
}

AccMgr_Output AccMgr_openLoginDialog() {
    auto args = createFakeArgs();
    QApplication application(std::get<0>(args), std::get<1>(args));
    AccMgr_Output output{};
    std::string jwtStr{};
    auto *loginWindow = new Ui::LoginWindow{&jwtStr};
    loginWindow->show();
    int appRet = QApplication::exec();
    if (!jwtStr.empty()) {
        output.jwt = new char[jwtStr.size() + 1];
        memcpy(output.jwt, jwtStr.c_str(), jwtStr.size() + 1);
    } else output.error = appRet ? appRet : -2137;
    return output;
}

int AccMgr_openRegistrationDialog() {
    auto args = createFakeArgs();
    QApplication application(std::get<0>(args), std::get<1>(args));

    Ui::RegistrationDialog registerWindow{};
    registerWindow.show();
    int appRet = QApplication::exec();
    return appRet;
}

void AccMgr_Output_free(AccMgr_Output *p) {
    delete [] p->jwt;
    p->jwt = nullptr;
    delete [] p->server;
    p->server = nullptr;
}
