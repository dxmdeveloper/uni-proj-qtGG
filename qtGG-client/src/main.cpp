#include <QApplication>
#include <QPushButton>
#include "ListWindow/ListWindow.hpp"
#include <accmgr.h>

int main(int argc, char *argv[]) {
    auto accmgrOut = AccMgr_runAndReturnJWT();
    return 0;
}