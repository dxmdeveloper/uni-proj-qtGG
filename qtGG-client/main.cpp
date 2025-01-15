#include <QApplication>
#include <QPushButton>
#include "ListWindow/ListWindow.hpp"

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    Ui::ListWindow list_window {};
    list_window.show();
    return QApplication::exec();
}