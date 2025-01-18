#include "ListWindow.hpp"
#include <QPushButton>
#include <QMenuBar>

namespace Ui {
    ListWindow::ListWindow() {
        QWidget *central = new QWidget(this);
        setCentralWidget(central);

        createMenuBar();
        resize(280, 600);
    }

    void ListWindow::createMenuBar() {
        auto appMenu = menuBar()->addMenu(tr("&Application"));
        appMenu->addAction(tr("&Options"));
        appMenu->addAction(tr("&Quit"));

        auto aboutMenu = menuBar()->addAction(tr("&About"));

    }
}
