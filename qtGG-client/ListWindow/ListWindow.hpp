#pragma once
#include <QMainWindow>

namespace Ui {
    class ListWindow : public QMainWindow {
        Q_OBJECT

    public:
        ListWindow();

    private:
        void createMenuBar();
    };
}
