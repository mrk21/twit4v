#include <twit4v/main_window.hpp>

namespace Twit4v {
    MainWindow::MainWindow(QWidget * parent) : QMainWindow(parent), label("hello world") {
        this->setCentralWidget(&this->label);
    }
}
