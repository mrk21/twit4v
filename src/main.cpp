#include <QApplication>
#include <twit4v/main_window.hpp>

int main(int argc, char ** argv) {
    QApplication app(argc, argv);
    Twit4v::MainWindow main;
    main.show();
    return app.exec();
}
