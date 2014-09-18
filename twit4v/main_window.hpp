#ifndef TWIT4V_MAIN_WINDOW_HPP
#define TWIT4V_MAIN_WINDOW_HPP

#include <QMainWindow>
#include <QLabel>

namespace Twit4v {
    class MainWindow: public QMainWindow {
        Q_OBJECT
        
    public:
        explicit MainWindow(QWidget * parent = nullptr);
        
    private:
        QLabel label;
    };
}

#endif
