#ifndef TWIT4V_MAIN_WINDOW_HPP
#define TWIT4V_MAIN_WINDOW_HPP

#include <QMainWindow>
#include <memory>

namespace Twit4v {
    namespace Ui {
        class MainWindow;
    }
    
    class MainWindow: public QMainWindow {
        Q_OBJECT
        
    public:
        explicit MainWindow(QWidget * parent = nullptr);
        
    private slots:
        void on_submitButton_clicked();
        
    private:
        std::shared_ptr<Ui::MainWindow> ui;
    };
}

#endif
