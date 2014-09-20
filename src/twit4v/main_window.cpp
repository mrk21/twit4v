#include <twit4v/main_window.hpp>
#include "ui_main_window.h"

namespace Twit4v {
    MainWindow::MainWindow(QWidget * parent) : QMainWindow(parent), ui(std::make_shared<Ui::MainWindow>()) {
        this->ui->setupUi(this);
    }
    
    void MainWindow::on_submitButton_clicked() {
        QString string = this->ui->lineEdit->text();
        this->ui->lineEdit->clear();
        this->ui->textEdit->append(string);
    }
}
