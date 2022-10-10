#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <pcap.h>
#include <datapacketItem.h>
#include <QDebug>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void showNetworkCard();
    int capture();


private slots:
    void on_comboBox_currentIndexChanged(int index);
public slots:
    void dataPacketHander(dataPacketItem data);

private:
    Ui::MainWindow *ui;

    pcap_if_t* device;
    pcap_if_t * alldevices;
    pcap_t* pointer;
    char ERRBUFF[PCAP_ERRBUF_SIZE];

};
#endif // MAINWINDOW_H
