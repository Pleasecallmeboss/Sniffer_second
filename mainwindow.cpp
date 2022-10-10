#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <multhread.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    multhread* thread = new multhread;
    showNetworkCard();
    //得加static，triggered没有()
    static bool isstart = false;
    connect(ui->actionrunandstop,&QAction::triggered,this,[=](){
        isstart = !isstart;
        if(isstart)
        {
            int res = capture();
            if(res != -1 && pointer)
            {
                thread->setPointer(pointer);
                thread->setFlag();
                thread->start();
                ui->actionrunandstop->setIcon(QIcon(":/export.png"));
                ui->comboBox->setEnabled(false);
            }
        }
        else
        {
            thread->stop();
            pcap_close(pointer);
            pointer = nullptr;
            ui->actionrunandstop->setIcon(QIcon(":/run.png"));
            ui->comboBox->setEnabled(true);
        }
    });
    connect(thread,&multhread::send,this,&MainWindow::dataPacketHander);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::showNetworkCard()
{
    int n = pcap_findalldevs(&alldevices,ERRBUFF);
    if(n != 1)
    {
        statusBar()->showMessage("have detect device");
        ui->comboBox->addItem("please choose a interface");
        device = alldevices;
        while(device != nullptr)
        {
            QString str = QString(device->name);
            str.replace("\\Device\\NPF_ ","");
            ui->comboBox->addItem(str + device->description);
            device = device->next;
        }
    }
    return ;


}




void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    if(index == 0)
    {
        return;
    }
    int i = 0;
    for(device = alldevices; i < index - 1; device = device -> next,i++)
    {}
}

int MainWindow::capture()
{
    pointer = pcap_open_live(device->name, 65535, 1, 1000, ERRBUFF);
    if(pointer == nullptr)
    {
        pcap_freealldevs(alldevices);
        device = nullptr;
        statusBar()->showMessage("open failed");
        return -1;

    }
    else
    {
        statusBar()->showMessage("open successfully");
        if((pcap_datalink(pointer)) != DLT_EN10MB)
        {
            pcap_close(pointer);
            pointer = nullptr;
            pcap_freealldevs(alldevices);
            device = nullptr;
            return -1;
        }

    }
    return 0;
}

void MainWindow::dataPacketHander(dataPacketItem data)
{
    if(data.getProtocolTypeToString() == "ICMP")
    {
        qDebug() << data.getTimestamp() << " " << data.getProtocolTypeToString() << " " << data.getInfo() ;
    }
}
