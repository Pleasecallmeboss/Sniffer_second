#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <multhread.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
//    ui setting
    ui->setupUi(this);
    ui->statusbar->showMessage("Welcome to Sniffer!");
    ui->toolBar->addAction(ui->actionrunandstop);
    ui->toolBar->addAction(ui->actionclear);
    ui->toolBar->setMovable(false);
    ui->tableWidget->setShowGrid(false);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->treeWidget->setHeaderHidden(true);

    ui->tableWidget->setColumnCount(7);
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    QStringList title = {"NO.","Time","Source","Destination","Protocol","Length","Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);
    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,300);
    ui->tableWidget->setColumnWidth(3,300);
    ui->tableWidget->setColumnWidth(4,100);
    ui->tableWidget->setColumnWidth(5,100);
    ui->tableWidget->setColumnWidth(6,1000);

    countNumber = 0;
    rowNumber = -1;
    multhread* thread = new multhread;
    showNetworkCard();
    //得加static，triggered没有()
    static bool isstart = false;
    connect(ui->actionrunandstop,&QAction::triggered,this,[=](){
        isstart = !isstart;
        if(isstart)
        {
            ui->tableWidget->clearContents();
            ui->tableWidget->setRowCount(0);
            countNumber = 0;
            rowNumber = -1;
            int dataSize = this->dataPackageItemVector.size();
            for(int i = 0;i < dataSize;i++){
                free((char*)(this->dataPackageItemVector[i].pkt_content));
                this->dataPackageItemVector[i].pkt_content = nullptr;
            }
            QVector<dataPacketItem>().swap(dataPackageItemVector);

            int res = capture();
            if(res != -1 && pointer)
            {
                thread->setPointer(pointer);
                thread->setFlag();
                thread->start();
                ui->actionrunandstop->setIcon(QIcon(":/export.png"));
                ui->comboBox->setEnabled(false);
            }
            else
            {
                isstart = !isstart;
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
    // free the memory you have allocated!
    int dataSize = this->dataPackageItemVector.size();
    for(int i = 0;i<dataSize;i++){
        free((char*)(this->dataPackageItemVector[i].pkt_content));
        this->dataPackageItemVector[i].pkt_content = nullptr;
    }
    // do not use 'data.clear()' only,it can't free totally!
    QVector<dataPacketItem>().swap(dataPackageItemVector);
    delete ui;
}

void MainWindow::showNetworkCard()
{
    int n = pcap_findalldevs(&alldevices,ERRBUFF);
    if(n != 1)
    {
        statusBar()->showMessage("Have detected device");
        ui->comboBox->addItem("Please choose a interface(ac7e wifi)");
        device = alldevices;
        while(device != nullptr)
        {
//            无线网卡{ac7e0f27-8355-44a8-bada-7c6895909601}
            QString str = QString(device->name);
            str.replace("\\Device\\NPF_","");
            ui->comboBox->addItem(str + device->description );
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
    if(device)
    {
        pointer = pcap_open_live(device->name, 65535, 1, 1000, ERRBUFF);
    }
    else
    {
        this->statusBar()->showMessage("Please choose a NetCard!!!");
        return -1;
    }
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
    ui->tableWidget->insertRow(countNumber);
    this->dataPackageItemVector.push_back(data);
    QString type = data.getProtocolTypeToString();
    QColor color;
    // show different color
    if(type == "TCP"){
        color = QColor(216,191,216);
    }else if(type == "TCP"){
        color = QColor(144,238,144);
    }
    else if(type == "ARP"){
        color = QColor(238,238,0);
    }
    else if(type == "DNS"){
        color = QColor(255,255,224);
    }else if(type == "TLS" || type == "SSL"){
        color = QColor(210,149,210);
    }else{
        color = QColor(255,218,185);
    }
    ui->tableWidget->setItem(countNumber,0,new QTableWidgetItem(QString::number(countNumber + 1)));
    ui->tableWidget->setItem(countNumber,1,new QTableWidgetItem(data.getTimestamp()));
    ui->tableWidget->setItem(countNumber,2,new QTableWidgetItem(data.getSource()));
    ui->tableWidget->setItem(countNumber,3,new QTableWidgetItem(data.getDestination()));
    ui->tableWidget->setItem(countNumber,4,new QTableWidgetItem(type));
    ui->tableWidget->setItem(countNumber,5,new QTableWidgetItem(data.getLength()));
    ui->tableWidget->setItem(countNumber,6,new QTableWidgetItem(data.getInfo()));
    // set color
    for(int i = 0;i < 7;i++){
        ui->tableWidget->item(countNumber,i)->setBackground(color);
    }
    countNumber++;
}

void MainWindow::on_tableWidget_cellClicked(int row, int column)
{
    if(rowNumber == row || row < 0){
        return;
    }else{
        ui->treeWidget->clear();
        rowNumber = row;
        if(rowNumber < 0 || rowNumber > dataPackageItemVector.size())
            return;
        QString desMac = dataPackageItemVector[rowNumber].getDesMacAddr();
        QString srcMac = dataPackageItemVector[rowNumber].getSrcMacAddr();
        QString type = dataPackageItemVector[rowNumber].getMacType();
        QString tree1 = "Ethernet, Src:" +srcMac + ", Dst:" + desMac;
        QTreeWidgetItem*item = new QTreeWidgetItem(QStringList()<<tree1);
        ui->treeWidget->addTopLevelItem(item);

        item->addChild(new QTreeWidgetItem(QStringList()<<"Destination:" + desMac));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Source:" + srcMac));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + type));

        QString packageType = dataPackageItemVector[rowNumber].getProtocolTypeToString();
        // arp package analysis
        if(packageType == "ARP"){
            QString ArpType = dataPackageItemVector[rowNumber].getArpOperationCode();
            QTreeWidgetItem*item2 = new QTreeWidgetItem(QStringList()<<"Address Resolution Protocol " + ArpType);
            ui->treeWidget->addTopLevelItem(item2);
            QString HardwareType = dataPackageItemVector[rowNumber].getArpHardwareType();
            QString protocolType = dataPackageItemVector[rowNumber].getArpProtocolType();
            QString HardwareSize = dataPackageItemVector[rowNumber].getArpHardwareLength();
            QString protocolSize = dataPackageItemVector[rowNumber].getArpProtocolLength();
            QString srcMacAddr = dataPackageItemVector[rowNumber].getArpSourceEtherAddr();
            QString desMacAddr = dataPackageItemVector[rowNumber].getArpDestinationEtherAddr();
            QString srcIpAddr = dataPackageItemVector[rowNumber].getArpSourceIpAddr();
            QString desIpAddr = dataPackageItemVector[rowNumber].getArpDestinationIpAddr();

            item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware type:" + HardwareType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol type:" + protocolType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware size:" + HardwareSize));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol size:" + protocolSize));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Opcode:" + ArpType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender MAC address:" + srcMacAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender IP address:" + srcIpAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Target MAC address:" + desMacAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Target IP address:" + desIpAddr));
            return;
        }else { // ip package analysis
            QString srcIp = dataPackageItemVector[rowNumber].getSrcIpAddr();
            QString desIp = dataPackageItemVector[rowNumber].getDesIpAddr();

            QTreeWidgetItem*item3 = new QTreeWidgetItem(QStringList()<<"Internet Protocol Version 4, Src:" + srcIp + ", Dst:" + desIp);
            ui->treeWidget->addTopLevelItem(item3);

            QString version = dataPackageItemVector[rowNumber].getIpVersion();
            QString headerLength = dataPackageItemVector[rowNumber].getIpHeaderLength();
            QString Tos = dataPackageItemVector[rowNumber].getIpTos();
            QString totalLength = dataPackageItemVector[rowNumber].getIpTotalLength();
            QString id = "0x" + dataPackageItemVector[rowNumber].getIpIdentification();
            QString flags = dataPackageItemVector[rowNumber].getIpFlag();
            if(flags.size()<2)
                flags = "0" + flags;
            flags = "0x" + flags;
            QString FragmentOffset = dataPackageItemVector[rowNumber].getIpFragmentOffset();
            QString ttl = dataPackageItemVector[rowNumber].getIpTTL();
            QString protocol = dataPackageItemVector[rowNumber].getIpProtocol();
            QString checksum = "0x" + dataPackageItemVector[rowNumber].getIpCheckSum();
            int dataLengthofIp = totalLength.toUtf8().toInt() - 20;
            item3->addChild(new QTreeWidgetItem(QStringList()<<"0100 .... = Version:" + version));
            item3->addChild(new QTreeWidgetItem(QStringList()<<".... 0101 = Header Length:" + headerLength));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"TOS:" + Tos));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Total Length:" + totalLength));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Identification:" + id));

            QString reservedBit = dataPackageItemVector[rowNumber].getIpReservedBit();
            QString DF = dataPackageItemVector[rowNumber].getIpDF();
            QString MF = dataPackageItemVector[rowNumber].getIpMF();
            QString FLAG = ",";

            if(reservedBit == "1"){
                FLAG += "Reserved bit";
            }
            else if(DF == "1"){
                FLAG += "Don't fragment";
            }
            else if(MF == "1"){
                FLAG += "More fragment";
            }
            if(FLAG.size() == 1)
                FLAG = "";
            QTreeWidgetItem*bitTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags + FLAG);
            item3->addChild(bitTree);
            QString temp = reservedBit == "1"?"Set":"Not set";
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<reservedBit + "... .... = Reserved bit:" + temp));
            temp = DF == "1"?"Set":"Not set";
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<"." + DF + ".. .... = Don't fragment:" + temp));
            temp = MF == "1"?"Set":"Not set";
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<".." + MF + ". .... = More fragment:" + temp));

            item3->addChild(new QTreeWidgetItem(QStringList()<<"Fragment Offset:" + FragmentOffset));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Time to Live:" + ttl));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Protocol:" + protocol));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Header checksum:" + checksum));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Source Address:" + srcIp));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Destination Address:" + desIp));

            if(packageType == "TCP" || packageType == "TLS" || packageType == "SSL"){
                QString desPort = dataPackageItemVector[rowNumber].getTcpDestinationPort();
                QString srcPort = dataPackageItemVector[rowNumber].getTcpSourcePort();
                QString ack = dataPackageItemVector[rowNumber].getTcpAcknowledgment();
                QString seq = dataPackageItemVector[rowNumber].getTcpSequence();
                QString headerLength = dataPackageItemVector[rowNumber].getTcpHeaderLength();
                int rawLength = dataPackageItemVector[rowNumber].getTcpRawHeaderLength().toUtf8().toInt();
                dataLengthofIp -= (rawLength * 4);
                QString dataLength = QString::number(dataLengthofIp);
                QString flag = dataPackageItemVector[rowNumber].getTcpFlags();
                while(flag.size()<2)
                    flag = "0" + flag;
                flag = "0x" + flag;
                QTreeWidgetItem*item4 = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort + ",Seq:" + seq + ", Ack:" + ack + ", Len:" + dataLength);

                ui->treeWidget->addTopLevelItem(item4);
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number (raw) :" + seq));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Ackowledgment Number (raw) :" + ack));


                QString sLength = QString::number(rawLength,2);
                while(sLength.size()<4)
                    sLength = "0" + sLength;
                item4->addChild(new QTreeWidgetItem(QStringList()<<sLength + " .... = Header Length:" + headerLength));

                QString PSH = dataPackageItemVector[rowNumber].getTcpPSH();
                QString URG = dataPackageItemVector[rowNumber].getTcpURG();
                QString ACK = dataPackageItemVector[rowNumber].getTcpACK();
                QString RST = dataPackageItemVector[rowNumber].getTcpRST();
                QString SYN = dataPackageItemVector[rowNumber].getTcpSYN();
                QString FIN = dataPackageItemVector[rowNumber].getTcpFIN();
                QString FLAG = "";

                if(PSH == "1")
                    FLAG += "PSH,";
                if(URG == "1")
                    FLAG += "UGR,";
                if(ACK == "1")
                    FLAG += "ACK,";
                if(RST == "1")
                    FLAG += "RST,";
                if(SYN == "1")
                    FLAG += "SYN,";
                if(FIN == "1")
                    FLAG += "FIN,";
                FLAG = FLAG.left(FLAG.length()-1);
                if(SYN == "1"){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 0 (relative ack number)"));
                }
                if(SYN == "1" && ACK == "1"){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 1 (relative ack number)"));
                }
                QTreeWidgetItem*flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flag + " (" + FLAG + ")");
                item4->addChild(flagTree);
                QString temp = URG == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + URG + ". .... = Urgent(URG):" + temp));
                temp = ACK == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + ACK + " .... = Acknowledgment(ACK):" + temp));
                temp = PSH == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + PSH + "... = Push(PSH):" + temp));
                temp = RST == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + RST + ".. = Reset(RST):" + temp));
                temp = SYN == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .." + SYN + ". = Syn(SYN):" + temp));
                temp = FIN == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ..." + FIN + " = Fin(FIN):" + temp));

                QString window = dataPackageItemVector[rowNumber].getTcpWindowSize();
                QString checksum = "0x" + dataPackageItemVector[rowNumber].getTcpCheckSum();
                QString urgent = dataPackageItemVector[rowNumber].getTcpUrgentPointer();
                item4->addChild(new QTreeWidgetItem(QStringList()<<"window:" + window));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Urgent Pointer:" + urgent));
                if((rawLength * 4) > 20){
                    QTreeWidgetItem * optionTree = new QTreeWidgetItem(QStringList()<<"Options: (" + QString::number(rawLength * 4 - 20) + ") bytes");
                    item4->addChild(optionTree);
                    for(int j = 0;j < (rawLength * 4 - 20);){
                        int kind = dataPackageItemVector[rowNumber].getTcpOperationRawKind(j);
                        switch (kind) {
                        case 0:{
                            QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - End of List (EOL)");
                            optionTree->addChild(subTree);
                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind:End of List (0)"));
                            optionTree->addChild(subTree);
                            j++;
                            break;
                        }case 1:{
                            QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - No-Operation (NOP)");
                            optionTree->addChild(subTree);
                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: No-Operation (1)"));
                            optionTree->addChild(subTree);
                            j++;
                            break;
                        }
                        case 2:{
                            u_short mss;
                            if(dataPackageItemVector[rowNumber].getTcpOperationMSS(j,mss)){
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - Maximun Segment Size: " + QString::number(mss) + " bytes");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: Maximun Segment Size (2)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 4"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"MSS Value: " + QString::number(mss)));
                                j += 4;
                            }
                            break;
                        }
                        case 3:{
                            u_char shift;
                            if(dataPackageItemVector[rowNumber].getTcpOperationWSOPT(j,shift)){
                                int factor = 1 << shift;
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - Window scale: " + QString::number(shift) + " (multiply by " + QString::number(factor) + ")");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: Window scale (3)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 3"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Shift Count: " + QString::number(shift)));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"[Multiplier: " + QString::number(factor) + "]"));
                                j += 3;
                            }
                            break;
                        }
                        case 4:{
                            if(dataPackageItemVector[rowNumber].getTcpOperationSACKP(j)){
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - SACK Permitted");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: SCAK Permitted (4)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 2"));
                                j += 2;
                            }
                            break;
                        }
                        case 5:{
                            u_char length = 0;
                            QVector<u_int>edge;
                            if(dataPackageItemVector[rowNumber].getTcpOperationSACK(j,length,edge)){
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - SACK");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: SCAK (5)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(length)));
                                int num = edge.size();
                                for(int k = 0;k < num;k += 2){
                                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"left edge = " + QString::number(edge[k])));
                                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"right edge = " + QString::number(edge[k + 1])));
                                }
                                j += length;
                            }
                            break;
                        }
                        case 8:{
                            u_int value = 0;
                            u_int reply = 0;
                            if(dataPackageItemVector[rowNumber].getTcpOperationTSPOT(j,value,reply)){
                                QString val = QString::number(value);
                                QString rep = QString::number(reply);
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - TimeStamps: TSval " +val + ", TSecr " + rep);
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: Time Stamp Option (8)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 10"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Timestamp value: " + val));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Timestamp echo reply: " + rep));
                                j += 10;
                            }
                            break;
                        }
                        case 19:{
                            j += 18;
                            break;
                        }
                        case 28:{
                            j += 4;
                            break;
                        }
                        default:{
                            j++;
                            break;
                        }
                        }
                    }
                }
                if(dataLengthofIp > 0){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"TCP Payload (" + QString::number(dataLengthofIp) + ")"));
                    if(packageType == "TLS"){
                        QTreeWidgetItem* tlsTree = new QTreeWidgetItem(QStringList()<<"Transport Layer Security");
                        ui->treeWidget->addTopLevelItem(tlsTree);
                        u_char contentType = 0;
                        u_short version = 0;
                        u_short length = 0;
                        dataPackageItemVector[rowNumber].getTlsBasicInfo((rawLength * 4),contentType,version,length);
                        QString type = dataPackageItemVector[rowNumber].getTlsContentType(contentType);
                        QString vs = dataPackageItemVector[rowNumber].getTlsVersion(version);
                        switch (contentType) {
                        case 20:{
                            // ... TODO
                            break;
                        }
                        case 21:{
                            QTreeWidgetItem* tlsSubree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: Encrypted Alert");
                            tlsTree->addChild(tlsSubree);
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Alert Message: Encrypted Alert"));
                            break;
                        }
                        case 22:{ // handshake
                            u_char handshakeType = 0;
                            dataPackageItemVector[rowNumber].getTlsHandshakeType((rawLength * 4 + 5),handshakeType);
                            if(handshakeType == 1){ // client hello
                                int tlsLength = 0;
                                u_short rawVersion = 0;
                                QString random = "";
                                u_char sessionLength = 0;
                                QString sessionId = "";
                                u_short cipherLength = 0;
                                QVector<u_short>cipher;
                                u_char cmLength = 0;
                                QVector<u_char>compressionMethod;
                                u_short extensionLength = 0;
                                dataPackageItemVector[rowNumber].getTlsClientHelloInfo((rawLength * 4 + 5),handshakeType,tlsLength,rawVersion,random,sessionLength,sessionId,cipherLength,cipher,cmLength,compressionMethod,extensionLength);

                                QString type = dataPackageItemVector[rowNumber].getTlsHandshakeType(handshakeType);
                                QString tlsVersion = dataPackageItemVector[rowNumber].getTlsVersion(rawVersion);

                                QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
                                tlsTree->addChild(tlsSubTree);
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

                                QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
                                tlsSubTree->addChild(handshakeTree);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + tlsVersion + " (0x0" + QString::number(rawVersion) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Random: " + random));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID Length: " + QString::number(sessionLength)));
                                if(sessionLength > 0){
                                    handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID: " + sessionId));
                                }
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suites Length: " + QString::number(cipherLength)));
                                if(cipherLength > 0){
                                    QTreeWidgetItem* cipherTree = new QTreeWidgetItem(QStringList()<<"Cipher Suites (" + QString::number(cipherLength/2) + " suites)");
                                    handshakeTree->addChild(cipherTree);
                                    for(int k = 0;k < cipherLength/2;k++){
                                        QString temp = dataPackageItemVector[rowNumber].getTlsHandshakeCipherSuites(cipher[k]);
                                        cipherTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suite: " + temp));
                                    }
                                }
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Method Length: " + QString::number(cmLength)));
                                if(cmLength > 0){
                                    QTreeWidgetItem* cmTree = new QTreeWidgetItem(QStringList()<<"Compression Methods (" + QString::number(cmLength) + " method)");
                                    handshakeTree->addChild(cmTree);
                                    for(int k = 0;k < cmLength;k++){
                                        QString temp = dataPackageItemVector[rowNumber].getTlsHandshakeCompression(compressionMethod[k]);
                                        cmTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Methods: " + temp + " (" + QString::number(compressionMethod[k]) + ")"));
                                    }
                                }
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Extensions Length: " + QString::number(extensionLength)));
                                if(extensionLength > 0){
                                    int exOffset = (rawLength * 4) + (tlsLength - extensionLength + 5 + 4);
                                    for(int k = 0;k < extensionLength;){
                                        int code = dataPackageItemVector[rowNumber].getTlsExtensionType(exOffset);
                                        u_short exType = 0;
                                        u_short exLength = 0;
                                        switch (code) {
                                        case 0:{ // server_name
                                            u_short listLength = 0;
                                            u_char nameType = 0;
                                            u_short nameLength = 0;
                                            QString name = "";
                                            dataPackageItemVector[rowNumber].getTlsExtensionServerName(exOffset,exType,exLength,listLength,nameType,nameLength,name);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            if(exLength > 0 && listLength > 0){
                                                QTreeWidgetItem*serverTree = new QTreeWidgetItem(QStringList()<<"Server Name Indication extension");
                                                extensionTree->addChild(serverTree);
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name list length: " + QString::number(listLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name Type: " + QString::number(nameType)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name length: " + QString::number(nameLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name: " + name));
                                            }
                                            break;
                                        }
                                        case 11:{// ec_point_format
                                            u_char ecLength = 0;
                                            QVector<u_char>EC;
                                            dataPackageItemVector[rowNumber].getTlsExtensionEcPointFormats(exOffset,exType,exLength,ecLength,EC);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"EC point formats Length: " + QString::number(ecLength)));
                                            QTreeWidgetItem* EXTree = new QTreeWidgetItem(QStringList()<<"Elliptic curves point formats (" + QString::number(ecLength) + ")");
                                            extensionTree->addChild(EXTree);
                                            for(int g = 0;g < ecLength;g++){
                                                QString temp = dataPackageItemVector[rowNumber].getTlsHandshakeExtensionECPointFormat(EC[g]);
                                                EXTree->addChild(new QTreeWidgetItem(QStringList()<<temp));
                                            }
                                            break;
                                        }
                                        case 10:{// supported_groups
                                            u_short groupListLength = 0;
                                            QVector<u_short>group;
                                            dataPackageItemVector[rowNumber].getTlsExtensionSupportGroups(exOffset,exType,exLength,groupListLength,group);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Groups List Length: " + QString::number(groupListLength)));
                                            QTreeWidgetItem* sptTree = new QTreeWidgetItem(QStringList()<<"Supported Groups (" + QString::number(groupListLength/2) + " groups)");
                                            extensionTree->addChild(sptTree);
                                            for(int g = 0;g < groupListLength/2;g++){
                                                QString temp = dataPackageItemVector[rowNumber].getTlsHandshakeExtensionSupportGroup(group[g]);
                                                sptTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Group: " + temp));
                                            }
                                            break;
                                        }
                                        case 35:{// session_ticket
                                            dataPackageItemVector[rowNumber].getTlsExtensionSessionTicket(exOffset,exType,exLength);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 22:{// encrypt_then_mac
                                            dataPackageItemVector[rowNumber].getTlsExtensionEncryptThenMac(exOffset,exType,exLength);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 23:{// extended_master_secret
                                            dataPackageItemVector[rowNumber].getTlsExtensionExtendMasterSecret(exOffset,exType,exLength);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 13:{// signature_algorithms
                                            u_short algorithmLength = 0;
                                            QVector<u_short>algorithm;
                                            dataPackageItemVector[rowNumber].getTlsExtensionSignatureAlgorithms(exOffset,exType,exLength,algorithmLength,algorithm);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms Length: " + QString::number(algorithmLength)));
                                            QTreeWidgetItem* sigTree = new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms (" + QString::number(algorithmLength/2) + " algorithms)");
                                            extensionTree->addChild(sigTree);
                                            for(int g = 0;g < algorithmLength/2;g++){
                                                QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Signature Algorithm: 0x0" + QString::number(algorithm[g],16));
                                                sigTree->addChild(subTree);
                                                QString hash = dataPackageItemVector[rowNumber].getTlsHadshakeExtensionHash((algorithm[g] & 0xff00) >> 8);
                                                QString sig = dataPackageItemVector[rowNumber].getTlsHadshakeExtensionSignature((algorithm[g] & 0x00ff));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Hash: " + hash + " (" + QString::number((algorithm[g] & 0xff00) >> 8) + ")"));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Signature: " + sig + " (" + QString::number(algorithm[g] & 0x00ff) + ")"));
                                            }
                                            break;
                                        }
                                        case 43:{// supported_versions
                                            u_char supportLength = 0;
                                            QVector<u_short>supportVersion;
                                            dataPackageItemVector[rowNumber].getTlsExtensionSupportVersions(exOffset,exType,exLength,supportLength,supportVersion);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Versions length: " + QString::number(supportLength)));
                                            for(int g = 0;g < supportLength/2;g++){
                                                QString temp = dataPackageItemVector[rowNumber].getTlsVersion(supportVersion[g]);
                                                extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Version: " + temp));
                                            }
                                            break;
                                        }
                                        case 51:{// key_share
                                            u_short shareLength = 0;
                                            u_short group = 0;
                                            u_short exchangeLength = 0;
                                            QString exchange = "";
                                            dataPackageItemVector[rowNumber].getTlsExtensionKeyShare(exOffset,exType,exLength,shareLength,group,exchangeLength,exchange);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));

                                            QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Key Share extension");
                                            extensionTree->addChild(subTree);
                                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"Client Key Share Length: " + QString::number(shareLength)));
                                            QTreeWidgetItem* entryTree = new QTreeWidgetItem(QStringList()<<"Key Share Entry: Group ");
                                            subTree->addChild(entryTree);
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Group: " + QString::number(group)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange Length: " + QString::number(exchangeLength)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange: " + exchange));
                                            break;
                                        }
                                        case 21:{// padding
                                            QString rdata = "";
                                            dataPackageItemVector[rowNumber].getTlsExtensionPadding(exOffset,exType,exLength,rdata);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (21)"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Padding Data: " + rdata));
                                            break;
                                        }
                                        default:{
                                            QString rdata = "";
                                            dataPackageItemVector[rowNumber].getTlsExtensionOther(exOffset,exType,exLength,rdata);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (" + QString::number(exType) + ")"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Data: " + rdata));

                                            break;
                                        }
                                        }
                                        k += (exLength + 4);
                                        exOffset += (exLength + 4);
                                    }
                                }
                            }
                            else if(handshakeType == 2){// Server hello
                                int tlsLength = 0;
                                u_short rawVersion = 0;
                                QString random = "";
                                u_char sessionLength = 0;
                                QString sessionId = "";
                                u_short cipher = 0;
                                u_char compressionMethod = 0;
                                u_short extensionLength = 0;
                                dataPackageItemVector[rowNumber].getTlsServerHelloInfo((rawLength * 4 + 5),handshakeType,tlsLength,rawVersion,random,sessionLength,sessionId,cipher,compressionMethod,extensionLength);
                                QString type = dataPackageItemVector[rowNumber].getTlsHandshakeType(handshakeType);
                                QString tlsVersion = dataPackageItemVector[rowNumber].getTlsVersion(rawVersion);

                                QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
                                tlsTree->addChild(tlsSubTree);
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

                                QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
                                tlsSubTree->addChild(handshakeTree);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + tlsVersion + " (0x0" + QString::number(rawVersion,16) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Random: " + random));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID Length: " + QString::number(sessionLength)));
                                if(sessionLength > 0){
                                    handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID: " + sessionId));
                                }
                                QString temp = dataPackageItemVector[rowNumber].getTlsHandshakeCipherSuites(cipher);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suites: " +temp));
                                temp = dataPackageItemVector[rowNumber].getTlsHandshakeCompression(compressionMethod);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Methods: " + temp + " (" + QString::number(compressionMethod) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Extensions Length: " + QString::number(extensionLength)));
                                if(extensionLength > 0){
                                    int exOffset = (rawLength * 4) + (tlsLength - extensionLength + 5 + 4);
                                    for(int k = 0;k < extensionLength;){
                                        int code = dataPackageItemVector[rowNumber].getTlsExtensionType(exOffset);
                                        u_short exType = 0;
                                        u_short exLength = 0;
                                        switch (code) {
                                        case 0:{ // server_name
                                            u_short listLength = 0;
                                            u_char nameType = 0;
                                            u_short nameLength = 0;
                                            QString name = "";
                                            dataPackageItemVector[rowNumber].getTlsExtensionServerName(exOffset,exType,exLength,listLength,nameType,nameLength,name);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            if(exLength > 0 && listLength > 0){
                                                QTreeWidgetItem*serverTree = new QTreeWidgetItem(QStringList()<<"Server Name Indication extension");
                                                extensionTree->addChild(serverTree);
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name list length: " + QString::number(listLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name Type: " + QString::number(nameType)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name length: " + QString::number(nameLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name: " + name));
                                            }
                                            break;
                                        }
                                        case 11:{// ec_point_format
                                            u_char ecLength = 0;
                                            QVector<u_char>EC;
                                            dataPackageItemVector[rowNumber].getTlsExtensionEcPointFormats(exOffset,exType,exLength,ecLength,EC);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"EC point formats Length: " + QString::number(ecLength)));
                                            QTreeWidgetItem* EXTree = new QTreeWidgetItem(QStringList()<<"Elliptic curves point formats (" + QString::number(ecLength) + ")");
                                            extensionTree->addChild(EXTree);
                                            for(int g = 0;g < ecLength;g++){
                                                QString temp = dataPackageItemVector[rowNumber].getTlsHandshakeExtensionECPointFormat(EC[g]);
                                                EXTree->addChild(new QTreeWidgetItem(QStringList()<<temp));
                                            }
                                            break;
                                        }
                                        case 10:{// supported_groups
                                            u_short groupListLength = 0;
                                            QVector<u_short>group;
                                            dataPackageItemVector[rowNumber].getTlsExtensionSupportGroups(exOffset,exType,exLength,groupListLength,group);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Groups List Length: " + QString::number(groupListLength)));
                                            QTreeWidgetItem* sptTree = new QTreeWidgetItem(QStringList()<<"Supported Groups (" + QString::number(groupListLength/2) + " groups)");
                                            extensionTree->addChild(sptTree);
                                            for(int g = 0;g < groupListLength/2;g++){
                                                QString temp = dataPackageItemVector[rowNumber].getTlsHandshakeExtensionSupportGroup(group[g]);
                                                sptTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Group: " + temp));
                                            }
                                            break;
                                        }
                                        case 35:{// session_ticket
                                            dataPackageItemVector[rowNumber].getTlsExtensionSessionTicket(exOffset,exType,exLength);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 22:{// encrypt_then_mac
                                            dataPackageItemVector[rowNumber].getTlsExtensionEncryptThenMac(exOffset,exType,exLength);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 23:{// extended_master_secret
                                            dataPackageItemVector[rowNumber].getTlsExtensionExtendMasterSecret(exOffset,exType,exLength);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 13:{// signature_algorithms
                                            u_short algorithmLength = 0;
                                            QVector<u_short>algorithm;
                                            dataPackageItemVector[rowNumber].getTlsExtensionSignatureAlgorithms(exOffset,exType,exLength,algorithmLength,algorithm);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms Length: " + QString::number(algorithmLength)));
                                            QTreeWidgetItem* sigTree = new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms (" + QString::number(algorithmLength/2) + " algorithms)");
                                            extensionTree->addChild(sigTree);
                                            for(int g = 0;g < algorithmLength/2;g++){
                                                QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Signature Algorithm: 0x0" + QString::number(algorithm[g],16));
                                                sigTree->addChild(subTree);
                                                QString hash = dataPackageItemVector[rowNumber].getTlsHadshakeExtensionHash((algorithm[g] & 0xff00) >> 8);
                                                QString sig = dataPackageItemVector[rowNumber].getTlsHadshakeExtensionSignature((algorithm[g] & 0x00ff));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Hash: " + hash + " (" + QString::number((algorithm[g] & 0xff00) >> 8) + ")"));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Signature: " + sig + " (" + QString::number(algorithm[g] & 0x00ff) + ")"));
                                            }
                                            break;
                                        }
                                        case 43:{// supported_versions
                                            u_char supportLength = 0;
                                            QVector<u_short>supportVersion;
                                            dataPackageItemVector[rowNumber].getTlsExtensionSupportVersions(exOffset,exType,exLength,supportLength,supportVersion);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Versions length: " + QString::number(supportLength)));
                                            for(int g = 0;g < supportLength/2;g++){
                                                QString temp = dataPackageItemVector[rowNumber].getTlsVersion(supportVersion[g]);
                                                extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Version: " + temp));
                                            }
                                            break;
                                        }
                                        case 51:{// key_share
                                            u_short shareLength = 0;
                                            u_short group = 0;
                                            u_short exchangeLength = 0;
                                            QString exchange = "";
                                            dataPackageItemVector[rowNumber].getTlsExtensionKeyShare(exOffset,exType,exLength,shareLength,group,exchangeLength,exchange);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));

                                            QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Key Share extension");
                                            extensionTree->addChild(subTree);
                                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"Client Key Share Length: " + QString::number(shareLength)));
                                            QTreeWidgetItem* entryTree = new QTreeWidgetItem(QStringList()<<"Key Share Entry: Group ");
                                            subTree->addChild(entryTree);
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Group: " + QString::number(group)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange Length: " + QString::number(exchangeLength)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange: " + exchange));
                                            break;
                                        }
                                        case 21:{// padding
                                            QString rdata = "";
                                            dataPackageItemVector[rowNumber].getTlsExtensionPadding(exOffset,exType,exLength,rdata);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (21)"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Padding Data: " + rdata));
                                            break;
                                        }
                                        default:{
                                            QString rdata = "";
                                            dataPackageItemVector[rowNumber].getTlsExtensionOther(exOffset,exType,exLength,rdata);
                                            QString subType = dataPackageItemVector[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (" + QString::number(exType) + ")"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Data: " + rdata));

                                            break;
                                        }
                                        }
                                        k += (exLength + 4);
                                        exOffset += (exLength + 4);
                                    }
                                }

                            }
                            else if(handshakeType == 12){// Server Key Exchange
                                int tlsLength = 0;
                                u_char curveType = 0;
                                u_short curveName = 0;
                                u_char pubLength = 0;
                                QString pubKey = "";
                                u_short sigAlgorithm = 0;
                                u_short sigLength = 0;
                                QString sig = "";
                                dataPackageItemVector[rowNumber].getTlsServerKeyExchange((rawLength * 4 + 5),handshakeType,tlsLength,curveType,curveName,pubLength,pubKey,sigAlgorithm,sigLength,sig);
                                QString type = dataPackageItemVector[rowNumber].getTlsHandshakeType(handshakeType);

                                QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
                                tlsTree->addChild(tlsSubTree);
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

                                QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
                                tlsSubTree->addChild(handshakeTree);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

                            }
                            // ... TODO
                            break;
                        }
                        case 23:{
                            QTreeWidgetItem* tlsSubree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: http-over-tls");
                            tlsTree->addChild(tlsSubree);
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Encrypted Application Data: ..."));
                            break;
                        }
                        default:break;
                        }
                    }else if(packageType == "SSL"){
                        ui->treeWidget->addTopLevelItem(new QTreeWidgetItem(QStringList()<<"Transport Layer Security"));
                    }
                }
            }else if(packageType == "UDP" || packageType == "DNS"){
                QString srcPort = dataPackageItemVector[rowNumber].getUdpSourcePort();
                QString desPort = dataPackageItemVector[rowNumber].getUdpDestinationPort();
                QString Length = dataPackageItemVector[rowNumber].getUdpDataLength();
                QString checksum = "0x" + dataPackageItemVector[rowNumber].getUdpCheckSum();
                QTreeWidgetItem*item5 = new QTreeWidgetItem(QStringList()<<"User Datagram Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort);
                ui->treeWidget->addTopLevelItem(item5);
                item5->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
                item5->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
                item5->addChild(new QTreeWidgetItem(QStringList()<<"length:" + Length));
                item5->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:" + checksum));
                int udpLength = Length.toUtf8().toInt();
                if(udpLength > 0){
                    item5->addChild(new QTreeWidgetItem(QStringList()<<"UDP PayLoad (" + QString::number(udpLength - 8) + " bytes)"));
                }
                if(packageType == "DNS"){
                    QString transaction = "0x" + dataPackageItemVector[rowNumber].getDnsTransactionId();
                    QString QR = dataPackageItemVector[rowNumber].getDnsFlagsQR();
                    QString temp = "";
                    if(QR == "0") temp = "query";
                    if(QR == "1") temp = "response";
                    QString flags = "0x" + dataPackageItemVector[rowNumber].getDnsFlags();
                    QTreeWidgetItem*dnsTree = new QTreeWidgetItem(QStringList()<<"Domain Name System (" + temp + ")");
                    ui->treeWidget->addTopLevelItem(dnsTree);
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Transaction ID:" + transaction));
                    QTreeWidgetItem* flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags);
                    dnsTree->addChild(flagTree);
                    temp = QR == "1"?"Message is a response":"Message is a query";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<QR + "... .... .... .... = Response:" + temp));
                    QString Opcode = dataPackageItemVector[rowNumber].getDnsFlagsOpcode();
                    if(Opcode == "0") temp = "Standard query (0)";
                    else if(Opcode == "1") temp = "Reverse query (1)";
                    else if(Opcode == "2") temp = "Status request (2)";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".000 " + Opcode + "... .... .... = Opcode:" + temp));
                    if(QR == "1"){
                        QString AA = dataPackageItemVector[rowNumber].getDnsFlagsAA();
                        temp = AA == "1"?"Server is an authority for domain":"Server is not an authority for domain";
                        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ." + AA + ".. .... .... = Authoritative:" + temp));
                    }
                    QString TC = dataPackageItemVector[rowNumber].getDnsFlagsTC();
                    temp = TC == "1"?"Message is truncated":"Message is not truncated";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + TC + ". .... .... = Truncated:" + temp));

                    QString RD = dataPackageItemVector[rowNumber].getDnsFlagsRD();
                    temp = RD == "1"?"Do query recursively":"Do query not recursively";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + RD + " .... .... = Recursion desired:" + temp));

                    if(QR == "1"){
                        QString RA = dataPackageItemVector[rowNumber].getDnsFlagsRA();
                        temp = RA == "1"?"Server can do recursive queries":"Server can not do recursive queries";
                        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + RA + "... .... = Recursion available:" + temp));
                    }
                    QString Z = dataPackageItemVector[rowNumber].getDnsFlagsZ();
                    while(Z.size()<3)
                        Z = "0" + Z;
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + Z + " .... = Z:reserved(" + Z + ")"));
                    if(QR == "1"){
                        QString Rcode = dataPackageItemVector[rowNumber].getDnsFlagsRcode();
                        if(Rcode == "0")
                            temp = "No error (0)";
                        else if(Rcode == "1") temp = "Format error (1)";
                        else if(Rcode == "2") temp = "Server failure (2)";
                        else if(Rcode == "3") temp = "Name Error (3)";
                        else if(Rcode == "4") temp = "Not Implemented (4)";
                        else if(Rcode == "5") temp = "Refused (5)";
                        int code = Rcode.toUtf8().toInt();
                        QString bCode = QString::number(code,2);
                        while (bCode.size()<4)
                            bCode = "0" + bCode;
                        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .... " + bCode + " = Reply code:" + temp));
                    }

                    QString question = dataPackageItemVector[rowNumber].getDnsQuestionNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Questions:" + question));
                    QString answer = dataPackageItemVector[rowNumber].getDnsAnswerNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Answer RRs:" + answer));
                    QString authority = dataPackageItemVector[rowNumber].getDnsAuthorityNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Authority RRs:" + authority));
                    QString additional = dataPackageItemVector[rowNumber].getDnsAdditionalNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Additional RRs:" + additional));
                    int offset = 0;
                    if(question == "1"){
                        QString domainInfo;
                        int Type;
                        int Class;
                        dataPackageItemVector[rowNumber].getDnsQueriesDomain(domainInfo,Type,Class);
                        QTreeWidgetItem*queryDomainTree = new QTreeWidgetItem(QStringList()<<"Queries");
                        dnsTree->addChild(queryDomainTree);
                        offset += (4 + domainInfo.size() + 2);
                        QString type = dataPackageItemVector[rowNumber].getDnsDomainType(Type);
                        QTreeWidgetItem*querySubTree = new QTreeWidgetItem(QStringList()<<domainInfo + " type " + type + ", class IN");
                        queryDomainTree->addChild(querySubTree);
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Name:" + domainInfo));
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"[Name Length:" + QString::number(domainInfo.size()) + "]"));
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + type + "(" + QString::number(Type) + ")"));
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Class: IN (0x000" + QString::number(Class) + ")"));
                    }
                    int answerNumber = answer.toUtf8().toInt();
                    if(answerNumber > 0){
                        QTreeWidgetItem*answerTree = new QTreeWidgetItem(QStringList()<<"Answers");
                        dnsTree->addChild(answerTree);
                        for(int i = 0;i< answerNumber;i++){
                            QString name1;
                            QString name2;
                            u_short type;
                            u_short Class;
                            u_int ttl;
                            u_short length;

                            int tempOffset = dataPackageItemVector[rowNumber].getDnsAnswersDomain(offset,name1,type,Class,ttl,length,name2);
                            QString sType = dataPackageItemVector[rowNumber].getDnsDomainType(type);
                            QString temp = "";
                            if(type == 1) temp = "addr";
                            else if(type == 5) temp = "cname";
                            QTreeWidgetItem*answerSubTree = new QTreeWidgetItem(QStringList()<<name1 + ": type " + sType + ",class IN, " + temp + ":" + name2);
                            answerTree->addChild(answerSubTree);
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Name:" + name1));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + sType + "(" + QString::number(type) + ")"));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Class: IN (0x000" + QString::number(Class) + ")"));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Time to live:" + QString::number(ttl) + "(" + QString::number(ttl) + " second)"));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Data length:" + QString::number(length)));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<sType + ":" + name2));

                            offset += tempOffset;
                        }
                    }
                }
            }else if(packageType == "ICMP"){
                dataLengthofIp -= 8;
                QTreeWidgetItem*item6 = new QTreeWidgetItem(QStringList()<<"Internet Message Protocol");
                ui->treeWidget->addTopLevelItem(item6);
                QString type = dataPackageItemVector[rowNumber].getIcmpType();
                QString code = dataPackageItemVector[rowNumber].getIcmpCode();
                QString info = ui->tableWidget->item(row,6)->text();
                QString checksum = "0x" + dataPackageItemVector[rowNumber].getIcmpCheckSum();
                QString id = dataPackageItemVector[rowNumber].getIcmpIdentification();
                QString seq = dataPackageItemVector[rowNumber].getIcmpSequeue();
                item6->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"code:" + code));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:" + checksum));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"Identifier:" + id));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number:" + seq));
                if(dataLengthofIp > 0){
                    QTreeWidgetItem* dataItem = new QTreeWidgetItem(QStringList()<<"Data (" + QString::number(dataLengthofIp) + ") bytes");
                    item6->addChild(dataItem);
                    QString icmpData = dataPackageItemVector[rowNumber].getIcmpData(dataLengthofIp);
                    dataItem->addChild(new QTreeWidgetItem(QStringList()<<icmpData));
                }
            }
        }
        // the ethernet may have padding to ensure that the minimum length of the dataPackageItemVector packet is greater than 46
        int macDataLength = dataPackageItemVector[rowNumber].getIpTotalLength().toUtf8().toInt();
        int dataPackageLength = dataPackageItemVector[rowNumber].getLength().toUtf8().toInt();
        int delta = dataPackageLength - macDataLength;
        if(delta > 14){
            int padding = delta - 14;
            QString pad = "";
            while (pad.size() < padding * 2) {
                pad += "00";
            }
            item->addChild(new QTreeWidgetItem(QStringList()<<"Padding: " + pad));
        }
    }
}
