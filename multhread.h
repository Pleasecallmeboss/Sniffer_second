#ifndef MULTHREAD_H
#define MULTHREAD_H

#include <pcap.h>
#include <QThread>
#include <datapacketItem.h>

class multhread:public QThread  //qthread是qt定义的管理线程的中间人，相当于劳务中心
{
    Q_OBJECT
public:
    multhread();
    void setFlag();
    void resetFlag();
    void setPointer(pcap_t* pointer);
    void run() override;
    void stop();
    QString byteToString(u_char* str,int size);

    int ethernetPacketHandle(const u_char* captureContent,QString& info);
    QString arpPacketHandle(const u_char* captureContent);
    int ipPacketHandle(const u_char* captureContent,int& ipContentSize);
    QString icmpPackageHandle(const u_char* captureContent);
    int udpPacketHandle(const u_char *pkt_content,QString&info);
    int tcpPacketHandle(const u_char *pkt_content,QString &info,int ipPackage);
    QString dnsPacketHandle(const u_char *pkt_content);

private:
    pcap_t* pointer;
    pcap_pkthdr* captureHeader;
    const u_char* captureContent;
    time_t local_time_sec;
    struct tm local_time;
    char timeString[16];
    bool isDone;

signals:
    void send(dataPacketItem data);
};

#endif // MULTHREAD_H
