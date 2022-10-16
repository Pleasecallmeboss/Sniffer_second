#include "multhread.h"
#include <QDebug>
#include <datapacketItem.h>

multhread::multhread()
{
    this->isDone = true;
}

void multhread::setFlag()
{
    this->isDone = false;
}


void multhread::resetFlag()
{
    this->isDone = true;
}

void multhread::setPointer(pcap_t* pointer)
{
    this->pointer = pointer;
}

void multhread::run()
{
    while(true)
    {
        if(isDone)
            break;
        else
        {
            int res = pcap_next_ex(pointer,&captureHeader,&captureContent);
            if(res != 0)
            {
//                qDebug() << "length of portion present" << packetheader->len;
//                qDebug() << "length of this packet (off wire)" << packetheader->caplen;
                local_time_sec = captureHeader->ts.tv_sec;
                localtime_s(&local_time, &local_time_sec);
                strftime( timeString, sizeof(timeString), "%H:%M:%S", &local_time);
//                qDebug() << timeString;

                QString info;
                int res = ethernetPacketHandle(captureContent,info);
                if(res)
                {
                    int len = captureHeader->len;
                    dataPacketItem data;
                    data.setInfo(info);
                    data.setLength(captureHeader->len);
                    data.setTimestamp(timeString);
                    data.setProtocolType(res);
                    data.setPointerToContent(captureContent,len);
                    emit send(data);
                }

                }
            else
                continue;
        }
    }
}

void multhread::stop()
{
    resetFlag();
    quit();     //通知劳务中心停止干活
    wait();     //收拾房间、整理东西
}

int multhread::ethernetPacketHandle(const u_char* captureContent , QString &info)
{
    ETHERNET_HEADER* ethernet_header;
    ethernet_header = (ETHERNET_HEADER*)captureContent;
    u_short datatype;
    datatype = ntohs(ethernet_header->type);
    switch(datatype)
    {
    case 0x0800:
    {
        int ipContentSize = 0;
        int res = ipPacketHandle(captureContent,ipContentSize);
        switch (res) {
        case 1:{// icmp package
            info = icmpPackageHandle(captureContent);
            return 2;
        }
        case 6:{// tcp package
            return tcpPacketHandle(captureContent,info,ipContentSize);

        }
        case 17:{ // udp package
            int type = udpPacketHandle(captureContent,info);
            return type;
        }
        default:break;
        }
        break;
    }
    case 0x0806:
    {
        info = arpPacketHandle(captureContent);
        return 1;
    }
    default:
    {
        break;
    }
    }
    return 0;
}

QString multhread::arpPacketHandle(const u_char *captureContent)
{
    ARP_HEADER* arp_header;
    arp_header = (ARP_HEADER*)(captureContent + 14);
    QString src_ip_addr = QString::number(*(arp_header->src_ip_addr)) + "." +
            QString::number(*(arp_header->src_ip_addr + 1)) + "." +
            QString::number(*(arp_header->src_ip_addr + 2)) + "." +
            QString::number(*(arp_header->src_ip_addr + 3)) ;

    QString des_ip_addr = QString::number(*(arp_header->des_ip_addr)) + "." +
            QString::number(*(arp_header->des_ip_addr + 1)) + "." +
            QString::number(*(arp_header->des_ip_addr + 2)) + "." +
            QString::number(*(arp_header->des_ip_addr + 3)) ;


    u_char* src_eth_addr = arp_header->src_eth_addr;
    QString src_mac_addr = byteToString(src_eth_addr,1) + ":"
            + byteToString((src_eth_addr+1),1) + ":"
            + byteToString((src_eth_addr+2),1) + ":"
            + byteToString((src_eth_addr+3),1) + ":"
            + byteToString((src_eth_addr+4),1) + ":"
            + byteToString((src_eth_addr+5),1);

    u_short op = ntohs(arp_header->op_code);
    QString res = "";

    switch (op){
    case 1:{
        res  = "Who has " + des_ip_addr + "? Tell " + src_ip_addr;
        break;
    }
    case 2:{
        res = src_ip_addr + " is at " + src_mac_addr;
        break;
    }
    default:break;
    }
    return res;
}

QString multhread::byteToString(u_char* str, int size)
{
     QString res = "";
     for(int i = 0; i < size ; i++)
     {
         char one = str[i] >> 4;
         if(one >= 0x0A)
             one += 0x41 - 0x0A;
         else one += 0x30;
         char two = str[i] & 0xF;
         if(two >= 0x0A)
             two += 0x41 - 0x0A;
         else two += 0x30;
         res.append(one);
         res.append(two);
     }
     return res;
}

int multhread::ipPacketHandle(const u_char *captureContent, int& ipContentSize)
{
    IP_HEADER* ip_header;
    ip_header = (IP_HEADER*)(captureContent + 14);
    ipContentSize = ntohl(ip_header->total_length - ((ip_header->versiosn_head_length & 0x0f) * 4));
    return ip_header->protocol;
}

QString multhread::icmpPackageHandle(const u_char *captureContent)
{
    ICMP_HEADER* icmp_header;
    icmp_header = (ICMP_HEADER*) captureContent + 14 + 20;
    u_char type = icmp_header->type;
    u_char code = icmp_header->code;
    QString result = "";
    switch (type) {
    case 0:{
        if(code == 0)
        {
            result += "Echo response (ping) ";
            result += "identification : " + QString::number(ntohs((icmp_header->identification)));
            result += "sequencde : " + QString::number(ntohs((icmp_header->sequence)));
            break;
        }
    }
    case 3:{
        switch (code) {
        case 0:{
            result = "Network unreachable";
            break;
        }
        case 1:{
            result = "Host unreachable";
            break;
        }
        case 2:{
            result = "Protocol unreachable";
            break;
        }
        case 3:{
            result = "Port unreachable";
            break;
        }
        case 4:{
            result = "Fragmentation is required, but DF is set";
            break;
        }
        case 5:{
            result = "Source route selection failed";
            break;
        }
        case 6:{
            result = "Unknown target network";
            break;
        }
        default:break;
        }
        break;
    }
    case 4:{
        result = "Source station suppression [congestion control]";
        break;
    }
    case 5:{
        result = "Relocation";
        break;
    }
    case 8:{
        if(code == 0)
        {
            result += "Echo request (ping)";
            result += " identification : " + QString::number(ntohs((icmp_header->identification)));
            result += " sequence : " + QString::number(ntohs((icmp_header->sequence)));
            break;
        }
    }
    default:{result = "There is no condithion " ;break;}
    }
    return result;
}

int multhread::tcpPacketHandle(const u_char *pkt_content,QString &info,int ipPackage){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    u_short src = ntohs(tcp->src_port);
    u_short des = ntohs(tcp->des_port);
    QString proSend = "";
    QString proRecv = "";
    int type = 3;
    int delta = (tcp->header_length >> 4) * 4;
    int tcpPayLoad = ipPackage - delta;
//    if((src == 443 || des == 443) && (tcpPayLoad > 0)){
    if((src == 443 || des == 443)){
        if(src == 443)
            proSend = "(https)";
        else proRecv = "(https)";
        u_char *ssl;
        ssl = (u_char*)(pkt_content + 14 + 20 + delta);
        u_char isTls = *(ssl);
        ssl++;
        u_short*pointer = (u_short*)(ssl);
        u_short version = ntohs(*pointer);
        if(isTls >= 20 && isTls <= 23 && version >= 0x0301 && version <= 0x0304){
            type = 6;
            switch(isTls){
            case 20:{
                info = "Change Cipher Spec";
                break;
            }
            case 21:{
                info = "Alert";
                break;
            }
            case 22:{
                info = "Handshake";
                ssl += 4;
                u_char type = (*ssl);
                switch (type) {
                case 1: {
                    info += " Client Hello";
                    break;
                }
                case 2: {
                    info += " Server hello";
                    break;
                }
                case 4: {
                    info += " New Session Ticket";
                    break;
                }
                case 11:{
                    info += " Certificate";
                    break;
                }
                case 16:{
                    info += " Client Key Exchange";
                    break;
                }
                case 12:{
                    info += " Server Key Exchange";
                    break;
                }
                case 14:{
                    info += " Server Hello Done";
                    break;
                }
                default:break;
                }
                break;
            }
            case 23:{
                info = "Application Data";
                break;
            }
            default:{
                break;
            }
            }
            return type;
        }else type = 7;
    }

    if(type == 7){
        info = "Continuation Data";
    }
    else{
        info += QString::number(src) + proSend+ "->" + QString::number(des) + proRecv;
        QString flag = "";
        if(tcp->flags & 0x08) flag += "PSH,";
        if(tcp->flags & 0x10) flag += "ACK,";
        if(tcp->flags & 0x02) flag += "SYN,";
        if(tcp->flags & 0x20) flag += "URG,";
        if(tcp->flags & 0x01) flag += "FIN,";
        if(tcp->flags & 0x04) flag += "RST,";
        if(flag != ""){
            flag = flag.left(flag.length()-1);
            info += " [" + flag + "]";
        }
        u_int sequeue = ntohl(tcp->sequence);
        u_int ack = ntohl(tcp->ack);
        u_short window = ntohs(tcp->window_size);
        info += " Seq=" + QString::number(sequeue) + " Ack=" + QString::number(ack) + " win=" + QString::number(window) + " Len=" + QString::number(tcpPayLoad);
    }
    return type;
}

int multhread::udpPacketHandle(const u_char *pkt_content,QString&info){
    UDP_HEADER * udp;
    udp = (UDP_HEADER*)(pkt_content + 14 + 20);
    u_short desPort = ntohs(udp->des_port);
    u_short srcPort = ntohs(udp->src_port);
    if(desPort == 53){ // dns query
        info =  dnsPacketHandle(pkt_content);
        return 5;
    }
    else if(srcPort == 53){// dns reply
        info =  dnsPacketHandle(pkt_content);
        return 5;
    }
    else{
        QString res = QString::number(srcPort) + "->" + QString::number(desPort);
        res += " len=" + QString::number(ntohs(udp->data_length));
        info = res;
        return 4;
    }
}

QString multhread::dnsPacketHandle(const u_char *pkt_content){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    u_short identification = ntohs(dns->identification);
    u_short type = ntohs(dns->flags);
    QString info = "";
    if((type & 0xf800) == 0x0000){
        info = "Standard query ";
    }
    else if((type & 0xf800) == 0x8000){
        info = "Standard query response ";
    }
    QString name = "";
    char*domain = (char*)(pkt_content + 14 + 20 + 8 + 12);
    while(*domain != 0x00){
        if(domain && (*domain) <= 64){
            int length = *domain;
            domain++;
            for(int k = 0;k < length;k++){
                name += (*domain);
                domain++;
            }
            name += ".";
        }else break;
    }
    // DNS_QUESITON *qus = (DNS_QUESITON*)(pkt_content + 14 + 20 + 8 + 12 + stringLength);
    // qDebug()<<ntohs(qus->query_type);
    // qDebug()<<ntohs(qus->query_class);
    name = name.left(name.length()-1);
    return info + "0x" + QString::number(identification,16) + " " + name;
}
