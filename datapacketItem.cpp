#include "datapacketItem.h"


dataPacketItem::dataPacketItem():
    timestamp(""),
    info(""),
    protocolType(0),
    length(0)

{
    qRegisterMetaType<dataPacketItem>("dataPacketItem");

}

void dataPacketItem::setInfo(QString info)
{
    this->info = info;
}

void dataPacketItem::setLength(u_int length)
{
    this->length = length;
}

void dataPacketItem::setTimestamp(QString timestamp)
{
    this->timestamp = timestamp;
}

void dataPacketItem::setProtocolType(int protocolType)
{
    this->protocolType = protocolType;
}

QString dataPacketItem::getInfo()
{
    return info;
}

u_int dataPacketItem::getLength()
{
    return length;
}

QString dataPacketItem::getTimestamp()
{
    return timestamp;
}

QString dataPacketItem::getProtocolTypeToString()
{
    switch (this->protocolType)
    {
        case 1: return "ARP";
        case 2:  return "ICMP";
        case 3:  return "TCP";
        case 4:  return "UDP";
        case 5:  return "DNS";
        case 6:  return "TLS";
        case 7:  return "SSL";
        default:  return "";

    }
}
