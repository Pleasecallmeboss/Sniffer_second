#ifndef DATAPACKETITEM_H
#define DATAPACKETITEM_H
#include <QString>
#include <format.h>
#include <QMetaType>

class dataPacketItem
{
public:
    dataPacketItem();

    u_int getLength();
    QString getTimestamp();
    QString getInfo();
    QString getProtocolTypeToString();

    void setLength(u_int length);
    void setTimestamp(QString timestamp);
    void setInfo(QString info);
    void setProtocolType(int protocolType);
private:
    QString timestamp;
    QString info;
    int protocolType;
    u_int length;
};

#endif // DATAPACKETITEM_H
