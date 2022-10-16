#ifndef DATAPACKETITEM_H
#define DATAPACKETITEM_H
#include <QString>
#include <format.h>
#include <QMetaType>
#include <winsock2.h>
#include <QVector>

class dataPacketItem
{
public:
    const u_char* pkt_content;

    dataPacketItem();

    QString getLength();
    QString getTimestamp();
    QString getInfo();
    QString getProtocolTypeToString();

    void setLength(u_int length);
    void setTimestamp(QString timestamp);
    void setInfo(QString info);
    void setProtocolType(int protocolType);
    void setPointerToContent(const uchar* pkt_content, int size);
    QString getSource();
    QString getDestination();
    QString getDesMacAddr();
    QString getSrcMacAddr();
    QString getDesIpAddr();
    QString getSrcIpAddr();
    QString getMacType();
    QString getIpVersion();                   // get the ip version
    QString getIpHeaderLength();              // get the ip head length
    QString getIpTos();                       // get the ip tos
    QString getIpTotalLength();               // get the ip total package length
    QString getIpIdentification();            // get the ip identification
    QString getIpFlag();                      // get the ip flag
    QString getIpReservedBit();               // the reserved bit
    QString getIpDF();                        // Don't fragment
    QString getIpMF();                        // More fragment
    QString getIpFragmentOffset();            // get the offset of package
    QString getIpTTL();                       // get ip ttl [time to live]
    QString getIpProtocol();                  // get the ip protocol
    QString getIpCheckSum();                  // get the checksum

    // get the icmp info
    QString getIcmpType();                    // get the icmp type
    QString getIcmpCode();                    // get the icmp code
    QString getIcmpCheckSum();                // get the icmp checksum
    QString getIcmpIdentification();          // get the icmp identification
    QString getIcmpSequeue();                 // get the icmp sequence
    QString getIcmpData(int size);            // get the icmp data

    // get the arp info
    QString getArpHardwareType();             // get arp hardware type
    QString getArpProtocolType();             // get arp protocol type
    QString getArpHardwareLength();           // get arp hardware length
    QString getArpProtocolLength();           // get arp protocol length
    QString getArpOperationCode();            // get arp operation code
    QString getArpSourceEtherAddr();          // get arp source ethernet address
    QString getArpSourceIpAddr();             // get arp souce ip address
    QString getArpDestinationEtherAddr();     // get arp destination ethernet address
    QString getArpDestinationIpAddr();        // get arp destination ip address

    // get the tcp info
    QString getTcpSourcePort();               // get tcp source port
    QString getTcpDestinationPort();          // get tcp destination port
    QString getTcpSequence();                 // get tcp sequence
    QString getTcpAcknowledgment();           // get acknowlegment
    QString getTcpHeaderLength();             // get tcp head length
    QString getTcpRawHeaderLength();          // get tcp raw head length [default is 0x05]
    QString getTcpFlags();                    // get tcp flags
    QString getTcpPSH();                      // PSH flag
    QString getTcpACK();                      // ACK flag
    QString getTcpSYN();                      // SYN flag
    QString getTcpURG();                      // URG flag
    QString getTcpFIN();                      // FIN flag
    QString getTcpRST();                      // RST flag
    QString getTcpWindowSize();               // get tcp window size
    QString getTcpCheckSum();                 // get tcp checksum
    QString getTcpUrgentPointer();            // get tcp urgent pointer
    QString getTcpOperationKind(int kind);    // get tcp option kind
    int getTcpOperationRawKind(int offset);   // get tcp raw option kind

    /*
     * tcp optional parts
    */
    bool getTcpOperationMSS(int offset,u_short& mss);                          // kind = 2
    bool getTcpOperationWSOPT(int offset,u_char&shit);                         // kind = 3
    bool getTcpOperationSACKP(int offset);                                     // kind = 4
    bool getTcpOperationSACK(int offset,u_char&length,QVector<u_int>&edge);    // kind = 5
    bool getTcpOperationTSPOT(int offset,u_int& value,u_int&reply);            // kind = 8

    // get the udp info
    QString getUdpSourcePort();               // get udp source port
    QString getUdpDestinationPort();          // get udp destination port
    QString getUdpDataLength();               // get udp data length
    QString getUdpCheckSum();                 // get udp checksum

    // get the dns info
    QString getDnsTransactionId();            // get dns transaction id
    QString getDnsFlags();                    // get dns flags
    QString getDnsFlagsQR();                  // get dns flag QR
    QString getDnsFlagsOpcode();              // get dns flag operation code
    QString getDnsFlagsAA();                  // get dns flag AA
    QString getDnsFlagsTC();                  // get dns flag TC
    QString getDnsFlagsRD();                  // get dns flag RD
    QString getDnsFlagsRA();                  // get dns flag RA
    QString getDnsFlagsZ();                   // get dns flag Z [reserved]
    QString getDnsFlagsRcode();               // get dns flag Rcode
    QString getDnsQuestionNumber();           // get dns question number
    QString getDnsAnswerNumber();             // get dns answer number
    QString getDnsAuthorityNumber();          // get dns authority number
    QString getDnsAdditionalNumber();         // get dns addition number
    void getDnsQueriesDomain(QString&name,int&Type,int&Class);
    QString getDnsDomainType(int type);
    QString getDnsDomainName(int offset);
    int getDnsAnswersDomain(int offset,QString&name1,u_short&Type,u_short& Class,u_int&ttl,u_short&dataLength,QString& name2);

    // get the tls info
    bool getisTlsProtocol(int offset);
    void getTlsBasicInfo(int offset,u_char&contentType,u_short&version,u_short&length);
    void getTlsClientHelloInfo(int offset,u_char&handShakeType,int& length,u_short&version,QString&random,u_char&sessionIdLength,QString&sessionId,u_short&cipherLength,QVector<u_short>&cipherSuit,u_char& cmLength,QVector<u_char>&CompressionMethod,u_short&extensionLength);
    void getTlsServerHelloInfo(int offset,u_char&handShakeType,int&length,u_short&version,QString& random,u_char&sessionIdLength,QString&sessionId,u_short&cipherSuit,u_char&compressionMethod,u_short&extensionLength);
    void getTlsServerKeyExchange(int offset,u_char&handShakeType,int&length,u_char&curveType,u_short&curveName,u_char&pubLength,QString&pubKey,u_short&sigAlgorithm,u_short&sigLength,QString&sig);
    u_short getTlsExtensionType(int offset);
    void getTlsHandshakeType(int offset,u_char&type);

    /*
     * these functions are used to parse the extension parts
     * extension parts are common in handshake parts (client hello,server hello ...)
     * there are some extension types are not included in, maybe you should refer the official API
    */
    void getTlsExtensionServerName(int offset,u_short&type,u_short&length,u_short&listLength,u_char&nameType,u_short&nameLength,QString& name);
    void getTlsExtensionSignatureAlgorithms(int offset,u_short&type,u_short&length,u_short&algorithmLength,QVector<u_short>&signatureAlgorithm);
    void getTlsExtensionSupportGroups(int offset,u_short&type,u_short&length,u_short&groupListLength,QVector<u_short>&group);
    void getTlsExtensionEcPointFormats(int offset,u_short&type,u_short&length,u_char& ecLength,QVector<u_char>&EC);
    void getTlsExtensionSessionTicket(int offset,u_short&type,u_short&length);
    void getTlsExtensionEncryptThenMac(int offset,u_short&type,u_short&length);
    void getTlsExtensionSupportVersions(int offset,u_short&type,u_short&length,u_char&supportLength,QVector<u_short>&supportVersion);
    void getTlsExtensionPskKeyExchangeModes(int offset,u_short&type,u_short&length,u_char&modeLength,QVector<u_char>&mode);
    void getTlsExtensionKeyShare(int offset,u_short&type,u_short&length,u_short&shareLength,u_short&group,u_short&exchangeLength,QString& exchange);
    void getTlsExtensionOther(int offset,u_short&type,u_short&length,QString& data);
    void getTlsExtensionExtendMasterSecret(int offset,u_short&type,u_short&length);
    void getTlsExtensionPadding(int offset,u_short&type,u_short&length,QString&data);

    /*
     * when transfer data,some types will be encoded,like using 0x01 to represent the MD5 in extension hash part
     * to visual display these types,we need to decode and analysis
     * this functions are used to do these analisis
     * however,some types may be the custom types, so we can't decode
     * also,there are some rules not be included, maybe you should refer the official API
    */
    // Parsing the encode data
    static QString getTlsHandshakeType(int type);                          // Parsing TLS handshake type
    static QString getTlsContentType(int type);                            // Parsing TLS content type
    static QString getTlsVersion(int version);                             // Parsing TLS version
    static QString getTlsHandshakeCipherSuites(u_short code);              // Parsing TLS cipher suite
    static QString getTlsHandshakeCompression(u_char code);                // Parsing TLS compression
    static QString getTlsHandshakeExtension(u_short type);                 // Parsing TLS extension
    static QString getTlsHandshakeExtensionECPointFormat(u_char type);     // Parsing TLS EC point format
    static QString getTlsHandshakeExtensionSupportGroup(u_short type);     // Parsing TLS support group
    static QString getTlsHadshakeExtensionSignature(u_char type);          // Parsing TLS signature
    static QString getTlsHadshakeExtensionHash(u_char type);               // Parsing TLS hash

    QString byteToString(u_char* str,int size);
private:
    QString timestamp;
    QString info;
    int protocolType;
    u_int length;

};

#endif // DATAPACKETITEM_H
