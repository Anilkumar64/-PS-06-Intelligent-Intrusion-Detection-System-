#pragma once
#include <QObject>
#include "Types.h"

class PacketParser : public QObject
{
    Q_OBJECT

public:
    explicit PacketParser(QObject *parent = nullptr);

public slots:
    void onRawPacket(const RawPacket &raw);

signals:
    void packetParsed(const ParsedPacket &pkt);

private:
    ParsedPacket parseEthernet(const uint8_t *data, uint32_t len,
                               std::chrono::steady_clock::time_point ts);
    ParsedPacket parseIP(const uint8_t *data, uint32_t len,
                         std::chrono::steady_clock::time_point ts);
};