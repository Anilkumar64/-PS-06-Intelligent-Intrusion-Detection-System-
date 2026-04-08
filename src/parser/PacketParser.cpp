#include "PacketParser.h"
#include <cstring>
#include <netinet/in.h>

// Ethernet header: 14 bytes
static constexpr uint32_t ETH_HEADER_LEN = 14;
// IP header minimum: 20 bytes
static constexpr uint32_t IP_HEADER_MIN = 20;
// TCP header minimum: 20 bytes
static constexpr uint32_t TCP_HEADER_MIN = 20;
// UDP header: 8 bytes
static constexpr uint32_t UDP_HEADER_LEN = 8;

PacketParser::PacketParser(QObject *parent) : QObject(parent) {}

void PacketParser::onRawPacket(const RawPacket &raw)
{
    if (raw.data.size() < ETH_HEADER_LEN)
        return;
    auto pkt = parseEthernet(raw.data.data(), raw.caplen, raw.timestamp);
    if (pkt.valid)
        emit packetParsed(pkt);
}

ParsedPacket PacketParser::parseEthernet(const uint8_t *data, uint32_t len,
                                         std::chrono::steady_clock::time_point ts)
{
    // EtherType is bytes 12-13 (big-endian)
    uint16_t ethertype = (static_cast<uint16_t>(data[12]) << 8) | data[13];

    // 0x0800 = IPv4
    if (ethertype == 0x0800 && len > ETH_HEADER_LEN)
    {
        return parseIP(data + ETH_HEADER_LEN, len - ETH_HEADER_LEN, ts);
    }
    // Skip IPv6, ARP, etc.
    return {};
}

ParsedPacket PacketParser::parseIP(const uint8_t *data, uint32_t len,
                                   std::chrono::steady_clock::time_point ts)
{
    if (len < IP_HEADER_MIN)
        return {};

    ParsedPacket pkt;
    pkt.timestamp = ts;

    uint8_t ihl = (data[0] & 0x0F) * 4; // IP header length
    if (len < ihl)
        return {};

    uint8_t proto = data[9];
    pkt.src_ip = (static_cast<uint32_t>(data[12]) << 24) |
                 (static_cast<uint32_t>(data[13]) << 16) |
                 (static_cast<uint32_t>(data[14]) << 8) |
                 static_cast<uint32_t>(data[15]);
    pkt.dst_ip = (static_cast<uint32_t>(data[16]) << 24) |
                 (static_cast<uint32_t>(data[17]) << 16) |
                 (static_cast<uint32_t>(data[18]) << 8) |
                 static_cast<uint32_t>(data[19]);
    pkt.packet_size = static_cast<uint16_t>(len);

    const uint8_t *transport = data + ihl;
    uint32_t tlen = len - ihl;

    if (proto == static_cast<uint8_t>(Protocol::TCP) && tlen >= TCP_HEADER_MIN)
    {
        pkt.protocol = Protocol::TCP;
        pkt.src_port = (static_cast<uint16_t>(transport[0]) << 8) | transport[1];
        pkt.dst_port = (static_cast<uint16_t>(transport[2]) << 8) | transport[3];
        pkt.tcp_flags = transport[13];
        pkt.valid = true;
    }
    else if (proto == static_cast<uint8_t>(Protocol::UDP) && tlen >= UDP_HEADER_LEN)
    {
        pkt.protocol = Protocol::UDP;
        pkt.src_port = (static_cast<uint16_t>(transport[0]) << 8) | transport[1];
        pkt.dst_port = (static_cast<uint16_t>(transport[2]) << 8) | transport[3];
        pkt.valid = true;
    }
    else if (proto == static_cast<uint8_t>(Protocol::ICMP))
    {
        pkt.protocol = Protocol::ICMP;
        pkt.valid = true;
    }

    return pkt;
}