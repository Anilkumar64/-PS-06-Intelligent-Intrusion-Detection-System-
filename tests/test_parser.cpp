/**
 * test_parser.cpp — Unit tests for PacketParser.
 *
 * Build standalone:
 *   g++ -std=c++20 -I../src test_parser.cpp ../src/parser/PacketParser.cpp \
 *       $(pkg-config --cflags --libs Qt6Core) -o test_parser
 *
 * Or via CMake test target:  cmake --build . --target test_parser
 */

#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include "parser/PacketParser.h"

// ─── Helpers ──────────────────────────────────────────────────────────────────
static RawPacket makeRaw(const std::vector<uint8_t> &bytes)
{
    RawPacket p;
    p.data = bytes;
    p.caplen = static_cast<uint32_t>(bytes.size());
    p.timestamp = std::chrono::steady_clock::now();
    return p;
}

// Build a minimal Ethernet + IPv4 + TCP frame
static std::vector<uint8_t> makeTCPPacket(
    uint32_t srcIP, uint32_t dstIP,
    uint16_t srcPort, uint16_t dstPort,
    uint8_t tcpFlags = 0x02 /*SYN*/)
{
    std::vector<uint8_t> buf(14 + 20 + 20, 0);

    // Ethernet (14 bytes) — EtherType = 0x0800 (IPv4)
    buf[12] = 0x08;
    buf[13] = 0x00;

    // IPv4 (20 bytes)
    uint8_t *ip = buf.data() + 14;
    ip[0] = 0x45; // version=4, IHL=5
    ip[9] = 6;    // protocol = TCP
    ip[12] = (srcIP >> 24) & 0xFF;
    ip[13] = (srcIP >> 16) & 0xFF;
    ip[14] = (srcIP >> 8) & 0xFF;
    ip[15] = srcIP & 0xFF;
    ip[16] = (dstIP >> 24) & 0xFF;
    ip[17] = (dstIP >> 16) & 0xFF;
    ip[18] = (dstIP >> 8) & 0xFF;
    ip[19] = dstIP & 0xFF;

    // TCP (20 bytes)
    uint8_t *tcp = buf.data() + 14 + 20;
    tcp[0] = (srcPort >> 8) & 0xFF;
    tcp[1] = srcPort & 0xFF;
    tcp[2] = (dstPort >> 8) & 0xFF;
    tcp[3] = dstPort & 0xFF;
    tcp[12] = 0x50; // data offset = 5 (20 bytes)
    tcp[13] = tcpFlags;

    return buf;
}

static std::vector<uint8_t> makeUDPPacket(
    uint32_t srcIP, uint32_t dstIP,
    uint16_t srcPort, uint16_t dstPort)
{
    std::vector<uint8_t> buf(14 + 20 + 8, 0);

    buf[12] = 0x08;
    buf[13] = 0x00;

    uint8_t *ip = buf.data() + 14;
    ip[0] = 0x45;
    ip[9] = 17; // UDP
    ip[12] = (srcIP >> 24) & 0xFF;
    ip[13] = (srcIP >> 16) & 0xFF;
    ip[14] = (srcIP >> 8) & 0xFF;
    ip[15] = srcIP & 0xFF;
    ip[16] = (dstIP >> 24) & 0xFF;
    ip[17] = (dstIP >> 16) & 0xFF;
    ip[18] = (dstIP >> 8) & 0xFF;
    ip[19] = dstIP & 0xFF;

    uint8_t *udp = buf.data() + 14 + 20;
    udp[0] = (srcPort >> 8) & 0xFF;
    udp[1] = srcPort & 0xFF;
    udp[2] = (dstPort >> 8) & 0xFF;
    udp[3] = dstPort & 0xFF;

    return buf;
}

// ─── Tests ────────────────────────────────────────────────────────────────────
static int passed = 0, failed = 0;

#define CHECK(name, cond)                              \
    do                                                 \
    {                                                  \
        if (cond)                                      \
        {                                              \
            std::cout << "  PASS  " << (name) << "\n"; \
            ++passed;                                  \
        }                                              \
        else                                           \
        {                                              \
            std::cout << "  FAIL  " << (name) << "\n"; \
            ++failed;                                  \
        }                                              \
    } while (0)

void test_tcp_parse()
{
    std::cout << "\n[PacketParser] TCP parsing\n";

    PacketParser parser;
    ParsedPacket result;
    bool got = false;

    QObject::connect(&parser, &PacketParser::packetParsed,
                     [&](const ParsedPacket &p)
                     { result = p; got = true; });

    uint32_t srcIP = (192 << 24) | (168 << 16) | (1 << 8) | 10;
    uint32_t dstIP = (10 << 24) | (0 << 16) | (0 << 8) | 1;
    uint16_t srcPort = 54321;
    uint16_t dstPort = 80;

    auto raw = makeRaw(makeTCPPacket(srcIP, dstIP, srcPort, dstPort, 0x02));
    parser.onRawPacket(raw);

    CHECK("got packet", got);
    CHECK("valid flag", result.valid);
    CHECK("protocol TCP", result.protocol == Protocol::TCP);
    CHECK("src_ip correct", result.src_ip == srcIP);
    CHECK("dst_ip correct", result.dst_ip == dstIP);
    CHECK("src_port correct", result.src_port == srcPort);
    CHECK("dst_port correct", result.dst_port == dstPort);
    CHECK("SYN flag set", result.isSYN());
    CHECK("ACK flag not set", !result.isACK());
}

void test_udp_parse()
{
    std::cout << "\n[PacketParser] UDP parsing\n";

    PacketParser parser;
    ParsedPacket result;
    bool got = false;

    QObject::connect(&parser, &PacketParser::packetParsed,
                     [&](const ParsedPacket &p)
                     { result = p; got = true; });

    uint32_t srcIP = (172 << 24) | (16 << 16) | (0 << 8) | 5;
    uint32_t dstIP = (8 << 24) | (8 << 16) | (8 << 8) | 8;
    uint16_t srcPort = 1234;
    uint16_t dstPort = 53;

    auto raw = makeRaw(makeUDPPacket(srcIP, dstIP, srcPort, dstPort));
    parser.onRawPacket(raw);

    CHECK("got packet", got);
    CHECK("valid", result.valid);
    CHECK("protocol UDP", result.protocol == Protocol::UDP);
    CHECK("dst_port 53 DNS", result.dst_port == 53);
}

void test_short_packet_rejected()
{
    std::cout << "\n[PacketParser] Short/malformed packet rejection\n";

    PacketParser parser;
    bool got = false;
    QObject::connect(&parser, &PacketParser::packetParsed,
                     [&](const ParsedPacket &)
                     { got = true; });

    // Too short to be Ethernet
    auto raw = makeRaw({0x00, 0x01, 0x02});
    parser.onRawPacket(raw);
    CHECK("short packet rejected", !got);

    // Ethernet but non-IPv4 EtherType (ARP = 0x0806)
    got = false;
    std::vector<uint8_t> arp(14, 0);
    arp[12] = 0x08;
    arp[13] = 0x06;
    parser.onRawPacket(makeRaw(arp));
    CHECK("ARP dropped (not IPv4)", !got);
}

void test_ip_to_string()
{
    std::cout << "\n[Types] ipToString\n";
    CHECK("192.168.1.1", ipToString((192 << 24) | (168 << 16) | (1 << 8) | 1) == "192.168.1.1");
    CHECK("10.0.0.1", ipToString((10 << 24) | (0 << 16) | (0 << 8) | 1) == "10.0.0.1");
    CHECK("8.8.8.8", ipToString((8 << 24) | (8 << 16) | (8 << 8) | 8) == "8.8.8.8");
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main()
{
    std::cout << "=== PacketParser Unit Tests ===\n";

    // Qt event loop not needed for direct slot calls in tests
    test_ip_to_string();
    test_tcp_parse();
    test_udp_parse();
    test_short_packet_rejected();

    std::cout << "\n--- Results: " << passed << " passed, " << failed << " failed ---\n";
    return (failed > 0) ? 1 : 0;
}