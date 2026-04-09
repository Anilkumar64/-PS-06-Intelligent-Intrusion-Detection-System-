#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <cstddef>
#include <array>

// ─────────────────────────────────────────────
//  Raw packet (from libpcap)
// ─────────────────────────────────────────────
struct RawPacket
{
    std::vector<uint8_t> data;
    std::chrono::steady_clock::time_point timestamp;
    uint32_t caplen{0};
};

// ─────────────────────────────────────────────
//  Parsed packet fields
// ─────────────────────────────────────────────
enum class Protocol : uint8_t
{
    UNKNOWN = 0,
    TCP = 6,
    UDP = 17,
    ICMP = 1
};

struct ParsedPacket
{
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    Protocol protocol{Protocol::UNKNOWN};
    uint16_t packet_size{0};
    uint8_t tcp_flags{0}; // SYN=0x02, ACK=0x10, RST=0x04, FIN=0x01
    bool valid{false};
    std::chrono::steady_clock::time_point timestamp;

    // TCP flag helpers
    bool isSYN() const
    {
        if (protocol != Protocol::TCP)
            return false;

        const uint8_t SYN = 0x02;
        const uint8_t ACK = 0x10;

        bool syn = (tcp_flags & SYN);
        bool ack = (tcp_flags & ACK);

        return syn && !ack; // 🔥 ONLY pure SYN
    }
    bool isACK() const { return (tcp_flags & 0x10) != 0; }
    bool isRST() const { return (tcp_flags & 0x04) != 0; }
    bool isFIN() const { return (tcp_flags & 0x01) != 0; }
};

// ─────────────────────────────────────────────
//  Flow key — 5-tuple (protocol + IPs + ports)
// ─────────────────────────────────────────────
struct FlowKey
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    Protocol protocol;

    bool operator==(const FlowKey &o) const
    {
        return src_ip == o.src_ip && dst_ip == o.dst_ip &&
               src_port == o.src_port && dst_port == o.dst_port &&
               protocol == o.protocol;
    }
};

struct FlowKeyHash
{
    std::size_t operator()(const FlowKey &k) const
    {
        std::size_t h = 0;
        auto mix = [&](std::size_t v)
        {
            h ^= v + 0x9e3779b9 + (h << 6) + (h >> 2);
        };
        mix(std::hash<uint32_t>{}(k.src_ip));
        mix(std::hash<uint32_t>{}(k.dst_ip));
        mix(std::hash<uint16_t>{}(k.src_port));
        mix(std::hash<uint16_t>{}(k.dst_port));
        mix(std::hash<uint8_t>{}(static_cast<uint8_t>(k.protocol)));
        return h;
    }
};

// ─────────────────────────────────────────────
//  Flow statistics (sliding window)
// ─────────────────────────────────────────────
struct FlowStats
{
    FlowKey key;
    uint64_t packet_count{0};
    uint64_t byte_count{0};
    uint32_t syn_count{0};
    uint32_t unique_dst_ports{0};     // per 5-tuple flow
    uint32_t src_unique_dst_ports{0}; // per src_ip across ALL flows — for port scan
    uint32_t connection_attempts{0};
    uint64_t src_total_packets{0}; // per src_ip in window — real attack volume
    double packet_rate{0.0};       // packets per second (per src_ip)
    double avg_packet_size{0.0};
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
};

// ─────────────────────────────────────────────
//  ML Feature vector
// ─────────────────────────────────────────────
struct FeatureVector
{
    // Raw rates (per-source-IP aggregated, not per-flow)
    double packet_rate{0.0};      // pkts/sec in window
    double unique_ports{0.0};     // unique dst ports seen from this src_ip
    double syn_count{0.0};        // raw SYN count (used by rules directly)
    double avg_packet_size{0.0};  // bytes
    double connection_count{0.0}; // total packets from src_ip in window

    // Derived ratio features — these are what make ML discriminative
    double syn_ratio{0.0};      // syn_count / packet_count (0=normal, ~1=flood)
    double port_scan_rate{0.0}; // unique_ports / window_secs (ports/sec)
    double bytes_per_sec{0.0};  // throughput
};

// ─────────────────────────────────────────────
//  Detection result
// ─────────────────────────────────────────────
enum class Severity : uint8_t
{
    NORMAL = 0,
    SUSPICIOUS = 1,
    ATTACK = 2
};

struct DetectionResult
{
    Severity severity{Severity::NORMAL};
    std::string attack_type; // "Port Scan", "SYN Flood", "DoS", "Anomaly"
    std::string reason;      // human-readable explanation
    std::string src_ip_str;
    uint32_t src_ip{0};
    double anomaly_score{0.0};
    bool rule_triggered{false};
    bool ml_triggered{false};
    std::chrono::steady_clock::time_point timestamp;
};

// ─────────────────────────────────────────────
//  Helper: uint32 IP → "a.b.c.d"
// ─────────────────────────────────────────────
inline std::string ipToString(uint32_t ip)
{
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}