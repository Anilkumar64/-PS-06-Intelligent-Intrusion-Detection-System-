#include "FlowTracker.h"
#include <QDebug>

FlowTracker::FlowTracker(QObject *parent, int windowSecs)
    : QObject(parent), m_windowSecs(windowSecs)
{
    m_cleanupTimer = new QTimer(this);
    connect(m_cleanupTimer, &QTimer::timeout,
            this, &FlowTracker::onCleanupTimer);
    m_cleanupTimer->start(5000);
}

// FlowTracker.cpp — onParsedPacket()
// REPLACE the current function body with:

void FlowTracker::onParsedPacket(const ParsedPacket &pkt)
{
    FlowKey key{pkt.src_ip, pkt.dst_ip, pkt.src_port,
                pkt.dst_port, pkt.protocol};

    auto now = pkt.timestamp;
    auto cutoff = now - std::chrono::seconds(m_windowSecs);

    FlowStats stats; // computed inside lock, emitted outside

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto &win = m_flows[key];
        if (m_firstSeen.find(key) == m_firstSeen.end())
            m_firstSeen[key] = now;
        win.evictBefore(cutoff);
        win.push(now, pkt.packet_size, pkt.isSYN(), pkt.dst_port);

        auto &src = m_srcWindows[pkt.src_ip];
        src.evictBefore(cutoff);
        src.push(now, pkt.dst_port, pkt.isSYN(), pkt.packet_size);

        stats = computeStats(key, win, src, m_windowSecs, now);
    } // ← mutex released here

    emit flowUpdated(stats); // ← safe: no lock held
}

FlowStats FlowTracker::computeStats(const FlowKey &key,
                                    FlowWindow &win,
                                    SrcWindow &src,
                                    int windowSecs,
                                    std::chrono::steady_clock::time_point now)
{
    FlowStats stats;
    stats.key = key;

    if (win.entries.empty())
        return stats;

    double windowDur = static_cast<double>(windowSecs);

    // Per-flow stats
    stats.packet_count = static_cast<uint64_t>(win.entries.size());
    stats.unique_dst_ports = static_cast<uint32_t>(win.port_set.size());
    stats.avg_packet_size = win.avgPacketSize();
    stats.first_seen = m_firstSeen[key];
    stats.last_seen = now;

    // Per-source-IP aggregated stats — real attack surface
    stats.src_total_packets = static_cast<uint64_t>(src.entries.size());
    stats.src_unique_dst_ports = static_cast<uint32_t>(src.port_set.size());
    stats.syn_count = src.synCount(); // SYN from ALL flows of this IP

    // Rate is based on src_ip total, not per-flow
    stats.packet_rate = stats.src_total_packets / windowDur;
    stats.connection_attempts = stats.src_total_packets;

    // Byte count from per-flow window
    uint64_t bytes = 0;
    for (auto &e : win.entries)
        bytes += e.size;
    stats.byte_count = bytes;

    return stats;
}

void FlowTracker::onCleanupTimer()
{
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(m_windowSecs * 3);

    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto it = m_flows.begin(); it != m_flows.end();)
    {
        if (it->second.entries.empty() ||
            it->second.entries.back().ts < cutoff)
        {
            m_firstSeen.erase(it->first);
            it = m_flows.erase(it);
        }
        else
            ++it;
    }

    for (auto it = m_srcWindows.begin(); it != m_srcWindows.end();)
    {
        if (it->second.entries.empty() ||
            it->second.entries.back().ts < cutoff)
            it = m_srcWindows.erase(it);
        else
            ++it;
    }
}