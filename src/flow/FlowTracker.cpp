#include "FlowTracker.h"
#include <QDebug>

FlowTracker::FlowTracker(QObject *parent, int windowSecs)
    : QObject(parent), m_windowSecs(windowSecs)
{
    m_cleanupTimer = new QTimer(this);
    connect(m_cleanupTimer, &QTimer::timeout,
            this, &FlowTracker::onCleanupTimer);
    m_cleanupTimer->start(5000); // cleanup every 5s
}

void FlowTracker::onParsedPacket(const ParsedPacket &pkt)
{
    FlowKey key{pkt.src_ip, pkt.dst_ip, pkt.src_port,
                pkt.dst_port, pkt.protocol};

    auto now = pkt.timestamp;
    auto cutoff = now - std::chrono::seconds(m_windowSecs);

    std::lock_guard<std::mutex> lock(m_mutex);

    auto &win = m_flows[key];
    if (m_firstSeen.find(key) == m_firstSeen.end())
        m_firstSeen[key] = now;

    // Evict old entries
    win.evictBefore(cutoff);

    // Add new entry
    win.push(now, pkt.packet_size, pkt.isSYN(), pkt.dst_port);

    // Emit updated stats
    emit flowUpdated(computeStats(key, win, now));
}

FlowStats FlowTracker::computeStats(const FlowKey &key,
                                    FlowWindow &win,
                                    std::chrono::steady_clock::time_point now)
{
    FlowStats stats;
    stats.key = key;

    if (win.entries.empty())
        return stats;

    double windowDur = static_cast<double>(m_windowSecs);

    stats.packet_count = static_cast<uint64_t>(win.entries.size());
    stats.syn_count = win.synCount();
    stats.unique_dst_ports = static_cast<uint32_t>(win.port_set.size());
    stats.packet_rate = stats.packet_count / windowDur;
    stats.avg_packet_size = win.avgPacketSize();
    stats.connection_attempts = stats.packet_count; // proxy
    stats.first_seen = m_firstSeen[key];
    stats.last_seen = now;

    // Byte count
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

    // Remove flows with no recent activity
    for (auto it = m_flows.begin(); it != m_flows.end();)
    {
        if (it->second.entries.empty() ||
            it->second.entries.back().ts < cutoff)
        {
            m_firstSeen.erase(it->first);
            it = m_flows.erase(it);
        }
        else
        {
            ++it;
        }
    }
}