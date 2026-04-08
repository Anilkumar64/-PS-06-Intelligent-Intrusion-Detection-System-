#pragma once
#include <QObject>
#include <QTimer>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <mutex>
#include "Types.h"

// Per-flow sliding window: tracks all packets in last N seconds
struct FlowWindow
{
    struct Entry
    {
        std::chrono::steady_clock::time_point ts;
        uint16_t size;
        bool isSYN;
        uint16_t dst_port;
    };

    std::deque<Entry> entries;
    uint32_t unique_dst_ports_total{0};
    std::unordered_set<uint16_t> port_set;

    void push(std::chrono::steady_clock::time_point ts,
              uint16_t size, bool syn, uint16_t dport)
    {
        entries.push_back({ts, size, syn, dport});
        port_set.insert(dport);
    }

    void evictBefore(std::chrono::steady_clock::time_point cutoff)
    {
        while (!entries.empty() && entries.front().ts < cutoff)
        {
            entries.pop_front();
        }
    }

    uint32_t synCount() const
    {
        uint32_t c = 0;
        for (auto &e : entries)
            if (e.isSYN)
                ++c;
        return c;
    }

    double avgPacketSize() const
    {
        if (entries.empty())
            return 0.0;
        double sum = 0;
        for (auto &e : entries)
            sum += e.size;
        return sum / entries.size();
    }
};

class FlowTracker : public QObject
{
    Q_OBJECT

public:
    explicit FlowTracker(QObject *parent = nullptr,
                         int windowSecs = 3);

public slots:
    void onParsedPacket(const ParsedPacket &pkt);

signals:
    void flowUpdated(const FlowStats &stats);

private slots:
    void onCleanupTimer();

private:
    FlowStats computeStats(const FlowKey &key, FlowWindow &win,
                           std::chrono::steady_clock::time_point now);

    std::unordered_map<FlowKey, FlowWindow, FlowKeyHash> m_flows;
    std::unordered_map<FlowKey, std::chrono::steady_clock::time_point,
                       FlowKeyHash>
        m_firstSeen;
    std::mutex m_mutex;
    int m_windowSecs;
    QTimer *m_cleanupTimer;
};