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
    std::unordered_set<uint16_t> port_set;

    void push(std::chrono::steady_clock::time_point ts,
              uint16_t size, bool syn, uint16_t dport)
    {
        entries.push_back({ts, size, syn, dport});
        port_set.insert(dport);
    }

    void evictBefore(std::chrono::steady_clock::time_point cutoff)
    {
        bool evicted = false;
        while (!entries.empty() && entries.front().ts < cutoff)
        {
            entries.pop_front();
            evicted = true;
        }
        if (evicted)
        {
            port_set.clear();
            for (auto &e : entries)
                port_set.insert(e.dst_port);
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

// Per-source-IP aggregated window — tracks behavior across ALL flows from one IP
// This is what detects port scans and distributed floods
struct SrcWindow
{
    struct Entry
    {
        std::chrono::steady_clock::time_point ts;
        uint16_t dst_port;
        bool isSYN;
        uint16_t size;
    };

    std::deque<Entry> entries;
    std::unordered_set<uint16_t> port_set; // unique dst ports across all flows

    void push(std::chrono::steady_clock::time_point ts,
              uint16_t dst_port, bool syn, uint16_t size)
    {
        entries.push_back({ts, dst_port, syn, size});
        port_set.insert(dst_port);
    }

    void evictBefore(std::chrono::steady_clock::time_point cutoff)
    {
        bool evicted = false;
        while (!entries.empty() && entries.front().ts < cutoff)
        {
            entries.pop_front();
            evicted = true;
        }
        if (evicted)
        {
            port_set.clear();
            for (auto &e : entries)
                port_set.insert(e.dst_port);
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
                           SrcWindow &src, int windowSecs,
                           std::chrono::steady_clock::time_point now);

    std::unordered_map<FlowKey, FlowWindow, FlowKeyHash> m_flows;
    std::unordered_map<uint32_t, SrcWindow> m_srcWindows; // keyed by src_ip
    std::unordered_map<FlowKey, std::chrono::steady_clock::time_point,
                       FlowKeyHash>
        m_firstSeen;
    std::mutex m_mutex;
    int m_windowSecs;
    QTimer *m_cleanupTimer;
};