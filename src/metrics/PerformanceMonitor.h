#pragma once
#include <QObject>
#include <QTimer>
#include <deque>
#include <mutex>
#include <atomic>
#include "SystemStats.h"
#include "../Types.h"

/**
 * PerformanceMonitor
 *
 * Tracks packets/sec, detection latency (avg + p99), CPU usage,
 * and memory usage.  Emits a SystemStats snapshot every second.
 */
class PerformanceMonitor : public QObject
{
    Q_OBJECT

public:
    explicit PerformanceMonitor(QObject *parent = nullptr);

    // Call these from the pipeline
    void onPacketIn(uint32_t bytes);
    void onDetectionLatency(double ns);
    void onAlert(bool isAttack);
    void setActiveFlows(uint32_t count);
    void setMLReady(bool ready);
    void setMLScore(double score);
    void setDropped(uint64_t dropped);

signals:
    void statsUpdated(const SystemStats &stats);

private slots:
    void onTick();

private:
    double readCpuPercent();
    double readMemMB();
    double percentile99(std::deque<double> &v);

    QTimer *m_timer{nullptr};

    // Counters (thread-safe with atomic)
    std::atomic<uint64_t> m_totalPackets{0};
    std::atomic<uint64_t> m_totalBytes{0};
    std::atomic<uint64_t> m_totalAlerts{0};
    std::atomic<uint64_t> m_alertsAttack{0};
    std::atomic<uint64_t> m_alertsSuspicious{0};
    std::atomic<uint32_t> m_activeFlows{0};
    std::atomic<uint64_t> m_dropped{0};
    std::atomic<bool> m_mlReady{false};
    std::atomic<double> m_mlScoreLast{0.0};

    // Per-interval counters (reset each tick)
    std::atomic<uint64_t> m_intervalPackets{0};
    std::atomic<uint64_t> m_intervalBytes{0};

    // Latency samples (mutex-protected)
    std::mutex m_latMutex;
    std::deque<double> m_latencySamples; // ns, last 1s window
    static constexpr int kMaxLatencySamples{10000};

    // CPU tracking
    uint64_t m_prevCpuTotal{0};
    uint64_t m_prevCpuIdle{0};
};