#pragma once
#include <QObject>
#include <QTimer>
#include <deque>
#include <mutex>
#include <atomic>
#include "SystemStats.h"
#include "../Types.h"

class PerformanceMonitor : public QObject
{
    Q_OBJECT
public:
    explicit PerformanceMonitor(QObject *parent = nullptr);

    void recordPacket(uint32_t byteSize);
    void recordDetection(const DetectionResult &result,
                         std::chrono::steady_clock::time_point captureTime);

    void setUsingKernelModule(bool v) { m_usingKernel = v; }
    void setDroppedPackets(uint64_t n) { m_droppedPackets.store(n); }
    void setActiveFlows(uint32_t n) { m_activeFlows.store(n); }
    void setMlReady(bool v) { m_mlReady = v; }

    const SystemStats &lastStats() const { return m_last; }

signals:
    void statsUpdated(const SystemStats &stats);

private slots:
    void onTick();

private:
    float readCpuUsage();
    float readMemMb();

    QTimer *m_timer{nullptr};

    struct PktSample
    {
        std::chrono::steady_clock::time_point ts;
        uint32_t size;
    };
    std::deque<PktSample> m_window;
    std::mutex m_windowMutex;

    std::deque<double> m_latencies;
    std::mutex m_latMutex;

    std::atomic<uint64_t> m_cntSuspicious{0};
    std::atomic<uint64_t> m_cntAttack{0};
    std::atomic<uint64_t> m_droppedPackets{0};
    std::atomic<uint32_t> m_activeFlows{0};

    bool m_usingKernel{false};
    bool m_mlReady{false};

    SystemStats m_last;

    uint64_t m_prevIdle{0}, m_prevTotal{0};
};