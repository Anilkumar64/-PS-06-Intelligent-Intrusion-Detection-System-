#include "PerformanceMonitor.h"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <cmath>
#include <QDebug>

PerformanceMonitor::PerformanceMonitor(QObject *parent) : QObject(parent)
{
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &PerformanceMonitor::onTick);
    m_timer->start(1000);
}

void PerformanceMonitor::recordPacket(uint32_t byteSize)
{
    std::lock_guard<std::mutex> lock(m_windowMutex);
    m_window.push_back({std::chrono::steady_clock::now(), byteSize});
}

void PerformanceMonitor::recordDetection(
    const DetectionResult &result,
    std::chrono::steady_clock::time_point captureTime)
{
    auto now = std::chrono::steady_clock::now();
    double ns = std::chrono::duration<double, std::nano>(now - captureTime).count();

    {
        std::lock_guard<std::mutex> lock(m_latMutex);
        m_latencies.push_back(ns);
        if (m_latencies.size() > 10000)
            m_latencies.pop_front();
    }

    switch (result.severity)
    {
    case Severity::SUSPICIOUS:
        m_cntSuspicious.fetch_add(1);
        break;
    case Severity::ATTACK:
        m_cntAttack.fetch_add(1);
        break;
    default:
        break;
    }
}

void PerformanceMonitor::onTick()
{
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(1);

    SystemStats s;
    s.timestamp = now;

    // Packet rate & bytes/sec
    {
        std::lock_guard<std::mutex> lock(m_windowMutex);
        while (!m_window.empty() && m_window.front().ts < cutoff)
            m_window.pop_front();

        uint64_t byteSum = 0;
        for (auto &p : m_window)
            byteSum += p.size;
        s.packets_per_sec = static_cast<double>(m_window.size());
        s.bytes_per_sec = static_cast<double>(byteSum);
    }

    // Latency (stored as nanoseconds — UI divides by 1000 for µs)
    {
        std::lock_guard<std::mutex> lock(m_latMutex);
        if (!m_latencies.empty())
        {
            double sum = 0;
            for (double v : m_latencies)
                sum += v;
            s.latency_avg_ns = sum / static_cast<double>(m_latencies.size());

            std::vector<double> sorted(m_latencies.begin(), m_latencies.end());
            std::sort(sorted.begin(), sorted.end());
            size_t idx = static_cast<size_t>(
                             std::ceil(0.99 * static_cast<double>(sorted.size()))) -
                         1;
            s.latency_p99_ns = sorted[std::min(idx, sorted.size() - 1)];
        }
    }

    // Alert counters
    s.alerts_suspicious = m_cntSuspicious.load();
    s.alerts_attack = m_cntAttack.load();
    s.total_alerts = s.alerts_suspicious + s.alerts_attack;

    // Totals
    s.total_packets = static_cast<uint64_t>(s.packets_per_sec) + m_last.total_packets;
    s.dropped_packets = m_droppedPackets.load();
    s.active_flows = m_activeFlows.load();
    s.using_kernel_module = m_usingKernel;
    s.ml_ready = m_mlReady;
    s.cpu_percent = readCpuUsage();
    s.mem_mb = readMemMb();

    m_last = s;
    emit statsUpdated(s);
}

float PerformanceMonitor::readCpuUsage()
{
    std::ifstream f("/proc/stat");
    if (!f.is_open())
        return 0.0f;
    std::string line;
    std::getline(f, line);
    std::istringstream iss(line);
    std::string label;
    iss >> label;
    uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
    iss >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
    uint64_t totalIdle = idle + iowait;
    uint64_t total = totalIdle + user + nice + system + irq + softirq + steal;
    float pct = 0.0f;
    if (total > m_prevTotal)
    {
        uint64_t diffTotal = total - m_prevTotal;
        uint64_t diffIdle = totalIdle - m_prevIdle;
        pct = 100.0f * static_cast<float>(diffTotal - diffIdle) /
              static_cast<float>(diffTotal);
    }
    m_prevTotal = total;
    m_prevIdle = totalIdle;
    return pct;
}

float PerformanceMonitor::readMemMb()
{
    std::ifstream f("/proc/self/status");
    if (!f.is_open())
        return 0.0f;
    std::string line;
    while (std::getline(f, line))
    {
        if (line.rfind("VmRSS:", 0) == 0)
        {
            uint64_t kb = 0;
            std::istringstream iss(line);
            std::string key;
            iss >> key >> kb;
            return static_cast<float>(kb) / 1024.0f;
        }
    }
    return 0.0f;
}