#include "PerformanceMonitor.h"
#include <QDebug>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <cstring>
#include <sys/resource.h>
#include <unistd.h>

PerformanceMonitor::PerformanceMonitor(QObject *parent) : QObject(parent)
{
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &PerformanceMonitor::onTick);
    m_timer->start(1000); // 1Hz snapshot
}

// ── Public update methods ─────────────────────────────────────────────────────

void PerformanceMonitor::onPacketIn(uint32_t bytes)
{
    ++m_totalPackets;
    ++m_intervalPackets;
    m_totalBytes += bytes;
    m_intervalBytes += bytes;
}

void PerformanceMonitor::onDetectionLatency(double ns)
{
    std::lock_guard<std::mutex> lock(m_latMutex);
    m_latencySamples.push_back(ns);
    if (static_cast<int>(m_latencySamples.size()) > kMaxLatencySamples)
        m_latencySamples.pop_front();
}

void PerformanceMonitor::onAlert(bool isAttack)
{
    ++m_totalAlerts;
    if (isAttack)
        ++m_alertsAttack;
    else
        ++m_alertsSuspicious;
}

void PerformanceMonitor::setActiveFlows(uint32_t count) { m_activeFlows = count; }
void PerformanceMonitor::setMLReady(bool ready) { m_mlReady = ready; }
void PerformanceMonitor::setMLScore(double score) { m_mlScoreLast = score; }
void PerformanceMonitor::setDropped(uint64_t dropped) { m_dropped = dropped; }

// ── 1-second tick ─────────────────────────────────────────────────────────────

void PerformanceMonitor::onTick()
{
    SystemStats s;
    s.snapshot_time = std::chrono::steady_clock::now();

    // Throughput
    uint64_t ipkts = m_intervalPackets.exchange(0);
    uint64_t ibytes = m_intervalBytes.exchange(0);

    s.packets_per_sec = static_cast<double>(ipkts);
    s.bytes_per_sec = static_cast<double>(ibytes);
    s.total_packets = m_totalPackets.load();
    s.total_bytes = m_totalBytes.load();

    // Alerts
    s.total_alerts = m_totalAlerts.load();
    s.alerts_attack = m_alertsAttack.load();
    s.alerts_suspicious = m_alertsSuspicious.load();
    s.active_flows = m_activeFlows.load();
    s.dropped_packets = m_dropped.load();

    // Latency
    {
        std::lock_guard<std::mutex> lock(m_latMutex);
        if (!m_latencySamples.empty())
        {
            double sum = 0;
            for (double v : m_latencySamples)
                sum += v;
            s.latency_avg_ns = sum / m_latencySamples.size();
            s.latency_p99_ns = percentile99(m_latencySamples);
            s.latency_max_ns = *std::max_element(
                m_latencySamples.begin(), m_latencySamples.end());
        }
        m_latencySamples.clear(); // reset window
    }

    // System
    s.cpu_percent = readCpuPercent();
    s.mem_mb = readMemMB();
    s.ml_ready = m_mlReady.load();
    s.ml_score_last = m_mlScoreLast.load();

    emit statsUpdated(s);
}

// ── CPU from /proc/stat ───────────────────────────────────────────────────────

double PerformanceMonitor::readCpuPercent()
{
    std::ifstream f("/proc/stat");
    if (!f.is_open())
        return 0.0;

    std::string line;
    std::getline(f, line); // "cpu  user nice system idle ..."
    std::istringstream iss(line);
    std::string tag;
    uint64_t user, nice, sys, idle, iowait, irq, softirq, steal;
    iss >> tag >> user >> nice >> sys >> idle >> iowait >> irq >> softirq >> steal;

    uint64_t total = user + nice + sys + idle + iowait + irq + softirq + steal;
    uint64_t dTotal = total - m_prevCpuTotal;
    uint64_t dIdle = idle - m_prevCpuIdle;

    m_prevCpuTotal = total;
    m_prevCpuIdle = idle;

    if (dTotal == 0)
        return 0.0;
    return 100.0 * (1.0 - static_cast<double>(dIdle) / static_cast<double>(dTotal));
}

// ── RSS from /proc/self/status ────────────────────────────────────────────────

double PerformanceMonitor::readMemMB()
{
    std::ifstream f("/proc/self/status");
    if (!f.is_open())
        return 0.0;
    std::string line;
    while (std::getline(f, line))
    {
        if (line.rfind("VmRSS:", 0) == 0)
        {
            std::istringstream iss(line.substr(6));
            uint64_t kb;
            iss >> kb;
            return kb / 1024.0;
        }
    }
    return 0.0;
}

// ── p99 latency ───────────────────────────────────────────────────────────────

double PerformanceMonitor::percentile99(std::deque<double> &v)
{
    if (v.empty())
        return 0.0;
    std::vector<double> tmp(v.begin(), v.end());
    std::sort(tmp.begin(), tmp.end());
    size_t idx = static_cast<size_t>(0.99 * (tmp.size() - 1));
    return tmp[idx];
}