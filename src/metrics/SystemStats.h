#pragma once
#include <cstdint>
#include <chrono>

/**
 * SystemStats — point-in-time snapshot of IDS performance metrics.
 * Emitted periodically by PerformanceMonitor and consumed by the UI.
 */
struct SystemStats
{
    // Throughput
    double packets_per_sec{0.0};
    double bytes_per_sec{0.0};
    uint64_t total_packets{0};
    uint64_t total_bytes{0};

    // Detection
    uint64_t total_alerts{0};
    uint64_t alerts_attack{0};
    uint64_t alerts_suspicious{0};
    uint32_t active_flows{0};

    // Latency (nanoseconds)
    double latency_avg_ns{0.0};
    double latency_p99_ns{0.0};
    double latency_max_ns{0.0};

    // System
    double cpu_percent{0.0}; // process CPU %
    double mem_mb{0.0};      // RSS in MB
    uint64_t dropped_packets{0};

    // ML
    bool ml_ready{false};
    double ml_score_last{0.0};

    std::chrono::steady_clock::time_point snapshot_time;
};