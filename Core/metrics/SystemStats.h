#pragma once
#include <cstdint>
#include <chrono>

// ─────────────────────────────────────────────────────────────────────────────
//  SystemStats — live performance snapshot emitted every second.
//  Field names match exactly what TrafficPanel, MetricsBar, TrafficChart use.
// ─────────────────────────────────────────────────────────────────────────────
struct SystemStats
{
    // ── Throughput ────────────────────────────────────────────────────────
    double packets_per_sec{0.0};
    double bytes_per_sec{0.0};
    uint64_t total_packets{0};
    uint64_t dropped_packets{0};

    // ── Detection latency (nanoseconds) ──────────────────────────────────
    // Stored as ns — UI divides by 1000 to display µs
    double latency_avg_ns{0.0};
    double latency_p99_ns{0.0};

    // ── Alert counters (cumulative) ───────────────────────────────────────
    uint64_t total_alerts{0}; // suspicious + attack
    uint64_t alerts_suspicious{0};
    uint64_t alerts_attack{0};

    // ── Flows ─────────────────────────────────────────────────────────────
    uint32_t active_flows{0};

    // ── System resources ──────────────────────────────────────────────────
    float cpu_percent{0.0f};
    float mem_mb{0.0f}; // RSS in MB

    // ── ML subprocess status ──────────────────────────────────────────────
    bool ml_ready{false};

    // ── Capture source ────────────────────────────────────────────────────
    bool using_kernel_module{false};

    std::chrono::steady_clock::time_point timestamp;
};