#include "RuleEngine.h"
#include <sstream>
#include <iomanip>

RuleEngine::RuleEngine(QObject *parent) : QObject(parent) {}

std::optional<RuleMatch> RuleEngine::evaluate(const FlowStats &stats,
                                              const FeatureVector &fv)
{
    // ── Rule 1: Port Scan ──────────────────────────────────────────────────
    // Use src_unique_dst_ports — counts ports across ALL flows from this IP
    // A 5-tuple flow will only ever have 1 dst_port, so we must use src-level
    uint32_t scanPorts = stats.src_unique_dst_ports;
    if (scanPorts >= m_thresh.portScanUniquePortsMin)
    {
        std::ostringstream oss;
        oss << "Port scan: " << scanPorts
            << " unique ports from " << ipToString(stats.key.src_ip)
            << " in " << 3 << "s window"
            << " (threshold: " << m_thresh.portScanUniquePortsMin << ")";
        return RuleMatch{
            "Port Scan",
            oss.str(),
            (scanPorts >= m_thresh.portScanUniquePortsMin * 3)
                ? Severity::ATTACK
                : Severity::SUSPICIOUS};
    }

    // ── Rule 2: SYN Flood ──────────────────────────────────────────────────
    // Use syn_ratio — far more reliable than raw count
    // Normal: ~0.05  |  SYN flood: ~1.0
    if (fv.syn_ratio >= m_thresh.synFloodRatioMin &&
        fv.packet_rate >= m_thresh.synFloodRateMin)
    {
        std::ostringstream oss;
        oss << "SYN flood: ratio=" << std::fixed << std::setprecision(2)
            << fv.syn_ratio
            << " (" << static_cast<int>(fv.syn_count) << " SYNs"
            << " / " << static_cast<int>(fv.connection_count) << " pkts)"
            << " at " << std::setprecision(1) << fv.packet_rate << " pkt/s";
        return RuleMatch{"SYN Flood", oss.str(), Severity::ATTACK};
    }

    // ── Rule 3: DoS (volumetric) ───────────────────────────────────────────
    if (fv.packet_rate >= m_thresh.dosPacketRateMin)
    {
        std::ostringstream oss;
        oss << "DoS flood: " << std::fixed << std::setprecision(1)
            << fv.packet_rate << " pkt/s"
            << " (" << static_cast<int>(fv.bytes_per_sec / 1000) << " KB/s)"
            << " (threshold: " << m_thresh.dosPacketRateMin << ")";
        return RuleMatch{"DoS Attack", oss.str(), Severity::ATTACK};
    }

    // ── Rule 4: Adaptive baseline ─────────────────────────────────────────
    if (m_baselinePacketRate > 0.0 &&
        fv.packet_rate >= m_baselinePacketRate * m_thresh.adaptiveSuspiciousMultiplier)
    {
        std::ostringstream oss;
        oss << "Traffic spike: " << std::fixed << std::setprecision(1)
            << fv.packet_rate << " pkt/s is "
            << std::setprecision(1) << (fv.packet_rate / m_baselinePacketRate)
            << "x above baseline (" << m_baselinePacketRate << " pkt/s)";
        return RuleMatch{"Traffic Spike", oss.str(), Severity::SUSPICIOUS};
    }

    return std::nullopt;
}

// RuleEngine.cpp — updateBaseline() — REPLACE:

void RuleEngine::updateBaseline(double normalPacketRate)
{
    if (m_baselinePacketRate == 0.0)
    {
        m_baselinePacketRate = normalPacketRate;
        return;
    }
    // Adaptive alpha: converge faster when current rate >> baseline
    // Prevents cold-start false positives from file downloads / video streams
    double ratio = (m_baselinePacketRate > 0.0)
                       ? normalPacketRate / m_baselinePacketRate
                       : 1.0;
    double alpha = (ratio > 5.0)   ? 0.7
                   : (ratio > 2.0) ? 0.5
                                   : 0.3;
    m_baselinePacketRate = (1.0 - alpha) * m_baselinePacketRate + alpha * normalPacketRate;
}