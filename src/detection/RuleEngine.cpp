#include "RuleEngine.h"
#include <sstream>
#include <iomanip>
#include <cmath>

RuleEngine::RuleEngine(QObject *parent) : QObject(parent) {}

std::optional<RuleMatch> RuleEngine::evaluate(const FlowStats &stats,
                                              const FeatureVector &fv)
{
    // ── Rule 1: Port Scan ─────────────────────────────────────────────────
    // Many unique destination ports in the sliding window = horizontal scan
    if (stats.unique_dst_ports >= m_thresh.portScanUniquePortsMin)
    {
        std::ostringstream oss;
        oss << "Port scan: " << stats.unique_dst_ports
            << " unique ports probed in window "
            << "(threshold: " << m_thresh.portScanUniquePortsMin << ")";
        return RuleMatch{
            "Port Scan",
            oss.str(),
            (stats.unique_dst_ports >= m_thresh.portScanUniquePortsMin * 3)
                ? Severity::ATTACK
                : Severity::SUSPICIOUS};
    }

    // ── Rule 2: SYN Flood ─────────────────────────────────────────────────
    // Very high SYN count with high packet rate
    if (stats.syn_count >= m_thresh.synFloodSynMin &&
        fv.packet_rate >= 50.0)
    {
        std::ostringstream oss;
        oss << "SYN flood: " << stats.syn_count
            << " SYN packets at " << std::fixed << std::setprecision(1)
            << fv.packet_rate << " pkt/s"
            << " (SYN threshold: " << m_thresh.synFloodSynMin << ")";
        return RuleMatch{
            "SYN Flood",
            oss.str(),
            Severity::ATTACK};
    }

    // ── Rule 3: DoS (volumetric) ──────────────────────────────────────────
    if (fv.packet_rate >= m_thresh.dosPacketRateMin)
    {
        std::ostringstream oss;
        oss << "DoS / volumetric flood: " << std::fixed
            << std::setprecision(1) << fv.packet_rate
            << " pkt/s (threshold: " << m_thresh.dosPacketRateMin << ")";
        return RuleMatch{
            "DoS Attack",
            oss.str(),
            Severity::ATTACK};
    }

    // ── Rule 4: Adaptive — suspicious burst above baseline ────────────────
    if (m_baselinePacketRate > 0.0 &&
        fv.packet_rate >= m_baselinePacketRate * m_thresh.adaptiveSuspiciousMultiplier)
    {
        std::ostringstream oss;
        oss << "Traffic spike: " << std::fixed << std::setprecision(1)
            << fv.packet_rate << " pkt/s is "
            << std::setprecision(1)
            << (fv.packet_rate / m_baselinePacketRate)
            << "x above baseline (" << m_baselinePacketRate << " pkt/s)";
        return RuleMatch{
            "Traffic Spike",
            oss.str(),
            Severity::SUSPICIOUS};
    }

    return std::nullopt;
}

void RuleEngine::updateBaseline(double normalPacketRate)
{
    // Exponential moving average
    if (m_baselinePacketRate == 0.0)
        m_baselinePacketRate = normalPacketRate;
    else
        m_baselinePacketRate = 0.9 * m_baselinePacketRate + 0.1 * normalPacketRate;
}