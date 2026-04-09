#pragma once
#include <QObject>
#include <optional>
#include "Types.h"

struct RuleThresholds
{
    // Port scan: unique dst ports seen from this src_ip across all flows
    uint32_t portScanUniquePortsMin{15};

    // SYN flood: ratio threshold (0.0-1.0) AND minimum packet rate
    // Normal browsing: ratio ~0.05  |  SYN flood: ratio ~0.9+
    double synFloodRatioMin{0.85}; // 70%+ of packets are pure SYNs
    double synFloodRateMin{50.0};  // at least 20 pkt/s (avoid 1-pkt false positives)

    // DoS: volumetric — high packet rate regardless of type
    double dosPacketRateMin{500.0};

    // Adaptive baseline: spike multiplier
    double adaptiveSuspiciousMultiplier{5.0};
};

struct RuleMatch
{
    std::string type;
    std::string reason;
    Severity severity;
};

class RuleEngine : public QObject
{
    Q_OBJECT

public:
    explicit RuleEngine(QObject *parent = nullptr);

    std::optional<RuleMatch> evaluate(const FlowStats &stats,
                                      const FeatureVector &fv);

    void setThresholds(const RuleThresholds &t) { m_thresh = t; }
    const RuleThresholds &thresholds() const { return m_thresh; }

    void updateBaseline(double normalPacketRate);

private:
    RuleThresholds m_thresh;
    double m_baselinePacketRate{0.0};
};
