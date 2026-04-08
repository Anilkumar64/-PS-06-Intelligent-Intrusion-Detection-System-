#pragma once
#include <QObject>
#include <optional>
#include "Types.h"

// Configurable thresholds
struct RuleThresholds
{
    // Port scan: many unique destination ports in window
    uint32_t portScanUniquePortsMin{15};

    // SYN flood: high SYN count, low ACK ratio
    uint32_t synFloodSynMin{50};

    // DoS: extremely high packet rate
    double dosPacketRateMin{500.0}; // pkts/sec

    // Adaptive baseline: multiplier above normal to flag suspicious
    double adaptiveSuspiciousMultiplier{3.0};
};

struct RuleMatch
{
    std::string type;   // "Port Scan", "SYN Flood", "DoS"
    std::string reason; // Explanation with numeric details
    Severity severity;
};

class RuleEngine : public QObject
{
    Q_OBJECT

public:
    explicit RuleEngine(QObject *parent = nullptr);

    // Returns a match if any rule fires, else nullopt
    std::optional<RuleMatch> evaluate(const FlowStats &stats,
                                      const FeatureVector &fv);

    // Update thresholds at runtime
    void setThresholds(const RuleThresholds &t) { m_thresh = t; }
    const RuleThresholds &thresholds() const { return m_thresh; }

    // Adaptive baseline update (call periodically with "normal" traffic stats)
    void updateBaseline(double normalPacketRate);

private:
    RuleThresholds m_thresh;
    double m_baselinePacketRate{0.0};
};