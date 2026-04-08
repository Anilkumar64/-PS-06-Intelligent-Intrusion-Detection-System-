#include "DecisionEngine.h"
#include <QDebug>

DecisionEngine::DecisionEngine(QObject *parent) : QObject(parent) {}

void DecisionEngine::onFeaturesReady(const FlowStats &stats,
                                     const FeatureVector &fv)
{
    auto rule = m_rules.evaluate(stats, fv);
    double anomaly = m_ml.score(fv);
    auto result = decide(stats, fv, rule, anomaly);

    // Rate-limit NORMAL emissions (only emit SUSPICIOUS/ATTACK immediately)
    auto now = std::chrono::steady_clock::now();
    if (result.severity == Severity::NORMAL)
    {
        auto &last = m_lastEmit[stats.key.src_ip];
        if (now - last < std::chrono::milliseconds(500))
            return;
        last = now;
        emit normalFlowSeen(fv.packet_rate);
    }

    emit detectionResult(result);

    // Feed normal traffic into baseline
    if (result.severity == Severity::NORMAL)
        m_rules.updateBaseline(fv.packet_rate);
}

DetectionResult DecisionEngine::decide(const FlowStats &stats,
                                       const FeatureVector &fv,
                                       const std::optional<RuleMatch> &rule,
                                       double anomalyScore)
{
    DetectionResult result;
    result.src_ip = stats.key.src_ip;
    result.src_ip_str = ipToString(stats.key.src_ip);
    result.anomaly_score = anomalyScore;
    result.timestamp = stats.last_seen;

    bool mlFlag = (anomalyScore > 0.5);
    bool ruleFlag = rule.has_value();

    result.rule_triggered = ruleFlag;
    result.ml_triggered = mlFlag;

    if (ruleFlag)
    {
        // Rule takes precedence — it's explicit and explainable
        result.severity = rule->severity;
        result.attack_type = rule->type;
        result.reason = rule->reason;
        if (mlFlag)
            result.reason += " | AI also flagged (score=" +
                             std::to_string(anomalyScore).substr(0, 4) + ")";
    }
    else if (mlFlag)
    {
        // Only AI flagged — lower confidence, mark as suspicious
        result.severity = Severity::SUSPICIOUS;
        result.attack_type = "Anomaly";
        result.reason = "ML anomaly detection score=" +
                        std::to_string(anomalyScore).substr(0, 4) +
                        " | pkt_rate=" +
                        std::to_string(static_cast<int>(fv.packet_rate)) +
                        " ports=" + std::to_string(static_cast<int>(fv.unique_ports));
    }
    else
    {
        result.severity = Severity::NORMAL;
        result.attack_type = "";
        result.reason = "";
    }

    return result;
}