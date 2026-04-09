#include "DecisionEngine.h"
#include <QDebug>
#include <fstream>

DecisionEngine::DecisionEngine(QObject *parent)
    : QObject(parent),
      m_cache(512, 2000) // 512 entries, 2-second TTL
{
}

// ── Main entry point (called from FeatureExtractor via signal) ───────────────
void DecisionEngine::onFeaturesReady(const FlowStats &stats,
                                     const FeatureVector &fv)
{
    // 1. Rule-based detection
    auto rule = m_rules.evaluate(stats, fv);

    // 2. ML scoring (with cache)
    MLResult ml;
    auto cached = m_cache.get(fv);
    if (cached.has_value())
    {
        ml = *cached;
    }
    else
    {
        ml = m_ml.score(fv);
        m_cache.put(fv, ml);
    }

    // 3. Fuse results
    auto result = decide(stats, fv, rule, ml);

    // 4. Time now (IMPORTANT: used by both cleanup + rate-limit)
    auto now = std::chrono::steady_clock::now();

    // 🔥 CLEANUP BLOCK — ADD HERE
    if (now - m_lastEmitCleanup > std::chrono::seconds(60))
    {
        auto cutoff = now - std::chrono::seconds(5);

        for (auto it = m_lastEmit.begin(); it != m_lastEmit.end();)
        {
            if (it->second < cutoff)
                it = m_lastEmit.erase(it);
            else
                ++it;
        }

        m_lastEmitCleanup = now;
    }

    // 5. Rate-limit NORMAL emissions
    if (result.severity == Severity::NORMAL)
    {
        auto &last = m_lastEmit[stats.key.src_ip];

        if (now - last < std::chrono::milliseconds(500))
            return;

        last = now;
        emit normalFlowSeen(fv.packet_rate);
    }

    // 6. Emit detection
    emit detectionResult(result);

    // 🔥 ADD THIS FOR EVALUATION LOGGING

    std::string actual = "UNKNOWN";

    // TEMP: set manually based on your test
    // You MUST change this during testing
    // Example:
    actual = "NORMAL";
    // actual = "SYN_FLOOD";
    // actual = "PORT_SCAN";

    std::string pred;

    // Map your result to label
    if (result.severity == Severity::NORMAL)
        pred = "NORMAL";
    else if (result.attack_type.find("SYN") != std::string::npos)
        pred = "SYN_FLOOD";
    else if (result.attack_type.find("Port") != std::string::npos)
        pred = "PORT_SCAN";
    else
        pred = "ATTACK";

    // Write to file
    std::ofstream log("/home/anilreddy/Documents/Projects/IIDS/ml/ml_predictions.log", std::ios::app);
    if (log.is_open())
    {
        log << "ACTUAL=" << actual << " PRED=" << pred << std::endl;
    }

    // 7. Adaptive baseline update
    if (result.severity == Severity::NORMAL)
        m_rules.updateBaseline(fv.packet_rate);
}

// ── Fusion logic ─────────────────────────────────────────────────────────────
DetectionResult DecisionEngine::decide(const FlowStats &stats,
                                       const FeatureVector &fv,
                                       const std::optional<RuleMatch> &rule,
                                       const MLResult &ml)
{
    DetectionResult result;
    result.src_ip = stats.key.src_ip;
    result.src_ip_str = ipToString(stats.key.src_ip);
    result.anomaly_score = ml.score;
    result.timestamp = stats.last_seen;

    // ML flags:
    // mlAnomaly = Isolation Forest says something is wrong (score >= 0.5)
    // mlLabel   = Random Forest identified a specific attack class
    // NOTE: score=1.0 with label=Normal means iForest says anomaly but RF
    //       couldn't classify it — still flag as suspicious, don't ignore it.
    bool mlAnomaly = (ml.score >= 0.5);
    bool mlLabel = (ml.label != "Normal" && ml.label != "Other" &&
                    !ml.label.empty());
    bool mlFlag = mlAnomaly || mlLabel;

    bool ruleFlag = rule.has_value();

    result.rule_triggered = ruleFlag;
    result.ml_triggered = mlFlag;

    // ── Scenario 1: Rule fired ──────────────────────────────────────────────
    if (ruleFlag)
    {
        result.severity = rule->severity;
        result.attack_type = rule->type;
        result.reason = rule->reason;

        // Append ML context if it also flagged something
        if (mlFlag)
        {
            result.reason += " | ML: " + ml.label +
                             " (score=" +
                             std::to_string(ml.score).substr(0, 6) + ")";
        }
        return result;
    }

    // ── Scenario 2: Only ML flagged ─────────────────────────────────────────
    if (mlFlag)
    {
        // If RF gave a specific attack class, elevate to ATTACK
        // If only anomaly score is high, keep as SUSPICIOUS
        if (mlLabel)
        {
            result.severity = Severity::ATTACK;
            result.attack_type = ml.label; // e.g. "PortScan", "DoS", "DDoS"
            result.reason = "ML classifier: " + ml.label +
                            " | anomaly score=" +
                            std::to_string(ml.score).substr(0, 6) +
                            " | pkt_rate=" +
                            std::to_string(static_cast<int>(fv.packet_rate)) +
                            " | ports=" +
                            std::to_string(static_cast<int>(fv.unique_ports)) +
                            " | syn=" +
                            std::to_string(static_cast<int>(fv.syn_count));
        }
        else
        {
            // iForest says anomaly (score >= 0.5) but RF couldn't classify it
            // (label = Normal/Other). Still suspicious — log both signals.
            result.severity = Severity::SUSPICIOUS;
            result.attack_type = "Anomaly";
            result.reason = "iForest score=" +
                            std::to_string(ml.score).substr(0, 6) +
                            " RF=" + ml.label +
                            " | pkt_rate=" +
                            std::to_string(static_cast<int>(fv.packet_rate)) +
                            " | ports=" +
                            std::to_string(static_cast<int>(fv.unique_ports)) +
                            " | syn=" +
                            std::to_string(static_cast<int>(fv.syn_count));
        }
        return result;
    }

    // ── Scenario 3: Nothing flagged ─────────────────────────────────────────
    result.severity = Severity::NORMAL;
    result.attack_type = "";
    result.reason = "";
    return result;
}