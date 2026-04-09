#pragma once
#include <QObject>
#include <unordered_map>
#include <chrono>
#include <optional>
#include "Types.h"
#include "RuleEngine.h"
#include "../ml/MLBridge.h"
#include "../ml/MLResultCache.h"

class DecisionEngine : public QObject
{
    Q_OBJECT

public:
    explicit DecisionEngine(QObject *parent = nullptr);

public slots:
    void onFeaturesReady(const FlowStats &stats, const FeatureVector &fv);

signals:
    void detectionResult(const DetectionResult &result);
    void normalFlowSeen(double packetRate); // feeds RuleEngine baseline

private:
    DetectionResult decide(const FlowStats &stats,
                           const FeatureVector &fv,
                           const std::optional<RuleMatch> &rule,
                           const MLResult &ml);

    RuleEngine m_rules;
    MLBridge m_ml;
    MLResultCache m_cache; // LRU cache — avoids rescoring unchanged flows

    // Rate-limit NORMAL events: max one per 500 ms per source IP
    std::unordered_map<uint32_t,
                       std::chrono::steady_clock::time_point>
        m_lastEmit;
    std::chrono::steady_clock::time_point m_lastEmitCleanup{};
};