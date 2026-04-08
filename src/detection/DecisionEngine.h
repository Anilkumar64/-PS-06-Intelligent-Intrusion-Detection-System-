#pragma once
#include <QObject>
#include "Types.h"
#include "RuleEngine.h"
#include "../ml/MLBridge.h"

class DecisionEngine : public QObject
{
    Q_OBJECT

public:
    explicit DecisionEngine(QObject *parent = nullptr);

public slots:
    void onFeaturesReady(const FlowStats &stats, const FeatureVector &fv);

signals:
    void detectionResult(const DetectionResult &result);
    void normalFlowSeen(double packetRate); // for baseline adaptation

private:
    DetectionResult decide(const FlowStats &stats,
                           const FeatureVector &fv,
                           const std::optional<RuleMatch> &rule,
                           double anomalyScore);

    RuleEngine m_rules;
    MLBridge m_ml;

    // Only emit results for significant events + once per second per IP
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> m_lastEmit;
};