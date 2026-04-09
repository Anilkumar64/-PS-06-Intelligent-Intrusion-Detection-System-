#pragma once
#include <QObject>
#include "Types.h"

class FeatureExtractor : public QObject
{
    Q_OBJECT

public:
    explicit FeatureExtractor(QObject *parent = nullptr);

public slots:
    void onFlowUpdated(const FlowStats &stats);

signals:
    // Emits both the raw stats and computed feature vector together
    void featuresReady(const FlowStats &stats, const FeatureVector &features);

private:
    FeatureVector extract(const FlowStats &stats);
};