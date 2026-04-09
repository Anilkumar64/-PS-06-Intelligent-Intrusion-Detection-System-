#pragma once
#include <QWidget>
#include <QLabel>
#include "../metrics/SystemStats.h"

/**
 * MetricsBar — thin bottom strip showing real-time performance metrics.
 *
 *  [ pkt/s: 1024 ]  [ flows: 42 ]  [ latency: 0.8µs ]  [ CPU: 3.2% ]  [ ML: READY ]  [ dropped: 0 ]
 */
class MetricsBar : public QWidget
{
    Q_OBJECT

public:
    explicit MetricsBar(QWidget *parent = nullptr);

public slots:
    void onStatsUpdated(const SystemStats &stats);

private:
    QLabel *makeLabel(const QString &text);

    QLabel *m_pktRate{nullptr};
    QLabel *m_flows{nullptr};
    QLabel *m_latency{nullptr};
    QLabel *m_cpu{nullptr};
    QLabel *m_mlStatus{nullptr};
    QLabel *m_dropped{nullptr};
    QLabel *m_totalAlerts{nullptr};
};