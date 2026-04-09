#pragma once
#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include "../metrics/SystemStats.h"

/**
 * TrafficPanel — live stat tiles: pkt/s, active flows, total pkts, alerts.
 */
class StatTile : public QFrame
{
    Q_OBJECT
public:
    explicit StatTile(const QString &label, const QString &unit,
                      const QString &accentColor, QWidget *parent = nullptr);
    void setValue(const QString &v);
    void setSubValue(const QString &v);

private:
    QLabel *m_valueLabel{nullptr};
    QLabel *m_subLabel{nullptr};
};

class TrafficPanel : public QWidget
{
    Q_OBJECT
public:
    explicit TrafficPanel(QWidget *parent = nullptr);

public slots:
    void onStatsUpdated(const SystemStats &stats);

private:
    StatTile *m_pktRate{nullptr};
    StatTile *m_activeFlows{nullptr};
    StatTile *m_totalPkts{nullptr};
    StatTile *m_alerts{nullptr};
    StatTile *m_latency{nullptr};
    StatTile *m_cpu{nullptr};
};