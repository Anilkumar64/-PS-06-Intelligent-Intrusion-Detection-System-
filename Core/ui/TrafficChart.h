#pragma once
#include <QWidget>
#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QtCharts/QAreaSeries>
#include <QtCharts/QValueAxis>
#include "../metrics/SystemStats.h"

QT_USE_NAMESPACE

/**
 * TrafficChart — 60-second rolling pkt/s graph with alert spike markers.
 */
class TrafficChart : public QWidget
{
    Q_OBJECT
public:
    explicit TrafficChart(QWidget *parent = nullptr);

public slots:
    void onStatsUpdated(const SystemStats &stats);

private:
    QChartView *m_chartView{nullptr};
    QChart *m_chart{nullptr};
    QLineSeries *m_series{nullptr};
    QAreaSeries *m_area{nullptr};
    QLineSeries *m_zero{nullptr}; // baseline for area fill
    QValueAxis *m_axisX{nullptr};
    QValueAxis *m_axisY{nullptr};

    int m_tick{0};
    double m_maxY{100.0};
    static constexpr int kWindow{60}; // seconds shown
};