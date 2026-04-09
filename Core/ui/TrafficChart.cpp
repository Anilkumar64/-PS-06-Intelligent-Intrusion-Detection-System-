#include "TrafficChart.h"
#include <QVBoxLayout>
#include <QLabel>
#include <QtCharts/QChart>
#include <QGradient>
#include <QPen>
#include <QColor>

TrafficChart::TrafficChart(QWidget *parent)
    : QWidget(parent)
{
    setMinimumHeight(200);

    // ── Series ────────────────────────────────────────────────────────────
    m_series = new QLineSeries;
    m_zero = new QLineSeries;
    m_area = new QAreaSeries(m_series, m_zero);

    QPen linePen(QColor("#5b9cf6"));
    linePen.setWidth(2);
    m_series->setPen(linePen);

    QLinearGradient gradient(0, 0, 0, 1);
    gradient.setCoordinateMode(QGradient::ObjectMode);
    gradient.setColorAt(0.0, QColor(91, 156, 246, 120));
    gradient.setColorAt(1.0, QColor(91, 156, 246, 10));
    m_area->setBrush(gradient);
    m_area->setPen(Qt::NoPen);

    // Pre-fill with zeros
    for (int i = 0; i < kWindow; ++i)
    {
        m_series->append(i, 0);
        m_zero->append(i, 0);
    }

    // ── Chart ─────────────────────────────────────────────────────────────
    m_chart = new QChart;
    m_chart->addSeries(m_area);
    m_chart->legend()->hide();
    m_chart->setBackgroundBrush(QColor("#1e2030"));
    m_chart->setBackgroundRoundness(0);
    m_chart->setMargins(QMargins(4, 4, 4, 4));
    m_chart->setTitle("");

    // Axes
    m_axisX = new QValueAxis;
    m_axisX->setRange(0, kWindow);
    m_axisX->setTickCount(7);
    m_axisX->setLabelFormat("%d s");
    m_axisX->setLabelsColor(QColor("#585b70"));
    m_axisX->setGridLineColor(QColor("#2a2d3a"));
    m_axisX->setLinePen(QPen(QColor("#2a2d3a")));

    m_axisY = new QValueAxis;
    m_axisY->setRange(0, m_maxY);
    m_axisY->setLabelFormat("%.0f");
    m_axisY->setLabelsColor(QColor("#585b70"));
    m_axisY->setGridLineColor(QColor("#2a2d3a"));
    m_axisY->setLinePen(QPen(QColor("#2a2d3a")));
    m_axisY->setTitleText("pkt/s");
    m_axisY->setTitleBrush(QColor("#585b70"));

    m_chart->addAxis(m_axisX, Qt::AlignBottom);
    m_chart->addAxis(m_axisY, Qt::AlignLeft);
    m_area->attachAxis(m_axisX);
    m_area->attachAxis(m_axisY);

    // ── Chart view ────────────────────────────────────────────────────────
    m_chartView = new QChartView(m_chart, this);
    m_chartView->setRenderHint(QPainter::Antialiasing);
    m_chartView->setFrameShape(QFrame::NoFrame);
    m_chartView->setStyleSheet("background:transparent; border:none;");

    // Header
    QLabel *title = new QLabel("📈  Traffic — Packet Rate (60s window)");
    title->setStyleSheet("color:#8b8fa8; font-size:11px; padding:4px 6px;");

    QVBoxLayout *lay = new QVBoxLayout(this);
    lay->setContentsMargins(0, 0, 0, 0);
    lay->setSpacing(0);
    lay->addWidget(title);
    lay->addWidget(m_chartView);

    setStyleSheet("background:#1e2030; border:1px solid #2a2d3a; border-radius:6px;");
}

void TrafficChart::onStatsUpdated(const SystemStats &stats)
{
    double rate = stats.packets_per_sec;

    // Shift all points left by 1
    auto pts = m_series->points();
    for (int i = 0; i < pts.size(); ++i)
        m_series->replace(i, i, (i + 1 < pts.size()) ? pts[i + 1].y() : rate);

    auto zpts = m_zero->points();
    for (int i = 0; i < zpts.size(); ++i)
        m_zero->replace(i, i, 0);

    // Append new value at rightmost position
    m_series->replace(kWindow - 1, kWindow - 1, rate);

    // Auto-scale Y axis
    if (rate > m_maxY * 0.9)
    {
        m_maxY = rate * 1.5;
        m_axisY->setMax(m_maxY);
    }
    else if (rate < m_maxY * 0.3 && m_maxY > 100)
    {
        m_maxY = qMax(100.0, rate * 2.0);
        m_axisY->setMax(m_maxY);
    }

    ++m_tick;
}