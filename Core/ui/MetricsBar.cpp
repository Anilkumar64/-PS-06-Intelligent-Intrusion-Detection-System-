#include "MetricsBar.h"
#include <QHBoxLayout>
#include <QFrame>

// ─── Separator helper ─────────────────────────────────────────────────────────
static QFrame *makeSep()
{
    auto *f = new QFrame;
    f->setFrameShape(QFrame::VLine);
    f->setFixedHeight(18);
    f->setStyleSheet("color:#2a2d3a;");
    return f;
}

// ─── Constructor ──────────────────────────────────────────────────────────────
MetricsBar::MetricsBar(QWidget *parent) : QWidget(parent)
{
    setFixedHeight(36);
    setStyleSheet(
        "MetricsBar {"
        "  background:#1a1d27;"
        "  border-top:1px solid #2a2d3a;"
        "}");

    m_pktRate = makeLabel("pkt/s: —");
    m_flows = makeLabel("flows: —");
    m_latency = makeLabel("latency: —");
    m_cpu = makeLabel("CPU: —");
    m_mlStatus = makeLabel("ML: —");
    m_totalAlerts = makeLabel("alerts: 0");
    m_dropped = makeLabel("dropped: 0");

    auto *lay = new QHBoxLayout(this);
    lay->setContentsMargins(10, 0, 10, 0);
    lay->setSpacing(0);

    lay->addWidget(m_pktRate);
    lay->addWidget(makeSep());
    lay->addWidget(m_flows);
    lay->addWidget(makeSep());
    lay->addWidget(m_latency);
    lay->addWidget(makeSep());
    lay->addWidget(m_cpu);
    lay->addWidget(makeSep());
    lay->addWidget(m_mlStatus);
    lay->addWidget(makeSep());
    lay->addWidget(m_totalAlerts);
    lay->addStretch();
    lay->addWidget(makeSep());
    lay->addWidget(m_dropped);
}

// ─── makeLabel ────────────────────────────────────────────────────────────────
QLabel *MetricsBar::makeLabel(const QString &text)
{
    auto *l = new QLabel(text);
    l->setStyleSheet(
        "QLabel { color:#8b8fa8; font-size:11px; padding:0 10px; }");
    l->setTextFormat(Qt::RichText);
    return l;
}

// ─── onStatsUpdated ───────────────────────────────────────────────────────────
void MetricsBar::onStatsUpdated(const SystemStats &stats)
{
    // Packet rate
    m_pktRate->setText(
        QString("pkt/s: <b style='color:#cdd6f4;'>%1</b>")
            .arg(stats.packets_per_sec, 0, 'f', 1));

    // Active flows
    m_flows->setText(
        QString("flows: <b style='color:#cdd6f4;'>%1</b>")
            .arg(stats.active_flows));

    // Detection latency — colour by severity
    double latUs = stats.latency_avg_ns / 1000.0;
    QString latColor =
        latUs < 10.0 ? "#a6e3a1" : // green  — excellent
            latUs < 100.0 ? "#fab387"
                          : // orange — acceptable
            "#f38ba8";      // red    — high
    m_latency->setText(
        QString("latency: <b style='color:%1;'>%2 µs</b>")
            .arg(latColor)
            .arg(latUs, 0, 'f', 1));

    // CPU usage
    QString cpuColor =
        stats.cpu_percent < 50.0 ? "#a6e3a1" : stats.cpu_percent < 80.0 ? "#fab387"
                                                                        : "#f38ba8";
    m_cpu->setText(
        QString("CPU: <b style='color:%1;'>%2%</b>")
            .arg(cpuColor)
            .arg(stats.cpu_percent, 0, 'f', 1));

    // ML status
    m_mlStatus->setText(
        stats.ml_ready
            ? "ML: <b style='color:#a6e3a1;'>READY</b>"
            : "ML: <b style='color:#f38ba8;'>OFFLINE</b>");

    // Total alerts
    QString alertColor = stats.total_alerts > 0 ? "#f38ba8" : "#cdd6f4";
    m_totalAlerts->setText(
        QString("alerts: <b style='color:%1;'>%2</b>")
            .arg(alertColor)
            .arg(stats.total_alerts));

    // Dropped packets
    QString dropColor = stats.dropped_packets > 0 ? "#fab387" : "#585b70";
    m_dropped->setText(
        QString("dropped: <b style='color:%1;'>%2</b>")
            .arg(dropColor)
            .arg(stats.dropped_packets));
}