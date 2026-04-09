#include "TrafficPanel.h"
#include <QGridLayout>
#include <cmath>

// ── StatTile ──────────────────────────────────────────────────────────────────

StatTile::StatTile(const QString &label, const QString &unit,
                   const QString &accentColor, QWidget *parent)
    : QFrame(parent)
{
    setFrameShape(QFrame::NoFrame);
    setStyleSheet(QString(R"(
        StatTile {
            background: #0d1117;
            border: 1px solid %1;
            border-radius: 8px;
        }
    )")
                      .arg(accentColor));

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(18, 14, 18, 14);
    root->setSpacing(4);

    auto *topLabel = new QLabel(label, this);
    topLabel->setStyleSheet("color: #8b949e; font: 11px 'JetBrains Mono', monospace; letter-spacing: 1px;");

    m_valueLabel = new QLabel("—", this);
    m_valueLabel->setStyleSheet(QString("color: %1; font: bold 28px 'JetBrains Mono', monospace;")
                                    .arg(accentColor));

    m_subLabel = new QLabel(unit, this);
    m_subLabel->setStyleSheet("color: #484f58; font: 10px 'JetBrains Mono', monospace;");

    root->addWidget(topLabel);
    root->addWidget(m_valueLabel);
    root->addWidget(m_subLabel);
}

void StatTile::setValue(const QString &v) { m_valueLabel->setText(v); }
void StatTile::setSubValue(const QString &v) { m_subLabel->setText(v); }

// ── TrafficPanel ──────────────────────────────────────────────────────────────

TrafficPanel::TrafficPanel(QWidget *parent) : QWidget(parent)
{
    setStyleSheet("background: transparent;");

    auto *grid = new QGridLayout(this);
    grid->setSpacing(10);
    grid->setContentsMargins(0, 0, 0, 0);

    m_pktRate = new StatTile("PACKETS / SEC", "pkt/s", "#58a6ff", this);
    m_activeFlows = new StatTile("ACTIVE FLOWS", "flows", "#3fb950", this);
    m_totalPkts = new StatTile("TOTAL PACKETS", "captured", "#d2a8ff", this);
    m_alerts = new StatTile("TOTAL ALERTS", "detected", "#f85149", this);
    m_latency = new StatTile("DETECT LATENCY", "avg / p99", "#ffa657", this);
    m_cpu = new StatTile("CPU USAGE", "process", "#79c0ff", this);

    grid->addWidget(m_pktRate, 0, 0);
    grid->addWidget(m_activeFlows, 0, 1);
    grid->addWidget(m_totalPkts, 0, 2);
    grid->addWidget(m_alerts, 1, 0);
    grid->addWidget(m_latency, 1, 1);
    grid->addWidget(m_cpu, 1, 2);
}

static QString fmtLarge(uint64_t v)
{
    if (v < 1000)
        return QString::number(v);
    if (v < 1000000)
        return QString("%1K").arg(v / 1000.0, 0, 'f', 1);
    return QString("%1M").arg(v / 1000000.0, 0, 'f', 2);
}

void TrafficPanel::onStatsUpdated(const SystemStats &s)
{
    m_pktRate->setValue(QString::number(static_cast<int>(s.packets_per_sec)));
    m_pktRate->setSubValue(QString("%1 KB/s")
                               .arg(s.bytes_per_sec / 1024.0, 0, 'f', 1));

    m_activeFlows->setValue(QString::number(s.active_flows));

    m_totalPkts->setValue(fmtLarge(s.total_packets));
    m_totalPkts->setSubValue(QString("dropped: %1").arg(s.dropped_packets));

    m_alerts->setValue(fmtLarge(s.total_alerts));
    m_alerts->setSubValue(QString("attack: %1  suspicious: %2")
                              .arg(s.alerts_attack)
                              .arg(s.alerts_suspicious));

    m_latency->setValue(QString("%1 µs")
                            .arg(s.latency_avg_ns / 1000.0, 0, 'f', 1));
    m_latency->setSubValue(QString("p99: %1 µs")
                               .arg(s.latency_p99_ns / 1000.0, 0, 'f', 1));

    m_cpu->setValue(QString("%1%").arg(s.cpu_percent, 0, 'f', 1));
    m_cpu->setSubValue(QString("%1 MB RSS").arg(s.mem_mb, 0, 'f', 0));
}