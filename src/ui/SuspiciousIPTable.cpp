#include "SuspiciousIPTable.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QDateTime>
#include <QColor>

static const QStringList kHeaders{
    "Source IP", "Total Hits", "Attacks", "Last Type", "Anomaly Score", "Status"};

SuspiciousIPTable::SuspiciousIPTable(QWidget *parent) : QWidget(parent)
{
    setStyleSheet("background: transparent;");

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(8);

    // ── Header bar ────────────────────────────────────────────────────────────
    auto *hdr = new QHBoxLayout;
    auto *title = new QLabel("FLAGGED HOSTS", this);
    title->setStyleSheet("color: #ffa657; font: bold 13px 'JetBrains Mono', monospace; letter-spacing: 2px;");

    m_countLabel = new QLabel("0 hosts tracked", this);
    m_countLabel->setStyleSheet("color: #8b949e; font: 11px 'JetBrains Mono', monospace;");

    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText("search IP…");
    m_filter->setFixedWidth(160);
    m_filter->setStyleSheet(R"(
        QLineEdit {
            background: #161b22; border: 1px solid #30363d;
            border-radius: 4px; color: #c9d1d9;
            font: 11px 'JetBrains Mono', monospace; padding: 4px 8px;
        }
        QLineEdit:focus { border-color: #ffa657; }
    )");

    hdr->addWidget(title);
    hdr->addWidget(m_countLabel);
    hdr->addStretch();
    hdr->addWidget(m_filter);
    root->addLayout(hdr);

    // ── Table ─────────────────────────────────────────────────────────────────
    m_model = new QStandardItemModel(0, kHeaders.size(), this);
    m_model->setHorizontalHeaderLabels(kHeaders);

    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(0); // filter on IP column

    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    m_table->setSortingEnabled(true);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_table->verticalHeader()->setVisible(false);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(false);
    m_table->setStyleSheet(R"(
        QTableView {
            background: #0d1117;
            border: 1px solid #21262d;
            border-radius: 6px;
            color: #c9d1d9;
            font: 11px 'JetBrains Mono', monospace;
            gridline-color: #161b22;
        }
        QHeaderView::section {
            background: #161b22;
            color: #8b949e;
            border: none;
            border-bottom: 1px solid #30363d;
            padding: 6px 8px;
            font: bold 10px 'JetBrains Mono', monospace;
            letter-spacing: 1px;
        }
        QTableView::item:selected { background: #1f2937; }
        QScrollBar:vertical { background: #0d1117; width: 8px; }
        QScrollBar::handle:vertical { background: #30363d; border-radius: 4px; }
    )");
    root->addWidget(m_table);

    connect(m_filter, &QLineEdit::textChanged,
            this, &SuspiciousIPTable::onFilterChanged);
}

void SuspiciousIPTable::onDetectionResult(const DetectionResult &r)
{
    if (r.severity == Severity::NORMAL)
        return;
    updateRow(r.src_ip, r);
}

void SuspiciousIPTable::updateRow(uint32_t ip, const DetectionResult &r)
{
    auto it = m_records.find(ip);

    if (it == m_records.end())
    {
        // New IP — append row
        int row = m_model->rowCount();
        m_model->insertRow(row);

        IPRecord rec;
        rec.row = row;
        m_records[ip] = rec;
        it = m_records.find(ip);

        m_model->setItem(row, 0, new QStandardItem(QString::fromStdString(r.src_ip_str)));
        m_countLabel->setText(QString("%1 hosts tracked").arg(m_records.size()));
    }

    auto &rec = it->second;
    ++rec.hits;
    if (r.severity == Severity::ATTACK)
        ++rec.attackHits;
    rec.maxScore = std::max(rec.maxScore, r.anomaly_score);

    int row = rec.row;
    m_model->item(row, 1)->setText(QString::number(rec.hits));
    m_model->item(row, 2)->setText(QString::number(rec.attackHits));
    m_model->item(row, 3)->setText(QString::fromStdString(r.attack_type));
    m_model->item(row, 4)->setText(QString("%1").arg(rec.maxScore, 0, 'f', 3));

    QString status = (r.severity == Severity::ATTACK)       ? "⬤ ATTACK"
                     : (r.severity == Severity::SUSPICIOUS) ? "◈ SUSPICIOUS"
                                                            : "○ NORMAL";

    auto *statusItem = new QStandardItem(status);
    statusItem->setForeground(
        r.severity == Severity::ATTACK ? QColor("#f85149") : r.severity == Severity::SUSPICIOUS ? QColor("#ffa657")
                                                                                                : QColor("#3fb950"));
    m_model->setItem(row, 5, statusItem);
}

void SuspiciousIPTable::onFilterChanged(const QString &text)
{
    m_proxy->setFilterFixedString(text);
}