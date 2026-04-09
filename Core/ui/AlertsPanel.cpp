#include "AlertsPanel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidgetItem>
#include <QDateTime>
#include <QFont>
#include <QLabel>

AlertsPanel::AlertsPanel(QWidget *parent) : QWidget(parent)
{
    setStyleSheet("background: transparent;");

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(8);

    // ── Header bar ────────────────────────────────────────────────────────────
    auto *header = new QHBoxLayout;
    auto *title = new QLabel("LIVE ALERTS", this);
    title->setStyleSheet("color: #f85149; font: bold 13px 'JetBrains Mono', monospace; letter-spacing: 2px;");

    m_countLabel = new QLabel("0 attack  0 suspicious", this);
    m_countLabel->setStyleSheet("color: #8b949e; font: 11px 'JetBrains Mono', monospace;");

    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText("filter by IP or type…");
    m_filter->setFixedWidth(200);
    m_filter->setStyleSheet(R"(
        QLineEdit {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 4px;
            color: #c9d1d9;
            font: 11px 'JetBrains Mono', monospace;
            padding: 4px 8px;
        }
        QLineEdit:focus { border-color: #58a6ff; }
    )");

    m_clearBtn = new QPushButton("Clear", this);
    m_clearBtn->setFixedWidth(60);
    m_clearBtn->setStyleSheet(R"(
        QPushButton {
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 4px;
            color: #8b949e;
            font: 11px 'JetBrains Mono', monospace;
            padding: 4px;
        }
        QPushButton:hover { border-color: #58a6ff; color: #c9d1d9; }
        QPushButton:pressed { background: #161b22; }
    )");

    header->addWidget(title);
    header->addWidget(m_countLabel);
    header->addStretch();
    header->addWidget(m_filter);
    header->addWidget(m_clearBtn);
    root->addLayout(header);

    // ── Alert list ────────────────────────────────────────────────────────────
    m_list = new QListWidget(this);
    m_list->setStyleSheet(R"(
        QListWidget {
            background: #0d1117;
            border: 1px solid #21262d;
            border-radius: 6px;
            color: #c9d1d9;
            font: 11px 'JetBrains Mono', monospace;
        }
        QListWidget::item {
            padding: 6px 10px;
            border-bottom: 1px solid #161b22;
        }
        QListWidget::item:selected {
            background: #161b22;
            color: #58a6ff;
        }
        QScrollBar:vertical {
            background: #0d1117;
            width: 8px;
        }
        QScrollBar::handle:vertical {
            background: #30363d;
            border-radius: 4px;
        }
    )");
    m_list->setUniformItemSizes(false);
    root->addWidget(m_list);

    connect(m_filter, &QLineEdit::textChanged,
            this, &AlertsPanel::onFilterChanged);
    connect(m_clearBtn, &QPushButton::clicked,
            this, &AlertsPanel::onClearClicked);
}

void AlertsPanel::onDetectionResult(const DetectionResult &r)
{
    if (r.severity == Severity::NORMAL)
        return;
    addAlertRow(r);

    // Trim to max
    while (m_list->count() > kMaxRows)
        delete m_list->takeItem(0);
}

void AlertsPanel::addAlertRow(const DetectionResult &r)
{
    bool isAttack = (r.severity == Severity::ATTACK);
    if (isAttack)
        ++m_attackCount;
    else
        ++m_suspiciousCount;

    m_countLabel->setText(
        QString("%1 attack  %2 suspicious")
            .arg(m_attackCount)
            .arg(m_suspiciousCount));

    QString badge = isAttack ? "◉ ATTACK" : "◈ SUSPICIOUS";
    QString badgeClr = isAttack ? "#f85149" : "#ffa657";
    QString ts = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");

    auto *item = new QListWidgetItem(m_list);
    item->setData(Qt::UserRole, QString("%1 %2 %3")
                                    .arg(r.src_ip_str.c_str())
                                    .arg(r.attack_type.c_str())
                                    .arg(r.reason.c_str()));

    // Rich text via a QLabel delegate would be nicer, but for simplicity
    // we use foreground color + text with icon prefixes
    item->setText(QString("[%1]  %2  %3  |  %4  |  %5")
                      .arg(ts)
                      .arg(badge)
                      .arg(QString::fromStdString(r.src_ip_str).leftJustified(15))
                      .arg(QString::fromStdString(r.attack_type))
                      .arg(QString::fromStdString(r.reason)));
    item->setForeground(QColor(badgeClr));

    m_list->scrollToBottom();

    // Apply filter visibility
    if (!m_filter->text().isEmpty())
        item->setHidden(!item->data(Qt::UserRole).toString().contains(m_filter->text(), Qt::CaseInsensitive));
}

void AlertsPanel::onFilterChanged(const QString &text)
{
    for (int i = 0; i < m_list->count(); ++i)
    {
        auto *it = m_list->item(i);
        it->setHidden(text.isEmpty() ? false : !it->data(Qt::UserRole).toString().contains(text, Qt::CaseInsensitive));
    }
}

void AlertsPanel::onClearClicked()
{
    m_list->clear();
    m_attackCount = m_suspiciousCount = 0;
    m_countLabel->setText("0 attack  0 suspicious");
}