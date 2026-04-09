#include "LogsViewer.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDateTime>
#include <QScrollBar>

LogsViewer::LogsViewer(QWidget *parent) : QWidget(parent)
{
    setStyleSheet("background:#1e2030; border:1px solid #2a2d3a; border-radius:6px;");

    // ── Header ────────────────────────────────────────────────────────────
    QLabel *title = new QLabel("📋  System Logs");
    title->setStyleSheet("color:#8b8fa8; font-size:11px; padding:4px 6px;");

    m_filterEdit = new QLineEdit;
    m_filterEdit->setPlaceholderText("Search logs...");
    m_filterEdit->setStyleSheet(
        "QLineEdit { background:#252836; border:1px solid #3a3d4d; color:#cdd6f4;"
        " border-radius:4px; padding:3px 8px; font-size:11px; }");
    m_filterEdit->setFixedHeight(26);

    m_levelCombo = new QComboBox;
    m_levelCombo->addItems({"ALL", "DEBUG", "INFO", "WARN", "ERROR", "ATTACK"});
    m_levelCombo->setStyleSheet(
        "QComboBox { background:#252836; border:1px solid #3a3d4d; color:#cdd6f4;"
        " border-radius:4px; padding:2px 6px; font-size:11px; }"
        "QComboBox::drop-down { border:none; }"
        "QComboBox QAbstractItemView { background:#252836; color:#cdd6f4; }");
    m_levelCombo->setFixedWidth(90);

    m_countLabel = new QLabel("0 entries");
    m_countLabel->setStyleSheet("color:#585b70; font-size:10px;");

    QHBoxLayout *hdr = new QHBoxLayout;
    hdr->setContentsMargins(6, 4, 6, 4);
    hdr->addWidget(title);
    hdr->addStretch();
    hdr->addWidget(m_filterEdit);
    hdr->addWidget(m_levelCombo);
    hdr->addWidget(m_countLabel);

    // ── Log view ──────────────────────────────────────────────────────────
    m_view = new QPlainTextEdit;
    m_view->setReadOnly(true);
    m_view->setMaximumBlockCount(kMaxEntries);
    m_view->setStyleSheet(
        "QPlainTextEdit { background:#11131f; color:#cdd6f4;"
        " border:none; font-family:'Fira Code','Consolas','Courier New',monospace;"
        " font-size:11px; }"
        "QScrollBar:vertical { background:#1e2030; width:6px; }"
        "QScrollBar::handle:vertical { background:#3a3d4d; border-radius:3px; }");

    // ── Layout ────────────────────────────────────────────────────────────
    QVBoxLayout *lay = new QVBoxLayout(this);
    lay->setContentsMargins(0, 0, 0, 0);
    lay->setSpacing(0);
    lay->addLayout(hdr);
    lay->addWidget(m_view);

    connect(m_filterEdit, &QLineEdit::textChanged, this, &LogsViewer::onFilterChanged);
    connect(m_levelCombo, &QComboBox::currentTextChanged, this, &LogsViewer::onFilterChanged);
}

void LogsViewer::appendLog(const QString &msg, const QString &level)
{
    LogEntry e;
    e.timestamp = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
    e.level = level.toUpper();
    e.message = msg;

    m_entries.push_back(e);
    if (static_cast<int>(m_entries.size()) > kMaxEntries)
        m_entries.pop_front();

    // Apply current filter inline (avoid full rebuild on every entry)
    QString filterText = m_filterEdit->text().toLower();
    QString filterLevel = m_levelCombo->currentText();

    bool levelMatch = (filterLevel == "ALL") || (e.level == filterLevel);
    bool textMatch = filterText.isEmpty() ||
                     msg.toLower().contains(filterText) ||
                     e.level.toLower().contains(filterText);

    if (levelMatch && textMatch)
    {
        QString html = formatEntry(e.timestamp, e.level, e.message);
        m_view->appendHtml(html);

        // Auto-scroll to bottom
        QScrollBar *sb = m_view->verticalScrollBar();
        sb->setValue(sb->maximum());
    }

    m_countLabel->setText(QString("%1 entries").arg(m_entries.size()));
}

void LogsViewer::clear()
{
    m_entries.clear();
    m_view->clear();
    m_countLabel->setText("0 entries");
}

void LogsViewer::onFilterChanged()
{
    rebuildView();
}

void LogsViewer::rebuildView()
{
    m_view->clear();
    QString filterText = m_filterEdit->text().toLower();
    QString filterLevel = m_levelCombo->currentText();
    int shown = 0;

    for (const auto &e : m_entries)
    {
        bool levelMatch = (filterLevel == "ALL") || (e.level == filterLevel);
        bool textMatch = filterText.isEmpty() ||
                         e.message.toLower().contains(filterText) ||
                         e.level.toLower().contains(filterText);
        if (levelMatch && textMatch)
        {
            m_view->appendHtml(formatEntry(e.timestamp, e.level, e.message));
            ++shown;
        }
    }
    m_countLabel->setText(QString("%1 / %2 entries").arg(shown).arg(m_entries.size()));
}

QString LogsViewer::colorForLevel(const QString &level) const
{
    if (level == "ATTACK")
        return "#f38ba8";
    if (level == "ERROR")
        return "#f38ba8";
    if (level == "WARN")
        return "#fab387";
    if (level == "INFO")
        return "#a6e3a1";
    if (level == "DEBUG")
        return "#585b70";
    return "#cdd6f4";
}

QString LogsViewer::formatEntry(const QString &ts, const QString &level,
                                const QString &msg) const
{
    QString col = colorForLevel(level);
    QString lpad = level.leftJustified(6);
    return QString(
               "<span style='color:#585b70;'>%1</span> "
               "<span style='color:%2; font-weight:600;'>[%3]</span> "
               "<span style='color:#cdd6f4;'>%4</span>")
        .arg(ts.toHtmlEscaped())
        .arg(col)
        .arg(lpad.toHtmlEscaped())
        .arg(msg.toHtmlEscaped());
}