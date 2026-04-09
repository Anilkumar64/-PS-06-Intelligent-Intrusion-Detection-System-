#pragma once
#include <QWidget>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <deque>

/**
 * LogsViewer — structured log browser with level filter and text search.
 *
 *  ┌─[Filter: __________] [Level: ALL ▼]──────────────────┐
 *  │ [TIMESTAMP] [LEVEL]  message text                     │
 *  │  ...                                                  │
 *  └───────────────────────────────────────────────────────┘
 */
class LogsViewer : public QWidget
{
    Q_OBJECT

public:
    explicit LogsViewer(QWidget *parent = nullptr);

    // Append a new log entry. Level: INFO, WARN, ERROR, ATTACK, DEBUG
    void appendLog(const QString &msg, const QString &level = "INFO");

    void clear();

private slots:
    void onFilterChanged();

private:
    void rebuildView();
    QString colorForLevel(const QString &level) const;
    QString formatEntry(const QString &ts, const QString &level,
                        const QString &msg) const;

    struct LogEntry
    {
        QString timestamp;
        QString level;
        QString message;
    };

    QPlainTextEdit *m_view{nullptr};
    QLineEdit *m_filterEdit{nullptr};
    QComboBox *m_levelCombo{nullptr};
    QLabel *m_countLabel{nullptr};

    std::deque<LogEntry> m_entries;
    static constexpr int kMaxEntries{2000};
};