#pragma once
#include <QWidget>
#include <QTableView>
#include <QStandardItemModel>
#include <QLabel>
#include <QLineEdit>
#include <QSortFilterProxyModel>
#include <unordered_map>
#include "../Types.h"

/**
 * SuspiciousIPTable — per-IP aggregated threat tracker.
 * One row per unique source IP. Columns: IP, Hits, Last Attack, Score, Status.
 */
class SuspiciousIPTable : public QWidget
{
    Q_OBJECT
public:
    explicit SuspiciousIPTable(QWidget *parent = nullptr);

public slots:
    void onDetectionResult(const DetectionResult &result);

private slots:
    void onFilterChanged(const QString &text);

private:
    struct IPRecord
    {
        int row{-1};
        int hits{0};
        int attackHits{0};
        double maxScore{0.0};
    };

    void updateRow(uint32_t ip, const DetectionResult &r);
    void applyRowStyle(int row, Severity sev);

    QTableView *m_table{nullptr};
    QStandardItemModel *m_model{nullptr};
    QSortFilterProxyModel *m_proxy{nullptr};
    QLabel *m_countLabel{nullptr};
    QLineEdit *m_filter{nullptr};

    std::unordered_map<uint32_t, IPRecord> m_records;
};