#pragma once
#include <QWidget>
#include <QListWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include "../Types.h"

/**
 * AlertsPanel — live scrolling list of detection events.
 * Shows timestamp, severity badge, attack type, source IP, and reason.
 */
class AlertsPanel : public QWidget
{
    Q_OBJECT
public:
    explicit AlertsPanel(QWidget *parent = nullptr);

public slots:
    void onDetectionResult(const DetectionResult &result);

private slots:
    void onFilterChanged(const QString &text);
    void onClearClicked();

private:
    void addAlertRow(const DetectionResult &r);

    QListWidget *m_list{nullptr};
    QLabel *m_countLabel{nullptr};
    QLineEdit *m_filter{nullptr};
    QPushButton *m_clearBtn{nullptr};

    uint64_t m_attackCount{0};
    uint64_t m_suspiciousCount{0};

    static constexpr int kMaxRows{500};
};