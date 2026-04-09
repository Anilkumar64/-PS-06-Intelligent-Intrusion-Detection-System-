#pragma once
#include <QMainWindow>
#include <QLabel>
#include <QComboBox>
#include <QPushButton>
#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QToolBar>
#include <QStatusBar>
#include <QTimer>
#include <QSystemTrayIcon>

#include "TrafficPanel.h"
#include "TrafficChart.h"
#include "AlertsPanel.h"
#include "SuspiciousIPTable.h"
#include "LogsViewer.h"
#include "MetricsBar.h"
#include "UIBridge.h"
#include "../pipeline/ProcessingPipeline.h"

/**
 * MainWindow — top-level Qt6 IDS dashboard.
 *
 * Layout (QGridLayout inside central widget):
 *
 *   ┌─────────────────────────────────────────────────┐
 *   │  QToolBar: [iface selector] [▶ Start] [status]  │
 *   ├─────────────────────────────────────────────────┤
 *   │  TrafficPanel (stat tiles)          │ Alerts     │
 *   ├────────────────────────┬────────────┤ Panel      │
 *   │  TrafficChart          │ Suspicious │ (scroll)   │
 *   │  (60s rolling graph)   │ IP Table   │            │
 *   ├────────────────────────┴────────────┤            │
 *   │  LogsViewer (filter + log stream)   │            │
 *   ├─────────────────────────────────────────────────┤
 *   │  MetricsBar: pkt/s | latency | CPU | ML status  │
 *   └─────────────────────────────────────────────────┘
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartStop();
    void onInterfaceChanged(const QString &iface);
    void onDetectionResult(const DetectionResult &result);
    void onStatsUpdated(const SystemStats &stats);
    void onPipelineError(const QString &msg);
    void onPipelineStarted(const QString &iface, bool kernelModule);
    void onPulseTick();

private:
    void setupToolBar();
    void setupCentralWidget();
    void setupStatusBar();
    void setupConnections();
    void applyDarkTheme();
    void addLog(const QString &msg, const QString &level = "INFO");
    void showTrayNotification(const DetectionResult &result);

    // ── Pipeline ─────────────────────────────────────────────────────────
    ProcessingPipeline *m_pipeline{nullptr};
    UIBridge *m_bridge{nullptr};

    // ── Toolbar widgets ──────────────────────────────────────────────────
    QComboBox *m_ifaceCombo{nullptr};
    QPushButton *m_startBtn{nullptr};
    QLabel *m_liveIndicator{nullptr};
    QLabel *m_uptimeLabel{nullptr};

    // ── Panels ───────────────────────────────────────────────────────────
    TrafficPanel *m_trafficPanel{nullptr};
    TrafficChart *m_trafficChart{nullptr};
    AlertsPanel *m_alertsPanel{nullptr};
    SuspiciousIPTable *m_ipTable{nullptr};
    LogsViewer *m_logsViewer{nullptr};
    MetricsBar *m_metricsBar{nullptr};

    // ── State ────────────────────────────────────────────────────────────
    bool m_running{false};
    QTimer *m_pulseTimer{nullptr};
    QTimer *m_uptimeTimer{nullptr};
    int m_uptimeSeconds{0};
    int m_alertCount{0};

    QSystemTrayIcon *m_tray{nullptr};
};