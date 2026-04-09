#include "MainWindow.h"
#include <QApplication>
#include <QGridLayout>
#include <QFrame>
#include <QFont>
#include <QIcon>
#include <QMessageBox>
#include <QDateTime>
#include <QSizePolicy>
#include <QPainter>

// ─── Constructor ──────────────────────────────────────────────────────────────
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("IDS — Intelligent Intrusion Detection System");
    setMinimumSize(1280, 800);
    resize(1440, 900);

    m_pipeline = new ProcessingPipeline(this);
    m_bridge = new UIBridge(this);

    applyDarkTheme();
    setupToolBar();
    setupCentralWidget();
    setupStatusBar();
    setupConnections();

    // Pulse timer — blinks the live indicator dot
    m_pulseTimer = new QTimer(this);
    m_pulseTimer->setInterval(600);
    connect(m_pulseTimer, &QTimer::timeout, this, &MainWindow::onPulseTick);

    // Uptime counter — ticks every second while running
    m_uptimeTimer = new QTimer(this);
    m_uptimeTimer->setInterval(1000);
    connect(m_uptimeTimer, &QTimer::timeout, this, [this]
            {
        ++m_uptimeSeconds;
        int h = m_uptimeSeconds / 3600;
        int m = (m_uptimeSeconds % 3600) / 60;
        int s =  m_uptimeSeconds % 60;
        m_uptimeLabel->setText(
            QString("Uptime  %1:%2:%3")
                .arg(h, 2, 10, QChar('0'))
                .arg(m, 2, 10, QChar('0'))
                .arg(s, 2, 10, QChar('0'))); });

    // System tray icon (graceful if no icon theme)
    m_tray = new QSystemTrayIcon(this);
    m_tray->show();

    addLog("IDS dashboard initialized.", "INFO");
}

// ─── Destructor ───────────────────────────────────────────────────────────────
MainWindow::~MainWindow()
{
    if (m_running)
        m_pipeline->stop();
}

// ─── setupToolBar ─────────────────────────────────────────────────────────────
void MainWindow::setupToolBar()
{
    QToolBar *tb = addToolBar("Main");
    tb->setMovable(false);
    tb->setIconSize({18, 18});
    tb->setFixedHeight(48);
    tb->setStyleSheet(
        "QToolBar {"
        "  background:#1a1d27;"
        "  border-bottom:1px solid #2a2d3a;"
        "  padding:4px 12px;"
        "  spacing:6px;"
        "}");

    // Brand
    auto *brand = new QLabel("🛡  IDS v1.0");
    brand->setStyleSheet(
        "color:#5b9cf6; font-weight:700; font-size:15px; margin-right:20px;");
    tb->addWidget(brand);

    // Interface label
    auto *ifLbl = new QLabel("Interface:");
    ifLbl->setStyleSheet("color:#8b8fa8; margin-right:4px;");
    tb->addWidget(ifLbl);

    // Interface combo
    m_ifaceCombo = new QComboBox;
    m_ifaceCombo->setFixedWidth(160);
    m_ifaceCombo->setStyleSheet(
        "QComboBox {"
        "  background:#252836; border:1px solid #3a3d4d;"
        "  color:#cdd6f4; border-radius:4px; padding:4px 8px;"
        "}"
        "QComboBox::drop-down { border:none; }"
        "QComboBox QAbstractItemView {"
        "  background:#252836; color:#cdd6f4;"
        "}");

    const QStringList ifaces = m_pipeline->availableInterfaces();
    if (ifaces.isEmpty())
        m_ifaceCombo->addItem("(no interfaces)");
    else
        m_ifaceCombo->addItems(ifaces);
    tb->addWidget(m_ifaceCombo);

    tb->addSeparator();

    // Start / Stop button
    m_startBtn = new QPushButton("▶  Start Capture");
    m_startBtn->setFixedSize(150, 32);
    m_startBtn->setStyleSheet(
        "QPushButton {"
        "  background:#26a269; color:#ffffff; border:none;"
        "  border-radius:6px; font-weight:600; font-size:13px;"
        "}"
        "QPushButton:hover  { background:#2ec27e; }"
        "QPushButton:pressed{ background:#1e8752; }");
    tb->addWidget(m_startBtn);

    tb->addSeparator();

    // Live indicator
    m_liveIndicator = new QLabel("⬤  IDLE");
    m_liveIndicator->setStyleSheet(
        "color:#585b70; font-size:12px; font-weight:600;");
    tb->addWidget(m_liveIndicator);

    // Expanding spacer
    auto *spacer = new QWidget;
    spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    tb->addWidget(spacer);

    // Uptime label
    m_uptimeLabel = new QLabel("Uptime  00:00:00");
    m_uptimeLabel->setStyleSheet(
        "color:#585b70; font-size:12px; margin-right:8px;");
    tb->addWidget(m_uptimeLabel);
}

// ─── setupCentralWidget ───────────────────────────────────────────────────────
void MainWindow::setupCentralWidget()
{
    auto *central = new QWidget(this);
    central->setStyleSheet("background:#11131f;");
    setCentralWidget(central);

    auto *grid = new QGridLayout(central);
    grid->setContentsMargins(8, 8, 8, 4);
    grid->setSpacing(6);

    // Row 0 — stat tiles, full width
    m_trafficPanel = new TrafficPanel;
    grid->addWidget(m_trafficPanel, 0, 0, 1, 3);

    // Row 1, cols 0-1 — rolling chart
    m_trafficChart = new TrafficChart;
    m_trafficChart->setMinimumHeight(220);
    grid->addWidget(m_trafficChart, 1, 0, 1, 2);

    // Rows 1-2, col 2 — alerts panel (right column, tall)
    m_alertsPanel = new AlertsPanel;
    m_alertsPanel->setMinimumWidth(320);
    grid->addWidget(m_alertsPanel, 1, 2, 2, 1);

    // Row 2, col 0 — suspicious IP table
    m_ipTable = new SuspiciousIPTable;
    grid->addWidget(m_ipTable, 2, 0);

    // Row 2, col 1 — logs viewer
    m_logsViewer = new LogsViewer;
    grid->addWidget(m_logsViewer, 2, 1);

    // Row 3 — metrics bar, full width
    m_metricsBar = new MetricsBar;
    m_metricsBar->setFixedHeight(36);
    grid->addWidget(m_metricsBar, 3, 0, 1, 3);

    // Column stretch: chart+logs wider, alerts narrower
    grid->setColumnStretch(0, 3);
    grid->setColumnStretch(1, 3);
    grid->setColumnStretch(2, 2);

    // Row stretch: tiles and metrics bar fixed, content rows flex
    grid->setRowStretch(0, 0);
    grid->setRowStretch(1, 3);
    grid->setRowStretch(2, 3);
    grid->setRowStretch(3, 0);
}

// ─── setupStatusBar ───────────────────────────────────────────────────────────
void MainWindow::setupStatusBar()
{
    statusBar()->setStyleSheet(
        "QStatusBar {"
        "  background:#1a1d27; color:#585b70;"
        "  border-top:1px solid #2a2d3a;"
        "}");
    statusBar()->showMessage("Ready — select an interface and press Start.");
}

// ─── setupConnections ─────────────────────────────────────────────────────────
void MainWindow::setupConnections()
{
    // Toolbar controls
    connect(m_startBtn, &QPushButton::clicked,
            this, &MainWindow::onStartStop);
    connect(m_ifaceCombo, &QComboBox::currentTextChanged,
            this, &MainWindow::onInterfaceChanged);

    // Pipeline → MainWindow
    connect(m_pipeline, &ProcessingPipeline::detectionResult,
            this, &MainWindow::onDetectionResult, Qt::QueuedConnection);
    connect(m_pipeline, &ProcessingPipeline::statsUpdated,
            this, &MainWindow::onStatsUpdated, Qt::QueuedConnection);
    connect(m_pipeline, &ProcessingPipeline::pipelineError,
            this, &MainWindow::onPipelineError, Qt::QueuedConnection);
    connect(m_pipeline, &ProcessingPipeline::pipelineStarted,
            this, &MainWindow::onPipelineStarted, Qt::QueuedConnection);

    // Pipeline → UIBridge → panels (throttled fan-out)
    connect(m_pipeline, &ProcessingPipeline::statsUpdated,
            m_bridge, &UIBridge::onStatsUpdated, Qt::QueuedConnection);
    connect(m_bridge, &UIBridge::forwardStats,
            m_trafficPanel, &TrafficPanel::onStatsUpdated);
    connect(m_bridge, &UIBridge::forwardStats,
            m_trafficChart, &TrafficChart::onStatsUpdated);
    connect(m_bridge, &UIBridge::forwardStats,
            m_metricsBar, &MetricsBar::onStatsUpdated);

    // Detection results → panels (direct queued)
    connect(m_pipeline, &ProcessingPipeline::detectionResult,
            m_alertsPanel, &AlertsPanel::onDetectionResult, Qt::QueuedConnection);
    connect(m_pipeline, &ProcessingPipeline::detectionResult,
            m_ipTable, &SuspiciousIPTable::onDetectionResult, Qt::QueuedConnection);
}

// ─── onStartStop ──────────────────────────────────────────────────────────────
void MainWindow::onStartStop()
{
    if (!m_running)
    {
        // ── Start ──────────────────────────────────────────────────────────
        QString iface = m_ifaceCombo->currentText();
        if (iface.isEmpty() || iface == "(no interfaces)")
        {
            QMessageBox::warning(this, "IDS",
                                 "No network interface selected.\n"
                                 "Please choose an interface from the dropdown.");
            return;
        }

        if (!m_pipeline->start(iface))
        {
            addLog("Failed to start pipeline on: " + iface, "ERROR");
            return;
        }

        m_running = true;
        m_uptimeSeconds = 0;
        m_alertCount = 0;

        m_startBtn->setText("⏹  Stop Capture");
        m_startBtn->setStyleSheet(
            "QPushButton {"
            "  background:#c01c28; color:#fff; border:none;"
            "  border-radius:6px; font-weight:600; font-size:13px;"
            "}"
            "QPushButton:hover { background:#e01b24; }");

        m_pulseTimer->start();
        m_uptimeTimer->start();
        m_ifaceCombo->setEnabled(false);

        addLog("Capture started on interface: " + iface, "INFO");
    }
    else
    {
        // ── Stop ───────────────────────────────────────────────────────────
        m_pipeline->stop();
        m_running = false;

        m_startBtn->setText("▶  Start Capture");
        m_startBtn->setStyleSheet(
            "QPushButton {"
            "  background:#26a269; color:#fff; border:none;"
            "  border-radius:6px; font-weight:600; font-size:13px;"
            "}"
            "QPushButton:hover { background:#2ec27e; }");

        m_pulseTimer->stop();
        m_uptimeTimer->stop();
        m_ifaceCombo->setEnabled(true);

        m_liveIndicator->setText("⬤  IDLE");
        m_liveIndicator->setStyleSheet(
            "color:#585b70; font-size:12px; font-weight:600;");

        addLog("Capture stopped.", "INFO");
    }
}

// ─── onInterfaceChanged ───────────────────────────────────────────────────────
void MainWindow::onInterfaceChanged(const QString &iface)
{
    if (!iface.isEmpty() && iface != "(no interfaces)")
        addLog("Interface selected: " + iface, "DEBUG");
}

// ─── onDetectionResult ────────────────────────────────────────────────────────
void MainWindow::onDetectionResult(const DetectionResult &result)
{
    if (result.severity == Severity::NORMAL)
        return;

    ++m_alertCount;

    QString level = (result.severity == Severity::ATTACK) ? "ATTACK" : "WARN";
    QString msg = QString("[%1] %2 from %3 — %4")
                      .arg(level)
                      .arg(QString::fromStdString(result.attack_type))
                      .arg(QString::fromStdString(result.src_ip_str))
                      .arg(QString::fromStdString(result.reason));

    addLog(msg, level);

    if (result.severity == Severity::ATTACK)
        showTrayNotification(result);
}

// ─── onStatsUpdated ───────────────────────────────────────────────────────────
void MainWindow::onStatsUpdated(const SystemStats &stats)
{
    statusBar()->showMessage(
        QString("Packets: %1  |  Flows: %2  |  Alerts: %3  |  Latency: %4 µs  |  CPU: %5%")
            .arg(stats.total_packets)
            .arg(stats.active_flows)
            .arg(stats.total_alerts)
            .arg(stats.latency_avg_ns / 1000.0, 0, 'f', 1)
            .arg(stats.cpu_percent, 0, 'f', 1));
}

// ─── onPipelineError ──────────────────────────────────────────────────────────
void MainWindow::onPipelineError(const QString &msg)
{
    addLog("Pipeline error: " + msg, "ERROR");
    if (m_running)
        onStartStop(); // auto-stop
    QMessageBox::critical(this, "IDS — Pipeline Error", msg);
}

// ─── onPipelineStarted ────────────────────────────────────────────────────────
void MainWindow::onPipelineStarted(const QString &iface, bool kernelModule)
{
    QString mode = kernelModule
                       ? "kernel module (netlink)"
                       : "libpcap (userspace)";
    addLog(QString("Pipeline active on %1 via %2").arg(iface).arg(mode), "INFO");
}

// ─── onPulseTick ─────────────────────────────────────────────────────────────
void MainWindow::onPulseTick()
{
    static bool on = true;
    on = !on;
    m_liveIndicator->setText("⬤  LIVE");
    m_liveIndicator->setStyleSheet(
        on ? "color:#a6e3a1; font-size:12px; font-weight:600;"
           : "color:#2a5c3a; font-size:12px; font-weight:600;");
}

// ─── addLog ───────────────────────────────────────────────────────────────────
void MainWindow::addLog(const QString &msg, const QString &level)
{
    if (m_logsViewer)
        m_logsViewer->appendLog(msg, level);
}

// ─── showTrayNotification ────────────────────────────────────────────────────
void MainWindow::showTrayNotification(const DetectionResult &result)
{
    if (!m_tray || !QSystemTrayIcon::supportsMessages())
        return;
    m_tray->showMessage(
        "⚠  Attack Detected",
        QString("%1  —  %2")
            .arg(QString::fromStdString(result.attack_type))
            .arg(QString::fromStdString(result.src_ip_str)),
        QSystemTrayIcon::Warning,
        3000);
}

// ─── applyDarkTheme ───────────────────────────────────────────────────────────
void MainWindow::applyDarkTheme()
{
    qApp->setStyle("Fusion");

    QPalette p;
    p.setColor(QPalette::Window, QColor("#11131f"));
    p.setColor(QPalette::WindowText, QColor("#cdd6f4"));
    p.setColor(QPalette::Base, QColor("#1e2030"));
    p.setColor(QPalette::AlternateBase, QColor("#252836"));
    p.setColor(QPalette::Text, QColor("#cdd6f4"));
    p.setColor(QPalette::Button, QColor("#1a1d27"));
    p.setColor(QPalette::ButtonText, QColor("#cdd6f4"));
    p.setColor(QPalette::Highlight, QColor("#5b9cf6"));
    p.setColor(QPalette::HighlightedText, QColor("#ffffff"));
    p.setColor(QPalette::ToolTipBase, QColor("#252836"));
    p.setColor(QPalette::ToolTipText, QColor("#cdd6f4"));
    p.setColor(QPalette::Link, QColor("#5b9cf6"));
    qApp->setPalette(p);
}