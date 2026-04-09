#include "ProcessingPipeline.h"

#include "../capture/PacketCapture.h"
#include "../capture/NetlinkReceiver.h"
#include "../parser/PacketParser.h"
#include "../flow/FlowTracker.h"
#include "../features/FeatureExtractor.h"
#include "../detection/DecisionEngine.h"
#include "../metrics/PerformanceMonitor.h"

#include <QDebug>

// ── Constructor / Destructor ─────────────────────────────────────────────────

ProcessingPipeline::ProcessingPipeline(QObject *parent) : QObject(parent) {}

ProcessingPipeline::~ProcessingPipeline()
{
    stop();
}

// ── Available interfaces ─────────────────────────────────────────────────────

QStringList ProcessingPipeline::availableInterfaces() const
{
    return PacketCapture::availableInterfaces();
}

// ── Start ────────────────────────────────────────────────────────────────────

bool ProcessingPipeline::start(const QString &iface)
{
    if (m_running)
        stop();

    // ── Create stages ────────────────────────────────────────────────────────
    m_capture = std::make_unique<PacketCapture>();
    m_netlink = std::make_unique<NetlinkReceiver>();
    m_parser = std::make_unique<PacketParser>();
    m_flow = std::make_unique<FlowTracker>(nullptr, 3);
    m_features = std::make_unique<FeatureExtractor>();
    m_detection = std::make_unique<DecisionEngine>();
    m_monitor = std::make_unique<PerformanceMonitor>();

    // ── Create worker threads ────────────────────────────────────────────────
    m_captureThread = new QThread(this);
    m_processingThread = new QThread(this);
    m_detectionThread = new QThread(this);

    // Move stages to their threads
    m_capture->moveToThread(m_captureThread);
    m_netlink->moveToThread(m_captureThread);
    m_parser->moveToThread(m_processingThread);
    m_flow->moveToThread(m_processingThread);
    m_features->moveToThread(m_processingThread);
    m_detection->moveToThread(m_detectionThread);
    // m_monitor stays on main thread (emits to UI)

    // ── Wire up signals/slots ────────────────────────────────────────────────
    setupConnections();

    // ── Start threads ────────────────────────────────────────────────────────
    m_captureThread->start(QThread::TimeCriticalPriority);
    m_processingThread->start(QThread::HighPriority);
    m_detectionThread->start(QThread::NormalPriority);

    // ── Try kernel module first, fall back to libpcap ────────────────────────
    bool useKernel = m_netlink->start();

    QString activeIface = iface;
    if (!useKernel)
    {
        // Kernel module not available — use libpcap
        if (activeIface.isEmpty())
        {
            auto ifaces = PacketCapture::availableInterfaces();
            if (ifaces.isEmpty())
            {
                emit pipelineError("No network interfaces found");
                teardown();
                return false;
            }
            // Prefer a non-loopback interface
            for (const auto &i : ifaces)
            {
                if (i != "lo" && i != "any")
                {
                    activeIface = i;
                    break;
                }
            }
            if (activeIface.isEmpty())
                activeIface = ifaces.first();
        }

        if (!m_capture->startCapture(activeIface))
        {
            emit pipelineError("Failed to start packet capture on " + activeIface);
            teardown();
            return false;
        }
    }

    m_running = true;
    emit pipelineStarted(useKernel ? "kernel-module" : activeIface, useKernel);
    return true;
}

// ── Stop ─────────────────────────────────────────────────────────────────────

void ProcessingPipeline::stop()
{
    if (!m_running)
        return;
    m_running = false;

    if (m_capture)
        m_capture->stopCapture();
    if (m_netlink)
        m_netlink->stop();

    teardown();
}

void ProcessingPipeline::teardown()
{
    for (QThread *t : {m_captureThread, m_processingThread, m_detectionThread})
    {
        if (t)
        {
            t->quit();
            t->wait(3000);
        }
    }
    m_captureThread = m_processingThread = m_detectionThread = nullptr;

    m_capture.reset();
    m_netlink.reset();
    m_parser.reset();
    m_flow.reset();
    m_features.reset();
    m_detection.reset();
    m_monitor.reset();
}

// ── Signal wiring ────────────────────────────────────────────────────────────

void ProcessingPipeline::setupConnections()
{
    // Capture → Parser (cross-thread: queued automatically)
    connect(m_capture.get(), &PacketCapture::packetCaptured,
            m_parser.get(), &PacketParser::onRawPacket,
            Qt::QueuedConnection);

    connect(m_netlink.get(), &NetlinkReceiver::packetCaptured,
            m_parser.get(), &PacketParser::onRawPacket,
            Qt::QueuedConnection);

    // Packet counting for metrics
    connect(m_capture.get(), &PacketCapture::statsUpdated, this, [this](quint64, quint64 dropped)
            { m_monitor->setDropped(dropped); }, Qt::QueuedConnection);

    // Parser → FlowTracker
    connect(m_parser.get(), &PacketParser::packetParsed,
            m_flow.get(), &FlowTracker::onParsedPacket,
            Qt::QueuedConnection);

    // Count packets for monitor
    connect(m_parser.get(), &PacketParser::packetParsed, this, [this](const ParsedPacket &pkt)
            { m_monitor->onPacketIn(pkt.packet_size); }, Qt::QueuedConnection);

    // FlowTracker → FeatureExtractor
    connect(m_flow.get(), &FlowTracker::flowUpdated,
            m_features.get(), &FeatureExtractor::onFlowUpdated,
            Qt::QueuedConnection);

    // Track active flows
    connect(m_flow.get(), &FlowTracker::flowUpdated, this, [this](const FlowStats &)
            {
                // approximate: could track a counter in FlowTracker itself
            },
            Qt::QueuedConnection);

    // FeatureExtractor → DecisionEngine
    connect(m_features.get(), &FeatureExtractor::featuresReady,
            m_detection.get(), &DecisionEngine::onFeaturesReady,
            Qt::QueuedConnection);

    // DecisionEngine → pipeline output
    connect(m_detection.get(), &DecisionEngine::detectionResult, this, [this](const DetectionResult &r)
            {
                if (r.severity != Severity::NORMAL)
                    m_monitor->onAlert(r.severity == Severity::ATTACK);
                emit detectionResult(r); }, Qt::QueuedConnection);

    // Monitor → UI
    connect(m_monitor.get(), &PerformanceMonitor::statsUpdated,
            this, &ProcessingPipeline::statsUpdated);

    // Errors
    connect(m_capture.get(), &PacketCapture::captureError,
            this, &ProcessingPipeline::pipelineError, Qt::QueuedConnection);
    connect(m_netlink.get(), &NetlinkReceiver::receiverError,
            this, &ProcessingPipeline::pipelineError, Qt::QueuedConnection);
}