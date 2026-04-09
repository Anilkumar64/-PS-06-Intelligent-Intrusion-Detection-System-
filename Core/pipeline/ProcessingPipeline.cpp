#include "ProcessingPipeline.h"
#include <QDebug>
#include <QThread>

ProcessingPipeline::ProcessingPipeline(QObject *parent) : QObject(parent)
{
    m_capture = std::make_unique<PacketCapture>();
    m_netlink = std::make_unique<NetlinkReceiver>();
    m_parser = std::make_unique<PacketParser>();
    m_flow = std::make_unique<FlowTracker>(nullptr, 3);
    m_features = std::make_unique<FeatureExtractor>();
    m_decision = std::make_unique<DecisionEngine>();
    m_monitor = std::make_unique<PerformanceMonitor>();

    m_parserThread = new QThread(this);
    m_flowThread = new QThread(this);
    m_featureThread = new QThread(this);
    m_decisionThread = new QThread(this);

    m_parserThread->setObjectName("ids-parser");
    m_flowThread->setObjectName("ids-flow");
    m_featureThread->setObjectName("ids-features");
    m_decisionThread->setObjectName("ids-decision");

    m_parser->moveToThread(m_parserThread);
    m_flow->moveToThread(m_flowThread);
    m_features->moveToThread(m_featureThread);
    m_decision->moveToThread(m_decisionThread);

    connectStages();

    m_parserThread->start(QThread::HighPriority);
    m_flowThread->start(QThread::NormalPriority);
    m_featureThread->start(QThread::NormalPriority);
    m_decisionThread->start(QThread::NormalPriority);
}

ProcessingPipeline::~ProcessingPipeline()
{
    stop();
    teardownThreads();
}

QStringList ProcessingPipeline::availableInterfaces()
{
    return PacketCapture::availableInterfaces();
}

void ProcessingPipeline::connectStages()
{
    // Parser → FlowTracker
    connect(m_parser.get(), &PacketParser::packetParsed,
            m_flow.get(), &FlowTracker::onParsedPacket,
            Qt::QueuedConnection);

    // FlowTracker → FeatureExtractor
    connect(m_flow.get(), &FlowTracker::flowUpdated,
            m_features.get(), &FeatureExtractor::onFlowUpdated,
            Qt::QueuedConnection);

    // FeatureExtractor → DecisionEngine
    connect(m_features.get(), &FeatureExtractor::featuresReady,
            m_decision.get(), &DecisionEngine::onFeaturesReady,
            Qt::QueuedConnection);

    // DecisionEngine → this
    connect(m_decision.get(), &DecisionEngine::detectionResult,
            this, &ProcessingPipeline::detectionResult,
            Qt::QueuedConnection);
    connect(m_decision.get(), &DecisionEngine::normalFlowSeen,
            this, &ProcessingPipeline::normalFlowSeen,
            Qt::QueuedConnection);

    // PerformanceMonitor → this
    connect(m_monitor.get(), &PerformanceMonitor::statsUpdated,
            this, &ProcessingPipeline::statsUpdated,
            Qt::QueuedConnection);

    // Capture errors → this
    connect(m_capture.get(), &PacketCapture::captureError,
            this, &ProcessingPipeline::pipelineError,
            Qt::QueuedConnection);
    connect(m_netlink.get(), &NetlinkReceiver::receiverError,
            this, &ProcessingPipeline::pipelineError,
            Qt::QueuedConnection);

    // libpcap drop counter → monitor
    connect(m_capture.get(), &PacketCapture::statsUpdated, this, [this](quint64, quint64 dropped)
            { m_monitor->setDroppedPackets(dropped); }, Qt::QueuedConnection);

    // netlink drop counter → monitor  (signal: statsUpdated(total, dropped))
    connect(m_netlink.get(), &NetlinkReceiver::statsUpdated, this, [this](quint64, quint64 dropped)
            { m_monitor->setDroppedPackets(dropped); }, Qt::QueuedConnection);

    // Packet count → monitor
    connect(m_parser.get(), &PacketParser::packetParsed, this, [this](const ParsedPacket &pkt)
            { m_monitor->recordPacket(pkt.packet_size); }, Qt::QueuedConnection);

    // Detection latency + ml_ready → monitor
    connect(m_decision.get(), &DecisionEngine::detectionResult, this, [this](const DetectionResult &r)
            {
                m_monitor->recordDetection(r, r.timestamp);
                m_monitor->setMlReady(true); }, Qt::QueuedConnection);
}

bool ProcessingPipeline::start(const QString &iface)
{
    if (m_running)
        return true;

    // Try kernel module first
    if (m_netlink->isKernelModulePresent() && m_netlink->start())
    {
        m_usingKernel = true;
        m_monitor->setUsingKernelModule(true);

        connect(m_netlink.get(), &NetlinkReceiver::packetCaptured,
                m_parser.get(), &PacketParser::onRawPacket,
                Qt::QueuedConnection);

        qInfo() << "[Pipeline] Using kernel module capture";
    }
    else
    {
        m_usingKernel = false;
        m_monitor->setUsingKernelModule(false);

        if (!m_capture->startCapture(iface))
        {
            emit pipelineError("Failed to start libpcap on " + iface);
            return false;
        }

        connect(m_capture.get(), &PacketCapture::packetCaptured,
                m_parser.get(), &PacketParser::onRawPacket,
                Qt::QueuedConnection);

        qInfo() << "[Pipeline] Using libpcap on" << iface;
    }

    m_running = true;
    emit pipelineStarted(iface, m_usingKernel);
    return true;
}

void ProcessingPipeline::stop()
{
    if (!m_running)
        return;
    m_running = false;
    m_capture->stopCapture();
    m_netlink->stop();
    m_monitor->setMlReady(false);
}

void ProcessingPipeline::teardownThreads()
{
    for (QThread *t : {m_parserThread, m_flowThread,
                       m_featureThread, m_decisionThread})
    {
        if (t)
        {
            t->quit();
            t->wait(3000);
        }
    }
}