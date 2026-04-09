#pragma once
#include <QObject>
#include <QString>
#include <QStringList>
#include <memory>

#include "../capture/PacketCapture.h"
#include "../capture/NetlinkReceiver.h"
#include "../parser/PacketParser.h"
#include "../flow/FlowTracker.h"
#include "../features/FeatureExtractor.h"
#include "../detection/RuleEngine.h"
#include "../detection/DecisionEngine.h"
#include "../metrics/PerformanceMonitor.h"

class ProcessingPipeline : public QObject
{
    Q_OBJECT
public:
    explicit ProcessingPipeline(QObject *parent = nullptr);
    ~ProcessingPipeline();

    // List available network interfaces (wraps PacketCapture::availableInterfaces)
    static QStringList availableInterfaces();

    // Start capture on the given interface.
    // Tries kernel module (netlink) first, falls back to libpcap.
    bool start(const QString &iface);
    void stop();

    bool isRunning() const { return m_running; }
    bool isUsingKernelModule() const { return m_usingKernel; }

    PerformanceMonitor *monitor() { return m_monitor.get(); }
    DecisionEngine *decisionEngine() { return m_decision.get(); }

signals:
    void detectionResult(const DetectionResult &result);
    void normalFlowSeen(double packetRate);
    void pipelineError(const QString &msg);
    void statsUpdated(const SystemStats &stats);

    // Emitted once capture is confirmed active
    // iface = interface name, kernelModule = true if using netlink
    void pipelineStarted(const QString &iface, bool kernelModule);

private:
    void connectStages();
    void teardownThreads();

    std::unique_ptr<PacketCapture> m_capture;
    std::unique_ptr<NetlinkReceiver> m_netlink;
    std::unique_ptr<PacketParser> m_parser;
    std::unique_ptr<FlowTracker> m_flow;
    std::unique_ptr<FeatureExtractor> m_features;
    std::unique_ptr<DecisionEngine> m_decision;
    std::unique_ptr<PerformanceMonitor> m_monitor;

    QThread *m_parserThread{nullptr};
    QThread *m_flowThread{nullptr};
    QThread *m_featureThread{nullptr};
    QThread *m_decisionThread{nullptr};

    bool m_running{false};
    bool m_usingKernel{false};
};