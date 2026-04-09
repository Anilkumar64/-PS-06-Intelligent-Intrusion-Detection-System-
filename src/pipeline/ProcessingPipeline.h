#pragma once
#include <QObject>
#include <QThread>
#include <QString>
#include <memory>
#include <atomic>
#include "Types.h"
#include "../metrics/SystemStats.h"

// Forward declarations
class PacketCapture;
class NetlinkReceiver;
class PacketParser;
class FlowTracker;
class FeatureExtractor;
class DecisionEngine;
class PerformanceMonitor;

/**
 * ProcessingPipeline
 *
 * Owns and wires together all processing stages:
 *
 *   [NetlinkReceiver | PacketCapture (fallback)]
 *       ↓ RawPacket
 *   [PacketParser]          — capture thread
 *       ↓ ParsedPacket
 *   [FlowTracker]           — processing thread
 *       ↓ FlowStats
 *   [FeatureExtractor]      — processing thread
 *       ↓ (FlowStats, FeatureVector)
 *   [DecisionEngine]        — detection thread
 *       ↓ DetectionResult
 *   [signals to UI]
 *
 * Threads:
 *   captureThread   — PacketCapture / NetlinkReceiver
 *   processingThread — Parser, FlowTracker, FeatureExtractor
 *   detectionThread  — DecisionEngine
 *   (UI thread)      — PerformanceMonitor, signal consumers
 */
class ProcessingPipeline : public QObject
{
    Q_OBJECT

public:
    explicit ProcessingPipeline(QObject *parent = nullptr);
    ~ProcessingPipeline();

    bool start(const QString &iface = QString());
    void stop();

    bool isRunning() const { return m_running; }
    QStringList availableInterfaces() const;

signals:
    // Forwarded from DecisionEngine
    void detectionResult(const DetectionResult &result);

    // Forwarded from PerformanceMonitor
    void statsUpdated(const SystemStats &stats);

    // Pipeline-level events
    void pipelineError(const QString &msg);
    void pipelineStarted(const QString &iface, bool kernelModule);

private:
    void setupConnections();
    void teardown();

    // Stages (owned, moved to worker threads)
    std::unique_ptr<PacketCapture> m_capture;
    std::unique_ptr<NetlinkReceiver> m_netlink;
    std::unique_ptr<PacketParser> m_parser;
    std::unique_ptr<FlowTracker> m_flow;
    std::unique_ptr<FeatureExtractor> m_features;
    std::unique_ptr<DecisionEngine> m_detection;
    std::unique_ptr<PerformanceMonitor> m_monitor;

    // Worker threads
    QThread *m_captureThread{nullptr};
    QThread *m_processingThread{nullptr};
    QThread *m_detectionThread{nullptr};

    std::atomic_bool m_running{false};
};
