#pragma once
#include <QObject>
#include "../metrics/SystemStats.h"

/**
 * UIBridge — thin fan-out relay between the pipeline and UI panels.
 *
 * Lives on the UI thread. Receives signals via QueuedConnection from
 * worker threads and re-emits them so multiple UI widgets can connect
 * without each needing a direct queued connection to the pipeline.
 *
 * Also acts as a place to do lightweight UI-thread transformations
 * (e.g., throttling update frequency).
 */
class UIBridge : public QObject
{
    Q_OBJECT

public:
    explicit UIBridge(QObject *parent = nullptr);

public slots:
    void onStatsUpdated(const SystemStats &stats);

signals:
    void forwardStats(const SystemStats &stats);
};