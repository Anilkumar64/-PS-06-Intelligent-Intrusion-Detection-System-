#include "UIBridge.h"
#include <QDateTime>

UIBridge::UIBridge(QObject *parent) : QObject(parent) {}

void UIBridge::onStatsUpdated(const SystemStats &stats)
{
    // Throttle: only forward if at least 200ms has passed since last forward.
    // This decouples the update rate of the pipeline from the UI repaint rate.
    static qint64 lastForwardMs = 0;
    qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (now - lastForwardMs < 200)
        return;
    lastForwardMs = now;

    emit forwardStats(stats);
}