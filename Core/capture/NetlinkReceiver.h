#pragma once
#include <QObject>
#include <QThread>
#include <atomic>
#include "Types.h"

/**
 * NetlinkReceiver
 *
 * Listens on a Generic Netlink socket for ids_pkt_desc messages
 * emitted by ids_kmod.ko and converts them into RawPacket signals
 * identical to what PacketCapture emits — so the rest of the pipeline
 * sees a uniform interface regardless of capture path.
 *
 * Falls back gracefully if the kernel module is not loaded.
 */
class NetlinkReceiver : public QObject
{
    Q_OBJECT

public:
    explicit NetlinkReceiver(QObject *parent = nullptr);
    ~NetlinkReceiver();

    bool start();
    void stop();

    bool isRunning() const { return m_running.load(); }
    bool isKernelModulePresent() const { return m_nlFd >= 0; }

signals:
    void packetCaptured(const RawPacket &pkt); // same signal as PacketCapture
    void receiverError(const QString &msg);
    void statsUpdated(quint64 total, quint64 dropped);

private:
    void receiveLoop();
    bool resolveFamily(); // resolve genl family id
    bool joinMcastGroup();

    int m_nlFd{-1};
    int m_familyId{-1};
    int m_mcastGrpId{-1};
    std::atomic_bool m_running{false};
    QThread *m_thread{nullptr};
    quint64 m_total{0};
};