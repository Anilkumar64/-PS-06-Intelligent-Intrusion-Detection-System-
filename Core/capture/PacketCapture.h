#pragma once
#include <QObject>
#include <QThread>
#include <QString>
#include <QStringList>
#include <pcap.h>
#include <atomic>
#include <functional>
#include "Types.h"

class PacketCapture : public QObject
{
    Q_OBJECT

public:
    explicit PacketCapture(QObject *parent = nullptr);
    ~PacketCapture();

    // List all available network interfaces
    static QStringList availableInterfaces();

    // Start/stop capture on a given interface
    bool startCapture(const QString &iface);
    void stopCapture();

    bool isRunning() const { return m_running.load(); }

signals:
    void packetCaptured(const RawPacket &pkt);
    void captureError(const QString &msg);
    void statsUpdated(quint64 totalPackets, quint64 droppedPackets);

private:
    void captureLoop();

    pcap_t *m_handle{nullptr};
    std::atomic_bool m_running{false};
    QThread *m_thread{nullptr};

    quint64 m_totalPackets{0};
    quint64 m_droppedPackets{0};

    static void pcapCallback(u_char *user,
                             const struct pcap_pkthdr *header,
                             const u_char *data);
};