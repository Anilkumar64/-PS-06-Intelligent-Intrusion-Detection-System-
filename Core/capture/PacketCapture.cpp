#include "PacketCapture.h"
#include <QDebug>
#include <cstring>

// ── Static pcap callback ────────────────────────────────────────────────────
void PacketCapture::pcapCallback(u_char *user,
                                 const struct pcap_pkthdr *header,
                                 const u_char *data)
{
    auto *self = reinterpret_cast<PacketCapture *>(user);
    if (!self || !self->m_running)
        return;

    RawPacket pkt;
    pkt.timestamp = std::chrono::steady_clock::now();
    pkt.caplen = header->caplen;
    pkt.data.assign(data, data + header->caplen);

    ++self->m_totalPackets;
    emit self->packetCaptured(pkt);
}

// ── Constructor / Destructor ────────────────────────────────────────────────
PacketCapture::PacketCapture(QObject *parent) : QObject(parent) {}

PacketCapture::~PacketCapture()
{
    stopCapture();
}

// ── List interfaces ─────────────────────────────────────────────────────────
QStringList PacketCapture::availableInterfaces()
{
    QStringList list;
    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        qWarning() << "pcap_findalldevs:" << errbuf;
        return list;
    }

    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next)
        if (d->name)
            list << QString(d->name);

    pcap_freealldevs(alldevs);
    return list;
}

// ── Start capture ───────────────────────────────────────────────────────────
bool PacketCapture::startCapture(const QString &iface)
{
    if (m_running)
        stopCapture();

    char errbuf[PCAP_ERRBUF_SIZE];
    m_handle = pcap_open_live(iface.toStdString().c_str(),
                              65535, // snaplen
                              1,     // promiscuous
                              100,   // timeout ms
                              errbuf);
    if (!m_handle)
    {
        emit captureError(QString("pcap_open_live: %1").arg(errbuf));
        return false;
    }

    // Set non-blocking so we can check m_running regularly
    pcap_setnonblock(m_handle, 1, errbuf);

    m_running = true;
    m_totalPackets = 0;
    m_droppedPackets = 0;

    // Run capture loop in a dedicated QThread
    m_thread = QThread::create([this]()
                               { captureLoop(); });
    m_thread->start(QThread::TimeCriticalPriority);

    return true;
}

// ── Stop capture ────────────────────────────────────────────────────────────
void PacketCapture::stopCapture()
{
    m_running = false;
    if (m_thread)
    {
        m_thread->wait(3000);
        delete m_thread;
        m_thread = nullptr;
    }
    if (m_handle)
    {
        pcap_close(m_handle);
        m_handle = nullptr;
    }
}

// ── Capture loop (runs in thread) ───────────────────────────────────────────
void PacketCapture::captureLoop()
{
    while (m_running)
    {
        int ret = pcap_dispatch(m_handle, 64,
                                pcapCallback,
                                reinterpret_cast<u_char *>(this));
        if (ret < 0)
        {
            if (m_running)
                emit captureError(QString("pcap_dispatch error: %1").arg(ret));
            break;
        }
        // If no packets, sleep briefly to avoid busy-spinning
        if (ret == 0)
        {
            QThread::usleep(1000); // 1ms
        }

        // Emit stats every ~500 packets
        if (m_totalPackets % 500 == 0)
        {
            struct pcap_stat ps{};
            if (pcap_stats(m_handle, &ps) == 0)
                m_droppedPackets = ps.ps_drop;
            emit statsUpdated(m_totalPackets, m_droppedPackets);
        }
    }
}