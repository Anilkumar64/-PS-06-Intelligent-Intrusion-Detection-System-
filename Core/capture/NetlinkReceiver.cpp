#include "NetlinkReceiver.h"
#include "../../Kernel_module/ids_kmod.h"
#include <QDebug>
#include <QThread>
#include <cstring>
#include <cerrno>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <unistd.h>

// ─── Raw netlink helpers (no libnl required) ──────────────────────────────────

// Alignment macros (mirror kernel NLA_* without libnl)
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + 3) & ~3)
#endif
#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif
#define NLA_DATA(nla) ((void *)(((char *)(nla)) + NLA_HDRLEN))
#define NLA_LEN(nla) ((int)((nla)->nla_len) - NLA_HDRLEN)
#define NLA_TYPE(nla) ((nla)->nla_type & 0x1FFF)
#define NLA_OK(nla, rem) ((rem) >= (int)sizeof(struct nlattr) &&     \
                          (nla)->nla_len >= sizeof(struct nlattr) && \
                          (nla)->nla_len <= (rem))
#define NLA_NEXT(nla, rem) ((rem) -= NLA_ALIGN((nla)->nla_len), \
                            (struct nlattr *)(((char *)(nla)) + NLA_ALIGN((nla)->nla_len)))

// genlmsghdr data starts right after the generic netlink header
static inline struct nlattr *genl_attrs(struct genlmsghdr *gnlh, int hdrlen)
{
    return reinterpret_cast<struct nlattr *>(
        reinterpret_cast<char *>(gnlh) + GENL_HDRLEN + hdrlen);
}
static inline int genl_attrs_len(struct nlmsghdr *nlh, int hdrlen)
{
    return static_cast<int>(nlh->nlmsg_len) - static_cast<int>(NLMSG_HDRLEN) - static_cast<int>(GENL_HDRLEN) - hdrlen;
}

// Build and send a simple Generic Netlink request
static int genl_send_simple(int fd, uint16_t type, uint8_t cmd,
                            const void *payload, int paylen)
{
    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr gnlh;
        char buf[256];
    } msg{};

    msg.nlh.nlmsg_type = type;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg.nlh.nlmsg_seq = 1;
    msg.nlh.nlmsg_pid = static_cast<uint32_t>(getpid());
    msg.gnlh.cmd = cmd;
    msg.gnlh.version = 1;

    if (payload && paylen > 0 && paylen < (int)sizeof(msg.buf))
        memcpy(msg.buf, payload, static_cast<size_t>(paylen));

    msg.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN + paylen);

    struct sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;

    return static_cast<int>(
        sendto(fd, &msg, msg.nlh.nlmsg_len, 0,
               reinterpret_cast<sockaddr *>(&addr), sizeof(addr)));
}

// ─── Constructor / Destructor ─────────────────────────────────────────────────
NetlinkReceiver::NetlinkReceiver(QObject *parent) : QObject(parent) {}

NetlinkReceiver::~NetlinkReceiver() { stop(); }

// ─── Start ────────────────────────────────────────────────────────────────────
bool NetlinkReceiver::start()
{
    if (m_running)
        stop();

    m_nlFd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (m_nlFd < 0)
    {
        emit receiverError(QString("netlink socket: %1").arg(strerror(errno)));
        return false;
    }

    struct sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    local.nl_pid = static_cast<uint32_t>(getpid());
    if (bind(m_nlFd, reinterpret_cast<sockaddr *>(&local), sizeof(local)) < 0)
    {
        emit receiverError(QString("netlink bind: %1").arg(strerror(errno)));
        close(m_nlFd);
        m_nlFd = -1;
        return false;
    }

    if (!resolveFamily())
    {
        close(m_nlFd);
        m_nlFd = -1;
        emit receiverError("ids_kmod not loaded — using libpcap fallback");
        return false;
    }

    if (!joinMcastGroup())
    {
        close(m_nlFd);
        m_nlFd = -1;
        return false;
    }

    m_running = true;
    m_thread = QThread::create([this]
                               { receiveLoop(); });
    m_thread->start(QThread::TimeCriticalPriority);
    return true;
}

// ─── Stop ─────────────────────────────────────────────────────────────────────
void NetlinkReceiver::stop()
{
    m_running = false;
    if (m_nlFd >= 0)
    {
        shutdown(m_nlFd, SHUT_RDWR); // unblock recv()
        close(m_nlFd);
        m_nlFd = -1;
    }
    if (m_thread)
    {
        m_thread->wait(2000);
        delete m_thread;
        m_thread = nullptr;
    }
}

// ─── resolveFamily ────────────────────────────────────────────────────────────
// Ask the kernel's Generic Netlink controller (family GENL_ID_CTRL) for the
// dynamic family id assigned to "ids_kmod".
bool NetlinkReceiver::resolveFamily()
{
    // Build NLA: CTRL_ATTR_FAMILY_NAME = "ids_kmod\0"
    const char *fname = IDS_NETLINK_FAMILY;
    int namelen = static_cast<int>(strlen(fname)) + 1;
    int attrlen = NLA_HDRLEN + NLA_ALIGN(namelen);

    std::vector<char> attrBuf(static_cast<size_t>(attrlen), 0);
    auto *nla = reinterpret_cast<struct nlattr *>(attrBuf.data());
    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    nla->nla_len = static_cast<uint16_t>(NLA_HDRLEN + namelen);
    memcpy(NLA_DATA(nla), fname, static_cast<size_t>(namelen));

    if (genl_send_simple(m_nlFd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
                         attrBuf.data(), attrlen) < 0)
        return false;

    // Read response
    char buf[1024];
    ssize_t len = recv(m_nlFd, buf, sizeof(buf), 0);
    if (len < static_cast<ssize_t>(sizeof(struct nlmsghdr)))
        return false;

    auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
    if (!NLMSG_OK(nlh, static_cast<uint32_t>(len)))
        return false;
    if (nlh->nlmsg_type == NLMSG_ERROR)
        return false;

    auto *gnlh = reinterpret_cast<struct genlmsghdr *>(NLMSG_DATA(nlh));
    auto *attrs = genl_attrs(gnlh, 0);
    int alen = genl_attrs_len(nlh, 0);

    for (struct nlattr *pos = attrs; NLA_OK(pos, alen); pos = NLA_NEXT(pos, alen))
    {
        switch (NLA_TYPE(pos))
        {
        case CTRL_ATTR_FAMILY_ID:
            m_familyId = *reinterpret_cast<uint16_t *>(NLA_DATA(pos));
            break;
        case CTRL_ATTR_MCAST_GROUPS:
        {
            // Nested: each group is another nested attr
            auto *grp = reinterpret_cast<struct nlattr *>(NLA_DATA(pos));
            int glen = NLA_LEN(pos);
            for (; NLA_OK(grp, glen); grp = NLA_NEXT(grp, glen))
            {
                auto *sub = reinterpret_cast<struct nlattr *>(NLA_DATA(grp));
                int slen = NLA_LEN(grp);
                const char *gname = nullptr;
                uint32_t gid = 0;
                for (; NLA_OK(sub, slen); sub = NLA_NEXT(sub, slen))
                {
                    if (NLA_TYPE(sub) == CTRL_ATTR_MCAST_GRP_NAME)
                        gname = reinterpret_cast<const char *>(NLA_DATA(sub));
                    if (NLA_TYPE(sub) == CTRL_ATTR_MCAST_GRP_ID)
                        gid = *reinterpret_cast<uint32_t *>(NLA_DATA(sub));
                }
                if (gname && strcmp(gname, IDS_MCAST_GROUP) == 0)
                    m_mcastGrpId = static_cast<int>(gid);
            }
            break;
        }
        default:
            break;
        }
    }

    return m_familyId > 0;
}

// ─── joinMcastGroup ───────────────────────────────────────────────────────────
bool NetlinkReceiver::joinMcastGroup()
{
    if (m_mcastGrpId < 0)
        return false;
    int grp = m_mcastGrpId;
    if (setsockopt(m_nlFd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                   &grp, sizeof(grp)) < 0)
    {
        emit receiverError(QString("join mcast: %1").arg(strerror(errno)));
        return false;
    }
    return true;
}

// ─── receiveLoop ──────────────────────────────────────────────────────────────
void NetlinkReceiver::receiveLoop()
{
    char buf[8192];
    while (m_running)
    {
        ssize_t len = recv(m_nlFd, buf, sizeof(buf), 0);
        if (len < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }

        auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
        uint32_t ulen = static_cast<uint32_t>(len);

        while (NLMSG_OK(nlh, ulen))
        {
            if (nlh->nlmsg_type == NLMSG_DONE ||
                nlh->nlmsg_type == NLMSG_ERROR)
                break;

            auto *gnlh = reinterpret_cast<struct genlmsghdr *>(NLMSG_DATA(nlh));
            if (gnlh->cmd == IDS_CMD_PKT_EVENT)
            {
                auto *attrs = genl_attrs(gnlh, 0);
                int alen = genl_attrs_len(nlh, 0);

                for (struct nlattr *pos = attrs;
                     NLA_OK(pos, alen);
                     pos = NLA_NEXT(pos, alen))
                {
                    if (NLA_TYPE(pos) == IDS_ATTR_PKT &&
                        NLA_LEN(pos) == static_cast<int>(sizeof(ids_pkt_desc)))
                    {
                        auto *desc = reinterpret_cast<const ids_pkt_desc *>(
                            NLA_DATA(pos));

                        RawPacket pkt;
                        pkt.timestamp = std::chrono::steady_clock::now();
                        pkt.caplen = sizeof(ids_pkt_desc);
                        pkt.data.resize(sizeof(ids_pkt_desc));
                        memcpy(pkt.data.data(), desc, sizeof(ids_pkt_desc));

                        ++m_total;
                        emit packetCaptured(pkt);

                        if (m_total % 500 == 0)
                            emit statsUpdated(m_total, 0);
                    }
                }
            }
            nlh = NLMSG_NEXT(nlh, ulen);
        }
    }
}