#include "FeatureExtractor.h"

FeatureExtractor::FeatureExtractor(QObject *parent) : QObject(parent) {}

void FeatureExtractor::onFlowUpdated(const FlowStats &stats)
{
    emit featuresReady(stats, extract(stats));
}

FeatureVector FeatureExtractor::extract(const FlowStats &stats)
{
    FeatureVector fv;

    double pkt_count = static_cast<double>(stats.src_total_packets);
    double syn = static_cast<double>(stats.syn_count);
    double ports = static_cast<double>(stats.src_unique_dst_ports);
    double pkt_rate = stats.packet_rate;
    double pkt_size = stats.avg_packet_size;
    double window = 3.0; // must match FlowTracker window

    // ── Raw features ────────────────────────────────────────────────────
    fv.packet_rate = pkt_rate;
    fv.unique_ports = ports;
    fv.syn_count = syn;
    fv.avg_packet_size = pkt_size;
    fv.connection_count = pkt_count;

    // ── Derived ratio features (what makes ML discriminative) ───────────
    // syn_ratio: ~0.05 for normal browsing, ~1.0 for SYN flood
    fv.syn_ratio = (pkt_count > 0) ? syn / pkt_count : 0.0;

    // port_scan_rate: ports touched per second — 0 for normal, high for nmap
    fv.port_scan_rate = ports / window;

    // bytes_per_sec: low for scans (tiny pkts), high for floods
    fv.bytes_per_sec = pkt_rate * pkt_size;

    return fv;
}