#include "FeatureExtractor.h"

FeatureExtractor::FeatureExtractor(QObject *parent) : QObject(parent) {}

void FeatureExtractor::onFlowUpdated(const FlowStats &stats)
{
    emit featuresReady(stats, extract(stats));
}

FeatureVector FeatureExtractor::extract(const FlowStats &stats)
{
    FeatureVector fv;
    fv.packet_rate = stats.packet_rate;
    fv.unique_ports = static_cast<double>(stats.unique_dst_ports);
    fv.syn_count = static_cast<double>(stats.syn_count);
    fv.avg_packet_size = stats.avg_packet_size;
    fv.connection_count = static_cast<double>(stats.connection_attempts);
    return fv;
}