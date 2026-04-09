#include "FeatureNormalizer.h"
#include <algorithm>
#include <stdexcept>

// ─── Constructor ─────────────────────────────────────────────────────────────
FeatureNormalizer::FeatureNormalizer(Mode mode, int fitSamples)
    : m_mode(mode), m_fitSamples(fitSamples)
{
    m_min.fill(std::numeric_limits<double>::max());
    m_max.fill(-std::numeric_limits<double>::max());
    m_mean.fill(0.0);
    m_M2.fill(0.0);
}

// ─── reset ───────────────────────────────────────────────────────────────────
void FeatureNormalizer::reset()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_samplesSeen = 0;
    m_fitted = false;
    m_min.fill(std::numeric_limits<double>::max());
    m_max.fill(-std::numeric_limits<double>::max());
    m_mean.fill(0.0);
    m_M2.fill(0.0);
}

// ─── setMode ─────────────────────────────────────────────────────────────────
void FeatureNormalizer::setMode(Mode mode)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_mode = mode;
}

// ─── setRange ────────────────────────────────────────────────────────────────
void FeatureNormalizer::setRange(int idx, double minVal, double maxVal)
{
    if (idx < 0 || idx >= NUM_FEATURES)
        return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_min[idx] = minVal;
    m_max[idx] = maxVal;
}

// ─── fit ─────────────────────────────────────────────────────────────────────
void FeatureNormalizer::fit(const FeatureVector &fv)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_fitted)
        return;

    Vec v = toArray(fv);
    ++m_samplesSeen;

    for (int i = 0; i < NUM_FEATURES; ++i)
    {
        // Min-max tracking
        m_min[i] = std::min(m_min[i], v[i]);
        m_max[i] = std::max(m_max[i], v[i]);

        // Welford online mean/variance
        double delta = v[i] - m_mean[i];
        m_mean[i] += delta / static_cast<double>(m_samplesSeen);
        double delta2 = v[i] - m_mean[i];
        m_M2[i] += delta * delta2;
    }

    if (m_samplesSeen >= m_fitSamples)
    {
        m_fitted = true;
    }
}

// ─── normalizeOne ────────────────────────────────────────────────────────────
double FeatureNormalizer::normalizeOne(int idx, double value) const
{
    if (m_mode == Mode::MinMax)
    {
        double range = m_max[idx] - m_min[idx];
        if (range < 1e-9)
            return 0.0;
        double scaled = (value - m_min[idx]) / range;
        return std::max(0.0, std::min(1.0, scaled)); // clamp to [0,1]
    }
    else
    {
        // Z-score
        if (m_samplesSeen < 2)
            return 0.0;
        double var = m_M2[idx] / static_cast<double>(m_samplesSeen - 1);
        double sd = std::sqrt(std::max(0.0, var));
        if (sd < 1e-9)
            return 0.0;
        return (value - m_mean[idx]) / sd;
    }
}

// ─── normalize ───────────────────────────────────────────────────────────────
FeatureVector FeatureNormalizer::normalize(const FeatureVector &fv) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_fitted)
        return fv; // pass-through during warmup

    Vec raw = toArray(fv);
    Vec out;
    for (int i = 0; i < NUM_FEATURES; ++i)
        out[i] = normalizeOne(i, raw[i]);
    return fromArray(out);
}

// ─── fitTransform ────────────────────────────────────────────────────────────
FeatureVector FeatureNormalizer::fitTransform(const FeatureVector &fv)
{
    fit(fv);
    return normalize(fv);
}

// ─── stats ───────────────────────────────────────────────────────────────────
FeatureNormalizer::FeatureStats FeatureNormalizer::stats(int idx) const
{
    if (idx < 0 || idx >= NUM_FEATURES)
        return {};
    std::lock_guard<std::mutex> lock(m_mutex);
    FeatureStats s;
    s.min = m_min[idx];
    s.max = m_max[idx];
    s.mean = m_mean[idx];
    if (m_samplesSeen >= 2)
    {
        double var = m_M2[idx] / static_cast<double>(m_samplesSeen - 1);
        s.stddev = std::sqrt(std::max(0.0, var));
    }
    return s;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
FeatureNormalizer::Vec FeatureNormalizer::toArray(const FeatureVector &fv)
{
    return {fv.packet_rate, fv.unique_ports, fv.syn_count,
            fv.avg_packet_size, fv.connection_count};
}

FeatureVector FeatureNormalizer::fromArray(const Vec &v)
{
    FeatureVector fv;
    fv.packet_rate = v[0];
    fv.unique_ports = v[1];
    fv.syn_count = v[2];
    fv.avg_packet_size = v[3];
    fv.connection_count = v[4];
    return fv;
}