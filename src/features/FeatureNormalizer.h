#pragma once
#include <array>
#include <cmath>
#include <limits>
#include <mutex>
#include "Types.h"

/**
 * FeatureNormalizer
 *
 * Normalizes FeatureVector values before they are passed to the ML scorer.
 * Two modes are supported and can be used independently per-feature:
 *
 *   1. Min-Max scaling  → maps value to [0, 1] using observed range
 *   2. Z-score (standard score) → (value - mean) / stddev
 *
 * The normalizer auto-calibrates from the first N samples it sees (online
 * fitting), then applies stable normalization thereafter. It can be
 * re-calibrated at any time via reset().
 *
 * Feature index mapping (matches FeatureVector field order):
 *   0 = packet_rate
 *   1 = unique_ports
 *   2 = syn_count
 *   3 = avg_packet_size
 *   4 = connection_count
 */
class FeatureNormalizer
{
public:
    static constexpr int NUM_FEATURES = 5;

    enum class Mode
    {
        MinMax,
        ZScore
    };

    explicit FeatureNormalizer(Mode mode = Mode::MinMax,
                               int fitSamples = 200);

    // Feed one feature vector into the online calibration.
    // Has no effect once the normalizer is fitted (fitSamples reached).
    void fit(const FeatureVector &fv);

    // Normalize a feature vector. Returns a copy with all values scaled.
    // Before fitting is complete, returns the raw vector unchanged.
    FeatureVector normalize(const FeatureVector &fv) const;

    // Convenience: fit then normalize in one call.
    FeatureVector fitTransform(const FeatureVector &fv);

    bool isFitted() const { return m_fitted; }
    int samplesSeen() const { return m_samplesSeen; }

    void reset();
    void setMode(Mode mode);

    // Manual override: set known min/max for a feature (0-based index).
    void setRange(int idx, double minVal, double maxVal);

    // Get current stats for diagnostics
    struct FeatureStats
    {
        double min{0}, max{0}, mean{0}, stddev{0};
    };
    FeatureStats stats(int featureIdx) const;

private:
    using Vec = std::array<double, NUM_FEATURES>;

    static Vec toArray(const FeatureVector &fv);
    static FeatureVector fromArray(const Vec &v);

    double normalizeOne(int idx, double value) const;

    Mode m_mode;
    int m_fitSamples;
    int m_samplesSeen{0};
    bool m_fitted{false};

    mutable std::mutex m_mutex;

    Vec m_min;
    Vec m_max;
    Vec m_mean;
    Vec m_M2; // for Welford variance
};