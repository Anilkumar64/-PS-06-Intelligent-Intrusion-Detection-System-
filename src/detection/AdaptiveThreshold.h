#pragma once
#include <cstdint>
#include <deque>
#include <cmath>
#include <chrono>
#include <mutex>

/**
 * AdaptiveThreshold
 *
 * Maintains a rolling statistical baseline of "normal" traffic for a single
 * metric (e.g. packet_rate, syn_count) and dynamically computes a detection
 * threshold as:
 *
 *     threshold = mean + k * stddev
 *
 * where k is a configurable sensitivity multiplier (default 3.0 = 3-sigma).
 *
 * Used by RuleEngine to replace hard-coded constants with thresholds that
 * auto-tune to the observed traffic profile on startup.
 *
 * Thread-safe: all public methods are protected by a mutex so the detection
 * thread can call isSuspicious() while the capture thread calls update().
 */
class AdaptiveThreshold
{
public:
    /**
     * @param windowSize   Number of samples kept in the rolling window.
     * @param kSigma       Threshold = mean + kSigma * stddev.
     * @param warmupSamples  Don't fire until at least this many samples seen.
     */
    explicit AdaptiveThreshold(int windowSize = 300,
                               double kSigma = 3.0,
                               int warmupSamples = 50);

    // Feed a new observation into the baseline window.
    void update(double value);

    // Returns true when value exceeds the adaptive threshold.
    // Always returns false during warmup phase.
    bool isSuspicious(double value) const;

    // Returns true when value exceeds mean + kSigma*2 (high-confidence attack).
    bool isAttack(double value) const;

    // Current computed threshold value (mean + k*stddev).
    double threshold() const;

    // Underlying stats (read-only snapshot).
    double mean() const;
    double stddev() const;
    double min() const { return m_min; }
    double max() const { return m_max; }

    // Number of samples currently in the window.
    int sampleCount() const;

    // True once warmup is complete and threshold is reliable.
    bool isWarmedUp() const;

    // Reset all state (e.g. when switching interfaces).
    void reset();

    // Change sensitivity at runtime.
    void setSigmaMultiplier(double k);
    double sigmaMultiplier() const { return m_kSigma; }

private:
    double computeMean() const;
    double computeStddev() const;

    mutable std::mutex m_mutex;
    std::deque<double> m_window;
    int m_windowSize;
    double m_kSigma;
    int m_warmupSamples;
    int m_totalSamples{0};

    // Running stats for O(1) mean/variance (Welford's online algorithm)
    double m_runMean{0.0};
    double m_runM2{0.0}; // sum of squared deviations

    double m_min{1e18};
    double m_max{-1e18};
};