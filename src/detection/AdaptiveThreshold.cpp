#include "AdaptiveThreshold.h"
#include <algorithm>
#include <numeric>
#include <stdexcept>

// ─── Constructor ─────────────────────────────────────────────────────────────
AdaptiveThreshold::AdaptiveThreshold(int windowSize, double kSigma,
                                     int warmupSamples)
    : m_windowSize(windowSize), m_kSigma(kSigma), m_warmupSamples(warmupSamples)
{
}

// ─── update ──────────────────────────────────────────────────────────────────
// Adds a new observation using Welford's online algorithm for O(1) mean/var.
// When the window is full, the oldest sample is removed and the running stats
// are corrected to approximate a rolling window.
void AdaptiveThreshold::update(double value)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    ++m_totalSamples;

    // ── Welford update for the incoming value ────────────────────────────
    double delta = value - m_runMean;
    m_runMean += delta / static_cast<double>(m_totalSamples);
    double delta2 = value - m_runMean;
    m_runM2 += delta * delta2;

    m_window.push_back(value);
    m_min = std::min(m_min, value);
    m_max = std::max(m_max, value);

    // ── Evict oldest sample when window is full ──────────────────────────
    if (static_cast<int>(m_window.size()) > m_windowSize)
    {
        double old = m_window.front();
        m_window.pop_front();

        // Reverse-Welford: remove the evicted sample from running stats.
        // This is an approximation (exact removal requires count-1 correction)
        // but is accurate enough for our anomaly detection use case.
        int n = static_cast<int>(m_window.size()) + 1; // before removal
        if (n > 1)
        {
            double oldMean = m_runMean;
            m_runMean = (m_runMean * n - old) / (n - 1);
            m_runM2 -= (old - oldMean) * (old - m_runMean);
            if (m_runM2 < 0.0)
                m_runM2 = 0.0; // numerical guard
        }
        else
        {
            m_runMean = 0.0;
            m_runM2 = 0.0;
        }
    }
}

// ─── mean / stddev ───────────────────────────────────────────────────────────
double AdaptiveThreshold::mean() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_runMean;
}

double AdaptiveThreshold::stddev() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    int n = static_cast<int>(m_window.size());
    if (n < 2)
        return 0.0;
    double variance = m_runM2 / static_cast<double>(n - 1);
    return std::sqrt(std::max(0.0, variance));
}

// ─── threshold ───────────────────────────────────────────────────────────────
double AdaptiveThreshold::threshold() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    int n = static_cast<int>(m_window.size());
    if (n < 2)
        return 1e18; // not yet calibrated — never fire
    double var = m_runM2 / static_cast<double>(n - 1);
    double sd = std::sqrt(std::max(0.0, var));
    return m_runMean + m_kSigma * sd;
}

// ─── isSuspicious ────────────────────────────────────────────────────────────
bool AdaptiveThreshold::isSuspicious(double value) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_totalSamples < m_warmupSamples)
        return false;
    int n = static_cast<int>(m_window.size());
    if (n < 2)
        return false;
    double var = m_runM2 / static_cast<double>(n - 1);
    double sd = std::sqrt(std::max(0.0, var));
    return value > (m_runMean + m_kSigma * sd);
}

// ─── isAttack ────────────────────────────────────────────────────────────────
// Higher bar: mean + 2*k*stddev (double sigma multiplier)
bool AdaptiveThreshold::isAttack(double value) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_totalSamples < m_warmupSamples)
        return false;
    int n = static_cast<int>(m_window.size());
    if (n < 2)
        return false;
    double var = m_runM2 / static_cast<double>(n - 1);
    double sd = std::sqrt(std::max(0.0, var));
    return value > (m_runMean + 2.0 * m_kSigma * sd);
}

// ─── sampleCount ─────────────────────────────────────────────────────────────
int AdaptiveThreshold::sampleCount() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<int>(m_window.size());
}

// ─── isWarmedUp ──────────────────────────────────────────────────────────────
bool AdaptiveThreshold::isWarmedUp() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_totalSamples >= m_warmupSamples;
}

// ─── reset ───────────────────────────────────────────────────────────────────
void AdaptiveThreshold::reset()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_window.clear();
    m_runMean = 0.0;
    m_runM2 = 0.0;
    m_totalSamples = 0;
    m_min = 1e18;
    m_max = -1e18;
}

// ─── setSigmaMultiplier ───────────────────────────────────────────────────────
void AdaptiveThreshold::setSigmaMultiplier(double k)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_kSigma = k;
}