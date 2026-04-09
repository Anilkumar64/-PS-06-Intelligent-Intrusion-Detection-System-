#include "MLResultCache.h"

// ─── Constructor ─────────────────────────────────────────────────────────────
MLResultCache::MLResultCache(size_t capacity, int ttlMs)
    : m_capacity(capacity), m_ttlMs(ttlMs)
{
    m_map.reserve(capacity);
}

// ─── makeKey ─────────────────────────────────────────────────────────────────
// Produces a 64-bit hash by discretising each feature into a bucket,
// then mixing with FNV-1a.
uint64_t MLResultCache::makeKey(const FeatureVector &fv) const
{
    // Discretise
    double b0 = bucket(fv.packet_rate, bucketPacketRate);
    double b1 = bucket(fv.unique_ports, bucketUniquePorts);
    double b2 = bucket(fv.syn_count, bucketSynCount);
    double b3 = bucket(fv.avg_packet_size, bucketAvgPacketSize);
    double b4 = bucket(fv.connection_count, bucketConnectionCount);

    // Encode as integers (multiply by 10 to preserve one decimal place)
    auto asInt = [](double v) -> uint64_t
    {
        return static_cast<uint64_t>(std::max(0.0, v * 10.0));
    };

    // FNV-1a 64-bit mix
    uint64_t h = 14695981039346656037ULL;
    auto mix = [&](uint64_t v)
    {
        // mix 8 bytes
        for (int i = 0; i < 8; ++i)
        {
            h ^= (v & 0xFF);
            h *= 1099511628211ULL;
            v >>= 8;
        }
    };

    mix(asInt(b0));
    mix(asInt(b1));
    mix(asInt(b2));
    mix(asInt(b3));
    mix(asInt(b4));

    return h;
}

// ─── get ─────────────────────────────────────────────────────────────────────
std::optional<double> MLResultCache::get(const FeatureVector &fv) const
{
    uint64_t key = makeKey(fv);
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_map.find(key);
    if (it == m_map.end())
    {
        ++m_misses;
        return std::nullopt;
    }

    // Check TTL
    if (m_ttlMs > 0)
    {
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - it->second.data.cachedAt)
                       .count();
        if (age > m_ttlMs)
        {
            ++m_misses;
            return std::nullopt; // stale — let caller re-score
        }
    }

    // Promote to front of LRU list
    m_lruList.splice(m_lruList.begin(), m_lruList, it->second.listIt);

    ++m_hits;
    return it->second.data.score;
}

// ─── put ─────────────────────────────────────────────────────────────────────
void MLResultCache::put(const FeatureVector &fv, double score)
{
    uint64_t key = makeKey(fv);
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_map.find(key);
    if (it != m_map.end())
    {
        // Update existing entry and move to front
        it->second.data = {score, std::chrono::steady_clock::now()};
        m_lruList.splice(m_lruList.begin(), m_lruList, it->second.listIt);
        return;
    }

    // Evict LRU entry if at capacity
    if (m_map.size() >= m_capacity)
    {
        uint64_t lruKey = m_lruList.back();
        m_lruList.pop_back();
        m_map.erase(lruKey);
    }

    // Insert new entry at front
    m_lruList.push_front(key);
    m_map[key] = MapEntry{
        {score, std::chrono::steady_clock::now()},
        m_lruList.begin()};
}

// ─── clear ───────────────────────────────────────────────────────────────────
void MLResultCache::clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_map.clear();
    m_lruList.clear();
    m_hits = 0;
    m_misses = 0;
}

// ─── size ────────────────────────────────────────────────────────────────────
size_t MLResultCache::size() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_map.size();
}