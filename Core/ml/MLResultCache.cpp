#include "MLResultCache.h"

// ── Constructor ──────────────────────────────────────────────────────────────
MLResultCache::MLResultCache(size_t capacity, int ttlMs)
    : m_capacity(capacity), m_ttlMs(ttlMs)
{
    m_map.reserve(capacity);
}

// ── makeKey — FNV-1a over discretised feature buckets ───────────────────────
// MLResultCache.cpp — makeKey() — REPLACE entire function body:

uint64_t MLResultCache::makeKey(const FeatureVector &fv) const
{
    // Bucket each feature to avoid cache thrash on tiny float differences
    double b0 = bucket(fv.packet_rate, bucketPacketRate);
    double b1 = bucket(fv.unique_ports, bucketUniquePorts);
    double b2 = bucket(fv.syn_count, bucketSynCount);
    double b3 = bucket(fv.avg_packet_size, bucketAvgPacketSize);
    double b4 = bucket(fv.connection_count, bucketConnectionCount);
    // Previously missing — these are the discriminative features:
    double b5 = std::floor(fv.syn_ratio * 20.0);       // 0.05 buckets
    double b6 = std::floor(fv.port_scan_rate * 5.0);   // 0.2 pps buckets
    double b7 = std::floor(fv.bytes_per_sec / 1000.0); // 1 KB/s buckets

    auto asInt = [](double v) -> uint64_t
    {
        return static_cast<uint64_t>(std::max(0.0, v * 10.0));
    };

    uint64_t h = 14695981039346656037ULL;
    auto mix = [&](uint64_t v)
    {
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
    mix(asInt(b5));
    mix(asInt(b6));
    mix(asInt(b7));
    return h;
}

// ── get ──────────────────────────────────────────────────────────────────────
std::optional<MLResult> MLResultCache::get(const FeatureVector &fv) const
{
    uint64_t key = makeKey(fv);
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_map.find(key);
    if (it == m_map.end())
    {
        ++m_misses;
        return std::nullopt;
    }

    // TTL check
    if (m_ttlMs > 0)
    {
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - it->second.data.cachedAt)
                       .count();
        if (age > m_ttlMs)
        {
            ++m_misses;
            return std::nullopt;
        }
    }

    // Promote to MRU
    m_lruList.splice(m_lruList.begin(), m_lruList, it->second.listIt);
    ++m_hits;
    return it->second.data.result;
}

// ── put ──────────────────────────────────────────────────────────────────────
void MLResultCache::put(const FeatureVector &fv, const MLResult &result)
{
    uint64_t key = makeKey(fv);
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_map.find(key);
    if (it != m_map.end())
    {
        it->second.data = {result, std::chrono::steady_clock::now()};
        m_lruList.splice(m_lruList.begin(), m_lruList, it->second.listIt);
        return;
    }

    // Evict LRU if at capacity
    if (m_map.size() >= m_capacity)
    {
        m_map.erase(m_lruList.back());
        m_lruList.pop_back();
    }

    m_lruList.push_front(key);
    m_map[key] = MapEntry{{result, std::chrono::steady_clock::now()},
                          m_lruList.begin()};
}

// ── clear / size ─────────────────────────────────────────────────────────────
void MLResultCache::clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_map.clear();
    m_lruList.clear();
    m_hits = m_misses = 0;
}

size_t MLResultCache::size() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_map.size();
}