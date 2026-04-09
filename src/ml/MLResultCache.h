#pragma once
#include <unordered_map>
#include <list>
#include <mutex>
#include <optional>
#include <cmath>
#include <chrono>
#include "Types.h"

/**
 * MLResultCache
 *
 * An LRU cache that memoizes ML anomaly scores for FeatureVector inputs.
 * Avoids calling the Python subprocess for flows whose features haven't
 * materially changed since the last scoring.
 *
 * Cache key: a discretized hash of the FeatureVector — each feature is
 * rounded to a configurable resolution before hashing, so nearly-identical
 * flows share a cache entry.
 *
 * Thread-safe: all operations protected by a mutex.
 */
class MLResultCache
{
public:
    struct CacheEntry
    {
        double score{0.0};
        std::chrono::steady_clock::time_point cachedAt;
    };

    explicit MLResultCache(size_t capacity = 512,
                           int ttlMs = 2000);

    // Look up a cached score. Returns nullopt on miss or stale entry.
    std::optional<double> get(const FeatureVector &fv) const;

    // Insert or update a score for the given feature vector.
    void put(const FeatureVector &fv, double score);

    void clear();
    size_t size() const;

    size_t hits() const { return m_hits; }
    size_t misses() const { return m_misses; }
    double hitRate() const
    {
        size_t total = m_hits + m_misses;
        return total == 0 ? 0.0 : static_cast<double>(m_hits) / total;
    }

    // Resolution buckets — tweak to trade precision for hit rate
    double bucketPacketRate{5.0};
    double bucketUniquePorts{1.0};
    double bucketSynCount{2.0};
    double bucketAvgPacketSize{50.0};
    double bucketConnectionCount{5.0};

private:
    uint64_t makeKey(const FeatureVector &fv) const;

    double bucket(double value, double resolution) const
    {
        if (resolution <= 0.0)
            return value;
        return std::round(value / resolution) * resolution;
    }

    // LRU: doubly-linked list (front = MRU) + hash map
    using KeyList = std::list<uint64_t>;

    struct MapEntry
    {
        CacheEntry data;
        KeyList::iterator listIt;
    };

    // All mutable: get() is logically const (read) but must update LRU order
    mutable std::mutex m_mutex;
    mutable std::unordered_map<uint64_t, MapEntry> m_map;
    mutable KeyList m_lruList;

    size_t m_capacity;
    int m_ttlMs;

    mutable size_t m_hits{0};
    mutable size_t m_misses{0};
};