#pragma once
#include <unordered_map>
#include <shared_mutex>
#include <optional>
#include <vector>
#include <mutex>
#include <functional>
#include <chrono>
#include "Types.h"

/**
 * FlowTable
 *
 * A thread-safe, concurrent hash-map of active network flows keyed by FlowKey.
 * Designed for the pattern where:
 *   - One capture thread writes (inserts/updates) at high frequency.
 *   - One or more detection threads read concurrently.
 *
 * Uses std::shared_mutex (readers-writer lock):
 *   - Multiple detection threads can read simultaneously (shared lock).
 *   - Capture thread takes exclusive lock only during updates.
 *
 * Also supports:
 *   - TTL-based eviction: flows idle longer than ttlSeconds are expired.
 *   - Bounded size: when maxFlows is exceeded, the oldest flows are removed.
 *   - Snapshot iteration: forEachFlow() takes a shared lock and calls a
 *     callback for each entry safely.
 */
class FlowTable
{
public:
    explicit FlowTable(size_t maxFlows = 65536,
                       int ttlSeconds = 30);

    // ── Write operations (exclusive lock) ────────────────────────────────

    // Insert or update a flow. Returns true if it was a new entry.
    bool upsert(const FlowKey &key, const FlowStats &stats);

    // Remove a specific flow. Returns true if found and removed.
    bool remove(const FlowKey &key);

    // Evict flows older than ttlSeconds. Returns count evicted.
    int evictExpired();

    // Remove all flows.
    void clear();

    // ── Read operations (shared lock) ────────────────────────────────────

    // Look up a flow. Returns nullopt if not found.
    std::optional<FlowStats> get(const FlowKey &key) const;

    // Returns true if the key exists.
    bool contains(const FlowKey &key) const;

    // Number of active flows.
    size_t size() const;

    // Iterate all flows under a shared lock.
    // Callback signature: void(const FlowKey&, const FlowStats&)
    void forEachFlow(const std::function<void(const FlowKey &,
                                              const FlowStats &)> &fn) const;

    // Collect all flows matching a predicate into a vector.
    // Useful for building the "Suspicious IP Table" snapshot.
    std::vector<FlowStats> filter(
        const std::function<bool(const FlowStats &)> &pred) const;

    // Return up to N flows with the highest packet_rate.
    std::vector<FlowStats> topByPacketRate(size_t n) const;

    // ── Stats ─────────────────────────────────────────────────────────────
    size_t totalInserts() const { return m_totalInserts; }
    size_t totalEvictions() const { return m_totalEvictions; }

private:
    void enforceBound(); // called under exclusive lock

    struct Entry
    {
        FlowStats stats;
        std::chrono::steady_clock::time_point insertedAt;
    };

    mutable std::shared_mutex m_mutex;
    std::unordered_map<FlowKey, Entry, FlowKeyHash> m_map;

    size_t m_maxFlows;
    int m_ttlSeconds;

    size_t m_totalInserts{0};
    size_t m_totalEvictions{0};
};