#include "FlowTable.h"
#include <algorithm>

// ─── Constructor ─────────────────────────────────────────────────────────────
FlowTable::FlowTable(size_t maxFlows, int ttlSeconds)
    : m_maxFlows(maxFlows), m_ttlSeconds(ttlSeconds)
{
    m_map.reserve(maxFlows / 2);
}

// ─── upsert ──────────────────────────────────────────────────────────────────
bool FlowTable::upsert(const FlowKey &key, const FlowStats &stats)
{
    std::unique_lock lock(m_mutex);

    auto it = m_map.find(key);
    bool isNew = (it == m_map.end());

    if (isNew)
    {
        m_map[key] = Entry{stats, std::chrono::steady_clock::now()};
        ++m_totalInserts;
        enforceBound();
    }
    else
    {
        it->second.stats = stats;
        // Don't update insertedAt — keep original insertion time for TTL.
    }

    return isNew;
}

// ─── remove ──────────────────────────────────────────────────────────────────
bool FlowTable::remove(const FlowKey &key)
{
    std::unique_lock lock(m_mutex);
    return m_map.erase(key) > 0;
}

// ─── evictExpired ────────────────────────────────────────────────────────────
int FlowTable::evictExpired()
{
    auto cutoff = std::chrono::steady_clock::now() - std::chrono::seconds(m_ttlSeconds);

    std::unique_lock lock(m_mutex);
    int count = 0;
    for (auto it = m_map.begin(); it != m_map.end();)
    {
        if (it->second.stats.last_seen < cutoff)
        {
            it = m_map.erase(it);
            ++count;
            ++m_totalEvictions;
        }
        else
        {
            ++it;
        }
    }
    return count;
}

// ─── clear ───────────────────────────────────────────────────────────────────
void FlowTable::clear()
{
    std::unique_lock lock(m_mutex);
    m_map.clear();
}

// ─── get ─────────────────────────────────────────────────────────────────────
std::optional<FlowStats> FlowTable::get(const FlowKey &key) const
{
    std::shared_lock lock(m_mutex);
    auto it = m_map.find(key);
    if (it == m_map.end())
        return std::nullopt;
    return it->second.stats;
}

// ─── contains ────────────────────────────────────────────────────────────────
bool FlowTable::contains(const FlowKey &key) const
{
    std::shared_lock lock(m_mutex);
    return m_map.count(key) > 0;
}

// ─── size ────────────────────────────────────────────────────────────────────
size_t FlowTable::size() const
{
    std::shared_lock lock(m_mutex);
    return m_map.size();
}

// ─── forEachFlow ─────────────────────────────────────────────────────────────
void FlowTable::forEachFlow(
    const std::function<void(const FlowKey &, const FlowStats &)> &fn) const
{
    std::shared_lock lock(m_mutex);
    for (const auto &[key, entry] : m_map)
        fn(key, entry.stats);
}

// ─── filter ──────────────────────────────────────────────────────────────────
std::vector<FlowStats> FlowTable::filter(
    const std::function<bool(const FlowStats &)> &pred) const
{
    std::vector<FlowStats> result;
    std::shared_lock lock(m_mutex);
    result.reserve(m_map.size() / 4);
    for (const auto &[key, entry] : m_map)
        if (pred(entry.stats))
            result.push_back(entry.stats);
    return result;
}

// ─── topByPacketRate ─────────────────────────────────────────────────────────
std::vector<FlowStats> FlowTable::topByPacketRate(size_t n) const
{
    std::vector<FlowStats> all;
    {
        std::shared_lock lock(m_mutex);
        all.reserve(m_map.size());
        for (const auto &[key, entry] : m_map)
            all.push_back(entry.stats);
    }
    // Partial sort — O(N log k)
    if (n >= all.size())
    {
        std::sort(all.begin(), all.end(),
                  [](const FlowStats &a, const FlowStats &b)
                  {
                      return a.packet_rate > b.packet_rate;
                  });
        return all;
    }
    std::partial_sort(all.begin(), all.begin() + static_cast<long>(n), all.end(),
                      [](const FlowStats &a, const FlowStats &b)
                      {
                          return a.packet_rate > b.packet_rate;
                      });
    all.resize(n);
    return all;
}

// ─── enforceBound (private, called under exclusive lock) ─────────────────────
void FlowTable::enforceBound()
{
    if (m_map.size() <= m_maxFlows)
        return;

    // Find and remove the flow with the oldest last_seen time.
    // O(N) but only triggered when the table overflows, which is rare.
    auto oldest = m_map.begin();
    for (auto it = m_map.begin(); it != m_map.end(); ++it)
    {
        if (it->second.stats.last_seen < oldest->second.stats.last_seen)
            oldest = it;
    }
    m_map.erase(oldest);
    ++m_totalEvictions;
}