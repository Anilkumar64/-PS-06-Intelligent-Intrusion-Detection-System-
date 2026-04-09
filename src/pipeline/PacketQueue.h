#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <chrono>

/**
 * PacketQueue<T>
 * Thread-safe bounded FIFO queue used between pipeline stages.
 * Producers call push(); consumers call pop() or tryPop().
 */
template <typename T>
class PacketQueue
{
public:
    explicit PacketQueue(size_t maxSize = 8192)
        : m_maxSize(maxSize) {}

    // Push item. Drops oldest if full (backpressure: never blocks producer).
    void push(T item)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queue.size() >= m_maxSize)
        {
            m_queue.pop(); // drop oldest
            ++m_dropped;
        }
        m_queue.push(std::move(item));
        m_cv.notify_one();
    }

    // Blocking pop — waits up to timeoutMs. Returns nullopt on timeout/shutdown.
    std::optional<T> pop(int timeoutMs = 100)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (!m_cv.wait_for(lock,
                           std::chrono::milliseconds(timeoutMs),
                           [this]
                           { return !m_queue.empty() || m_shutdown; }))
            return std::nullopt;

        if (m_shutdown && m_queue.empty())
            return std::nullopt;

        T item = std::move(m_queue.front());
        m_queue.pop();
        return item;
    }

    // Non-blocking try-pop.
    std::optional<T> tryPop()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queue.empty())
            return std::nullopt;
        T item = std::move(m_queue.front());
        m_queue.pop();
        return item;
    }

    void shutdown()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shutdown = true;
        m_cv.notify_all();
    }

    void reset()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        while (!m_queue.empty())
            m_queue.pop();
        m_shutdown = false;
        m_dropped = 0;
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.size();
    }

    uint64_t dropped() const { return m_dropped; }

private:
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::queue<T> m_queue;
    size_t m_maxSize;
    bool m_shutdown{false};
    uint64_t m_dropped{0};
};