#pragma once
#include <string>
#include <mutex>
#include "Types.h"

// Calls the Python Isolation Forest scorer via subprocess pipe.
// Thread-safe: uses a mutex around process stdin/stdout.
class MLBridge
{
public:
    MLBridge();
    ~MLBridge();

    // Returns anomaly score: 0.0 = normal, 1.0 = anomaly
    double score(const FeatureVector &fv);

    bool isReady() const { return m_ready; }

private:
    bool startProcess();
    void stopProcess();

    double parseResponse(const std::string &line);
    static std::string resolveScriptPath(const char *scriptName);

    FILE *m_write{nullptr}; // stdin  of Python process
    FILE *m_read{nullptr};  // stdout of Python process
    pid_t m_pid{-1};
    bool m_ready{false};
    std::mutex m_mutex;
};
