#pragma once
#include <string>
#include <mutex>
#include "Types.h"

// ─────────────────────────────────────────────────────────────────────────────
//  MLBridge
//
//  Manages a persistent Python subprocess running ml_scorer.py.
//  Sends feature vectors via stdin, receives "score,label\n" via stdout.
//
//  Protocol:
//    → "pkt_rate,unique_ports,syn_count,avg_pkt_size,conn_count\n"
//    ← "0.8700,PortScan\n"
//
//  score : 0.0 = normal, 1.0 = anomaly  (Isolation Forest)
//  label : one of Normal / PortScan / DoS / DDoS / BruteForce /
//          Botnet / Infiltration / Other  (Random Forest)
//
//  Thread-safe: mutex guards all subprocess I/O.
// ─────────────────────────────────────────────────────────────────────────────

struct MLResult
{
    double score{0.0}; // anomaly score from Isolation Forest
    std::string label; // attack class  from Random Forest
};

class MLBridge
{
public:
    MLBridge();
    ~MLBridge();

    // Score a feature vector.
    // Returns {0.0, "Normal"} if the subprocess is not ready.
    MLResult score(const FeatureVector &fv);

    bool isReady() const { return m_ready; }

private:
    bool startProcess();
    void stopProcess();
    MLResult parseResponse(const std::string &line);

    FILE *m_write{nullptr}; // stdin  of Python process
    FILE *m_read{nullptr};  // stdout of Python process
    pid_t m_pid{-1};
    bool m_ready{false};
    std::mutex m_mutex;
};