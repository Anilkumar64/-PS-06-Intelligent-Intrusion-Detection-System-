#include "MLBridge.h"
#include <cstdio>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <QDebug>
#include <QString>

// ── Constructor / Destructor ────────────────────────────────────────────────
MLBridge::MLBridge()
{
    m_ready = startProcess();
}

MLBridge::~MLBridge()
{
    stopProcess();
}

// ── Start Python subprocess ─────────────────────────────────────────────────
bool MLBridge::startProcess()
{
    int in_pipe[2], out_pipe[2];
    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0)
        return false;

    m_pid = fork();
    if (m_pid < 0)
        return false;

    if (m_pid == 0)
    {
        // Child — wire up pipes then exec Python
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        close(in_pipe[0]);
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);

        // ml_scorer.py must be in the working directory (build/)
        execlp("python3", "python3", "ml_scorer.py", nullptr);
        execlp("python", "python", "ml_scorer.py", nullptr);
        _exit(1);
    }

    // Parent
    close(in_pipe[0]);
    close(out_pipe[1]);

    m_write = fdopen(in_pipe[1], "w");
    m_read = fdopen(out_pipe[0], "r");

    if (!m_write || !m_read)
        return false;

    // Wait for "READY\n" handshake — ml_scorer.py prints this after loading
    // both model_iforest.pkl and model_rf.pkl
    char buf[32] = {};
    if (fgets(buf, sizeof(buf), m_read) == nullptr)
        return false;

    return (strncmp(buf, "READY", 5) == 0);
}

// ── Stop Python subprocess ──────────────────────────────────────────────────
void MLBridge::stopProcess()
{
    if (m_write)
    {
        fclose(m_write);
        m_write = nullptr;
    }
    if (m_read)
    {
        fclose(m_read);
        m_read = nullptr;
    }

    if (m_pid > 0)
    {
        kill(m_pid, SIGTERM);
        waitpid(m_pid, nullptr, 0);
        m_pid = -1;
    }
    m_ready = false;
}

// ── Score a feature vector ──────────────────────────────────────────────────
MLResult MLBridge::score(const FeatureVector &fv)
{
    // If ML not ready → safe fallback
    if (!m_ready || !m_write || !m_read)
    {
        qDebug() << "MLBridge: NOT READY — returning Normal";
        return {0.0, "Normal"};
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    // 🔥 DEBUG: Always print what we send to ML
    qDebug() << "ML INPUT:"
             << fv.packet_rate
             << fv.unique_ports
             << fv.syn_count
             << fv.avg_packet_size
             << fv.connection_count
             << "syn_ratio=" << fv.syn_ratio
             << "scan_rate=" << fv.port_scan_rate;

    // Send features to Python — 8 features now
    int ret = fprintf(m_write, "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f\n",
                      fv.packet_rate,
                      fv.unique_ports,
                      fv.syn_count,
                      fv.avg_packet_size,
                      fv.connection_count,
                      fv.syn_ratio,
                      fv.port_scan_rate,
                      fv.bytes_per_sec);

    if (ret < 0)
    {
        qDebug() << "MLBridge: WRITE FAILED";
        m_ready = false;
        return {0.0, "Normal"};
    }

    fflush(m_write);

    // Read response from Python
    char buf[128] = {};
    if (fgets(buf, sizeof(buf), m_read) == nullptr)
    {
        qDebug() << "MLBridge: READ FAILED — Python may have crashed";
        m_ready = false;
        return {0.0, "Normal"};
    }

    std::string response(buf);

    // 🔥 DEBUG: Show raw response
    qDebug() << "ML OUTPUT:" << QString::fromStdString(response);

    // Parse response safely
    try
    {
        return parseResponse(response);
    }
    catch (...)
    {
        qDebug() << "MLBridge: PARSE FAILED — bad response:" << QString::fromStdString(response);
        return {0.0, "Normal"};
    }
}

// ── Parse "score,label\n" response ─────────────────────────────────────────
MLResult MLBridge::parseResponse(const std::string &line)
{
    MLResult result{0.0, "Normal"};

    // Find the comma separating score from label
    auto comma = line.find(',');
    if (comma == std::string::npos)
    {
        // Old single-value format or error — parse as score only
        try
        {
            result.score = std::stod(line);
        }
        catch (...)
        {
        }
        return result;
    }

    try
    {
        result.score = std::stod(line.substr(0, comma));
    }
    catch (...)
    {
        result.score = 0.0;
    }

    // Strip trailing newline/whitespace from label
    std::string label = line.substr(comma + 1);
    while (!label.empty() &&
           (label.back() == '\n' || label.back() == '\r' ||
            label.back() == ' '))
        label.pop_back();

    if (!label.empty())
        result.label = label;

    return result;
}