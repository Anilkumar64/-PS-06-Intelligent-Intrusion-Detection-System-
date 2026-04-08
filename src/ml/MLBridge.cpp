#include "MLBridge.h"
#include <cstdio>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

MLBridge::MLBridge()
{
    m_ready = startProcess();
}

MLBridge::~MLBridge()
{
    stopProcess();
}

bool MLBridge::startProcess()
{
    // Two pipes: parent→child (stdin) and child→parent (stdout)
    int in_pipe[2], out_pipe[2];
    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0)
        return false;

    m_pid = fork();
    if (m_pid < 0)
        return false;

    if (m_pid == 0)
    {
        // Child: wire up pipes and exec Python
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        close(in_pipe[0]);
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);

        // Look for ml_scorer.py next to executable
        execlp("python3", "python3", "ml_scorer.py", nullptr);
        // fallback
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

    // Read the "READY" handshake line
    char buf[64] = {};
    if (fgets(buf, sizeof(buf), m_read) == nullptr)
        return false;

    return (strncmp(buf, "READY", 5) == 0);
}

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

double MLBridge::score(const FeatureVector &fv)
{
    if (!m_ready)
        return 0.0;

    std::lock_guard<std::mutex> lock(m_mutex);

    // Send CSV line: packet_rate,unique_ports,syn_count,avg_packet_size,connection_count
    fprintf(m_write, "%.4f,%.4f,%.4f,%.4f,%.4f\n",
            fv.packet_rate, fv.unique_ports, fv.syn_count,
            fv.avg_packet_size, fv.connection_count);
    fflush(m_write);

    // Read response line
    char buf[64] = {};
    if (fgets(buf, sizeof(buf), m_read) == nullptr)
    {
        m_ready = false;
        return 0.0;
    }

    return parseResponse(std::string(buf));
}

double MLBridge::parseResponse(const std::string &line)
{
    try
    {
        return std::stod(line);
    }
    catch (...)
    {
        return 0.0;
    }
}