# Intelligent Intrusion Detection System

A real-time, hybrid network intrusion detection system built in C++20. Captures live packets directly from the NIC, runs them through a multi-threaded processing pipeline, and detects threats using both a rule-based engine and a Python ML model — all with sub-millisecond alert latency.

Built and maintained over 8 months as a deep systems engineering project.

---

## Architecture

```
[NIC]
  ↓
[Kernel Module — ids_kmod.ko]        ← custom .ko intercepts at kernel level
  ↓
[PacketCapture — libpcap]            ← userspace capture via libpcap
  ↓
[PacketParser]                       ← dissects Ethernet → IP → TCP/UDP/ICMP
  ↓
[FeatureExtractor + FeatureNormalizer]
  ↓
[ProcessingPipeline — lock-free queue]
  ↓  
        ┌─────────────────────┬──────────────────────┐
   [RuleEngine]         [MLBridge → ml_scorer.py]   [FlowTracker]
   port scan            Random Forest / IForest      per-flow stats
   SYN flood            trained on CICIDS dataset    FlowTable
   ARP spoof            MLResultCache                
        └─────────────────────┴──────────────────────┘
  ↓
[DecisionEngine — fuses rule + ML output]
  ↓
[AlertsPanel — JSON events, <2ms latency]
  ↓
[Qt6 Dashboard — live traffic, alerts, metrics]
```

---

## What It Does

- **Live packet capture** from NIC using libpcap — no stored pcap files, pure stream processing
- **Custom kernel module** (`ids_kmod.ko`) that hooks into the kernel network stack
- **Dual detection engine:**
  - Rule engine catches known attacks: port scans, SYN floods, ARP spoofing, brute-force
  - ML bridge calls a Python Random Forest model trained on the CICIDS2017 dataset for anomaly detection
- **Lock-free packet queue** between capture and analysis threads — sustained throughput in load tests
- **Per-flow tracking** via FlowTable and FlowTracker for stateful connection analysis
- **Adaptive thresholds** that adjust to baseline traffic patterns
- **Qt6 dashboard** with live traffic graph, alert feed, suspicious IP table, and performance metrics

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | C++20 |
| Packet Capture | libpcap |
| Kernel Integration | Custom Linux Kernel Module (.ko) |
| ML Inference | Python 3, scikit-learn (Random Forest, Isolation Forest) |
| Training Data | CICIDS2017 Dataset (real attack traffic) |
| UI | Qt6 (Widgets, Charts) |
| Build System | CMake 3.20+ |
| IPC (C++ ↔ Python) | MLBridge subprocess / pipe |

---

## Project Structure

```
├── Core/
│   ├── capture/        # PacketCapture (libpcap), NetlinkReceiver
│   ├── parser/         # PacketParser — full protocol dissection
│   ├── features/       # FeatureExtractor, FeatureNormalizer
│   ├── pipeline/       # ProcessingPipeline, lock-free PacketQueue
│   ├── detection/      # RuleEngine, DecisionEngine, AdaptiveThreshold
│   ├── flow/           # FlowTracker, FlowTable
│   ├── ml/             # MLBridge (C++ → Python), MLResultCache
│   ├── metrics/        # PerformanceMonitor, SystemStats
│   └── ui/             # Qt6 dashboard components
├── Kernel_module/      # ids_kmod.c — custom .ko kernel module
├── ml/                 # train_model.py, ml_scorer.py, model_rf.pkl
├── MachineLearningCVE/ # CICIDS2017 dataset (real attack pcap CSVs)
├── tests/              # 4 test suites + simulate_attack.sh
└── docs/               # Architecture diagrams, demo guide, pipeline SVG
```

---

## Build & Run

### Prerequisites

```bash
sudo apt update
sudo apt install build-essential cmake qt6-base-dev qt6-charts-dev libpcap-dev pkg-config python3 python3-pip
pip3 install -r ml/requirements.txt
```

### Build Kernel Module

```bash
cd Kernel_module/
make
sudo make load       # insmod
# to unload: sudo make unload
```

### Build & Run IDS

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo ./IDS_System     # root required for raw packet capture
```

### Train ML Model (optional — pretrained pkl included)

```bash
cd ml/
python3 preprocess.py --input ../MachineLearningCVE --output .
python3 train_model.py --data . --output .
```

---

## Run Tests

```bash
cd build/
./test_parser       # packet parser unit tests
./test_rules        # rule engine tests
./test_flow         # flow tracker tests
./test_comprehensive  # end-to-end pipeline test

# Simulate attacks against a running instance
bash tests/simulate_attack.sh
```

---

## Detection Capabilities

| Attack Type | Detection Method |
|---|---|
| Port Scan | Rule engine — rapid multi-port access detection |
| SYN Flood | Rule engine — SYN rate threshold + AdaptiveThreshold |
| ARP Spoofing | Rule engine — ARP table anomaly detection |
| Brute Force | Rule engine — connection burst detection |
| Unknown/Zero-day | ML engine — Isolation Forest anomaly scoring |
| Traffic Anomalies | ML engine — Random Forest trained on CICIDS2017 |

---

## Performance

- Lock-free queue between capture and analysis threads eliminates blocking
- MLResultCache prevents redundant inference calls for repeated flow patterns
- PerformanceMonitor tracks live throughput and detection latency

---

## Dataset

Uses the **CICIDS2017 dataset** from the Canadian Institute for Cybersecurity — real attack traffic including DDoS, PortScan, Web Attacks, and Infiltration scenarios across multiple days.

---

## Demo

A demo recording is available in the repo: `video_20260410_004930.mp4`

Architecture diagrams and pipeline flow SVG are in `docs/`.
