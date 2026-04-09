
# 🛡️ Intelligent Intrusion Detection System (PS-06)

## 📌 Overview

The **Intelligent Intrusion Detection System (IDS)** is designed to address the increasing complexity and scale of modern cyber threats by providing a **real-time, adaptive, and high-performance network monitoring solution**.

Traditional IDS solutions rely heavily on static signatures, making them ineffective against **zero-day attacks and evolving threat patterns**. This project proposes a **hybrid detection system** that combines:

* ⚡ Rule-based detection (fast, deterministic)
* 🧠 Machine learning-based anomaly detection (adaptive, intelligent)

The system focuses on **real-time packet analysis**, enabling early detection of suspicious activities before they escalate into full-scale attacks.

---

## 🧠 System Approach (Mental Model)

The entire system is designed as a **real-time packet processing pipeline**:

```text
[Internet Traffic]
        ↓
[NIC (Network Interface Card)]
        ↓
[Kernel Network Stack → sk_buff]
        ↓
[Packet Capture (libpcap)]
        ↓
[Feature Extraction Engine]
        ↓
[Detection Engine (Rules + AI)]
        ↓
[Decision Engine]
        ↓
[Alerting & Logging System]
```

👉 The key idea:
**We do not store packets — we process them as a continuous stream.**

---

## ⚙️ How It Works

### 1. Packet Ingestion

* Incoming packets arrive at the **NIC**
* The Linux kernel processes them and represents each packet as an **`sk_buff` structure**
* The IDS taps into this flow using **libpcap**, without modifying kernel behavior

---

### 2. Packet Capture

* Using `libpcap`, the system captures **live network packets in real-time**
* Captured data includes:

  * Source IP
  * Destination IP
  * Port numbers
  * Protocol (TCP/UDP/ICMP)
  * Packet size
  * Timestamp

---

### 3. Feature Extraction

Raw packet data is transformed into structured features:

```json
{
  "src_ip": "192.168.1.10",
  "dst_ip": "8.8.8.8",
  "port": 443,
  "protocol": "TCP",
  "packet_rate": 120
}
```

These features represent **behavioral patterns**, not just raw data.

---

### 4. Detection Engine

#### 🔹 Rule-Based Detection

The first layer detects known attack patterns:

* Port scanning (multiple ports accessed rapidly)
* SYN flood attacks (high SYN packet rate)
* Abnormal connection bursts

👉 Provides **instant and deterministic detection**

---

#### 🔹 AI-Based Anomaly Detection

The second layer detects unknown threats using unsupervised learning:

* Models used:

  * Isolation Forest
  * One-Class SVM

👉 Key idea:

* AI does **not analyze raw packets**
* It analyzes **derived behavioral features**

Example input to model:

```text
[packet_rate, unique_ports, avg_packet_size, connection_count]
```

The model learns **normal network behavior** and flags deviations as anomalies.

---

### 5. Decision Engine

Outputs from both detection layers are combined:

```text
Rule Engine + AI Model → Final Classification
```

Classification:

* ✅ Normal
* ⚠️ Suspicious
* 🚨 Attack

---

### 6. Alerting & Logging

Detected threats are logged with full context:

```text
[ALERT]
IP: 192.168.1.5
Type: Port Scan
Reason: Accessed 200 ports in 2 seconds
```

The system provides:

* Real-time alerts
* Attack classification
* Detailed reasoning

---

## 🚀 Key Features

* ⚡ Real-time packet processing (no batch delays)
* 🧠 Hybrid detection (rules + AI)
* 📊 Behavioral analysis instead of static signatures
* 🔍 Explainable alerts (reason-based detection)
* 🧵 Multi-threaded processing for scalability
* 🧪 Attack simulation support (e.g., port scan, DoS)

---

## 🏗️ Tech Stack

### Core System

* C++20 (high-performance backend)
* libpcap (packet capture)
* Multithreading (parallel processing)

### Machine Learning

* Python (scikit-learn)
* Isolation Forest / One-Class SVM

### Visualization (Optional)

* CLI / Web dashboard (Flask / Node.js)

---

## 🧪 Testing & Simulation

The system supports simulated attack scenarios:

* Port scanning (`nmap`)
* SYN flood / DoS simulation
* Abnormal traffic generation

Performance metrics:

* Detection latency
* Throughput (packets/sec)
* Accuracy of anomaly detection

---

## 💣 Core Insight

> This system is not just an IDS — it is a **real-time packet stream analyzer with intelligent behavioral detection**.

---

## ⚠️ Design Principles

* No dependency on stored datasets
* No centralized packet storage
* Stream-based processing architecture
* Focus on low latency and real-time response

---

## 🔮 Future Enhancements

* Distributed IDS across multiple nodes
* Integration with firewalls for auto-blocking
* Deep packet inspection (DPI)
* Online learning models
* Cloud-based monitoring dashboard

---

## 🧩 Conclusion

By combining **efficient systems programming (C++)** with **intelligent anomaly detection**, this project delivers a scalable and adaptive IDS capable of detecting both known and unknown cyber threats in real time.

It demonstrates a strong integration of:

* Systems-level networking
* Real-time data processing
* Applied machine learning


#Working

Department 1 — Kernel
bashcd kernel_module/
make          # build .ko
sudo make load    # insmod
sudo make unload  # rmmod


Department 2 — Backend + GUI
bashcd core/
mkdir build && cd build
cmake .. && make -j$(nproc)
sudo ./IDS_System

Department 3 — ML
bashcd ml/
python3 preprocess.py --input ../MachineLearningCVE --output .
python3 train_model.py --data . --output .
# models stay here, core/ binary reads them at runtime