# SDN Network & Service Slicing with Real-Time Monitoring Dashboard

This project implements both **Topology Slicing** and **Service Slicing** in a Software Defined Networking (SDN) environment, using **Mininet** as the network emulator and **Ryu** as the OpenFlow controller.

## 🧩 Features

### 🔀 Topology Slicing
- Enforced **static routing** between specific host pairs.
- Predefined network paths were configured directly via flow rules in the controller.

### 🎥 Service Slicing
- **Video traffic (UDP on port 9999)** was prioritized over other types of traffic.
- Flow rules dynamically redirected traffic over higher-bandwidth paths.

### 📊 Real-Time Monitoring Dashboard
- Built with **Flask** and **HTML/JavaScript**.
- Visualized per-flow statistics such as **bandwidth**, **packet count**, and **delay**.
- Charts and tables auto-refresh in real-time for interactive analysis.

### 🔍 Dynamic Traffic Classification
- Used **flow statistics** (e.g., bandwidth) to dynamically detect video-like traffic.
- Adapted routing in real-time by modifying flow entries based on observed throughput.

### 🧪 Traffic Generation & Testing
- Validated with **iPerf** (for UDP video traffic) and **D-ITG** (for diverse traffic profiles).
- Monitored actual traffic routes with **tcpdump** on specific switch interfaces.

## 🛠 Technologies Used

- **SDN Controller:** Ryu (OpenFlow 1.3)
- **Network Emulator:** Mininet
- **Traffic Generators:** iPerf, D-ITG
- **Dashboard Backend:** Flask
- **Dashboard Frontend:** HTML, CSS, JavaScript
- **Other Tools:** tcpdump, Linux shell utilities

## 📂 Structure

- `topology.py` – Custom Mininet network topology
- `controller.py` – Ryu controller implementing slicing logic
- `server.py` – Flask server exposing stats to frontend
- `table.html` – Dashboard UI for real-time flow monitoring

