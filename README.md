# 🛰️ Network ML Analyzer

Real-time network traffic monitoring with Machine Learning anomaly detection. Built with Flask, Scapy, and a RandomForestClassifier, this project visualizes live bandwidth, packet details, destination trends, and classifies traffic as NORMAL or SUSPICIOUS in a dark-themed web dashboard.

---

## Table of Contents
- [Features](#features)
- [Project Structure](#project-structure)
- [Machine Learning Model](#machine-learning-model)
- [Training Pipeline](#training-pipeline)
- [Installation](#installation)
- [Usage](#usage)
- [Security Notes](#security-notes)
- [Contributing](#contributing)
- [Support](#support)

---

## Features

- Real-Time Network Monitoring
  - Live upload/download speed graph (KB/s)
  - Packet rate (packets/sec)
  - Total packets captured
  - Recent packet table showing Protocol, Source, Destination, and ML Prediction (NORMAL / SUSPICIOUS)

- ML-Powered Packet Classification
  - Uses a trained ML model (`packet_model.pkl`)
  - Extracts real-time packet metadata and classifies packets with low latency
  - Model: RandomForestClassifier (balanced for speed and accuracy)

- Network Utilities
  - Built-in traceroute with configurable target (default: `8.8.8.8`)
  - Real-time top destination IPs graph

- UI
  - Responsive, dark-themed dashboard built with Flask + AJAX + Chart.js
  - Auto-refreshing stats and visualizations

---

## Project Structure

network_ml/
├── dashboard.py                     # Flask UI dashboard  
├── live_monitor.py                  # Live bandwidth + system monitor  
├── live_ml_packets.py               # Real-time ML packet analyzer  
├── capture_packets_for_training.py  # Dataset generator  
├── train_model.py                   # ML model training  
├── packet_model.pkl                 # Trained ML model (binary)  
├── packets_dataset.csv              # Training dataset (CSV)  
├── traffic_data.csv                 # Monitoring dataset (CSV)  
├── requirements.txt  
├── .gitignore  
└── venv/                            # Virtual environment (should not be committed)

---

## Machine Learning Model

- Features used for training:
  - Packet size
  - Time delta between packets
  - Protocol
  - Source & destination ports
  - Derived behavioral metrics

- Model file: `packet_model.pkl` (RandomForestClassifier)

---

## Training Pipeline

1. Capture packets: `capture_packets_for_training.py`
2. Clean & prepare dataset (`packets_dataset.csv`)
3. Train model: `train_model.py`
4. Save final model as `packet_model.pkl`

---

## Installation

Clone the repository and install dependencies.

```bash
git clone https://github.com/S-Harshitha006/network-monitor-ml.git
cd network-monitor-ml
```

Create & activate a virtual environment:

- On macOS / Linux:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

- On Windows (PowerShell):
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```

- On Windows (cmd):
  ```cmd
  python -m venv venv
  .\venv\Scripts\activate
  ```

Install dependencies:
```bash
pip install -r requirements.txt
```

Note: Consider adding `venv/` to `.gitignore` if not already excluded.

---

## Usage

Start the dashboard:
```bash
python dashboard.py
```

Open your browser to:
http://127.0.0.1:8080

(If the port is configurable in `dashboard.py`, adjust the URL accordingly.)

---

## Security Notes

- All packet capture and ML inference happen locally.
- No packet data is sent to external servers by the project itself.
- Use this project for academic, research, or personal projects; ensure you comply with local laws and network policies before capturing traffic.

---

## Contributing

Contributions are welcome! Ideas to improve:
- Improved anomaly detection models
- UI redesign and accessibility enhancements
- Protocol-specific charts and insights
- Alerts / notifications and firewall automation
- Better dataset cleaning / feature engineering

Please open issues or submit pull requests.

---

## Support

If you find this project helpful, please star the repository on GitHub.
