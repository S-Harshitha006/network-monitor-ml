🛰️ Network ML Analyzer
Real-Time Network Traffic Monitoring + Machine Learning Anomaly Detection

A high-performance real-time network traffic analyzer powered by Machine Learning, built with Flask, Scapy, and RandomForestClassifier.
Visualizes live bandwidth usage, packet details, destination trends, and classifies traffic as NORMAL or SUSPICIOUS — all inside a beautiful, dark-themed web dashboard.

🚀 Features
🔹 Real-Time Network Monitoring

Live Upload/Download speed graph (KB/s)

Packet rate (packets/sec)

Total packets captured

Recent packet table with:

Protocol

Source

Destination

ML Prediction (NORMAL / SUSPICIOUS)

🔹 ML-Powered Packet Classification

Uses trained ML model: packet_model.pkl

Extracts real-time packet metadata

Classifies packets instantly

Lightweight & optimized for low-latency monitoring

Model: RandomForestClassifier (high speed + accuracy)

🔹 Network Utility Tools

Built-in Traceroute

Configurable probing target (default: 8.8.8.8)

Real-time Top Destination IPs graph

🔹 Clean & Modern UI

Fully responsive dashboard

Dark theme

Auto-refreshing stats

Built with Flask + AJAX + Chart.js

🧠 Machine Learning Model

Model trained using features:

Packet size

Time delta between packets

Protocol

Source & destination ports

Derived behavioral metrics

Training Pipeline:

Capture packets → capture_packets_for_training.py

Clean dataset

Train RandomForest model → train_model.py

Save final model as packet_model.pkl 

network_ml/
│
├── dashboard.py                     # Flask UI dashboard
├── live_monitor.py                  # Live bandwidth + system monitor
├── live_ml_packets.py               # Real-time ML packet analyzer
├── capture_packets_for_training.py  # Dataset generator
├── train_model.py                   # ML model training
│
├── packet_model.pkl                 # Trained ML model
├── packets_dataset.csv              # Training dataset
├── traffic_data.csv                 # Monitoring dataset
│
├── venv/                            # Virtual environment
├── requirements.txt
└── .gitignore

🛠️ Installation
git clone <your-repo-url>
cd network_ml

1️⃣ Create & activate virtual environment
python -m venv venv
.\venv\Scripts\activate

2️⃣ Install dependencies
pip install -r requirements.txt

▶️ Run the Dashboard
python dashboard.py

Open your browser:

👉 http://127.0.0.1:8080

📊 How It Works

Captures packets using Scapy

Extracts ML-relevant features

Sends features to the ML model

Dashboard updates every few seconds

Data & predictions stay local and private

No cloud servers, no data sharing

🔐 Security Notes

✔ Processes all network data locally
✔ No packets sent to the internet
✔ Safe for academic, research, or personal projects

🤝 Contributing

Pull requests are welcome!

Ideas you can add:

Improved anomaly detection

UI redesign

Protocol-specific charts

Alerts / Notifications

Firewall rule automation

⭐ Support

If you like this project, please ⭐ star the repo on GitHub.
