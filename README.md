🛰️ Network ML Analyzer

A real-time network traffic monitoring dashboard enhanced with Machine Learning for anomaly detection.
The system captures live packets, analyzes upload/download speed, shows destination trends, and uses an ML model to classify packets as NORMAL or SUSPICIOUS — all running in a Fast, Beautiful Web Dashboard (Flask).

🚀 Features
🔹 Real-Time Monitoring

Live upload & download speed graph (KB/s)

Packet rate (packets/sec)

Total packets captured

Recent packet list with protocol, source, destination, and ML prediction

🔹 ML-Powered Packet Classification

Trained ML model (packet_model.pkl)

Reads packet metadata in real time

Labels packets:
NORMAL or SUSPICIOUS

Lightweight & fast for live monitoring

🔹 Extra Network Tools

Traceroute utility

Configurable probe target (8.8.8.8 by default)

Live top destinations visualization

🔹 Clean, Responsive UI

Dark-themed dashboard

Fully browser-based

Updates automatically every few seconds

🧠 Machine Learning Model

The ML model is trained using:

Packet size

Time delta

Protocol type

Source/Destination ports

Additional derived network metrics

Steps included:

Packet capture for dataset creation (capture_packets_for_training.py)

Dataset cleaning/processing

Model training (train_model.py)

Saving model → packet_model.pkl

Model used: RandomForestClassifier (for speed + accuracy)

📂 Project Structure
network_ml/
│
├── dashboard.py                 # Main Flask dashboard
├── live_monitor.py              # Live system usage monitor
├── live_ml_packets.py           # ML classifier for live packets
├── capture_packets_for_training.py
├── train_model.py
│
├── packet_model.pkl             # Trained ML model
├── packets_dataset.csv          # Training dataset
├── traffic_data.csv             # Monitoring dataset
│
├── venv/                        # Virtual environment
├── .gitignore
└── requirements.txt

🛠️ Installation
cd network_ml

2️⃣ Create & activate virtual environment
python -m venv venv
.\venv\Scripts\activate

3️⃣ Install dependencies
pip install -r requirements.txt

▶️ Run the Dashboard

Start the live web dashboard:

python dashboard.py


Then open in browser:

http://127.0.0.1:8080

📊 How the Dashboard Works

Captures packets using Scapy

Extracts key features from each packet

Sends features to ML model

Updates dashboard every X seconds via AJAX

Displays predictions and statistical graphs

Everything runs locally — no external server needed.

🔐 Security Notes

Does NOT send any packet data to the internet

All processing happens on your machine

Safe for personal use & academic projects

🤝 Contributing

Pull requests are welcome.
New ideas: ML improvements, UI redesign, protocol breakdown, alerts system, firewall integration.

⭐ Support

If you like this project, consider giving the repo a star ⭐ on GitHub.
