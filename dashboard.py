"""
dashboard.py
Live packet + network diagnostics dashboard (Flask + Chart.js) with IsolationForest anomaly detection.

Run as Administrator (Windows) because packet sniffing requires elevated privileges.

Usage:
    python dashboard.py
Open browser: http://127.0.0.1:8080/
"""

import threading
import time
import psutil
import json
import subprocess
import platform
from collections import deque, Counter
from flask import Flask, render_template_string, jsonify, request
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNSQR
import socket
import os
import traceback

# ML imports
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import pandas as pd

# -------------------------
# CONFIG
# -------------------------
PORT = 8080
MAX_RECENT = 200  # keep last N packets in memory
PACKETS_WINDOW = 5  # seconds window for packets/sec calculation

MODEL_FILE = "packet_model.pkl"            # model filename
DATASET_FILE = "packets_dataset.csv"       # dataset used to (auto)train model if model missing
CONTAMINATION = 0.01                       # expected fraction of anomalies in training (adjustable)

# -------------------------
# Shared state
# -------------------------
net_state = {
    "upload_kbps": 0.0,
    "download_kbps": 0.0,
    "packets_per_sec": 0.0,
    "total_packets": 0,
}

recent_packets = deque(maxlen=MAX_RECENT)
packet_timestamps = deque()
dest_counter = Counter()

probe_state = {
    "last_target": None,
    "latency_ms": None,
    "packet_loss_pct": None,
    "jitter_ms": None,
    "traceroute": [],
    "last_probe_time": None
}

app = Flask(__name__)

# -------------------------
# UTIL FUNCTIONS
# -------------------------
def try_resolve(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def bytes_to_kb(b):
    return round(b / 1024.0, 2)

# -------------------------
# ML: load or train IsolationForest
# -------------------------
def proto_to_code(proto_str):
    # Map string proto to numeric code (TCP=6, UDP=17, IP=0/other)
    if proto_str == "TCP":
        return 6
    if proto_str == "UDP":
        return 17
    if proto_str == "ICMP":
        return 1
    return 0

def prepare_features_df(df):
    # ensure correct columns: ['size','proto','sport','dport','ttl']
    df = df.copy()
    if 'proto' in df.columns:
        df['proto_code'] = df['proto'].map({'TCP':6,'UDP':17,'ICMP':1}).fillna(0)
    else:
        df['proto_code'] = 0
    # fill missing ports/ttl
    for c in ['size','sport','dport','ttl']:
        if c not in df.columns:
            df[c] = 0
    X = df[['size','proto_code','sport','dport','ttl']].fillna(0).astype(float)
    return X

def load_or_train_model():
    # If model file exists, load it. Otherwise try to train from DATASET_FILE.
    if os.path.exists(MODEL_FILE):
        try:
            model = joblib.load(MODEL_FILE)
            print("Loaded model from", MODEL_FILE)
            return model
        except Exception as e:
            print("Failed to load model:", e)
            traceback.print_exc()

    # Train model from dataset if possible
    if os.path.exists(DATASET_FILE):
        try:
            print("Training IsolationForest from", DATASET_FILE)
            df = pd.read_csv(DATASET_FILE)
            X = prepare_features_df(df)
            model = IsolationForest(n_estimators=200, contamination=CONTAMINATION, random_state=42)
            model.fit(X)
            joblib.dump(model, MODEL_FILE)
            print("Trained and saved model to", MODEL_FILE)
            return model
        except Exception as e:
            print("Training failed:", e)
            traceback.print_exc()
    else:
        print("No model file and no dataset file found. Creating a default (untrained) IsolationForest.")
        # create a default model (will not be helpful until trained)
        model = IsolationForest(n_estimators=200, contamination=CONTAMINATION, random_state=42)
        return model

# Load model at startup
ml_model = load_or_train_model()

# Helper to get anomaly label and score
def model_predict_label_and_score(size, proto_code, sport, dport, ttl):
    try:
        features = np.array([[size, proto_code, sport, dport, ttl]], dtype=float)
        pred = ml_model.predict(features)[0]            # 1 = inlier (normal), -1 = outlier (anomaly)
        # decision_function -> higher means more normal; we'll convert to anomaly score 0..1
        score_raw = ml_model.decision_function(features)[0]  # higher is more normal
        # turn into anomaly_probability: lower score_raw -> higher anomaly prob
        # normalize using a logistic-like scaling (simple)
        anomaly_prob = 1.0 - (1.0 / (1.0 + np.exp(score_raw)))  # value between 0..1 (approx)
        label = "SUSPICIOUS" if int(pred) == -1 else "NORMAL"
        return label, float(round(anomaly_prob, 3))
    except Exception as e:
        # if model not ready or any error, default to NORMAL, prob 0.0
        return "NORMAL", 0.0

# -------------------------
# PACKET SNIFFER THREAD (modified to include ML)
# -------------------------
def packet_handler(pkt):
    """Called by scapy for each captured packet."""
    ts = time.time()
    packet_timestamps.append(ts)
    net_state["total_packets"] += 1

    proto = "OTHER"
    src = dst = None
    size = len(pkt)
    sport = dport = ttl = 0

    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        ttl = getattr(pkt[IP], "ttl", 0)

        if pkt.haslayer(TCP):
            proto = "TCP"
            sport = getattr(pkt[TCP], "sport", 0)
            dport = getattr(pkt[TCP], "dport", 0)
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = getattr(pkt[UDP], "sport", 0)
            dport = getattr(pkt[UDP], "dport", 0)
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        # DNS Query (optional)
        if pkt.haslayer(DNSQR):
            try:
                q = pkt[DNSQR].qname.decode().rstrip(".")
            except:
                q = None

        # ML prediction
        proto_code = proto_to_code(proto)
        ml_label, ml_prob = model_predict_label_and_score(size, proto_code, sport, dport, ttl)

        rec = {
            "time": time.strftime("%H:%M:%S", time.localtime(ts)),
            "proto": proto,
            "src": src,
            "dst": try_resolve(dst) or dst,
            "size": int(size),
            "sport": int(sport),
            "dport": int(dport),
            "ttl": int(ttl),
            "ml_label": ml_label,
            "ml_prob": ml_prob
        }

        recent_packets.appendleft(rec)
        dest_counter[rec["dst"]] += 1

def sniff_thread_func():
    # sniff on all interfaces, store=False for memory efficiency
    sniff(prn=packet_handler, store=False)

# -------------------------
# NETWORK SPEED THREAD
# -------------------------
def net_speed_thread():
    global net_state
    last = psutil.net_io_counters()
    last_time = time.time()
    while True:
        time.sleep(1)
        now = psutil.net_io_counters()
        now_time = time.time()
        dt = now_time - last_time
        if dt <= 0:
            continue
        sent = now.bytes_sent - last.bytes_sent
        recv = now.bytes_recv - last.bytes_recv
        net_state["upload_kbps"] = round((sent / dt) / 1024.0, 2)
        net_state["download_kbps"] = round((recv / dt) / 1024.0, 2)

        # packets per sec
        cutoff = time.time() - PACKETS_WINDOW
        while packet_timestamps and packet_timestamps[0] < cutoff:
            packet_timestamps.popleft()
        pps = len(packet_timestamps) / PACKETS_WINDOW
        net_state["packets_per_sec"] = round(pps, 2)

        last = now
        last_time = now_time

# -------------------------
# PING / JITTER / PACKET LOSS (uses system ping)
# -------------------------
def probe_host(host, count=6):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", host, "-n", str(count)]
    else:
        cmd = ["ping", host, "-c", str(count)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        out = proc.stdout
        loss = None
        avg = None
        jitter = None
        if system == "windows":
            import re
            m = re.search(r"Lost = \d+ \((\d+)% loss\)", out)
            if m:
                loss = int(m.group(1))
            m2 = re.search(r"Average = (\d+)ms", out)
            if m2:
                avg = float(m2.group(1))
            mmin = re.search(r"Minimum = (\d+)ms", out)
            mmax = re.search(r"Maximum = (\d+)ms", out)
            if mmin and mmax:
                jitter = float(int(mmax.group(1)) - int(mmin.group(1)))
        else:
            import re
            m = re.search(r"(\d+)% packet loss", out)
            if m:
                loss = int(m.group(1))
            m2 = re.search(r"rtt [\w/ ]+= ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+) ms", out)
            if m2:
                avg = float(m2.group(2))
                jitter = float(m2.group(4))
        return {"latency_ms": avg, "packet_loss_pct": loss, "jitter_ms": jitter, "raw": out}
    except Exception as e:
        return {"latency_ms": None, "packet_loss_pct": None, "jitter_ms": None, "error": str(e)}

def probe_thread_func():
    target = "8.8.8.8"
    while True:
        res = probe_host(target, count=6)
        probe_state["last_target"] = target
        probe_state["latency_ms"] = res.get("latency_ms")
        probe_state["packet_loss_pct"] = res.get("packet_loss_pct")
        probe_state["jitter_ms"] = res.get("jitter_ms")
        probe_state["last_probe_time"] = time.time()
        time.sleep(10)

# -------------------------
# TRACEROUTE (on-demand)
# -------------------------
def run_traceroute(dest):
    system = platform.system().lower()
    hops = []
    try:
        if system == "windows":
            proc = subprocess.run(["tracert", "-d", dest], capture_output=True, text=True, timeout=60)
            out = proc.stdout.splitlines()
            for line in out:
                hops.append(line.strip())
        else:
            proc = subprocess.run(["traceroute", "-n", dest], capture_output=True, text=True, timeout=60)
            hops = proc.stdout.splitlines()
    except Exception as e:
        hops = [f"Traceroute error: {e}"]
    probe_state["traceroute"] = hops
    return hops

# -------------------------
# FLASK API / DASHBOARD (HTML + JS)
# -------------------------
HTML_PAGE = """
<!doctype html>
<html>
<head>
  <title>Live Network Analyzer</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body{background:#0f1724;color:#e6eef8;font-family:Arial;padding:18px}
    .row{display:flex;gap:18px;align-items:flex-start}
    .card{background:#071229;padding:12px;border-radius:8px;box-shadow:0 6px 18px rgba(0,0,0,0.6);width:48%}
    .small{width:48%}
    h2{margin:6px 0 12px 0}
    pre{white-space:pre-wrap;word-break:break-word;background:#021025;padding:8px;border-radius:6px}
    table{width:100%}
    .suspicious{color:#ff6b6b}
    .normal{color:#9fd}
  </style>
</head>
<body>
  <h1>Live Network Analyzer</h1>
  <div class="row">
    <div class="card">
      <h2>Live Speed (KB/s)</h2>
      <canvas id="speedChart" height="180"></canvas>
    </div>
    <div class="card small">
      <h2>Packet & Probe Stats</h2>
      <div><b>Upload:</b> <span id="up">- KB/s</span></div>
      <div><b>Download:</b> <span id="down">- KB/s</span></div>
      <div><b>Packets/sec:</b> <span id="pps">-</span></div>
      <div><b>Total packets captured:</b> <span id="total">-</span></div>
      <hr/>
      <div><b>Probe target:</b> <span id="ptarget">-</span></div>
      <div><b>Latency (avg ms):</b> <span id="lat">-</span></div>
      <div><b>Packet loss (%):</b> <span id="loss">-</span></div>
      <div><b>Jitter (ms):</b> <span id="jitter">-</span></div>
      <div style="margin-top:10px">
        <input id="traceHost" placeholder="enter host (e.g. google.com)"/>
        <button onclick="doTrace()">Traceroute</button>
      </div>
      <pre id="traceOut"></pre>
    </div>
  </div>

  <div style="margin-top:18px" class="row">
    <div class="card" style="width:65%">
      <h2>Top Destinations (live)</h2>
      <canvas id="destChart" height="120"></canvas>
    </div>
    <div class="card small">
      <h2>Recent Packets</h2>
      <div id="recent" style="max-height:380px;overflow:auto"></div>
    </div>
  </div>

<script>
const speedCtx = document.getElementById('speedChart').getContext('2d');
const destCtx = document.getElementById('destChart').getContext('2d');

const speedChart = new Chart(speedCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      {label:'Upload KB/s', data:[], borderColor:'rgb(255,99,132)', fill:false},
      {label:'Download KB/s', data:[], borderColor:'rgb(75,192,192)', fill:false},
    ]
  },
  options:{animation:false,scales:{y:{beginAtZero:true}}}
});

const destChart = new Chart(destCtx, {
  type:'bar',
  data:{labels:[], datasets:[{label:'Packets', data:[], backgroundColor:'rgba(99,132,255,0.7)'}]},
  options:{animation:false,scales:{y:{beginAtZero:true}}}
});

function updateUI(){
  fetch('/api/state').then(r=>r.json()).then(d=>{
    document.getElementById('up').innerText = d.upload_kbps;
    document.getElementById('down').innerText = d.download_kbps;
    document.getElementById('pps').innerText = d.packets_per_sec;
    document.getElementById('total').innerText = d.total_packets;
    document.getElementById('ptarget').innerText = d.probe.last_target || '-';
    document.getElementById('lat').innerText = d.probe.latency_ms ?? '-';
    document.getElementById('loss').innerText = d.probe.packet_loss_pct ?? '-';
    document.getElementById('jitter').innerText = d.probe.jitter_ms ?? '-';

    // speed chart
    const t = new Date().toLocaleTimeString();
    speedChart.data.labels.push(t);
    speedChart.data.datasets[0].data.push(d.upload_kbps);
    speedChart.data.datasets[1].data.push(d.download_kbps);
    if (speedChart.data.labels.length > 40){
      speedChart.data.labels.shift();
      speedChart.data.datasets[0].data.shift();
      speedChart.data.datasets[1].data.shift();
    }
    speedChart.update();

    // top destinations
    const top = d.top_destinations;
    destChart.data.labels = top.map(x=>x[0]);
    destChart.data.datasets[0].data = top.map(x=>x[1]);
    destChart.update();

    // recent packets (with ML info)
    const recent = d.recent_packets;
    const el = document.getElementById('recent');
    el.innerHTML = recent.slice(0,60).map(p => {
      const cls = p.ml_label === 'SUSPICIOUS' ? 'suspicious' : 'normal';
      return `<div style="padding:6px;border-bottom:1px solid #07223a">
        <b>${p.time}</b> <span style="color:#9fd">${p.proto}</span>
        ${p.src} → ${p.dst}
        <div style="float:right"><span class="${cls}">${p.ml_label}</span> (${p.ml_prob})</div>
      </div>`;
    }).join('');

  });
}

setInterval(updateUI, 1000);
updateUI();

function doTrace(){
  const host = document.getElementById('traceHost').value;
  if(!host) return alert('Enter host');
  document.getElementById('traceOut').innerText = "Running traceroute...";
  fetch('/api/traceroute', {
    method:'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({host})
  }).then(r=>r.json()).then(data=>{
    document.getElementById('traceOut').innerText = data.hops.join('\\n');
  }).catch(e=>{
    document.getElementById('traceOut').innerText = 'Error: '+e;
  });
}
</script>
</body>
</html>
"""

# API endpoints
@app.route("/")
def index():
    return render_template_string(HTML_PAGE)

@app.route("/api/state")
def api_state():
    # top destinations (top 8)
    top = dest_counter.most_common(8)
    top_list = [(k, v) for k, v in top]
    # prepare recent packets small items (they already include ml_label, ml_prob)
    rec = list(recent_packets)[:200]
    return jsonify({
        "upload_kbps": net_state["upload_kbps"],
        "download_kbps": net_state["download_kbps"],
        "packets_per_sec": net_state["packets_per_sec"],
        "total_packets": net_state["total_packets"],
        "recent_packets": rec,
        "top_destinations": top_list,
        "probe": {
            "last_target": probe_state.get("last_target"),
            "latency_ms": probe_state.get("latency_ms"),
            "packet_loss_pct": probe_state.get("packet_loss_pct"),
            "jitter_ms": probe_state.get("jitter_ms"),
            "last_probe_time": probe_state.get("last_probe_time"),
        }
    })

@app.route("/api/traceroute", methods=["POST"])
def api_traceroute():
    body = request.get_json(force=True)
    host = body.get("host")
    if not host:
        return jsonify({"error": "no host provided", "hops": []})
    hops = run_traceroute(host)
    return jsonify({"hops": hops})

# -------------------------
# Start background threads and Flask app
# -------------------------
if __name__ == "__main__":
    # start sniffer thread
    t_sniff = threading.Thread(target=sniff_thread_func, daemon=True)
    t_sniff.start()

    # start speed meter
    t_speed = threading.Thread(target=net_speed_thread, daemon=True)
    t_speed.start()

    # start probe thread
    t_probe = threading.Thread(target=probe_thread_func, daemon=True)
    t_probe.start()

    # start Flask
    print("Starting Flask on port", PORT)
    app.run(host="0.0.0.0", port=PORT, debug=False)


