from scapy.all import sniff, IP, TCP, UDP
import time
import joblib

model = joblib.load('packet_model.pkl')
print("ML Live Packet Analyzer Running... Press CTRL+C to stop.")

def get_ports(pkt):
    sport = dport = 0
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    return sport, dport

def predict_packet(pkt):
    if IP not in pkt:
        return

    size = len(pkt)
    proto = 1 if pkt.haslayer(TCP) else (2 if pkt.haslayer(UDP) else 3)
    ttl = pkt[IP].ttl if hasattr(pkt[IP], "ttl") else 0
    sport, dport = get_ports(pkt)

    features = [[size, proto, sport, dport, ttl]]
    pred = model.predict(features)[0]

    label = "NORMAL" if pred == 0 else "SUSPICIOUS"

    print(f"{time.strftime('%H:%M:%S')} | {label} | {size}B | {pkt[IP].src} -> {pkt[IP].dst}")

sniff(prn=predict_packet, store=False)
