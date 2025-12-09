from scapy.all import sniff, IP, TCP, UDP
import csv, time

OUT_CSV = 'packets_dataset.csv'
print('Capturing packets for training. Press Ctrl+C to stop.')

# write header if file doesn't exist
try:
    with open(OUT_CSV, 'x', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp','size','proto','sport','dport','ttl'])
except FileExistsError:
    pass

def get_ports(pkt):
    sport = dport = 0
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    return sport, dport

def handle(pkt):
    if IP not in pkt:
        return
    ts = time.time()
    size = len(pkt)
    proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "IP")
    ttl = pkt[IP].ttl if hasattr(pkt[IP], "ttl") else 0
    sport, dport = get_ports(pkt)

    # append to CSV
    with open(OUT_CSV, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([ts, size, proto, sport, dport, ttl])

    print(f"{time.strftime('%H:%M:%S')}  {proto}  {size} bytes  {pkt[IP].src} -> {pkt[IP].dst}")

sniff(prn=handle, store=False)
