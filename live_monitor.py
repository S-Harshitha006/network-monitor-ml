import psutil
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import csv
from datetime import datetime

upload_speeds = []
download_speeds = []
times = []

with open("traffic_data.csv", "a", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "upload_kb", "download_kb"])

old = psutil.net_io_counters()

def update(frame):
    global old

    new = psutil.net_io_counters()

    upload = (new.bytes_sent - old.bytes_sent) / 1024
    download = (new.bytes_recv - old.bytes_recv) / 1024

    old = new

    current_time = datetime.now().strftime("%H:%M:%S")
    times.append(current_time)
    upload_speeds.append(upload)
    download_speeds.append(download)

    if len(times) > 60:
        times.pop(0)
        upload_speeds.pop(0)
        download_speeds.pop(0)

    with open("traffic_data.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([current_time, upload, download])

    plt.cla()
    plt.plot(times, upload_speeds, label="Upload KB/s")
    plt.plot(times, download_speeds, label="Download KB/s")
    plt.xticks(rotation=45)
    plt.legend()
    plt.tight_layout()
    plt.title("Live Network Traffic (KB/s)")
    plt.ylabel("Speed KB/s")

fig = plt.figure()
ani = animation.FuncAnimation(fig, update, interval=1000)

plt.show()
