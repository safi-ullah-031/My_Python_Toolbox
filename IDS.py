from scapy.all import sniff, IP, TCP, UDP, Raw
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import csv
import json
import datetime
import threading
import queue
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import requests

# 🚀 IDS Settings
THRESHOLD_SYN = 80  # SYN Flood threshold
PORT_SCAN_THRESHOLD = 15  # Port scan threshold
PAYLOAD_KEYWORDS = [b"attack", b"hacked", b"malware", b"exploit", b"password"]  # Suspicious payload words

attack_counts = {}  # Track detected attacks
ids_running = False  # IDS active flag
packet_queue = queue.Queue()  # Queue for packet processing

# 🌍 Get IP Geolocation
def get_geo_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json").json()
        return response.get("country", "Unknown")
    except:
        return "Unknown"

# 🕵️‍♂️ Deep Packet Inspection (DPI)
def analyze_packet(packet):
    if not ids_running:
        return  

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Detect SYN Flood (High SYN Requests)
        if packet.haslayer(TCP) and packet[TCP].flags == 2:
            attack_counts[src_ip] = attack_counts.get(src_ip, 0) + 1
            if attack_counts[src_ip] > THRESHOLD_SYN:
                log_alert("SYN Flood Detected", src_ip, dst_ip, timestamp)

        # Detect Port Scanning (Frequent Port Access)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            attack_counts[src_ip] = attack_counts.get(src_ip, 0) + 1
            if attack_counts[src_ip] > PORT_SCAN_THRESHOLD:
                log_alert("Port Scanning Detected", src_ip, dst_ip, timestamp)

        # Deep Payload Inspection (Detect Suspicious Content)
        if packet.haslayer(Raw):
            payload = packet[Raw].load.lower()
            if any(keyword in payload for keyword in PAYLOAD_KEYWORDS):
                log_alert("Suspicious Payload Detected", src_ip, dst_ip, timestamp)

# 📝 Log Alerts
def log_alert(alert_type, src_ip, dst_ip, timestamp):
    country = get_geo_location(src_ip)
    log_message = f"{timestamp} | {alert_type} | {src_ip} ({country}) → {dst_ip}\n"
    
    log_display.insert(tk.END, log_message)
    log_display.yview(tk.END)  # Auto-scroll

    attack_counts[alert_type] = attack_counts.get(alert_type, 0) + 1
    update_graph()

# 📊 Graph Animation Update
def update_graph(frame=None):
    if fig is None or ax is None:
        return  

    ax.clear()
    ax.set_facecolor("#222831")
    fig.patch.set_facecolor("#121212")

    attack_types = list(attack_counts.keys())
    attack_values = list(attack_counts.values())

    if attack_types:
        bars = ax.bar(attack_types, attack_values, color=['#FF5733', '#33FFBD', '#FFD700'])
        ax.set_title("Intrusion Detection Stats", fontsize=12, color="white")
        ax.set_ylabel("Count", fontsize=10, color="white")
        ax.set_xlabel("Attack Types", fontsize=10, color="white")
        ax.tick_params(colors='white')

        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, height, str(height), ha='center', va='bottom', fontsize=9, color='white')

    canvas.draw()

# 🎯 IDS Engine (Multi-threaded)
def process_packets():
    while True:
        packet = packet_queue.get()
        if packet:
            analyze_packet(packet)
        packet_queue.task_done()

# 🎯 Start IDS
def start_ids():
    global ids_running
    ids_running = True
    log_display.insert(tk.END, "✅ IDS Started...\n")

    thread = threading.Thread(target=lambda: sniff(prn=lambda p: packet_queue.put(p), store=False), daemon=True)
    thread.start()

# ⛔ Stop IDS
def stop_ids():
    global ids_running
    ids_running = False
    log_display.insert(tk.END, "⛔ IDS Stopped.\n")

# 📂 Export Logs
def export_logs():
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv"), ("JSON Files", "*.json")])
    if not file_path:
        return
    
    if file_path.endswith(".csv"):
        with open(file_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Timestamp", "Alert Type", "Source IP", "Destination IP"])
            for log in log_display.get("1.0", tk.END).strip().split("\n"):
                parts = log.split(" | ")
                if len(parts) == 4:
                    writer.writerow(parts)
    elif file_path.endswith(".json"):
        log_data = []
        for log in log_display.get("1.0", tk.END).strip().split("\n"):
            parts = log.split(" | ")
            if len(parts) == 4:
                log_data.append({"timestamp": parts[0], "alert_type": parts[1], "src_ip": parts[2], "dst_ip": parts[3]})
        
        with open(file_path, "w") as jsonfile:
            json.dump(log_data, jsonfile, indent=4)
    
    messagebox.showinfo("Export", "Logs saved successfully!")

# 🎨 GUI Configuration
ctk.set_appearance_mode("Dark")  
root = ctk.CTk()
root.title("🛡️ Intrusion Detection System (IDS)")
root.geometry("800x600")
root.configure(bg="#121212")

# 📌 Title Label
title_label = ctk.CTkLabel(root, text="🚀 Intrusion Detection System (IDS)", font=("Arial", 18, "bold"), text_color="white")
title_label.pack(pady=10)

# 📝 Log Display
log_display = scrolledtext.ScrolledText(root, width=90, height=12, state="normal", bg="#1E1E1E", fg="white", font=("Arial", 10))
log_display.pack(pady=10)

# 🎮 Buttons
btn_frame = ctk.CTkFrame(root, fg_color="#1E1E1E")
btn_frame.pack(pady=10)

start_btn = ctk.CTkButton(btn_frame, text="🚀 Start IDS", command=start_ids, fg_color="#00C853")
start_btn.grid(row=0, column=0, padx=10)

stop_btn = ctk.CTkButton(btn_frame, text="⛔ Stop IDS", command=stop_ids, fg_color="#FF3D00")
stop_btn.grid(row=0, column=1, padx=10)

export_btn = ctk.CTkButton(btn_frame, text="📂 Export Logs", command=export_logs, fg_color="#2979FF")
export_btn.grid(row=0, column=2, padx=10)

# 📊 Graph for Attack Statistics
fig, ax = plt.subplots(figsize=(6, 4))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack()

# 🛠️ **Fix Warning**: Set cache_frame_data=False
ani = animation.FuncAnimation(fig, update_graph, interval=2000, cache_frame_data=False)

# 🌍 Attack Tracking
attack_counts = {}

# 🚀 Start Processing Thread
threading.Thread(target=process_packets, daemon=True).start()

# 🎯 Run GUI
root.mainloop()
