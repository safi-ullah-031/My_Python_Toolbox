from scapy.all import sniff, IP, TCP, UDP
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import csv
import json
import datetime
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import requests

# 🚀 IDS Settings
THRESHOLD_SYN = 100
PORT_SCAN_THRESHOLD = 10
suspicious_ips = {}
ids_running = False  # Flag for starting/stopping IDS

# 🌍 Get IP Geolocation
def get_geo_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json").json()
        return response.get("country", "Unknown")
    except:
        return "Unknown"

# 🕵️‍♂️ Packet Handler
def packet_callback(packet):
    if not ids_running:
        return  # Stop processing if IDS is stopped

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if packet.haslayer(TCP) and packet[TCP].flags == 2:
            suspicious_ips[src_ip] = suspicious_ips.get(src_ip, 0) + 1
            if suspicious_ips[src_ip] > THRESHOLD_SYN:
                log_alert("SYN Flood Detected", src_ip, dst_ip, timestamp)

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            suspicious_ips[src_ip] = suspicious_ips.get(src_ip, 0) + 1
            if suspicious_ips[src_ip] > PORT_SCAN_THRESHOLD:
                log_alert("Port Scanning Detected", src_ip, dst_ip, timestamp)

# 📝 Log Alerts
def log_alert(alert_type, src_ip, dst_ip, timestamp):
    country = get_geo_location(src_ip)
    log_message = f"{timestamp} | {alert_type} | {src_ip} ({country}) → {dst_ip}\n"
    
    log_display.insert(tk.END, log_message)
    log_display.yview(tk.END)  # Auto-scroll

    attack_counts[alert_type] = attack_counts.get(alert_type, 0) + 1
    update_graph()

# 📈 Update Graph
def update_graph():
    attack_types = list(attack_counts.keys())
    attack_values = list(attack_counts.values())

    ax.clear()
    ax.bar(attack_types, attack_values, color=['red', 'blue'])
    ax.set_title("Intrusion Detection Stats")
    ax.set_ylabel("Count")

    canvas.draw()

# 🎯 Start IDS
def start_ids():
    global ids_running
    ids_running = True
    log_display.insert(tk.END, "🔍 IDS Started...\n")

    # Run IDS in a separate thread
    thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=False), daemon=True)
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
root = ctk.CTk()
root.title("Intrusion Detection System (IDS)")
root.geometry("700x500")

# 📌 Title Label
title_label = ctk.CTkLabel(root, text="🛡️ Intrusion Detection System", font=("Arial", 18, "bold"))
title_label.pack(pady=10)

# 📝 Log Display
log_display = scrolledtext.ScrolledText(root, width=80, height=15, state="normal")
log_display.pack(pady=10)

# 🎮 Buttons
btn_frame = ctk.CTkFrame(root)
btn_frame.pack(pady=10)

start_btn = ctk.CTkButton(btn_frame, text="🚀 Start IDS", command=start_ids)
start_btn.grid(row=0, column=0, padx=10)

stop_btn = ctk.CTkButton(btn_frame, text="⛔ Stop IDS", command=stop_ids)
stop_btn.grid(row=0, column=1, padx=10)

export_btn = ctk.CTkButton(btn_frame, text="📂 Export Logs", command=export_logs)
export_btn.grid(row=0, column=2, padx=10)

# 📊 Graph for Attack Statistics
fig, ax = plt.subplots(figsize=(5, 3))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack()

# 🌍 Attack Tracking
attack_counts = {}

# 🎯 Run GUI
root.mainloop()
