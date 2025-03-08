from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
import customtkinter as ctk
from tkinter import messagebox, StringVar
import threading
import datetime
import csv
import json
import requests

# 🎨 UI Theme Configuration
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# 📂 Log File Paths
CSV_LOG = "packet_sniffer_log.csv"
JSON_LOG = "packet_sniffer_log.json"

# 🛰️ Function to Get IP Geolocation
def get_geolocation(ip):
    """Fetches geolocation data for an IP address using an external API."""
    try:
        response = requests.get(f"https://ip-api.com/json/{ip}")
        data = response.json()
        if data["status"] == "success":
            return f"{data['city']}, {data['country']} ({data['isp']})"
        return "Unknown Location"
    except Exception:
        return "Geo Lookup Failed"

# 🔍 Packet Processing Function
def packet_callback(packet):
    """Processes captured packets based on the selected filter and logs details."""
    selected_protocol = protocol_var.get()
    protocol = "Unknown"
    src, dst, length, src_port, dst_port, raw_data = "N/A", "N/A", len(packet), "N/A", "N/A", "N/A"

    # Identify Protocol & Extract Details
    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
        if TCP in packet:
            protocol = "TCP"
            src_port, dst_port = packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port, dst_port = packet[UDP].sport, packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
    elif ARP in packet:
        protocol = "ARP"

    # Extract Payload (if available)
    if Raw in packet:
        raw_data = packet[Raw].load[:50]  # Limit raw data for readability

    # Apply Protocol Filter
    if selected_protocol != "All" and protocol != selected_protocol:
        return  

    # Geolocation Lookup for External IPs
    src_geo = get_geolocation(src) if "." in src else "Local Network"
    dst_geo = get_geolocation(dst) if "." in dst else "Local Network"

    # Format Packet Data
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    packet_info = (
        f"[{timestamp}] {protocol} | {src}:{src_port} ({src_geo}) → {dst}:{dst_port} ({dst_geo}) | {length} bytes\n"
        f"   Raw Data: {raw_data}\n"
    )

    # Update UI
    result_textbox.configure(state="normal")
    result_textbox.insert("end", packet_info)
    result_textbox.configure(state="disabled")

    # Save Packet to CSV
    with open(CSV_LOG, "a", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([timestamp, protocol, src, src_port, src_geo, dst, dst_port, dst_geo, length, raw_data])

    # Save Packet to JSON
    with open(JSON_LOG, "a") as json_file:
        json.dump({
            "timestamp": timestamp,
            "protocol": protocol,
            "source": {"ip": src, "port": src_port, "location": src_geo},
            "destination": {"ip": dst, "port": dst_port, "location": dst_geo},
            "length": length,
            "raw_data": raw_data.decode(errors="ignore") if isinstance(raw_data, bytes) else raw_data
        }, json_file)
        json_file.write("\n")

# 🚀 Function to Start Sniffing
def start_sniffing():
    """Starts packet sniffing in a separate thread."""
    try:
        result_textbox.configure(state="normal")
        result_textbox.delete("1.0", "end")  # Clear previous logs
        result_textbox.configure(state="disabled")

        sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=False))
        sniff_thread.daemon = True
        sniff_thread.start()

        status_label.configure(text="✅ Sniffing started!", text_color="green")
    except Exception as e:
        messagebox.showerror("Error", f"❌ Failed to start sniffing!\n{e}")

# 🎨 GUI Setup
root = ctk.CTk()
root.title("Advanced Packet Sniffer")
root.geometry("550x500")
root.resizable(False, False)

# 📌 Title
title_label = ctk.CTkLabel(root, text="📡 Advanced Packet Sniffer", font=("Arial", 18, "bold"))
title_label.pack(pady=10)

# 🎯 Protocol Selection Dropdown
protocol_var = StringVar(value="All")
protocol_label = ctk.CTkLabel(root, text="Filter by Protocol:", font=("Arial", 12))
protocol_label.pack()
protocol_menu = ctk.CTkOptionMenu(root, variable=protocol_var, values=["All", "TCP", "UDP", "ICMP", "ARP"])
protocol_menu.pack(pady=5)

# 🚀 Start Sniffing Button
start_button = ctk.CTkButton(root, text="🚀 Start Sniffing", font=("Arial", 14), command=start_sniffing)
start_button.pack(pady=10)

# 📡 Status Label
status_label = ctk.CTkLabel(root, text="Click to start sniffing...", font=("Arial", 12), text_color="gray")
status_label.pack(pady=5)

# 📜 Result Box
result_frame = ctk.CTkFrame(root, width=500, height=250, corner_radius=10)
result_frame.pack(pady=10)
result_textbox = ctk.CTkTextbox(result_frame, width=480, height=230, font=("Arial", 12), state="disabled", wrap="word")
result_textbox.pack(pady=10, padx=10)

# 🎛️ Run GUI
root.mainloop()
