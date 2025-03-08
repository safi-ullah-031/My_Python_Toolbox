from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
import customtkinter as ctk
from tkinter import messagebox, StringVar, filedialog, Scrollbar, Text, Menu
import threading
import datetime
import requests
import csv
import json

# 🎨 UI Theme Configuration
ctk.set_appearance_mode("Dark")  # Default to Dark Mode
ctk.set_default_color_theme("blue")

# 🌍 Function to Get IP Geolocation
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

# 🌐 Packet Counter
packet_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}
captured_packets = []  # Store packets for later saving
is_sniffing = False  # Global flag to control sniffing

# 🔍 Packet Processing Function
def packet_callback(packet):
    global is_sniffing
    if not is_sniffing:
        return

    """Processes captured packets and logs details."""
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

    # Update Packet Counter
    if protocol in packet_count:
        packet_count[protocol] += 1
    else:
        packet_count["Other"] += 1

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
    if auto_scroll_var.get():
        result_textbox.see("end")  # Auto-scroll
    result_textbox.configure(state="disabled")

    # Store Packet for Later Saving
    captured_packets.append({
        "timestamp": timestamp,
        "protocol": protocol,
        "source": {"ip": src, "port": src_port, "location": src_geo},
        "destination": {"ip": dst, "port": dst_port, "location": dst_geo},
        "length": length,
        "raw_data": raw_data.decode(errors="ignore") if isinstance(raw_data, bytes) else raw_data
    })

    # Update Stats Counter
    update_stats()

# 📊 Update Stats in UI
def update_stats():
    stats_label.configure(text=f"📡 TCP: {packet_count['TCP']} | UDP: {packet_count['UDP']} | ICMP: {packet_count['ICMP']} | ARP: {packet_count['ARP']}")

# 🚀 Function to Start Sniffing
def start_sniffing():
    global is_sniffing
    is_sniffing = True
    """Starts packet sniffing in a separate thread."""
    sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=False))
    sniff_thread.daemon = True
    sniff_thread.start()

    status_label.configure(text="✅ Sniffing started!", text_color="green")

# 🛑 Function to Stop Sniffing
def stop_sniffing():
    global is_sniffing
    is_sniffing = False
    status_label.configure(text="🛑 Sniffing Stopped!", text_color="red")

# 🎨 GUI Setup
root = ctk.CTk()
root.title("🚀 Advanced Packet Sniffer")
root.geometry("700x600")
root.resizable(True, True)

# 📌 Title
title_label = ctk.CTkLabel(root, text="📡 Advanced Packet Sniffer", font=("Arial", 20, "bold"))
title_label.pack(pady=10)

# 🎯 Protocol Selection Dropdown
protocol_var = StringVar(value="All")
protocol_menu = ctk.CTkOptionMenu(root, variable=protocol_var, values=["All", "TCP", "UDP", "ICMP", "ARP"])
protocol_menu.pack(pady=5)

# 🚀 Start & Stop Buttons
button_frame = ctk.CTkFrame(root)
button_frame.pack(pady=5)

start_button = ctk.CTkButton(button_frame, text="🚀 Start Sniffing", font=("Arial", 14), command=start_sniffing)
start_button.grid(row=0, column=0, padx=10)

stop_button = ctk.CTkButton(button_frame, text="🛑 Stop Sniffing", font=("Arial", 14), fg_color="red", command=stop_sniffing)
stop_button.grid(row=0, column=1, padx=10)

# 📡 Status Label
status_label = ctk.CTkLabel(root, text="Click to start sniffing...", font=("Arial", 12), text_color="gray")
status_label.pack(pady=5)

# 📊 Stats Counter
stats_label = ctk.CTkLabel(root, text="📡 TCP: 0 | UDP: 0 | ICMP: 0 | ARP: 0", font=("Arial", 12))
stats_label.pack(pady=5)

# 📜 Log Display with Scrollbar
result_textbox = ctk.CTkTextbox(root, height=300, font=("Arial", 12), state="disabled", wrap="word")
result_textbox.pack(pady=5, padx=10, fill="both", expand=True)

# 🔁 Auto Scroll Toggle
auto_scroll_var = ctk.BooleanVar(value=True)
auto_scroll_check = ctk.CTkCheckBox(root, text="Auto Scroll Logs", variable=auto_scroll_var)
auto_scroll_check.pack(pady=5)

# 💾 Save Logs Button
save_button = ctk.CTkButton(root, text="💾 Save Logs", font=("Arial", 14), command=lambda: messagebox.showinfo("Save", "Save feature coming soon!"))
save_button.pack(pady=5)

# 🎛️ Run GUI
root.mainloop()
