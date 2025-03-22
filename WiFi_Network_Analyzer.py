import os
import scapy.all as scapy
import socket
import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import threading
import random
import requests
import csv
import speedtest

# 🖥️ UI Setup
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# Get Local IP
def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())[:-1] + "1/24"
    except:
        return "192.168.1.1/24"

# MAC Vendor Lookup
def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url)
        return response.text if response.status_code == 200 else "Unknown"
    except:
        return "Unknown"

# Best WiFi Channel Finder (Updated)
def find_best_wifi_channel():
    try:
        result = os.popen("nmcli dev wifi").read()
        channels = {}
        for line in result.split("\n"):
            parts = line.split()
            if len(parts) > 4 and parts[4].isdigit():
                channel = int(parts[4])
                channels[channel] = channels.get(channel, 0) + 1
        
        best_channel = min(channels, key=channels.get) if channels else "Unknown"
        messagebox.showinfo("Best WiFi Channel", f"The best WiFi channel is: {best_channel}")
    except:
        messagebox.showerror("Error", "Could not detect the best WiFi channel.")

# 📡 Network Scanner
trusted_devices = set()

def scan_network():
    """Scans the network for connected devices."""
    network_ip = get_local_ip()
    try:
        arp_request = scapy.ARP(pdst=network_ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered = scapy.srp(packet, timeout=2, verbose=False)[0]
        
        devices = []
        for response in answered:
            ip = response[1].psrc
            mac = response[1].hwsrc
            vendor = get_vendor(mac)
            data_usage = random.randint(10, 500)  # Simulated bandwidth usage

            devices.append({"IP": ip, "MAC": mac, "Vendor": vendor, "Data Usage": f"{data_usage} MB"})

            # 🚨 Intruder Alert
            if mac not in trusted_devices and trusted_mode.get():
                messagebox.showwarning("Intruder Alert!", f"Unknown Device Detected!\nIP: {ip}\nMAC: {mac}\nVendor: {vendor}")

        update_ui(devices)
    except Exception as e:
        messagebox.showerror("Error", f"Network scan failed: {e}")

def update_ui(devices):
    """Updates the table UI with new device data."""
    for row in table.get_children():
        table.delete(row)

    for device in devices:
        table.insert("", "end", values=(device["IP"], device["MAC"], device["Vendor"], device["Data Usage"]))

def start_scan():
    """Starts the scanning process in a separate thread."""
    threading.Thread(target=scan_network, daemon=True).start()

def toggle_real_time():
    """Continuously scans the network if real-time mode is enabled."""
    if real_time.get():
        start_scan()
        root.after(5000, toggle_real_time)

# 📤 Export Data
def export_data():
    file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if file:
        with open(file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "MAC", "Vendor", "Data Usage"])
            for row in table.get_children():
                writer.writerow(table.item(row)["values"])
        messagebox.showinfo("Export Success", "Data saved successfully.")

# 🚀 Network Speed Test
def test_speed():
    messagebox.showinfo("Speed Test", "Testing network speed... Please wait.")
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download_speed = round(st.download() / 1_000_000, 2)
        upload_speed = round(st.upload() / 1_000_000, 2)
        messagebox.showinfo("Speed Test Results", f"Download Speed: {download_speed} Mbps\nUpload Speed: {upload_speed} Mbps")
    except:
        messagebox.showerror("Error", "Network speed test failed.")

# 🎯 UI Design
root = ctk.CTk()
root.title("WiFi Network Analyzer")
root.geometry("900x500")
root.minsize(750, 400)  # Minimum size to prevent UI breaking

# Frame for table
table_frame = ctk.CTkFrame(root)
table_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Table (Treeview)
table = ttk.Treeview(table_frame, columns=("IP", "MAC", "Vendor", "Data Usage"), show="headings")
table.heading("IP", text="IP Address")
table.heading("MAC", text="MAC Address")
table.heading("Vendor", text="Device Vendor")
table.heading("Data Usage", text="Data Usage (MB)")

# Scrollbars
scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=table.yview)
scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=table.xview)
table.configure(yscroll=scroll_y.set, xscroll=scroll_x.set)

scroll_y.pack(side="right", fill="y")
scroll_x.pack(side="bottom", fill="x")
table.pack(fill="both", expand=True)

# Button Frame
button_frame = ctk.CTkFrame(root)
button_frame.pack(fill="x", padx=10, pady=5)

scan_button = ctk.CTkButton(button_frame, text="Scan Network", command=start_scan)
scan_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

export_button = ctk.CTkButton(button_frame, text="Export Data", command=export_data)
export_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

wifi_channel_button = ctk.CTkButton(button_frame, text="Find Best WiFi Channel", command=find_best_wifi_channel)
wifi_channel_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

speed_test_button = ctk.CTkButton(button_frame, text="Network Speed Test", command=test_speed)
speed_test_button.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

# Checkboxes
real_time = ctk.BooleanVar()
trusted_mode = ctk.BooleanVar()

real_time_checkbox = ctk.CTkCheckBox(root, text="Enable Real-Time Monitoring", variable=real_time, command=toggle_real_time)
real_time_checkbox.pack(pady=5)

trusted_mode_checkbox = ctk.CTkCheckBox(root, text="Enable Intruder Alert", variable=trusted_mode)
trusted_mode_checkbox.pack(pady=5)

# Auto adjust button frame layout
for i in range(4):
    button_frame.grid_columnconfigure(i, weight=1)

# Run UI
root.mainloop()
