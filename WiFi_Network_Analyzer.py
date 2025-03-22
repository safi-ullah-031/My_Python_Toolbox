import os
import socket
import scapy.all as scapy
import customtkinter as ctk
import threading
import requests
import csv
import speedtest
from tkinter import ttk, messagebox, filedialog

# 🎨 UI Theme Setup
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# 🔍 Get Local Network IP
def get_network_ip():
    try:
        ip = socket.gethostbyname(socket.gethostname())
        return ip[:-1] + "1/24"  # Example: Converts 192.168.1.5 -> 192.168.1.1/24
    except:
        return "192.168.1.1/24"

# 🏷️ Get Device Vendor from MAC Address
def get_vendor(mac_address):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}")
        return response.text if response.status_code == 200 else "Unknown"
    except:
        return "Unknown"

# 📡 Scan Network for Connected Devices
def scan_network():
    network_ip = get_network_ip()
    try:
        request = scapy.ARP(pdst=network_ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / request
        responses = scapy.srp(packet, timeout=2, verbose=False)[0]

        devices = []
        for response in responses:
            ip = response[1].psrc
            mac = response[1].hwsrc
            vendor = get_vendor(mac)
            devices.append((ip, mac, vendor))

        update_device_list(devices)
    except Exception as e:
        messagebox.showerror("Error", f"Network scan failed: {e}")

# 📌 Update Table with Scanned Devices
def update_device_list(devices):
    table.delete(*table.get_children())  # Clear previous results
    for device in devices:
        table.insert("", "end", values=device)

# 🔄 Start Scan in Background
def start_scan():
    threading.Thread(target=scan_network, daemon=True).start()

# 📤 Export Data to CSV
def export_data():
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if file_path:
        with open(file_path, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["IP Address", "MAC Address", "Vendor"])
            for row in table.get_children():
                writer.writerow(table.item(row)["values"])
        messagebox.showinfo("Export Successful", "Data saved successfully!")

# 📶 Find Best WiFi Channel (Linux Only)
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
        messagebox.showinfo("Best WiFi Channel", f"Recommended WiFi Channel: {best_channel}")
    except:
        messagebox.showerror("Error", "Could not determine the best WiFi channel.")

# 🚀 Test Internet Speed
def test_speed():
    messagebox.showinfo("Speed Test", "Testing network speed... Please wait.")
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download = round(st.download() / 1_000_000, 2)  # Convert to Mbps
        upload = round(st.upload() / 1_000_000, 2)
        messagebox.showinfo("Speed Test Results", f"Download: {download} Mbps\nUpload: {upload} Mbps")
    except:
        messagebox.showerror("Error", "Network speed test failed.")

# 🎨 Create UI
root = ctk.CTk()
root.title("WiFi Network Analyzer")
root.geometry("700x450")
root.minsize(700, 400)

# 📋 Table for Displaying Devices
table_frame = ctk.CTkFrame(root)
table_frame.pack(fill="both", expand=True, padx=10, pady=10)

table = ttk.Treeview(table_frame, columns=("IP", "MAC", "Vendor"), show="headings")
table.heading("IP", text="IP Address")
table.heading("MAC", text="MAC Address")
table.heading("Vendor", text="Vendor")

scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=table.yview)
table.configure(yscroll=scroll_y.set)
scroll_y.pack(side="right", fill="y")
table.pack(fill="both", expand=True)

# 🎛️ Buttons Section
button_frame = ctk.CTkFrame(root)
button_frame.pack(fill="x", padx=10, pady=5)

ctk.CTkButton(button_frame, text="Scan Network", command=start_scan).pack(side="left", expand=True, padx=5, pady=5)
ctk.CTkButton(button_frame, text="Export Data", command=export_data).pack(side="left", expand=True, padx=5, pady=5)
ctk.CTkButton(button_frame, text="WiFi Channel", command=find_best_wifi_channel).pack(side="left", expand=True, padx=5, pady=5)
ctk.CTkButton(button_frame, text="Speed Test", command=test_speed).pack(side="left", expand=True, padx=5, pady=5)

# 🏁 Run Application
root.mainloop()
