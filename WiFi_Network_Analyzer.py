import os
import scapy.all as scapy
import socket
import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import threading
import random
import requests
import csv

# 🖥️ UI Setup
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# 🛠️ Get Local IP
def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())[:-1] + "1/24"
    except:
        return "192.168.1.1/24"

# 🌍 MAC Vendor Lookup
def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url)
        return response.text if response.status_code == 200 else "Unknown"
    except:
        return "Unknown"

# 🚨 Block Unwanted Devices
def block_device(mac):
    try:
        os.system(f"sudo iptables -A INPUT -m mac --mac-source {mac} -j DROP")
        messagebox.showinfo("Blocked", f"Device {mac} has been blocked!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to block device: {e}")

# 🔎 Best WiFi Channel Finder
def find_best_wifi_channel():
    try:
        result = os.popen("iwlist wlan0 scan | grep Frequency").read()
        channels = {}
        for line in result.split("\n"):
            if "Frequency" in line:
                freq = line.split(":")[1].split()[0]
                channels[freq] = channels.get(freq, 0) + 1
        best_channel = min(channels, key=channels.get) if channels else "Unknown"
        messagebox.showinfo("Best WiFi Channel", f"The best WiFi channel is: {best_channel}")
    except:
        messagebox.showerror("Error", "Could not detect the best WiFi channel.")

# 🌍 Approximate Geolocation
def get_location():
    try:
        response = requests.get("https://ipinfo.io/json").json()
        location_str = f"Location: {response['city']}, {response['region']}, {response['country']}\nIP: {response['ip']}"
        messagebox.showinfo("Your Approximate Location", location_str)
    except:
        messagebox.showerror("Error", "Could not fetch location details.")

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

# 🎯 UI Design
root = ctk.CTk()
root.title("WiFi Network Analyzer")
root.geometry("750x500")

frame = ctk.CTkFrame(root)
frame.pack(pady=10, fill="both", expand=True)

table = ttk.Treeview(frame, columns=("IP", "MAC", "Vendor", "Data Usage"), show="headings")
table.heading("IP", text="IP Address")
table.heading("MAC", text="MAC Address")
table.heading("Vendor", text="Device Vendor")
table.heading("Data Usage", text="Data Usage (MB)")
table.pack(fill="both", expand=True)

scan_button = ctk.CTkButton(root, text="Scan Network", command=start_scan)
scan_button.pack(pady=5)

real_time = ctk.BooleanVar()
trusted_mode = ctk.BooleanVar()

ctk.CTkCheckBox(root, text="Enable Real-Time Monitoring", variable=real_time, command=toggle_real_time).pack()

ctk.CTkButton(root, text="Find Best WiFi Channel", command=find_best_wifi_channel).pack()
ctk.CTkButton(root, text="Export Data", command=export_data).pack()

root.mainloop()
