import os
import scapy.all as scapy
import socket
import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import threading
import random
import requests
import csv
import subprocess
import platform

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

# 🏆 Best WiFi Channel Finder (Windows & Linux)
def find_best_wifi_channel():
    system_os = platform.system()
    
    if system_os == "Linux":
        try:
            output = subprocess.check_output(["iwlist", "wlan0", "scan"]).decode()
            frequencies = re.findall(r"Frequency:(\d+\.\d+) GHz", output)

            channel_counts = {}
            for freq in frequencies:
                channel_counts[freq] = channel_counts.get(freq, 0) + 1

            if channel_counts:
                best_channel = min(channel_counts, key=channel_counts.get)
                messagebox.showinfo("Best WiFi Channel", f"The best WiFi channel is: {best_channel} GHz")
            else:
                messagebox.showerror("Error", "No WiFi networks detected.")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan: {e}")

    elif system_os == "Windows":
        try:
            output = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"]).decode()
            channels = re.findall(r"Channel\s*:\s*(\d+)", output)

            channel_counts = {}
            for channel in channels:
                channel_counts[channel] = channel_counts.get(channel, 0) + 1

            if channel_counts:
                best_channel = min(channel_counts, key=channel_counts.get)
                messagebox.showinfo("Best WiFi Channel", f"The best WiFi channel is: {best_channel}")
            else:
                messagebox.showerror("Error", "No WiFi networks detected.")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan: {e}")

    else:
        messagebox.showerror("Unsupported OS", "Only Windows & Linux are supported.")

# 📡 Network Scanner
trusted_devices = set()

def scan_network():
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
    for row in table.get_children():
        table.delete(row)

    for device in devices:
        table.insert("", "end", values=(device["IP"], device["MAC"], device["Vendor"], device["Data Usage"]))

def start_scan():
    threading.Thread(target=scan_network, daemon=True).start()

def toggle_real_time():
    if real_time.get():
        start_scan()
        root.after(5000, toggle_real_time)

# ❌ Device Blocker (Blocks a MAC Address)
def block_device():
    selected = table.selection()
    if not selected:
        messagebox.showerror("Error", "No device selected to block.")
        return

    mac_address = table.item(selected[0])["values"][1]
    system_os = platform.system()

    try:
        if system_os == "Linux":
            os.system(f"sudo iptables -A INPUT -m mac --mac-source {mac_address} -j DROP")
            os.system(f"sudo iptables -A FORWARD -m mac --mac-source {mac_address} -j DROP")
        elif system_os == "Windows":
            os.system(f"netsh wlan delete filter permission=allow ssid= any networktype=infrastructure mac={mac_address}")
        else:
            messagebox.showerror("Unsupported OS", "MAC blocking not supported on this OS.")
            return

        messagebox.showinfo("Blocked", f"Device {mac_address} has been blocked.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to block device: {e}")

# 🌍 Internet Speed Test (Ping)
def ping_test():
    system_os = platform.system()
    try:
        if system_os == "Windows":
            output = subprocess.check_output(["ping", "-n", "4", "8.8.8.8"]).decode()
        else:
            output = subprocess.check_output(["ping", "-c", "4", "8.8.8.8"]).decode()
        
        messagebox.showinfo("Ping Test Result", output)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to perform ping test: {e}")

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
root.geometry("900x500")
root.minsize(750, 400)

# Frame for table
table_frame = ctk.CTkFrame(root)
table_frame.pack(fill="both", expand=True, padx=10, pady=10)

table = ttk.Treeview(table_frame, columns=("IP", "MAC", "Vendor", "Data Usage"), show="headings")
table.heading("IP", text="IP Address")
table.heading("MAC", text="MAC Address")
table.heading("Vendor", text="Device Vendor")
table.heading("Data Usage", text="Data Usage (MB)")

scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=table.yview)
scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=table.xview)
table.configure(yscroll=scroll_y.set, xscroll=scroll_x.set)

scroll_y.pack(side="right", fill="y")
scroll_x.pack(side="bottom", fill="x")
table.pack(fill="both", expand=True)

# Buttons
button_frame = ctk.CTkFrame(root)
button_frame.pack(fill="x", padx=10, pady=5)

ctk.CTkButton(button_frame, text="Scan Network", command=start_scan).pack(side="left", padx=5)
ctk.CTkButton(button_frame, text="Export Data", command=export_data).pack(side="left", padx=5)
ctk.CTkButton(button_frame, text="Block Device", command=block_device).pack(side="left", padx=5)
ctk.CTkButton(button_frame, text="Ping Test", command=ping_test).pack(side="left", padx=5)
ctk.CTkButton(button_frame, text="Find Best WiFi Channel", command=find_best_wifi_channel).pack(side="left", padx=5)

# Run UI
root.mainloop()
