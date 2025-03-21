import os
import scapy.all as scapy
import socket
import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import threading
import json
import csv
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import random
import requests

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

# 🛑 Intruder Detection
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
            data_usage = random.randint(10, 500)  # Simulating bandwidth usage

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

# 📊 Signal Strength Simulation & Graph
signal_strengths = []

def update_signal_graph():
    """Simulates and updates the WiFi signal strength graph."""
    signal_strengths.append(random.randint(30, 100))
    if len(signal_strengths) > 10:
        signal_strengths.pop(0)
    
    ax.clear()
    ax.plot(range(len(signal_strengths)), signal_strengths, marker="o", linestyle="-", color="b")
    ax.set_title("WiFi Signal Strength")
    ax.set_ylim(0, 100)
    canvas.draw()
    
    if real_time.get():
        root.after(2000, update_signal_graph)

# 📤 Export Data
def export_data(file_type):
    """Exports the scanned results as CSV or JSON."""
    devices = [{"IP": table.item(row)["values"][0], "MAC": table.item(row)["values"][1], "Vendor": table.item(row)["values"][2], "Data Usage": table.item(row)["values"][3]} for row in table.get_children()]
    
    if file_type == "CSV":
        file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file:
            with open(file, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["IP", "MAC", "Vendor", "Data Usage"])
                writer.writeheader()
                writer.writerows(devices)
            messagebox.showinfo("Export Success", "Data saved successfully as CSV.")
    
    elif file_type == "JSON":
        file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file:
            with open(file, "w") as f:
                json.dump(devices, f, indent=4)
            messagebox.showinfo("Export Success", "Data saved successfully as JSON.")

# 📊 Save Graph as Image
def save_graph():
    file = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if file:
        fig.savefig(file)
        messagebox.showinfo("Export Success", "Graph saved successfully as PNG.")

# 🌍 Approximate Geolocation
def get_location():
    try:
        response = requests.get("https://ipinfo.io/json").json()
        location_str = f"Location: {response['city']}, {response['region']}, {response['country']}\nIP: {response['ip']}"
        messagebox.showinfo("Your Approximate Location", location_str)
    except:
        messagebox.showerror("Error", "Could not fetch location details.")

# 🎯 UI Design
root = ctk.CTk()
root.title("WiFi Network Analyzer")
root.geometry("700x550")

frame = ctk.CTkFrame(root)
frame.pack(pady=10, fill="both", expand=True)

table = ttk.Treeview(frame, columns=("IP", "MAC", "Vendor", "Data Usage"), show="headings")
table.heading("IP", text="IP Address")
table.heading("MAC", text="MAC Address")
table.heading("Vendor", text="Device Vendor")
table.heading("Data Usage", text="Data Usage (MB)")
table.pack(fill="both", expand=True)

# 📶 Signal Strength Graph
fig, ax = plt.subplots(figsize=(5, 2))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack()

# 🔘 Buttons and Options
scan_button = ctk.CTkButton(root, text="Scan Network", command=start_scan)
scan_button.pack(pady=5)

real_time = ctk.BooleanVar()
real_time_toggle = ctk.CTkCheckBox(root, text="Enable Real-Time Monitoring", variable=real_time, command=toggle_real_time)
real_time_toggle.pack()

trusted_mode = ctk.BooleanVar()
trusted_toggle = ctk.CTkCheckBox(root, text="Enable Intruder Detection", variable=trusted_mode)
trusted_toggle.pack()

export_frame = ctk.CTkFrame(root)
export_frame.pack(pady=5)

csv_button = ctk.CTkButton(export_frame, text="Export CSV", command=lambda: export_data("CSV"))
csv_button.pack(side="left", padx=10)

json_button = ctk.CTkButton(export_frame, text="Export JSON", command=lambda: export_data("JSON"))
json_button.pack(side="right", padx=10)

graph_button = ctk.CTkButton(root, text="Save Graph", command=save_graph)
graph_button.pack(pady=5)

location_button = ctk.CTkButton(root, text="Get Approximate Location", command=get_location)
location_button.pack(pady=5)

update_signal_graph()
root.mainloop()
