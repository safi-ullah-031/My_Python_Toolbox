import os
import scapy.all as scapy
import socket
import customtkinter as ctk
from tkinter import ttk, messagebox
import threading

# 🖥️ UI Setup
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# 🛠️ Get Local IP
def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())[:-1] + "1/24"
    except:
        return "192.168.1.1/24"

# 🔍 Scan Network
def scan_network():
    network_ip = get_local_ip()
    try:
        arp_request = scapy.ARP(pdst=network_ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered = scapy.srp(packet, timeout=2, verbose=False)[0]
        
        devices = []
        for response in answered:
            devices.append({
                "IP": response[1].psrc,
                "MAC": response[1].hwsrc
            })
        
        update_ui(devices)
    except Exception as e:
        messagebox.showerror("Error", f"Network scan failed: {e}")

# 🖥️ Update UI
def update_ui(devices):
    for row in table.get_children():
        table.delete(row)
    
    for device in devices:
        table.insert("", "end", values=(device["IP"], device["MAC"]))

# 🎯 Start Scan Thread
def start_scan():
    threading.Thread(target=scan_network, daemon=True).start()

# 📊 UI Design
root = ctk.CTk()
root.title("WiFi Network Analyzer")
root.geometry("500x400")

frame = ctk.CTkFrame(root)
frame.pack(pady=20, fill="both", expand=True)

table = ttk.Treeview(frame, columns=("IP", "MAC"), show="headings")
table.heading("IP", text="IP Address")
table.heading("MAC", text="MAC Address")
table.pack(fill="both", expand=True)

scan_button = ctk.CTkButton(root, text="Scan Network", command=start_scan)
scan_button.pack(pady=10)

root.mainloop()
