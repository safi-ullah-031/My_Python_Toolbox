from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import customtkinter as ctk
from tkinter import messagebox
import threading
import datetime

# 🎨 UI Theme Configuration
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# 📄 Log File Configuration
LOG_FILE = "packet_sniffer_log.txt"

# 🔍 Packet Sniffing Function
def packet_callback(packet):
    """Processes captured packets and displays relevant details."""
    protocol = "Unknown"
    src, dst, length = "N/A", "N/A", len(packet)

    # Identify Protocol
    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
    elif ARP in packet:
        protocol = "ARP"

    # Format Packet Data
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    packet_info = f"[{timestamp}] {protocol} | {src} → {dst} | {length
