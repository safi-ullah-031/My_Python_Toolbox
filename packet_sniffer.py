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
    try:
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
        packet_info = f"[{timestamp}] {protocol} | {src} → {dst} | {length} bytes\n"

        # Update GUI
        log_textbox.configure(state="normal")
        log_textbox.insert("end", packet_info)
        log_textbox.see("end")
        log_textbox.configure(state="disabled")

        # Save to Log File
        with open(LOG_FILE, "a") as log_file:
            log_file.write(packet_info)

    except Exception as e:
        messagebox.showerror("Error", f"❌ Packet Processing Failed!\n{e}")

# 🚀 Start Sniffing in Background
def start_sniffing():
    global sniffing_thread
    sniffing_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=False), daemon=True)
    sniffing_thread.start()
    start_button.configure(state="disabled", text="Sniffing...")

# 🛑 Stop Sniffing
def stop_sniffing():
    messagebox.showinfo("Info", "⚠️ Stop function is not available. Close the app to stop sniffing!")

# 🎭 Toggle Dark/Light Mode
def toggle_mode():
    ctk.set_appearance_mode(mode_switch.get())

# 📟 GUI Setup
root = ctk.CTk()
root.title("🕵️ Packet Sniffer")
root.geometry("600x400")
root.resizable(False, False)

# 📌 Title Label
title_label = ctk.CTkLabel(root, text="🔍 Network Packet Sniffer", font=("Arial", 18, "bold"))
title_label.pack(pady=10)

# 🚀 Start Button
start_button = ctk.CTkButton(root, text="▶ Start Sniffing", font=("Arial", 14), command=start_sniffing)
start_button.pack(pady=5)

# 🛑 Stop Button
stop_button = ctk.CTkButton(root, text="⏹ Stop Sniffing", font=("Arial", 14), fg_color="red", command=stop_sniffing)
stop_button.pack(pady=5)

# 📜 Log Frame
log_frame = ctk.CTkFrame(root, width=580, height=250, corner_radius=10)
log_frame.pack(pady=10)

# 📄 Log Text Box
log_textbox = ctk.CTkTextbox(log_frame, width=560, height=230, font=("Arial", 12), state="disabled", wrap="word")
log_textbox.pack(pady=10, padx=10)

# 🌗 Mode Switch
mode_switch = ctk.CTkOptionMenu(root, values=["Light", "Dark"], command=lambda _: toggle_mode())
mode_switch.set("System")
mode_switch.pack(pady=10)

# 🎬 Run GUI
root.mainloop()
