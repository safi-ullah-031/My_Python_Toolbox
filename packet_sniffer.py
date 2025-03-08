from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import customtkinter as ctk
from tkinter import messagebox, StringVar
import threading
import datetime

# 🎨 UI Theme Configuration
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# 📄 Log File Configuration
LOG_FILE = "packet_sniffer_log.txt"

# 🔍 Function to Process Captured Packets
def packet_callback(packet):
    """Processes captured packets based on the selected filter and logs details."""
    selected_protocol = protocol_var.get()
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

    # Apply Protocol Filter
    if selected_protocol != "All" and protocol != selected_protocol:
        return  # Skip packet if it doesn't match the selected filter

    # Format Packet Data
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    packet_info = f"[{timestamp}] {protocol} | {src} → {dst} | {length} bytes\n"

    # Update UI
    result_textbox.configure(state="normal")
    result_textbox.insert("end", packet_info)
    result_textbox.configure(state="disabled")

    # Save to Log File
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(packet_info)

# 🚀 Function to Start Packet Sniffing
def start_sniffing():
    """Starts sniffing packets in a separate thread."""
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

# 🛑 Function to Stop Sniffing (Currently Not Needed)
def stop_sniffing():
    """(Optional) Function to stop sniffing - Implement later if needed."""
    messagebox.showinfo("Info", "Stopping sniffing is not yet implemented!")

# 🎨 GUI Setup
root = ctk.CTk()
root.title("Packet Sniffer with Filtering")
root.geometry("500x450")
root.resizable(False, False)

# 📌 Title
title_label = ctk.CTkLabel(root, text="📡 Packet Sniffer", font=("Arial", 18, "bold"))
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
result_frame = ctk.CTkFrame(root, width=460, height=200, corner_radius=10)
result_frame.pack(pady=10)
result_textbox = ctk.CTkTextbox(result_frame, width=440, height=180, font=("Arial", 12), state="disabled", wrap="word")
result_textbox.pack(pady=10, padx=10)

# 🎛️ Run GUI
root.mainloop()
