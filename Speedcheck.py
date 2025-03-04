# 

import speedtest
import customtkinter as ctk
from tkinter import messagebox

# Initialize Theme
ctk.set_appearance_mode("System")  # Supports "Light", "Dark", "System"
ctk.set_default_color_theme("blue")

# Function to check network speed
def check_speed():
    try:
        status_label.configure(text="🔄 Testing network speed... Please wait...", text_color="orange")
        root.update_idletasks()

        # Use Speedtest API directly to avoid 403 error
        st = speedtest.Speedtest()
        st.get_best_server()
        st.download()
        st.upload()
        results = st.results.dict()  # Get results in dict format

        # Extract speed results
        download_speed = results["download"] / 1_000_000  # Convert to Mbps
        upload_speed = results["upload"] / 1_000_000  # Convert to Mbps
        ping_latency = results["ping"]

        # Display results in individual boxes
        download_result.configure(text=f"📶 {download_speed:.2f} Mbps", text_color="lime")
        upload_result.configure(text=f"📤 {upload_speed:.2f} Mbps", text_color="cyan")
        ping_result.configure(text=f"⏳ {ping_latency:.2f} ms", text_color="yellow")

        status_label.configure(text="✅ Speed Test Completed!", text_color="green")

    except Exception as e:
        messagebox.showerror("Error", f"❌ Speed Test Failed!\n{e}")

# Function to toggle dark/light mode
def toggle_mode():
    current_mode = mode_switch.get()
    ctk.set_appearance_mode(current_mode)

# GUI Window
root = ctk.CTk()
root.title("📡 Network Speed Tester")
root.geometry("450x500")
root.resizable(False, False)

# Title Label
title_label = ctk.CTkLabel(root, text="📡 Network Speed Tester", font=("Arial", 20, "bold"))
title_label.pack(pady=10)

# Speed Test Button
test_button = ctk.CTkButton(root, text="🚀 Start Speed Test", font=("Arial", 14), command=check_speed)
test_button.pack(pady=10)

# Status Label
status_label = ctk.CTkLabel(root, text="Click the button to test speed.", font=("Arial", 12), text_color="gray")
status_label.pack(pady=10)

# Frame for Results
result_frame = ctk.CTkFrame(root, width=400, height=180, corner_radius=10)
result_frame.pack(pady=10, padx=10)

# Download Speed Box
download_label = ctk.CTkLabel(result_frame, text="⬇️ Download Speed", font=("Arial", 14, "bold"))
download_label.pack(pady=(10, 5))

download_result = ctk.CTkLabel(result_frame, text="Waiting...", font=("Arial", 18, "bold"), text_color="gray")
download_result.pack()

# Upload Speed Box
upload_label = ctk.CTkLabel(result_frame, text="⬆️ Upload Speed", font=("Arial", 14, "bold"))
upload_label.pack(pady=(10, 5))

upload_result = ctk.CTkLabel(result_frame, text="Waiting...", font=("Arial", 18, "bold"), text_color="gray")
upload_result.pack()

# Ping Speed Box
ping_label = ctk.CTkLabel(result_frame, text="⚡ Ping Latency", font=("Arial", 14, "bold"))
ping_label.pack(pady=(10, 5))

ping_result = ctk.CTkLabel(result_frame, text="Waiting...", font=("Arial", 18, "bold"), text_color="gray")
ping_result.pack()

# Mode Switch (Dark/Light)
mode_switch = ctk.CTkOptionMenu(root, values=["Light", "Dark"], command=lambda _: toggle_mode())
mode_switch.set("System")
mode_switch.pack(pady=10)

# Run GUI
root.mainloop()
import logging

# Create a logger
logger = logging.getLogger('network_speed_tester')
logger.setLevel(logging.INFO)

# Create a file handler and a stream handler
file_handler = logging.FileHandler('network_speed_tester.log')
stream_handler = logging.StreamHandler()

# Create a formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# ...

def check_speed():
    try:
        logger.info('Starting speed test')
        status_label.configure(text="🔄 Testing network speed... Please wait...", text_color="orange")
        root.update_idletasks()

        # Use Speedtest API directly to avoid 403 error
        st = speedtest.Speedtest()
        st.get_best_server()
        st.download()
        st.upload()
        results = st.results.dict()  # Get results in dict format

        # Extract speed results
        download_speed = results["download"] / 1_000_000  # Convert to Mbps
        upload_speed = results["upload"] / 1_000_000  # Convert to Mbps
        ping_latency = results["ping"]

        # Display results in individual boxes
        download_result.configure(text=f"📶 {download_speed:.2f} Mbps", text_color="lime")
        upload_result.configure(text=f"📤 {upload_speed:.2f} Mbps", text_color="cyan")
        ping_result.configure(text=f"⏳ {ping_latency:.2f} ms", text_color="yellow")

        logger.info('Speed test completed')
        logger.info(f'Download speed: {download_speed:.2f} Mbps')
        logger.info(f'Upload speed: {upload_speed:.2f} Mbps')
        logger.info(f'Ping latency: {ping_latency:.2f} ms')

        status_label.configure(text="✅ Speed Test Completed!", text_color="green")

    except Exception as e:
        logger.error('Speed test failed')
        logger.error(str(e))
        messagebox.showerror("Error", f"❌ Speed Test Failed!\n{e}")

# ...