import speedtest
import customtkinter as ctk
from tkinter import messagebox

# Initialize Theme
ctk.set_appearance_mode("System")  # Supports "Light", "Dark", "System"
ctk.set_default_color_theme("blue")

# Function to check network speed
def check_speed():
    try:
        result_label.configure(text="🔄 Testing network speed... Please wait...")
        root.update_idletasks()

        # Speed test initialization
        st = speedtest.Speedtest()
        st.get_best_server()

        # Measure speeds
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps
        ping_latency = st.results.ping

        # Display results
        result_label.configure(
            text=(
                f"📶 Download Speed: {download_speed:.2f} Mbps\n"
                f"📤 Upload Speed: {upload_speed:.2f} Mbps\n"
                f"⏳ Ping Latency: {ping_latency:.2f} ms"
            )
        )

    except Exception as e:
        messagebox.showerror("Error", f"❌ Speed Test Failed!\n{e}")

# Function to toggle dark/light mode
def toggle_mode():
    current_mode = mode_switch.get()
    if current_mode == "Dark":
        ctk.set_appearance_mode("Dark")
    else:
        ctk.set_appearance_mode("Light")

# GUI Window
root = ctk.CTk()
root.title("Network Speed Tester")
root.geometry("420x380")
root.resizable(False, False)

# Title Label
title_label = ctk.CTkLabel(root, text="📡 Network Speed Tester", font=("Arial", 18, "bold"))
title_label.pack(pady=10)

# Speed Test Button
test_button = ctk.CTkButton(root, text="🚀 Start Speed Test", font=("Arial", 14), command=check_speed)
test_button.pack(pady=10)

# Result Label
result_label = ctk.CTkLabel(root, text="Click the button to test speed.", font=("Arial", 12))
result_label.pack(pady=20)

# Mode Switch (Dark/Light)
mode_switch = ctk.CTkOptionMenu(root, values=["Light", "Dark"], command=lambda _: toggle_mode())
mode_switch.set("System")
mode_switch.pack(pady=10)

# Run GUI
root.mainloop()
