import speedtest
import tkinter as tk
from tkinter import messagebox

def check_speed():
    try:
        result_label.config(text="🔄 Testing network speed... Please wait.")
        root.update_idletasks()

        # Initialize Speedtest
        st = speedtest.Speedtest()
        st.get_best_server()

        # Measure speeds
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps
        ping_latency = st.results.ping

        # Display results
        result_text = (
            f"📶 Download Speed: {download_speed:.2f} Mbps\n"
            f"📤 Upload Speed: {upload_speed:.2f} Mbps\n"
            f"⏳ Ping Latency: {ping_latency:.2f} ms"
        )
        result_label.config(text=result_text)

    except Exception as e:
        messagebox.showerror("Error", f"❌ Speed Test Failed!\n{e}")

# GUI Window
root = tk.Tk()
root.title("Network Speed Tester")
root.geometry("400x300")
root.resizable(False, False)

# Title Label
title_label = tk.Label(root, text="📡 Network Speed Tester", font=("Arial", 14, "bold"))
title_label.pack(pady=10)

# Speed Test Button
test_button = tk.Button(root, text="Start Speed Test", font=("Arial", 12), command=check_speed)
test_button.pack(pady=10)

# Result Label
result_label = tk.Label(root, text="Click the button to test speed.", font=("Arial", 12))
result_label.pack(pady=20)

# Run GUI
root.mainloop()
