import speedtest
import customtkinter as ctk
from tkinter import messagebox

# Initialize Theme
ctk.set_appearance_mode("System")  # Supports "Light", "Dark", "System"
ctk.set_default_color_theme("blue")

# Function to update UI text
def update_result_text(label, message, color):
    label.configure(text=message, text_color=color)
    root.update_idletasks()

# Function to insert text into the result box
def insert_text(tag, message):
    result_textbox.insert("end", message + "\n", tag)

# Function to check network speed
def check_speed():
    try:
        steps = {
            "Finding best server...": "orange",
            "Testing Download Speed...": "blue",
            "Testing Upload Speed...": "blue"
        }

        for step, color in steps.items():
            update_result_text(result_label, f"🔄 {step}", color)

        # Speed test initialization
        st = speedtest.Speedtest()
        st.get_best_server()

        # Measure speeds
        download_speed = st.download() / 1_000_000  # Mbps
        upload_speed = st.upload() / 1_000_000  # Mbps
        ping_latency = st.results.ping

        # Display results in the result box
        result_textbox.configure(state="normal")
        result_textbox.delete("1.0", "end")  # Clear previous results

        result_data = {
            "📶 Download Speed:": (download_speed, "green"),
            "📤 Upload Speed:": (upload_speed, "blue"),
            "⏳ Ping Latency:": (ping_latency, "red")
        }

        for key, (value, color) in result_data.items():
            insert_text(color, f"{key} {value:.2f} Mbps" if "Speed" in key else f"{key} {value:.2f} ms")
            result_textbox.tag_config(color, foreground=color)

        result_textbox.configure(state="disabled")
        update_result_text(result_label, "✅ Speed Test Completed!", "green")

    except Exception as e:
        messagebox.showerror("Error", f"❌ Speed Test Failed!\n{e}")

# Function to toggle dark/light mode
def toggle_mode():
    ctk.set_appearance_mode(mode_switch.get())

# GUI Window
root = ctk.CTk()
root.title("🚀 Network Speed Tester")
root.geometry("420x400")
root.resizable(False, False)

# UI Elements
title_label = ctk.CTkLabel(root, text="📡 Network Speed Tester", font=("Arial", 18, "bold"))
title_label.pack(pady=10)

test_button = ctk.CTkButton(root, text="🚀 Start Speed Test", font=("Arial", 14), command=check_speed)
test_button.pack(pady=10)

result_label = ctk.CTkLabel(root, text="Click the button to test speed.", font=("Arial", 12), text_color="gray")
result_label.pack(pady=10)

result_frame = ctk.CTkFrame(root, width=380, height=120, corner_radius=10)
result_frame.pack(pady=10)

result_textbox = ctk.CTkTextbox(result_frame, width=360, height=100, font=("Arial", 12), state="disabled", wrap="word")
result_textbox.pack(pady=10, padx=10)

mode_switch = ctk.CTkOptionMenu(root, values=["Light", "Dark"], command=lambda _: toggle_mode())
mode_switch.set("System")
mode_switch.pack(pady=10)

# Run GUI
root.mainloop()
