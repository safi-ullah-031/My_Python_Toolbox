import speedtest
import customtkinter as ctk
from tkinter import messagebox

# Initialize Theme
ctk.set_appearance_mode("System")  # Supports "Light", "Dark", "System"
ctk.set_default_color_theme("blue")

def update_result_text(message, color="gray"):
    """ Updates the result label with a new message and color. """
    result_label.configure(text=message, text_color=color)
    root.update_idletasks()

def insert_result_text(text, color):
    """ Inserts result data into the text box with color formatting. """
    result_textbox.insert("end", text + "\n", color)
    result_textbox.tag_config(color, foreground=color)

def run_speed_test():
    """ Performs a network speed test and updates the UI with results. """
    try:
        update_result_text("🔄 Finding best server...", "orange")

        # Initialize Speedtest
        st = speedtest.Speedtest()
        st.get_best_server()

        # Run Tests
        update_result_text("🚀 Testing Download Speed...", "blue")
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        
        update_result_text("📤 Testing Upload Speed...", "blue")
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps
        
        ping_latency = st.results.ping  # Ping in ms

        # Display Results
        result_textbox.configure(state="normal")
        result_textbox.delete("1.0", "end")

        results = {
            "📶 Download Speed:": (download_speed, "green"),
            "📤 Upload Speed:": (upload_speed, "blue"),
            "⏳ Ping Latency:": (ping_latency, "red")
        }

        for label, (value, color) in results.items():
            value_text = f"{label} {value:.2f} Mbps" if "Speed" in label else f"{label} {value:.2f} ms"
            insert_result_text(value_text, color)

        result_textbox.configure(state="disabled")
        update_result_text("✅ Speed Test Completed!", "green")

    except Exception as e:
        messagebox.showerror("Error", f"❌ Speed Test Failed!\n{e}")

def create_ui():
    """ Creates the GUI layout and components. """
    global root, result_label, result_textbox

    # Main Window
    root = ctk.CTk()
    root.title("🚀 Network Speed Tester")
    root.geometry("420x400")
    root.resizable(False, False)

    # UI Elements
    ctk.CTkLabel(root, text="📡 Network Speed Tester", font=("Arial", 18, "bold")).pack(pady=10)
    
    ctk.CTkButton(root, text="🚀 Start Speed Test", font=("Arial", 14), command=run_speed_test).pack(pady=10)

    result_label = ctk.CTkLabel(root, text="Click the button to test speed.", font=("Arial", 12), text_color="gray")
    result_label.pack(pady=10)

    result_frame = ctk.CTkFrame(root, width=380, height=120, corner_radius=10)
    result_frame.pack(pady=10)

    result_textbox = ctk.CTkTextbox(result_frame, width=360, height=100, font=("Arial", 12), state="disabled", wrap="word")
    result_textbox.pack(pady=10, padx=10)

    mode_switch = ctk.CTkOptionMenu(root, values=["Light", "Dark"], command=ctk.set_appearance_mode)
    mode_switch.set("System")
    mode_switch.pack(pady=10)

    root.mainloop()

# Run Application
create_ui()
