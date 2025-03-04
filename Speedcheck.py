# import speedtest
# import customtkinter as ctk
# from tkinter import messagebox

# # Initialize Theme
# ctk.set_appearance_mode("System")  # Supports "Light", "Dark", "System"
# ctk.set_default_color_theme("blue")

# # Function to check network speed
# def check_speed():
#     try:
#         result_label.configure(text="🔄 Testing network speed... Please wait...")
#         root.update_idletasks()

#         # Speed test initialization
#         st = speedtest.Speedtest()
#         st.get_best_server()

#         # Measure speeds
#         download_speed = st.download() / 1_000_000  # Convert to Mbps
#         upload_speed = st.upload() / 1_000_000  # Convert to Mbps
#         ping_latency = st.results.ping

#         # Display results
#         result_label.configure(
#             text=(
#                 f"📶 Download Speed: {download_speed:.2f} Mbps\n"
#                 f"📤 Upload Speed: {upload_speed:.2f} Mbps\n"
#                 f"⏳ Ping Latency: {ping_latency:.2f} ms"
#             )
#         )

#     except Exception as e:
#         messagebox.showerror("Error", f"❌ Speed Test Failed!\n{e}")

# # Function to toggle dark/light mode
# def toggle_mode():
#     current_mode = mode_switch.get()
#     if current_mode == "Dark":
#         ctk.set_appearance_mode("Dark")
#     else:
#         ctk.set_appearance_mode("Light")

# # GUI Window
# root = ctk.CTk()
# root.title("Network Speed Tester")
# root.geometry("420x380")
# root.resizable(False, False)

# # Title Label
# title_label = ctk.CTkLabel(root, text="📡 Network Speed Tester", font=("Arial", 18, "bold"))
# title_label.pack(pady=10)

# # Speed Test Button
# test_button = ctk.CTkButton(root, text="🚀 Start Speed Test", font=("Arial", 14), command=check_speed)
# test_button.pack(pady=10)

# # Result Label
# result_label = ctk.CTkLabel(root, text="Click the button to test speed.", font=("Arial", 12))
# result_label.pack(pady=20)

# # Mode Switch (Dark/Light)
# mode_switch = ctk.CTkOptionMenu(root, values=["Light", "Dark"], command=lambda _: toggle_mode())
# mode_switch.set("System")
# mode_switch.pack(pady=10)

# # Run GUI
# root.mainloop()


import speedtest
import customtkinter as ctk
from tkinter import messagebox

# Initialize Theme
ctk.set_appearance_mode("System")  # Supports "Light", "Dark", "System"
ctk.set_default_color_theme("blue")

# Function to check network speed
def check_speed():
    try:
        result_label.configure(text="🔄 Testing network speed... Please wait...", text_color="orange")
        root.update_idletasks()

        # Speed test initialization
        st = speedtest.Speedtest()
        st.get_best_server()

        # Measure speeds
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps
        ping_latency = st.results.ping

        # Display results in the result box
        result_textbox.configure(state="normal")  # Enable editing
        result_textbox.delete("1.0", "end")  # Clear previous results
        result_textbox.insert("1.0", f"📶 Download Speed: {download_speed:.2f} Mbps\n")
        result_textbox.insert("2.0", f"📤 Upload Speed: {upload_speed:.2f} Mbps\n")
        result_textbox.insert("3.0", f"⏳ Ping Latency: {ping_latency:.2f} ms\n")
        result_textbox.configure(state="disabled")  # Disable editing
        result_label.configure(text="✅ Speed Test Completed!", text_color="green")

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
root.geometry("420x400")
root.resizable(False, False)

# Title Label
title_label = ctk.CTkLabel(root, text="📡 Network Speed Tester", font=("Arial", 18, "bold"))
title_label.pack(pady=10)

# Speed Test Button
test_button = ctk.CTkButton(root, text="🚀 Start Speed Test", font=("Arial", 14), command=check_speed)
test_button.pack(pady=10)

# Result Label
result_label = ctk.CTkLabel(root, text="Click the button to test speed.", font=("Arial", 12), text_color="gray")
result_label.pack(pady=10)

# Frame for Results Box
result_frame = ctk.CTkFrame(root, width=380, height=120, corner_radius=10)
result_frame.pack(pady=10)

# Text Box for Results
result_textbox = ctk.CTkTextbox(result_frame, width=360, height=100, font=("Arial", 12), state="disabled", wrap="word")
result_textbox.pack(pady=10, padx=10)

# Mode Switch (Dark/Light)
mode_switch = ctk.CTkOptionMenu(root, values=["Light", "Dark"], command=lambda _: toggle_mode())
mode_switch.set("System")
mode_switch.pack(pady=10)

# Run GUI
root.mainloop()
