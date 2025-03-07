import psutil
import customtkinter as ctk
import os
from tkinter import messagebox

# Initialize UI Theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# List of known keylogger process names (add more if needed)
KNOWN_KEYLOGGERS = ["keylogger.exe", "hooker.exe", "spy.exe", "logger.exe"]

def detect_keyloggers():
    """Scans running processes for potential keyloggers and alerts the user."""
    suspicious_processes = []
    
    # Check all running processes
    for process in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            process_name = process.info['name']
            process_path = process.info['exe'] or "Unknown Path"

            # Compare with known keyloggers
            if any(keyword in process_name.lower() for keyword in KNOWN_KEYLOGGERS):
                suspicious_processes.append((process_name, process_path))
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    # Display results
    result_textbox.configure(state="normal")
    result_textbox.delete("1.0", "end")

    if suspicious_processes:
        result_textbox.insert("1.0", "🚨 WARNING: Potential Keyloggers Detected!\n", "red")
        for name, path in suspicious_processes:
            result_textbox.insert("end", f"🛑 {name} - {path}\n", "red")
        result_textbox.tag_config("red", foreground="red")
        messagebox.showwarning("Warning", "Potential keylogger detected!")
    else:
        result_textbox.insert("1.0", "✅ No Keyloggers Found!", "green")
        result_textbox.tag_config("green", foreground="green")

    result_textbox.configure(state="disabled")

def terminate_suspicious():
    """Find and terminate keylogger processes."""
    terminated = []
    for process in psutil.process_iter(['pid', 'name']):
        try:
            if any(keyword in process.info['name'].lower() for keyword in KNOWN_KEYLOGGERS):
                psutil.Process(process.info['pid']).terminate()
                terminated.append(process.info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if terminated:
        messagebox.showinfo("Success", f"Terminated: {', '.join(terminated)}")
    else:
        messagebox.showinfo("Info", "No suspicious processes found.")

def create_ui():
    """Builds the GUI for the tool."""
    global root, result_textbox

    # Main Window
    root = ctk.CTk()
    root.title("🔍 Keylogger Detector")
    root.geometry("460x400")
    root.resizable(False, False)

    # Title Label
    ctk.CTkLabel(root, text="🛡️ Keylogger Detector", font=("Arial", 18, "bold")).pack(pady=10)

    # Scan Button
    ctk.CTkButton(root, text="🔍 Scan for Keyloggers", font=("Arial", 14), command=detect_keyloggers).pack(pady=5)

    # Terminate Button
    ctk.CTkButton(root, text="❌ Terminate Suspicious Processes", font=("Arial", 14), command=terminate_suspicious).pack(pady=5)

    # Result Frame
    result_frame = ctk.CTkFrame(root, width=420, height=180, corner_radius=10)
    result_frame.pack(pady=10)

    # Result Textbox
    result_textbox = ctk.CTkTextbox(result_frame, width=400, height=160, font=("Arial", 12), state="disabled", wrap="word")
    result_textbox.pack(pady=10, padx=10)

    # Mode Switch (Dark/Light)
    mode_switch = ctk.CTkOptionMenu(root, values=["Light", "Dark"], command=ctk.set_appearance_mode)
    mode_switch.set("System")
    mode_switch.pack(pady=10)

    root.mainloop()

# Run the Application
create_ui()
