import psutil
import customtkinter as ctk
import os
import shutil
import time
import threading
from tkinter import messagebox
import winreg

# Initialize UI Theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# List of known keylogger process names (extend as needed)
KNOWN_KEYLOGGERS = ["keylogger.exe", "hooker.exe", "spy.exe", "logger.exe"]

# Suspicious directories to scan
SUSPICIOUS_DIRS = [r"C:\Users\Public", r"C:\Windows\Temp", r"C:\Users\Public\Libraries"]

# List of suspicious registry keys
SUSPICIOUS_REG_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
]

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

def scan_hidden_files():
    """Scans for suspicious hidden keylogger files."""
    detected_files = []
    
    for directory in SUSPICIOUS_DIRS:
        try:
            for file in os.listdir(directory):
                file_path = os.path.join(directory, file)
                if os.path.isfile(file_path) and file.startswith("."):  # Hidden file check
                    detected_files.append(file_path)
        except PermissionError:
            continue

    # Display results
    result_textbox.configure(state="normal")
    result_textbox.insert("end", "\n🔍 Scanning for Hidden Keyloggers...\n")
    
    if detected_files:
        for file in detected_files:
            result_textbox.insert("end", f"⚠️ Suspicious File: {file}\n", "orange")
            result_textbox.tag_config("orange", foreground="orange")
    else:
        result_textbox.insert("end", "✅ No Hidden Keyloggers Found!\n", "green")

    result_textbox.configure(state="disabled")

def check_registry():
    """Scans suspicious registry keys for keyloggers."""
    suspicious_entries = []

    for key in SUSPICIOUS_REG_KEYS:
        try:
            reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key)
            i = 0
            while True:
                try:
                    value = winreg.EnumValue(reg, i)
                    if any(keyword in value[0].lower() for keyword in KNOWN_KEYLOGGERS):
                        suspicious_entries.append(value[0])
                except OSError:
                    break
                i += 1
        except FileNotFoundError:
            continue

    # Display results
    result_textbox.configure(state="normal")
    result_textbox.insert("end", "\n🔍 Scanning Registry...\n")

    if suspicious_entries:
        for entry in suspicious_entries:
            result_textbox.insert("end", f"⚠️ Suspicious Registry Key: {entry}\n", "red")
            result_textbox.tag_config("red", foreground="red")
    else:
        result_textbox.insert("end", "✅ No Suspicious Registry Entries Found!\n", "green")

    result_textbox.configure(state="disabled")

def delete_suspicious_files():
    """Deletes detected hidden keylogger files."""
    deleted_files = []

    for directory in SUSPICIOUS_DIRS:
        try:
            for file in os.listdir(directory):
                file_path = os.path.join(directory, file)
                if os.path.isfile(file_path) and file.startswith("."):
                    os.remove(file_path)
                    deleted_files.append(file_path)
        except PermissionError:
            continue

    if deleted_files:
        messagebox.showinfo("Deleted", f"Deleted: {', '.join(deleted_files)}")
    else:
        messagebox.showinfo("Info", "No suspicious files found.")

def create_ui():
    """Builds the GUI for the tool."""
    global root, result_textbox

    # Main Window
    root = ctk.CTk()
    root.title("🔍 Advanced Keylogger Detector")
    root.geometry("500x500")
    root.resizable(False, False)

    # Title Label
    ctk.CTkLabel(root, text="🛡️ Keylogger Detector", font=("Arial", 18, "bold")).pack(pady=10)

    # Buttons
    ctk.CTkButton(root, text="🔍 Scan Processes", font=("Arial", 14), command=detect_keyloggers).pack(pady=5)
    ctk.CTkButton(root, text="🛑 Kill Keyloggers", font=("Arial", 14), command=terminate_suspicious).pack(pady=5)
    ctk.CTkButton(root, text="📂 Scan Hidden Files", font=("Arial", 14), command=scan_hidden_files).pack(pady=5)
    ctk.CTkButton(root, text="🔎 Check Registry", font=("Arial", 14), command=check_registry).pack(pady=5)
    ctk.CTkButton(root, text="🗑️ Delete Keyloggers", font=("Arial", 14), command=delete_suspicious_files).pack(pady=5)

    # Result Frame
    result_frame = ctk.CTkFrame(root, width=460, height=200, corner_radius=10)
    result_frame.pack(pady=10)

    # Result Textbox
    result_textbox = ctk.CTkTextbox(result_frame, width=440, height=180, font=("Arial", 12), state="disabled", wrap="word")
    result_textbox.pack(pady=10, padx=10)

    # Mode Switch
    mode_switch = ctk.CTkOptionMenu(root, values=["Light", "Dark"], command=ctk.set_appearance_mode)
    mode_switch.set("System")
    mode_switch.pack(pady=10)

    root.mainloop()

# Run the Application
create_ui()
