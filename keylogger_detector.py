import psutil
import customtkinter as ctk
import os
import winreg
from tkinter import messagebox

# Initialize UI Theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# Configuration Variables
KNOWN_KEYLOGGERS = ["keylogger.exe", "hooker.exe", "spy.exe", "logger.exe"]
SUSPICIOUS_DIRS = [r"C:\Users\Public", r"C:\Windows\Temp"]
SUSPICIOUS_REG_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
]

# UI Update Helper
def update_result(message, color="black"):
    """Updates the UI text box with messages."""
    result_textbox.configure(state="normal")
    result_textbox.insert("end", f"{message}\n")
    result_textbox.tag_config(color, foreground=color)
    result_textbox.configure(state="disabled")

def scan_processes():
    """Scans running processes for known keyloggers."""
    found = [(p.info['name'], p.info['exe']) for p in psutil.process_iter(['pid', 'name', 'exe'])
             if any(k in (p.info['name'] or "").lower() for k in KNOWN_KEYLOGGERS)]
    
    result_textbox.configure(state="normal")
    result_textbox.delete("1.0", "end")
    
    if found:
        update_result("🚨 Potential Keyloggers Detected!", "red")
        for name, path in found:
            update_result(f"🛑 {name} - {path}", "red")
        messagebox.showwarning("Warning", "Potential keylogger detected!")
    else:
        update_result("✅ No Keyloggers Found!", "green")
    
def terminate_keyloggers():
    """Terminates detected keylogger processes."""
    terminated = []
    for p in psutil.process_iter(['pid', 'name']):
        if any(k in (p.info['name'] or "").lower() for k in KNOWN_KEYLOGGERS):
            psutil.Process(p.info['pid']).terminate()
            terminated.append(p.info['name'])
    
    msg = f"Terminated: {', '.join(terminated)}" if terminated else "No suspicious processes found."
    messagebox.showinfo("Process Termination", msg)

def scan_hidden_files():
    """Scans for suspicious hidden files in key directories."""
    detected = [os.path.join(dir, f) for dir in SUSPICIOUS_DIRS for f in os.listdir(dir)
                if os.path.isfile(os.path.join(dir, f)) and f.startswith(".")]
    
    update_result("\n🔍 Scanning Hidden Files...", "orange")
    
    if detected:
        for file in detected:
            update_result(f"⚠️ Suspicious File: {file}", "orange")
    else:
        update_result("✅ No Hidden Keyloggers Found!", "green")

def check_registry():
    """Checks Windows registry for suspicious auto-start programs."""
    found_entries = []
    
    for key in SUSPICIOUS_REG_KEYS:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as reg:
                i = 0
                while True:
                    try:
                        value = winreg.EnumValue(reg, i)[0]
                        if any(k in value.lower() for k in KNOWN_KEYLOGGERS):
                            found_entries.append(value)
                    except OSError:
                        break
                    i += 1
        except FileNotFoundError:
            continue

    update_result("\n🔍 Scanning Registry Entries...", "blue")
    
    if found_entries:
        for entry in found_entries:
            update_result(f"⚠️ Suspicious Registry Entry: {entry}", "red")
    else:
        update_result("✅ No Suspicious Registry Entries Found!", "green")

def delete_hidden_files():
    """Deletes detected hidden keylogger files."""
    deleted = [os.path.join(dir, f) for dir in SUSPICIOUS_DIRS for f in os.listdir(dir)
               if os.path.isfile(os.path.join(dir, f)) and f.startswith(".")]

    for file in deleted:
        os.remove(file)
    
    msg = f"Deleted: {', '.join(deleted)}" if deleted else "No suspicious files found."
    messagebox.showinfo("File Deletion", msg)

def create_ui():
    """Builds the GUI for the tool."""
    global root, result_textbox

    # Main Window
    root = ctk.CTk()
    root.title("🔍 Keylogger Detector")
    root.geometry("500x500")
    root.resizable(False, False)

    # Title Label
    ctk.CTkLabel(root, text="🛡️ Keylogger Detector", font=("Arial", 18, "bold")).pack(pady=10)

    # Buttons
    button_config = {"font": ("Arial", 14), "pady": 5}
    ctk.CTkButton(root, text="🔍 Scan Processes", command=scan_processes, **button_config).pack()
    ctk.CTkButton(root, text="🛑 Kill Keyloggers", command=terminate_keyloggers, **button_config).pack()
    ctk.CTkButton(root, text="📂 Scan Hidden Files", command=scan_hidden_files, **button_config).pack()
    ctk.CTkButton(root, text="🔎 Check Registry", command=check_registry, **button_config).pack()
    ctk.CTkButton(root, text="🗑️ Delete Hidden Files", command=delete_hidden_files, **button_config).pack()

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



def create_ui():
    """Builds the GUI for the tool."""
    global root, result_textbox

    # Main Window
    root = ctk.CTk()
    root.title("🔍 Keylogger Detector")
    root.geometry("500x500")
    root.resizable(False, False)



def create_ui():
    """Builds the GUI for the tool."""
    global root, result_textbox

    # Main Window
    root = ctk.CTk()
    root.title("🔍 Keylogger Detector")
    root.geometry("500x500")
    root.resizable(False, False)