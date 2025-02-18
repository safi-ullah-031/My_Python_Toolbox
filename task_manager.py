import os
import sys
import psutil
import tkinter as tk
from tkinter import ttk, messagebox

# Function to get the list of running processes
def get_processes(search_text=""):
    process_list.delete(*process_list.get_children())  # Clear the list

    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            
            # Filter processes based on search input
            if search_text.lower() in name.lower():
                process_list.insert("", "end", values=(pid, name))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

# Function to kill a selected process
def kill_selected_process():
    selected_item = process_list.selection()
    if not selected_item:
        messagebox.showwarning("No Selection", "Please select a process to terminate.")
        return

    # Get PID from selected row
    process_info = process_list.item(selected_item, "values")
    if not process_info:
        return

    pid = int(process_info[0])

    try:
        process = psutil.Process(pid)
        process.terminate()  # Kill process
        messagebox.showinfo("Success", f"Process {pid} ({process_info[1]}) terminated successfully.")
        get_processes()  # Refresh process list
    except psutil.NoSuchProcess:
        messagebox.showerror("Error", "Process no longer exists.")
    except psutil.AccessDenied:
        messagebox.showerror("Error", "Permission denied! Try running as administrator.")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {e}")

# Function to open Task Manager (OS-specific)
def open_task_manager():
    try:
        if sys.platform.startswith("win"):
            os.system("taskmgr")  # Windows Task Manager
        elif sys.platform.startswith("darwin"):
            os.system("open -a 'Activity Monitor'")  # macOS Activity Monitor
        elif sys.platform.startswith("linux"):
            os.system("gnome-system-monitor &")  # Linux System Monitor (GNOME)
        else:
            messagebox.showerror("Error", "Task Manager not supported on this OS.")
    except Exception as e:
        messagebox.showerror("Error", f"Could not open Task Manager: {e}")

# Function to refresh process list with search
def refresh_processes():
    search_text = search_var.get().strip()
    get_processes(search_text)

# Creating the GUI window
root = tk.Tk()
root.title("Cross-Platform Task Manager")
root.geometry("650x500")
root.configure(bg="#2e2e2e")

# Search bar
search_var = tk.StringVar()
search_entry = ttk.Entry(root, textvariable=search_var, width=50)
search_entry.pack(pady=10)
search_entry.insert(0, "Search process...")

# Process list (TreeView Table)
columns = ("PID", "Process Name")
process_list = ttk.Treeview(root, columns=columns, show="headings", height=15)

# Column headings
process_list.heading("PID", text="PID", anchor="center")
process_list.heading("Process Name", text="Process Name", anchor="w")

# Column width
process_list.column("PID", width=80, anchor="center")
process_list.column("Process Name", width=400, anchor="w")

process_list.pack(pady=10, padx=10, fill="both", expand=True)

# Buttons
button_frame = tk.Frame(root, bg="#2e2e2e")
button_frame.pack(pady=10)

kill_button = ttk.Button(button_frame, text="Kill Selected Process", command=kill_selected_process)
kill_button.grid(row=0, column=0, padx=10)

refresh_button = ttk.Button(button_frame, text="Refresh List", command=refresh_processes)
refresh_button.grid(row=0, column=1, padx=10)

task_manager_button = ttk.Button(button_frame, text="Open Task Manager", command=open_task_manager)
task_manager_button.grid(row=0, column=2, padx=10)

# Load processes initially
get_processes()

# Run the GUI
root.mainloop()
