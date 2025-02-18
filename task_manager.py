import tkinter as tk
from tkinter import ttk, messagebox
import psutil

# Function to fetch and display running processes
def update_process_list(search_text=""):
    process_list.delete(*process_list.get_children())  # Clear existing items
    
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
        update_process_list()
    except psutil.NoSuchProcess:
        messagebox.showerror("Error", "Process no longer exists.")
    except psutil.AccessDenied:
        messagebox.showerror("Error", "Permission denied! Try running as administrator.")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {e}")

# Function to refresh the process list
def refresh_processes():
    search_text = search_var.get().strip()
    update_process_list(search_text)

# Creating the GUI window
root = tk.Tk()
root.title("Task Manager - Process Killer")
root.geometry("600x500")
root.configure(bg="#1e1e1e")

# Search bar
search_var = tk.StringVar()
search_entry = ttk.Entry(root, textvariable=search_var, width=40)
search_entry.pack(pady=10)
search_entry.insert(0, "Search process...")

# Process list
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
button_frame = tk.Frame(root, bg="#1e1e1e")
button_frame.pack(pady=10)

kill_button = ttk.Button(button_frame, text="Kill Selected Process", command=kill_selected_process)
kill_button.grid(row=0, column=0, padx=10)

refresh_button = ttk.Button(button_frame, text="Refresh List", command=refresh_processes)
refresh_button.grid(row=0, column=1, padx=10)

# Load processes initially
update_process_list()

# Run the GUI
root.mainloop()
