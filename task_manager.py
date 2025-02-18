#This script will only work on Windows.

import os
import psutil

def list_running_processes():
    """Lists all running processes with their PID and name."""
    processes = []
    print("\nRunning Processes:")
    print(f"{'PID':<10}{'Process Name'}")
    print("-" * 30)
    
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            print(f"{pid:<10}{name}")
            processes.append((pid, name))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    return processes

def kill_process_by_pid(pid):
    """Terminates a process by its PID."""
    try:
        process = psutil.Process(pid)
        process.terminate()  # Terminate the process
        print(f"Process {pid} ({process.name()}) terminated successfully.")
    except psutil.NoSuchProcess:
        print("Error: No such process found.")
    except psutil.AccessDenied:
        print("Error: Permission denied. Try running as administrator.")
    except Exception as e:
        print(f"Unexpected error: {e}")

def kill_process_by_name(name):
    """Terminates a process by its name."""
    found = False
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        if proc.info['name'].lower() == name.lower():
            try:
                proc.terminate()
                print(f"Process {proc.info['pid']} ({proc.info['name']}) terminated successfully.")
                found = True
            except psutil.NoSuchProcess:
                print(f"Error: {proc.info['name']} process not found.")
            except psutil.AccessDenied:
                print(f"Error: Permission denied for {proc.info['name']}.")
            except Exception as e:
                print(f"Unexpected error: {e}")
    
    if not found:
        print("Error: No process found with that name.")

if __name__ == "__main__":
    while True:
        print("\nTask Manager Options:")
        print("1. View running processes")
        print("2. Kill a process by PID")
        print("3. Kill a process by name")
        print("4. Open Task Manager")
        print("5. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            list_running_processes()
        elif choice == "2":
            try:
                pid = int(input("Enter the PID of the process to kill: ").strip())
                kill_process_by_pid(pid)
            except ValueError:
                print("Error: Invalid PID. Please enter a number.")
        elif choice == "3":
            name = input("Enter the process name to kill (e.g., notepad.exe): ").strip()
            kill_process_by_name(name)
        elif choice == "4":
            # Open Task Manager (Windows only)
            os.system("taskmgr")
        elif choice == "5":
            print("Exiting Task Manager...")
            break
        else:
            print("Invalid choice. Please enter a valid option.")
