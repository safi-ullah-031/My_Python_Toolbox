import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import socket
import psutil
import json
import csv

class NetworkInfoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Info Tool")
        self.root.geometry("500x600")
        self.theme_var = tk.StringVar(value="Dark")

        self.build_ui()
        self.switch_theme()

        self.fetch_network_info()

    def build_ui(self):
        self.frame = tk.Frame(self.root)
        self.frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        self.output_text = tk.Text(self.frame, wrap=tk.WORD, height=25)
        self.output_text.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)

        self.bottom_frame = tk.Frame(self.root)
        self.bottom_frame.pack(fill=tk.X, padx=10, pady=10)

        self.fetch_btn = tk.Button(self.bottom_frame, text="Fetch Network Info", command=self.fetch_network_info)
        self.fetch_btn.pack(side=tk.LEFT, padx=5)

        self.save_btn = tk.Button(self.bottom_frame, text="Save As", command=self.save_file)
        self.save_btn.pack(side=tk.LEFT, padx=5)

        self.save_format = ttk.Combobox(self.bottom_frame, values=["TXT", "JSON", "CSV"], state="readonly")
        self.save_format.current(0)
        self.save_format.pack(side=tk.LEFT, padx=5)

        self.theme_switch = ttk.Combobox(self.bottom_frame, values=["Dark", "Light"], state="readonly", textvariable=self.theme_var)
        self.theme_switch.pack(side=tk.LEFT, padx=5)
        self.theme_switch.bind("<<ComboboxSelected>>", lambda e: self.switch_theme())

    def switch_theme(self):
        dark_mode = self.theme_var.get() == "Dark"

        bg_color = '#2b2b2b' if dark_mode else 'white'
        text_bg = '#1e1e1e' if dark_mode else 'white'
        text_fg = 'white' if dark_mode else 'black'
        button_bg = '#3a3a3a' if dark_mode else '#f0f0f0'
        button_fg = 'white' if dark_mode else 'black'

        self.root.configure(bg=bg_color)
        self.frame.configure(bg=bg_color)
        self.bottom_frame.configure(bg=bg_color)

        self.output_text.configure(bg=text_bg, fg=text_fg, insertbackground=text_fg)
        self.fetch_btn.configure(bg=button_bg, fg=button_fg)
        self.save_btn.configure(bg=button_bg, fg=button_fg)

    def fetch_network_info(self):
        data = self.get_network_info()
        output = self.format_network_info(data)
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert(tk.END, output)

    def save_file(self):
        format_choice = self.save_format.get()
        file_path = filedialog.asksaveasfilename(defaultextension=f".{format_choice.lower()}",
                                                  filetypes=[(f"{format_choice} files", f"*.{format_choice.lower()}"),
                                                             ("All files", "*.*")])
        if not file_path:
            return

        data = self.get_network_info()
        if format_choice == "TXT":
            with open(file_path, 'w') as file:
                file.write(self.output_text.get('1.0', tk.END))
        elif format_choice == "JSON":
            with open(file_path, 'w') as file:
                json.dump(data, file, indent=4)
        elif format_choice == "CSV":
            self.save_csv(file_path, data)

        messagebox.showinfo("Saved", f"File saved successfully as {format_choice}!")

    def save_csv(self, file_path, data):
        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Section", "Key", "Value"])

            for section, items in data.items():
                if isinstance(items, list):
                    for item in items:
                        writer.writerow([section, "", item])
                elif isinstance(items, dict):
                    for key, value in items.items():
                        writer.writerow([section, key, value])
                else:
                    writer.writerow([section, "", items])

    def get_network_info(self):
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)

        interfaces = {}
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interfaces[interface] = {
                        'IP Address': addr.address,
                        'Netmask': addr.netmask,
                        'MAC Address': next((a.address for a in addrs if a.family == psutil.AF_LINK), '-')
                    }

        dns_servers = self.get_dns_servers()

        return {
            "Hostname": hostname,
            "IP Address": ip_address,
            "Network Interfaces": interfaces,
            "DNS Servers": dns_servers
        }

    def get_dns_servers(self):
        dns_servers = []
        try:
            with open('/etc/resolv.conf', 'r') as file:
                for line in file:
                    if line.startswith('nameserver'):
                        dns_servers.append(line.split()[1])
        except FileNotFoundError:
            dns_servers = ["8.8.8.8", "8.8.4.4"]
        return dns_servers

    def format_network_info(self, data):
        output = []
        output.append("+------------------------------+")
        output.append(f"| Hostname: {data['Hostname']}")
        output.append(f"| IP Address: {data['IP Address']}")
        output.append("+------------------------------+\n")

        output.append("+------------------------------+")
        output.append("| Network Interfaces")
        for interface, info in data['Network Interfaces'].items():
            output.append(f"| {interface}:")
            for key, value in info.items():
                output.append(f"|   {key}: {value}")
            output.append("|----------------------------------|")
        output.append("+------------------------------+\n")

        output.append("+------------------------------+")
        output.append("| DNS Servers")
        for dns in data['DNS Servers']:
            output.append(f"| {dns}")
        output.append("+------------------------------+")
        return "\n".join(output)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkInfoApp(root)
    root.mainloop()
