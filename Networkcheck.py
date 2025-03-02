# # # # # import socket
# # # # # import uuid
# # # # # import psutil
# # # # # import os
# # # # # import subprocess
# # # # # import tkinter as tk
# # # # # from tkinter import scrolledtext

# # # # # def get_ip_address():
# # # # #     try:
# # # # #         hostname = socket.gethostname()
# # # # #         ip_address = socket.gethostbyname(hostname)
# # # # #         return ip_address
# # # # #     except Exception as e:
# # # # #         return f"Error: {str(e)}"

# # # # # def get_mac_address():
# # # # #     try:
# # # # #         mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 8)][::-1])
# # # # #         return mac
# # # # #     except Exception as e:
# # # # #         return f"Error: {str(e)}"

# # # # # def get_network_interfaces():
# # # # #     try:
# # # # #         interfaces = psutil.net_if_addrs()
# # # # #         network_data = {}
# # # # #         for interface, addresses in interfaces.items():
# # # # #             network_data[interface] = {}
# # # # #             for address in addresses:
# # # # #                 if address.family == socket.AF_INET:
# # # # #                     network_data[interface]['IP Address'] = address.address
# # # # #                     network_data[interface]['Netmask'] = address.netmask
# # # # #                 elif address.family == psutil.AF_LINK:
# # # # #                     network_data[interface]['MAC Address'] = address.address
# # # # #         return network_data
# # # # #     except Exception as e:
# # # # #         return f"Error: {str(e)}"

# # # # # def get_default_gateway():
# # # # #     try:
# # # # #         gateways_command = "ipconfig" if os.name == "nt" else "ip route show"
# # # # #         result = subprocess.check_output(gateways_command, shell=True, stderr=subprocess.DEVNULL, text=True)
        
# # # # #         if os.name == "nt":
# # # # #             for line in result.split("\n"):
# # # # #                 if "Default Gateway" in line:
# # # # #                     parts = line.split(":")
# # # # #                     if len(parts) > 1:
# # # # #                         return parts[1].strip()
# # # # #         else:
# # # # #             for line in result.split("\n"):
# # # # #                 if "default via" in line:
# # # # #                     return line.split()[2]
# # # # #         return "Default gateway not found"
# # # # #     except Exception as e:
# # # # #         return f"Error: {str(e)}"

# # # # # def get_dns_servers():
# # # # #     try:
# # # # #         dns_servers = []
# # # # #         if os.name == "nt":
# # # # #             result = subprocess.check_output("ipconfig /all", shell=True, stderr=subprocess.DEVNULL, text=True)
# # # # #             for line in result.split("\n"):
# # # # #                 if "DNS Servers" in line:
# # # # #                     dns_servers.append(line.split(":")[1].strip())
# # # # #         else:
# # # # #             with open("/etc/resolv.conf", "r") as file:
# # # # #                 for line in file:
# # # # #                     if line.startswith("nameserver"):
# # # # #                         dns_servers.append(line.split()[1].strip())
# # # # #         return dns_servers if dns_servers else ["DNS servers not found"]
# # # # #     except Exception as e:
# # # # #         return [f"Error: {str(e)}"]

# # # # # def fetch_network_info():
# # # # #     output_text.delete("1.0", tk.END)  # Clear previous output
# # # # #     try:
# # # # #         output_text.insert(tk.END, f"Hostname: {socket.gethostname()}\n")
# # # # #         output_text.insert(tk.END, f"IP Address: {get_ip_address()}\n")
# # # # #         output_text.insert(tk.END, f"MAC Address: {get_mac_address()}\n\n")

# # # # #         network_interfaces = get_network_interfaces()
# # # # #         if isinstance(network_interfaces, dict):
# # # # #             output_text.insert(tk.END, "Network Interfaces:\n")
# # # # #             for interface, details in network_interfaces.items():
# # # # #                 output_text.insert(tk.END, f"  {interface}:\n")
# # # # #                 for key, value in details.items():
# # # # #                     output_text.insert(tk.END, f"    {key}: {value}\n")
# # # # #         else:
# # # # #             output_text.insert(tk.END, network_interfaces + "\n")

# # # # #         output_text.insert(tk.END, f"\nDefault Gateway: {get_default_gateway()}\n")

# # # # #         dns_servers = get_dns_servers()
# # # # #         output_text.insert(tk.END, "\nDNS Servers:\n")
# # # # #         for dns in dns_servers:
# # # # #             output_text.insert(tk.END, f"  {dns}\n")
# # # # #     except Exception as e:
# # # # #         output_text.insert(tk.END, f"Unexpected error: {str(e)}")

# # # # # # GUI Setup
# # # # # root = tk.Tk()
# # # # # root.title("Network Info Tool")
# # # # # root.geometry("600x400")

# # # # # # Button to fetch data
# # # # # fetch_button = tk.Button(root, text="Fetch Network Info", command=fetch_network_info, font=("Arial", 12), bg="lightblue")
# # # # # fetch_button.pack(pady=10)

# # # # # # Scrollable Text Box
# # # # # output_text = scrolledtext.ScrolledText(root, width=70, height=20, font=("Courier", 10))
# # # # # output_text.pack(pady=10)

# # # # # # Run GUI
# # # # # root.mainloop()


# # # # import socket
# # # # import uuid
# # # # import psutil
# # # # import os
# # # # import subprocess
# # # # import tkinter as tk
# # # # from tkinter import ttk, messagebox

# # # # def get_ip_address():
# # # #     try:
# # # #         hostname = socket.gethostname()
# # # #         return socket.gethostbyname(hostname)
# # # #     except Exception as e:
# # # #         return f"Error: {str(e)}"

# # # # def get_mac_address():
# # # #     try:
# # # #         mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 8)][::-1])
# # # #         return mac
# # # #     except Exception as e:
# # # #         return f"Error: {str(e)}"

# # # # def get_network_interfaces():
# # # #     try:
# # # #         interfaces = psutil.net_if_addrs()
# # # #         network_data = {}
# # # #         for interface, addresses in interfaces.items():
# # # #             network_data[interface] = {}
# # # #             for address in addresses:
# # # #                 if address.family == socket.AF_INET:
# # # #                     network_data[interface]['IP Address'] = address.address
# # # #                     network_data[interface]['Netmask'] = address.netmask
# # # #                 elif address.family == psutil.AF_LINK:
# # # #                     network_data[interface]['MAC Address'] = address.address
# # # #         return network_data
# # # #     except Exception as e:
# # # #         return {"Error": str(e)}

# # # # def get_default_gateway():
# # # #     try:
# # # #         if os.name == "nt":
# # # #             result = subprocess.check_output("ipconfig", shell=True, text=True)
# # # #             for line in result.splitlines():
# # # #                 if "Default Gateway" in line and ":" in line:
# # # #                     return line.split(":")[1].strip()
# # # #         else:
# # # #             result = subprocess.check_output("ip route show", shell=True, text=True)
# # # #             for line in result.splitlines():
# # # #                 if "default via" in line:
# # # #                     return line.split()[2]
# # # #         return "Not Found"
# # # #     except Exception as e:
# # # #         return f"Error: {str(e)}"

# # # # def get_dns_servers():
# # # #     try:
# # # #         dns_servers = []
# # # #         if os.name == "nt":
# # # #             result = subprocess.check_output("ipconfig /all", shell=True, text=True)
# # # #             for line in result.splitlines():
# # # #                 if "DNS Servers" in line:
# # # #                     dns_servers.append(line.split(":")[1].strip())
# # # #         else:
# # # #             with open("/etc/resolv.conf", "r") as file:
# # # #                 for line in file:
# # # #                     if line.startswith("nameserver"):
# # # #                         dns_servers.append(line.split()[1].strip())
# # # #         return dns_servers if dns_servers else ["Not Found"]
# # # #     except Exception as e:
# # # #         return [f"Error: {str(e)}"]

# # # # def fetch_network_info():
# # # #     try:
# # # #         hostname_label_value.config(text=socket.gethostname())
# # # #         ip_label_value.config(text=get_ip_address())
# # # #         mac_label_value.config(text=get_mac_address())
# # # #         gateway_label_value.config(text=get_default_gateway())

# # # #         dns_servers = get_dns_servers()
# # # #         dns_textbox.delete("1.0", tk.END)
# # # #         for dns in dns_servers:
# # # #             dns_textbox.insert(tk.END, dns + "\n")

# # # #         interfaces = get_network_interfaces()
# # # #         interface_textbox.delete("1.0", tk.END)
# # # #         for interface, details in interfaces.items():
# # # #             interface_textbox.insert(tk.END, f"{interface}:\n")
# # # #             for key, value in details.items():
# # # #                 interface_textbox.insert(tk.END, f"  {key}: {value}\n")
# # # #             interface_textbox.insert(tk.END, "\n")
# # # #     except Exception as e:
# # # #         messagebox.showerror("Error", f"Failed to fetch network info: {str(e)}")

# # # # # GUI Setup
# # # # root = tk.Tk()
# # # # root.title("Network Information Tool")
# # # # root.geometry("700x500")
# # # # root.configure(bg="#f0f0f0")

# # # # # Main Frame for Layout
# # # # main_frame = ttk.Frame(root, padding=10)
# # # # main_frame.pack(fill=tk.BOTH, expand=True)

# # # # # === Hostname, IP, MAC, Gateway Section ===
# # # # basic_info_frame = ttk.LabelFrame(main_frame, text="Basic Info", padding=10)
# # # # basic_info_frame.pack(fill=tk.X, pady=5)

# # # # # Labels and Values
# # # # hostname_label = ttk.Label(basic_info_frame, text="Hostname:")
# # # # hostname_label.grid(row=0, column=0, sticky="w", padx=5, pady=2)
# # # # hostname_label_value = ttk.Label(basic_info_frame, text="N/A")
# # # # hostname_label_value.grid(row=0, column=1, sticky="w", padx=5)

# # # # ip_label = ttk.Label(basic_info_frame, text="IP Address:")
# # # # ip_label.grid(row=1, column=0, sticky="w", padx=5, pady=2)
# # # # ip_label_value = ttk.Label(basic_info_frame, text="N/A")
# # # # ip_label_value.grid(row=1, column=1, sticky="w", padx=5)

# # # # mac_label = ttk.Label(basic_info_frame, text="MAC Address:")
# # # # mac_label.grid(row=2, column=0, sticky="w", padx=5, pady=2)
# # # # mac_label_value = ttk.Label(basic_info_frame, text="N/A")
# # # # mac_label_value.grid(row=2, column=1, sticky="w", padx=5)

# # # # gateway_label = ttk.Label(basic_info_frame, text="Default Gateway:")
# # # # gateway_label.grid(row=3, column=0, sticky="w", padx=5, pady=2)
# # # # gateway_label_value = ttk.Label(basic_info_frame, text="N/A")
# # # # gateway_label_value.grid(row=3, column=1, sticky="w", padx=5)

# # # # # === Network Interfaces Section ===
# # # # interfaces_frame = ttk.LabelFrame(main_frame, text="Network Interfaces", padding=10)
# # # # interfaces_frame.pack(fill=tk.BOTH, expand=True, pady=5)

# # # # interface_textbox = tk.Text(interfaces_frame, height=8, wrap=tk.WORD, font=("Courier", 9))
# # # # interface_textbox.pack(fill=tk.BOTH, expand=True)

# # # # # === DNS Servers Section ===
# # # # dns_frame = ttk.LabelFrame(main_frame, text="DNS Servers", padding=10)
# # # # dns_frame.pack(fill=tk.BOTH, expand=True, pady=5)

# # # # dns_textbox = tk.Text(dns_frame, height=5, wrap=tk.WORD, font=("Courier", 9))
# # # # dns_textbox.pack(fill=tk.BOTH, expand=True)

# # # # # Fetch Button
# # # # fetch_button = ttk.Button(main_frame, text="Fetch Network Info", command=fetch_network_info)
# # # # fetch_button.pack(pady=10)

# # # # # Run the GUI
# # # # root.mainloop()


# # # import socket
# # # import uuid
# # # import psutil
# # # import os
# # # import subprocess
# # # import tkinter as tk
# # # from tkinter import ttk, messagebox

# # # # Functions to get network information
# # # def get_ip_address():
# # #     try:
# # #         hostname = socket.gethostname()
# # #         return socket.gethostbyname(hostname)
# # #     except Exception as e:
# # #         return f"Error: {str(e)}"

# # # def get_mac_address():
# # #     try:
# # #         mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 8)][::-1])
# # #         return mac
# # #     except Exception as e:
# # #         return f"Error: {str(e)}"

# # # def get_network_interfaces():
# # #     try:
# # #         interfaces = psutil.net_if_addrs()
# # #         network_data = {}
# # #         for interface, addresses in interfaces.items():
# # #             network_data[interface] = {}
# # #             for address in addresses:
# # #                 if address.family == socket.AF_INET:
# # #                     network_data[interface]['IP Address'] = address.address
# # #                     network_data[interface]['Netmask'] = address.netmask
# # #                 elif address.family == psutil.AF_LINK:
# # #                     network_data[interface]['MAC Address'] = address.address
# # #         return network_data
# # #     except Exception as e:
# # #         return {"Error": str(e)}

# # # def get_default_gateway():
# # #     try:
# # #         if os.name == "nt":
# # #             result = subprocess.check_output("ipconfig", shell=True, text=True)
# # #             for line in result.splitlines():
# # #                 if "Default Gateway" in line and ":" in line:
# # #                     return line.split(":")[1].strip()
# # #         else:
# # #             result = subprocess.check_output("ip route show", shell=True, text=True)
# # #             for line in result.splitlines():
# # #                 if "default via" in line:
# # #                     return line.split()[2]
# # #         return "Not Found"
# # #     except Exception as e:
# # #         return f"Error: {str(e)}"

# # # def get_dns_servers():
# # #     try:
# # #         dns_servers = []
# # #         if os.name == "nt":
# # #             result = subprocess.check_output("ipconfig /all", shell=True, text=True)
# # #             for line in result.splitlines():
# # #                 if "DNS Servers" in line:
# # #                     dns_servers.append(line.split(":")[1].strip())
# # #         else:
# # #             with open("/etc/resolv.conf", "r") as file:
# # #                 for line in file:
# # #                     if line.startswith("nameserver"):
# # #                         dns_servers.append(line.split()[1].strip())
# # #         return dns_servers if dns_servers else ["Not Found"]
# # #     except Exception as e:
# # #         return [f"Error: {str(e)}"]

# # # def fetch_network_info():
# # #     try:
# # #         hostname_label_value.config(text=socket.gethostname())
# # #         ip_label_value.config(text=get_ip_address())
# # #         mac_label_value.config(text=get_mac_address())
# # #         gateway_label_value.config(text=get_default_gateway())

# # #         dns_servers = get_dns_servers()
# # #         dns_textbox.delete("1.0", tk.END)
# # #         for dns in dns_servers:
# # #             dns_textbox.insert(tk.END, dns + "\n")

# # #         interfaces = get_network_interfaces()
# # #         interface_textbox.delete("1.0", tk.END)
# # #         for interface, details in interfaces.items():
# # #             interface_textbox.insert(tk.END, f"{interface}:\n")
# # #             for key, value in details.items():
# # #                 interface_textbox.insert(tk.END, f"  {key}: {value}\n")
# # #             interface_textbox.insert(tk.END, "\n")
# # #     except Exception as e:
# # #         messagebox.showerror("Error", f"Failed to fetch network info: {str(e)}")

# # # # === Theme Switcher (Light/Dark Mode) ===
# # # def toggle_theme():
# # #     global dark_mode
# # #     dark_mode = not dark_mode
# # #     apply_theme()

# # # def apply_theme():
# # #     bg_color = "#2E2E2E" if dark_mode else "#F0F0F0"
# # #     fg_color = "#FFFFFF" if dark_mode else "#000000"
# # #     textbox_bg = "#3E3E3E" if dark_mode else "#FFFFFF"
# # #     textbox_fg = "#FFFFFF" if dark_mode else "#000000"

# # #     root.config(bg=bg_color)
# # #     main_frame.config(bg=bg_color)

# # #     for widget in main_frame.winfo_children():
# # #         if isinstance(widget, ttk.LabelFrame) or isinstance(widget, ttk.Frame):
# # #             widget.config(style="Dark.TLabelframe" if dark_mode else "Light.TLabelframe")

# # #         for child in widget.winfo_children():
# # #             if isinstance(child, ttk.Label):
# # #                 child.config(background=bg_color, foreground=fg_color)
# # #             elif isinstance(child, tk.Text):
# # #                 child.config(background=textbox_bg, foreground=textbox_fg)

# # # # GUI Setup
# # # root = tk.Tk()
# # # root.title("Network Information Tool")
# # # root.geometry("700x500")

# # # dark_mode = False

# # # # Styles
# # # style = ttk.Style()
# # # style.configure("Light.TLabelframe", background="#F0F0F0", foreground="black")
# # # style.configure("Dark.TLabelframe", background="#2E2E2E", foreground="white")

# # # # Main Frame
# # # main_frame = tk.Frame(root, padx=10, pady=10)
# # # main_frame.pack(fill=tk.BOTH, expand=True)

# # # # Basic Info Section
# # # basic_info_frame = ttk.LabelFrame(main_frame, text="Basic Info", padding=10)
# # # basic_info_frame.pack(fill=tk.X, pady=5)

# # # labels = ["Hostname:", "IP Address:", "MAC Address:", "Default Gateway:"]
# # # basic_info_labels = []
# # # basic_info_values = []

# # # for idx, label_text in enumerate(labels):
# # #     lbl = ttk.Label(basic_info_frame, text=label_text, width=15)
# # #     lbl.grid(row=idx, column=0, sticky="w", padx=5, pady=2)
# # #     value = ttk.Label(basic_info_frame, text="N/A")
# # #     value.grid(row=idx, column=1, sticky="w", padx=5)
# # #     basic_info_labels.append(lbl)
# # #     basic_info_values.append(value)

# # # hostname_label_value, ip_label_value, mac_label_value, gateway_label_value = basic_info_values

# # # # Network Interfaces Section
# # # interfaces_frame = ttk.LabelFrame(main_frame, text="Network Interfaces", padding=10)
# # # interfaces_frame.pack(fill=tk.BOTH, expand=True, pady=5)

# # # interface_textbox = tk.Text(interfaces_frame, height=6, wrap=tk.WORD)
# # # interface_textbox.pack(fill=tk.BOTH, expand=True)

# # # # DNS Servers Section
# # # dns_frame = ttk.LabelFrame(main_frame, text="DNS Servers", padding=10)
# # # dns_frame.pack(fill=tk.BOTH, expand=True, pady=5)

# # # dns_textbox = tk.Text(dns_frame, height=4, wrap=tk.WORD)
# # # dns_textbox.pack(fill=tk.BOTH, expand=True)

# # # # Bottom Buttons
# # # button_frame = tk.Frame(main_frame)
# # # button_frame.pack(fill=tk.X, pady=10)

# # # fetch_button = ttk.Button(button_frame, text="Fetch Network Info", command=fetch_network_info)
# # # fetch_button.pack(side=tk.LEFT, padx=5)

# # # theme_button = ttk.Button(button_frame, text="Toggle Light/Dark", command=toggle_theme)
# # # theme_button.pack(side=tk.RIGHT, padx=5)

# # # apply_theme()  # Set initial theme
# # # root.mainloop()

# # import socket
# # import uuid
# # import psutil
# # import os
# # import subprocess
# # import tkinter as tk
# # from tkinter import ttk

# # # Functions to get network information
# # def get_ip_address():
# #     try:
# #         hostname = socket.gethostname()
# #         return socket.gethostbyname(hostname)
# #     except Exception as e:
# #         return f"Error: {str(e)}"

# # def get_mac_address():
# #     try:
# #         mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 8)][::-1])
# #         return mac
# #     except Exception as e:
# #         return f"Error: {str(e)}"

# # def get_network_interfaces():
# #     interfaces = psutil.net_if_addrs()
# #     network_data = {}
# #     for interface, addresses in interfaces.items():
# #         network_data[interface] = {}
# #         for address in addresses:
# #             if address.family == socket.AF_INET:
# #                 network_data[interface]['IP Address'] = address.address
# #                 network_data[interface]['Netmask'] = address.netmask
# #             elif address.family == psutil.AF_LINK:
# #                 network_data[interface]['MAC Address'] = address.address
# #     return network_data

# # def get_default_gateway():
# #     try:
# #         if os.name == "nt":
# #             result = subprocess.check_output("ipconfig", shell=True, text=True)
# #             for line in result.splitlines():
# #                 if "Default Gateway" in line and ":" in line:
# #                     return line.split(":")[1].strip()
# #         else:
# #             result = subprocess.check_output("ip route show", shell=True, text=True)
# #             for line in result.splitlines():
# #                 if "default via" in line:
# #                     return line.split()[2]
# #         return "Not Found"
# #     except Exception as e:
# #         return f"Error: {str(e)}"

# # def get_dns_servers():
# #     dns_servers = []
# #     if os.name == "nt":
# #         result = subprocess.check_output("ipconfig /all", shell=True, text=True)
# #         for line in result.splitlines():
# #             if "DNS Servers" in line:
# #                 dns_servers.append(line.split(":")[1].strip())
# #     else:
# #         with open("/etc/resolv.conf", "r") as file:
# #             for line in file:
# #                 if line.startswith("nameserver"):
# #                     dns_servers.append(line.split()[1].strip())
# #     return dns_servers if dns_servers else ["Not Found"]

# # # Function to fetch and display network info
# # def fetch_network_info():
# #     hostname = socket.gethostname()
# #     ip = get_ip_address()
# #     mac = get_mac_address()
# #     gateway = get_default_gateway()
# #     dns_servers = get_dns_servers()
# #     interfaces = get_network_interfaces()

# #     # Format the text like the requested boxed layout
# #     basic_info_text = (
# #         "+------------------------------+\n"
# #         f"| Hostname: {hostname}\n"
# #         f"| IP Address: {ip}\n"
# #         f"| MAC Address: {mac}\n"
# #         f"| Default Gateway: {gateway}\n"
# #         "+------------------------------+\n"
# #     )

# #     interface_text = "+------------------------------+\n| Network Interfaces\n"
# #     for interface, details in interfaces.items():
# #         interface_text += f"| {interface}:\n"
# #         for key, value in details.items():
# #             value = value if value else "-"
# #             interface_text += f"|   {key}: {value}\n"
# #         interface_text += "|----------------------------------\n"
# #     interface_text += "+------------------------------+\n"

# #     dns_text = "+------------------------------+\n| DNS Servers\n"
# #     for dns in dns_servers:
# #         dns_text += f"| {dns}\n"
# #     dns_text += "+------------------------------+\n"

# #     # Update Textbox
# #     output_textbox.config(state=tk.NORMAL)
# #     output_textbox.delete("1.0", tk.END)
# #     output_textbox.insert(tk.END, basic_info_text + "\n" + interface_text + "\n" + dns_text)
# #     output_textbox.config(state=tk.DISABLED)

# # # Function to toggle dark/light mode
# # def toggle_theme():
# #     global dark_mode
# #     dark_mode = not dark_mode
# #     apply_theme()

# # def apply_theme():
# #     bg_color = "#2E2E2E" if dark_mode else "#F0F0F0"
# #     fg_color = "#FFFFFF" if dark_mode else "#000000"
# #     textbox_bg = "#3E3E3E" if dark_mode else "#FFFFFF"
# #     textbox_fg = "#FFFFFF" if dark_mode else "#000000"

# #     root.config(bg=bg_color)
# #     frame.config(bg=bg_color)
# #     output_textbox.config(bg=textbox_bg, fg=textbox_fg, font=("Courier", 10, "normal"))

# #     fetch_button.config(bg="#555555" if dark_mode else "#DDDDDD")
# #     theme_button.config(bg="#555555" if dark_mode else "#DDDDDD")

# # # GUI Setup
# # root = tk.Tk()
# # root.title("Network Info Tool")
# # root.geometry("600x500")

# # dark_mode = False

# # # Main Frame
# # frame = tk.Frame(root, padx=10, pady=10)
# # frame.pack(fill=tk.BOTH, expand=True)

# # # Output Textbox
# # output_textbox = tk.Text(frame, height=25, wrap=tk.WORD, state=tk.DISABLED)
# # output_textbox.pack(fill=tk.BOTH, expand=True)

# # # Buttons
# # button_frame = tk.Frame(frame)
# # button_frame.pack(fill=tk.X, pady=5)

# # fetch_button = tk.Button(button_frame, text="Fetch Network Info", command=fetch_network_info)
# # fetch_button.pack(side=tk.LEFT, padx=5)

# # theme_button = tk.Button(button_frame, text="Toggle Light/Dark", command=toggle_theme)
# # theme_button.pack(side=tk.RIGHT, padx=5)

# # apply_theme()
# # root.mainloop()



# import socket
# import uuid
# import psutil
# import os
# import subprocess
# import tkinter as tk
# from tkinter import filedialog, messagebox

# # Functions to get network information
# def get_ip_address():
#     try:
#         hostname = socket.gethostname()
#         return socket.gethostbyname(hostname)
#     except Exception as e:
#         return f"Error: {str(e)}"

# def get_mac_address():
#     try:
#         mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 8)][::-1])
#         return mac
#     except Exception as e:
#         return f"Error: {str(e)}"

# def get_network_interfaces():
#     interfaces = psutil.net_if_addrs()
#     network_data = {}
#     for interface, addresses in interfaces.items():
#         network_data[interface] = {}
#         for address in addresses:
#             if address.family == socket.AF_INET:
#                 network_data[interface]['IP Address'] = address.address
#                 network_data[interface]['Netmask'] = address.netmask
#             elif address.family == psutil.AF_LINK:
#                 network_data[interface]['MAC Address'] = address.address
#     return network_data

# def get_default_gateway():
#     try:
#         if os.name == "nt":
#             result = subprocess.check_output("ipconfig", shell=True, text=True)
#             for line in result.splitlines():
#                 if "Default Gateway" in line and ":" in line:
#                     return line.split(":")[1].strip()
#         else:
#             result = subprocess.check_output("ip route show", shell=True, text=True)
#             for line in result.splitlines():
#                 if "default via" in line:
#                     return line.split()[2]
#         return "Not Found"
#     except Exception as e:
#         return f"Error: {str(e)}"

# def get_dns_servers():
#     dns_servers = []
#     if os.name == "nt":
#         result = subprocess.check_output("ipconfig /all", shell=True, text=True)
#         for line in result.splitlines():
#             if "DNS Servers" in line:
#                 dns_servers.append(line.split(":")[1].strip())
#     else:
#         with open("/etc/resolv.conf", "r") as file:
#             for line in file:
#                 if line.startswith("nameserver"):
#                     dns_servers.append(line.split()[1].strip())
#     return dns_servers if dns_servers else ["Not Found"]

# # Function to fetch and display network info
# def fetch_network_info():
#     global network_info_text
#     hostname = socket.gethostname()
#     ip = get_ip_address()
#     mac = get_mac_address()
#     gateway = get_default_gateway()
#     dns_servers = get_dns_servers()
#     interfaces = get_network_interfaces()

#     # Format the text in box style
#     basic_info_text = (
#         "+------------------------------+\n"
#         f"| Hostname: {hostname}\n"
#         f"| IP Address: {ip}\n"
#         f"| MAC Address: {mac}\n"
#         f"| Default Gateway: {gateway}\n"
#         "+------------------------------+\n"
#     )

#     interface_text = "+------------------------------+\n| Network Interfaces\n"
#     for interface, details in interfaces.items():
#         interface_text += f"| {interface}:\n"
#         for key, value in details.items():
#             value = value if value else "-"
#             interface_text += f"|   {key}: {value}\n"
#         interface_text += "|----------------------------------\n"
#     interface_text += "+------------------------------+\n"

#     dns_text = "+------------------------------+\n| DNS Servers\n"
#     for dns in dns_servers:
#         dns_text += f"| {dns}\n"
#     dns_text += "+------------------------------+\n"

#     network_info_text = basic_info_text + "\n" + interface_text + "\n" + dns_text

#     # Update Textbox
#     output_textbox.config(state=tk.NORMAL)
#     output_textbox.delete("1.0", tk.END)
#     output_textbox.insert(tk.END, network_info_text)
#     output_textbox.config(state=tk.DISABLED)

# # Function to toggle dark/light mode
# def toggle_theme():
#     global dark_mode
#     dark_mode = not dark_mode
#     apply_theme()

# def apply_theme():
#     bg_color = "#2E2E2E" if dark_mode else "#F0F0F0"
#     fg_color = "#FFFFFF" if dark_mode else "#000000"
#     textbox_bg = "#3E3E3E" if dark_mode else "#FFFFFF"
#     textbox_fg = "#FFFFFF" if dark_mode else "#000000"

#     root.config(bg=bg_color)
#     frame.config(bg=bg_color)
#     output_textbox.config(bg=textbox_bg, fg=textbox_fg, font=("Courier", 10, "normal"))

#     fetch_button.config(bg="#555555" if dark_mode else "#DDDDDD")
#     theme_button.config(bg="#555555" if dark_mode else "#DDDDDD")
#     save_button.config(bg="#555555" if dark_mode else "#DDDDDD")

# # Function to save network info to a file
# def save_to_file():
#     if not network_info_text.strip():
#         messagebox.showwarning("Warning", "No network information available to save. Please fetch the info first.")
#         return

#     file_path = filedialog.asksaveasfilename(
#         defaultextension=".txt",
#         filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
#     )
#     if file_path:
#         try:
#             with open(file_path, "w") as file:
#                 file.write(network_info_text)
#             messagebox.showinfo("Success", f"Network info saved to {file_path}")
#         except Exception as e:
#             messagebox.showerror("Error", f"Failed to save file: {str(e)}")

# # GUI Setup
# root = tk.Tk()
# root.title("Network Info Tool")
# root.geometry("600x500")

# dark_mode = False
# network_info_text = ""

# # Main Frame
# frame = tk.Frame(root, padx=10, pady=10)
# frame.pack(fill=tk.BOTH, expand=True)

# # Output Textbox
# output_textbox = tk.Text(frame, height=25, wrap=tk.WORD, state=tk.DISABLED)
# output_textbox.pack(fill=tk.BOTH, expand=True)

# # Buttons Frame
# button_frame = tk.Frame(frame)
# button_frame.pack(fill=tk.X, pady=5)

# fetch_button = tk.Button(button_frame, text="Fetch Network Info", command=fetch_network_info)
# fetch_button.pack(side=tk.LEFT, padx=5)

# save_button = tk.Button(button_frame, text="Save to File", command=save_to_file)
# save_button.pack(side=tk.LEFT, padx=5)

# theme_button = tk.Button(button_frame, text="Toggle Light/Dark", command=toggle_theme)
# theme_button.pack(side=tk.RIGHT, padx=5)

# apply_theme()
# root.mainloop()



import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import socket
import psutil
import json
import csv

def fetch_network_info():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)

    interfaces_info = {}
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                interfaces_info[interface] = {
                    'ip': addr.address,
                    'netmask': addr.netmask,
                    'mac': next((a.address for a in addrs if a.family == psutil.AF_LINK), '-')
                }

    mac_address = interfaces_info.get('Wi-Fi', {}).get('mac', '-')
    gateway = psutil.net_if_stats()

    dns_servers = []
    try:
        with open('/etc/resolv.conf', 'r') as file:
            for line in file:
                if line.startswith('nameserver'):
                    dns_servers.append(line.split()[1])
    except FileNotFoundError:
        dns_servers = ["8.8.8.8", "8.8.4.4"]

    update_ui(hostname, ip_address, mac_address, interfaces_info, dns_servers)

def update_ui(hostname, ip, mac, interfaces, dns_servers):
    output_text.delete('1.0', tk.END)

    output_text.insert(tk.END, "+------------------------------+\n")
    output_text.insert(tk.END, f"| Hostname: {hostname}\n")
    output_text.insert(tk.END, f"| IP Address: {ip}\n")
    output_text.insert(tk.END, f"| MAC Address: {mac}\n")
    output_text.insert(tk.END, f"| Default Gateway: -\n")
    output_text.insert(tk.END, "+------------------------------+\n\n")

    output_text.insert(tk.END, "+------------------------------+\n")
    output_text.insert(tk.END, "| Network Interfaces\n")

    for interface, info in interfaces.items():
        output_text.insert(tk.END, f"| {interface}:\n")
        output_text.insert(tk.END, f"|   IP Address: {info['ip']}\n")
        output_text.insert(tk.END, f"|   Netmask: {info['netmask']}\n")
        output_text.insert(tk.END, f"|   MAC Address: {info['mac']}\n")
        output_text.insert(tk.END, "|----------------------------------|\n")

    output_text.insert(tk.END, "+------------------------------+\n")
    output_text.insert(tk.END, "| DNS Servers\n")
    for dns in dns_servers:
        output_text.insert(tk.END, f"| {dns}\n")
    output_text.insert(tk.END, "+------------------------------+\n")

def save_file():
    format_choice = save_format.get()
    file_path = filedialog.asksaveasfilename(defaultextension=f".{format_choice.lower()}",
                                              filetypes=[(f"{format_choice} files", f"*.{format_choice.lower()}"),
                                                         ("All files", "*.*")])
    if not file_path:
        return

    if format_choice == "TXT":
        with open(file_path, 'w') as file:
            file.write(output_text.get('1.0', tk.END))
    elif format_choice == "JSON":
        data = parse_network_info()
        with open(file_path, 'w') as file:
            json.dump(data, file, indent=4)
    elif format_choice == "CSV":
        data = parse_network_info()
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

    messagebox.showinfo("Saved", f"File saved successfully as {format_choice}!")

def parse_network_info():
    lines = output_text.get('1.0', tk.END).strip().split('\n')
    data = {}
    section = None
    sub_section = None
    for line in lines:
        line = line.strip('| ').strip()
        if not line or line.startswith('+'):
            continue
        if line.endswith(':'):
            sub_section = line.rstrip(':')
            data[sub_section] = {}
        elif sub_section:
            if ':' in line:
                key, value = line.split(':', 1)
                data[sub_section][key.strip()] = value.strip()
        elif "DNS Servers" in line:
            section = "DNS Servers"
            data[section] = []
        elif section == "DNS Servers":
            data[section].append(line.strip())
        elif ':' in line:
            key, value = line.split(':', 1)
            data[key.strip()] = value.strip()
    return data

# GUI Setup
root = tk.Tk()
root.title("Network Info Tool")

root.geometry("500x600")
root.configure(bg='#2b2b2b')

frame = tk.Frame(root, bg='#2b2b2b')
frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

output_text = tk.Text(frame, wrap=tk.WORD, height=25, bg='#1e1e1e', fg='white', insertbackground='white')
output_text.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)

# Buttons & Save Format
bottom_frame = tk.Frame(root, bg='#2b2b2b')
bottom_frame.pack(fill=tk.X, padx=10, pady=10)

fetch_btn = tk.Button(bottom_frame, text="Fetch Network Info", command=fetch_network_info, bg='#3a3a3a', fg='white')
fetch_btn.pack(side=tk.LEFT, padx=5)

save_btn = tk.Button(bottom_frame, text="Save As", command=save_file, bg='#3a3a3a', fg='white')
save_btn.pack(side=tk.LEFT, padx=5)

save_format = ttk.Combobox(bottom_frame, values=["TXT", "JSON", "CSV"], state="readonly")
save_format.current(0)
save_format.pack(side=tk.LEFT, padx=5)

# Dark & Light Mode Switch
def switch_theme():
    if theme_var.get() == "Dark":
        root.configure(bg='#2b2b2b')
        frame.configure(bg='#2b2b2b')
        bottom_frame.configure(bg='#2b2b2b')
        output_text.configure(bg='#1e1e1e', fg='white', insertbackground='white')
        fetch_btn.configure(bg='#3a3a3a', fg='white')
        save_btn.configure(bg='#3a3a3a', fg='white')
    else:
        root.configure(bg='white')
        frame.configure(bg='white')
        bottom_frame.configure(bg='white')
        output_text.configure(bg='white', fg='black', insertbackground='black')
        fetch_btn.configure(bg='#f0f0f0', fg='black')
        save_btn.configure(bg='#f0f0f0', fg='black')

theme_var = tk.StringVar(value="Dark")
theme_switch = ttk.Combobox(bottom_frame, values=["Dark", "Light"], state="readonly", textvariable=theme_var)
theme_switch.pack(side=tk.LEFT, padx=5)
theme_switch.bind("<<ComboboxSelected>>", lambda e: switch_theme())

fetch_network_info()

root.mainloop()
