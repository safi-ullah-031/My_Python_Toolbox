'''import socket
import uuid
import psutil
import os
import subprocess

def get_ip_address():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return f"Error getting IP address: {str(e)}"

def get_mac_address():
    try:
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 8)][::-1])
        return mac
    except Exception as e:
        return f"Error getting MAC address: {str(e)}"

def get_network_interfaces():
    try:
        interfaces = psutil.net_if_addrs()
        network_data = {}
        for interface, addresses in interfaces.items():
            network_data[interface] = {}
            for address in addresses:
                if address.family == socket.AF_INET:  # IPv4
                    network_data[interface]['IP Address'] = address.address
                    network_data[interface]['Netmask'] = address.netmask
                elif address.family == psutil.AF_LINK:  # MAC Address
                    network_data[interface]['MAC Address'] = address.address
        return network_data
    except Exception as e:
        return f"Error getting network interfaces: {str(e)}"

def get_default_gateway():
    try:
        gateways = psutil.net_if_stats()
        gateways_command = "ipconfig" if os.name == "nt" else "ip route show"
        result = subprocess.check_output(gateways_command, shell=True, stderr=subprocess.DEVNULL, text=True)
        
        if os.name == "nt":
            for line in result.split("\n"):
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        return parts[1].strip()
        else:
            for line in result.split("\n"):
                if "default via" in line:
                    return line.split()[2]
        return "Default gateway not found"
    except Exception as e:
        return f"Error getting default gateway: {str(e)}"

def get_dns_servers():
    try:
        dns_servers = []
        if os.name == "nt":
            result = subprocess.check_output("ipconfig /all", shell=True, stderr=subprocess.DEVNULL, text=True)
            for line in result.split("\n"):
                if "DNS Servers" in line:
                    dns_servers.append(line.split(":")[1].strip())
        else:
            with open("/etc/resolv.conf", "r") as file:
                for line in file:
                    if line.startswith("nameserver"):
                        dns_servers.append(line.split()[1].strip())
        return dns_servers if dns_servers else ["DNS servers not found"]
    except Exception as e:
        return [f"Error getting DNS servers: {str(e)}"]

def main():
    print("Fetching Network Information...\n")

    try:
        print(f"Hostname: {socket.gethostname()}")
        print(f"IP Address: {get_ip_address()}")
        print(f"MAC Address: {get_mac_address()}\n")

        network_interfaces = get_network_interfaces()
        if isinstance(network_interfaces, dict):
            print("Network Interfaces:")
            for interface, details in network_interfaces.items():
                print(f"  {interface}:")
                for key, value in details.items():
                    print(f"    {key}: {value}")
        else:
            print(network_interfaces)

        print(f"\nDefault Gateway: {get_default_gateway()}")

        dns_servers = get_dns_servers()
        print("\nDNS Servers:")
        for dns in dns_servers:
            print(f"  {dns}")
        
    except Exception as e:
        print(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    main()
'''



import socket
import uuid
import psutil
import os
import subprocess
import tkinter as tk
from tkinter import scrolledtext

def get_ip_address():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return f"Error: {str(e)}"

def get_mac_address():
    try:
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 8)][::-1])
        return mac
    except Exception as e:
        return f"Error: {str(e)}"

def get_network_interfaces():
    try:
        interfaces = psutil.net_if_addrs()
        network_data = {}
        for interface, addresses in interfaces.items():
            network_data[interface] = {}
            for address in addresses:
                if address.family == socket.AF_INET:
                    network_data[interface]['IP Address'] = address.address
                    network_data[interface]['Netmask'] = address.netmask
                elif address.family == psutil.AF_LINK:
                    network_data[interface]['MAC Address'] = address.address
        return network_data
    except Exception as e:
        return f"Error: {str(e)}"

def get_default_gateway():
    try:
        gateways_command = "ipconfig" if os.name == "nt" else "ip route show"
        result = subprocess.check_output(gateways_command, shell=True, stderr=subprocess.DEVNULL, text=True)
        
        if os.name == "nt":
            for line in result.split("\n"):
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        return parts[1].strip()
        else:
            for line in result.split("\n"):
                if "default via" in line:
                    return line.split()[2]
        return "Default gateway not found"
    except Exception as e:
        return f"Error: {str(e)}"

def get_dns_servers():
    try:
        dns_servers = []
        if os.name == "nt":
            result = subprocess.check_output("ipconfig /all", shell=True, stderr=subprocess.DEVNULL, text=True)
            for line in result.split("\n"):
                if "DNS Servers" in line:
                    dns_servers.append(line.split(":")[1].strip())
        else:
            with open("/etc/resolv.conf", "r") as file:
                for line in file:
                    if line.startswith("nameserver"):
                        dns_servers.append(line.split()[1].strip())
        return dns_servers if dns_servers else ["DNS servers not found"]
    except Exception as e:
        return [f"Error: {str(e)}"]

def fetch_network_info():
    output_text.delete("1.0", tk.END)  # Clear previous output
    try:
        output_text.insert(tk.END, f"Hostname: {socket.gethostname()}\n")
        output_text.insert(tk.END, f"IP Address: {get_ip_address()}\n")
        output_text.insert(tk.END, f"MAC Address: {get_mac_address()}\n\n")

        network_interfaces = get_network_interfaces()
        if isinstance(network_interfaces, dict):
            output_text.insert(tk.END, "Network Interfaces:\n")
            for interface, details in network_interfaces.items():
                output_text.insert(tk.END, f"  {interface}:\n")
                for key, value in details.items():
                    output_text.insert(tk.END, f"    {key}: {value}\n")
        else:
            output_text.insert(tk.END, network_interfaces + "\n")

        output_text.insert(tk.END, f"\nDefault Gateway: {get_default_gateway()}\n")

        dns_servers = get_dns_servers()
        output_text.insert(tk.END, "\nDNS Servers:\n")
        for dns in dns_servers:
            output_text.insert(tk.END, f"  {dns}\n")
    except Exception as e:
        output_text.insert(tk.END, f"Unexpected error: {str(e)}")

# GUI Setup
root = tk.Tk()
root.title("Network Info Tool")
root.geometry("600x400")

# Button to fetch data
fetch_button = tk.Button(root, text="Fetch Network Info", command=fetch_network_info, font=("Arial", 12), bg="lightblue")
fetch_button.pack(pady=10)

# Scrollable Text Box
output_text = scrolledtext.ScrolledText(root, width=70, height=20, font=("Courier", 10))
output_text.pack(pady=10)

# Run GUI
root.mainloop()
