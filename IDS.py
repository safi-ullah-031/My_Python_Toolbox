from scapy.all import sniff, IP, TCP, UDP
import csv
import json
import datetime

# 🚀 Define Attack Signatures
THRESHOLD_SYN = 100  # SYN flood threshold
PORT_SCAN_THRESHOLD = 10  # Number of connections to different ports in a short time
suspicious_ips = {}

# 🕵️‍♂️ Packet Handler Function
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # SYN Flood Detection
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN flag
            suspicious_ips[src_ip] = suspicious_ips.get(src_ip, 0) + 1
            if suspicious_ips[src_ip] > THRESHOLD_SYN:
                log_alert("SYN Flood Detected", src_ip, dst_ip, timestamp)

        # Port Scanning Detection
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            suspicious_ips[src_ip] = suspicious_ips.get(src_ip, 0) + 1
            if suspicious_ips[src_ip] > PORT_SCAN_THRESHOLD:
                log_alert("Port Scanning Detected", src_ip, dst_ip, timestamp)

# 📝 Log Alerts to CSV & JSON
def log_alert(alert_type, src_ip, dst_ip, timestamp):
    print(f"⚠️ ALERT: {alert_type} from {src_ip} to {dst_ip} at {timestamp}")
    
    # Save to CSV
    with open("ids_alerts.csv", "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([timestamp, alert_type, src_ip, dst_ip])
    
    # Save to JSON
    alert_data = {"timestamp": timestamp, "alert_type": alert_type, "src_ip": src_ip, "dst_ip": dst_ip}
    with open("ids_alerts.json", "a") as jsonfile:
        json.dump(alert_data, jsonfile)
        jsonfile.write("\n")

# 🎯 Start IDS Monitoring
print("🔍 Intrusion Detection System is Running...")
sniff(prn=packet_callback, store=False)
