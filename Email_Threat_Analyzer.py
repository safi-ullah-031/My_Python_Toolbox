import re
import dns.resolver
import requests
import whois
import json
import email
from email import policy
from email.parser import BytesParser

# 🌍 IP Geolocation API (Use any free IP lookup service)
IP_GEOLOCATION_API = "http://ip-api.com/json/{}"

# 🚀 Phishing & Spam Indicators
PHISHING_KEYWORDS = ["urgent", "verify your account", "click here", "update payment", "login now"]
BLACKLIST_CHECK_API = "https://openphish.com/feed.txt"

# ✅ Email format validation
def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

# 🔍 Check MX records
def has_valid_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return len(mx_records) > 0
    except:
        return False

# 🚨 Phishing Pattern Detection
def detect_phishing(email):
    return any(keyword in email.lower() for keyword in PHISHING_KEYWORDS)

# ❌ Check if domain is in a phishing blacklist
def is_blacklisted(domain):
    try:
        response = requests.get(BLACKLIST_CHECK_API)
        if response.status_code == 200:
            return domain in response.text
    except:
        pass
    return False

# 🔍 WHOIS Lookup to check domain age and ownership
def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info.creation_date, domain_info.registrar
    except:
        return None, None

# 🌍 IP Geolocation Lookup
def get_ip_geolocation(ip):
    try:
        response = requests.get(IP_GEOLOCATION_API.format(ip))
        data = response.json()
        if response.status_code == 200 and data.get("status") == "success":
            return f"🌍 IP Location: {data['city']}, {data['country']} (ISP: {data['isp']})"
    except:
        pass
    return "⚠️ IP Geolocation Not Available"

# 🔎 Extract Sender’s IP from Email Header
def extract_sender_ip(email_header):
    received_lines = [line for line in email_header.split("\n") if line.lower().startswith("received:")]
    for line in received_lines:
        match = re.search(r"\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]", line)
        if match:
            return match.group(1)
    return None

# 🛡️ Check DNS SPF Record
def check_spf(domain):
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            if "v=spf1" in record.to_text():
                return "✅ SPF Record Found"
    except:
        pass
    return "❌ No SPF Record Found"

# 🛡️ Check DNS DKIM Record
def check_dkim(domain):
    try:
        dkim_record = f"default._domainkey.{domain}"
        dns.resolver.resolve(dkim_record, 'TXT')
        return "✅ DKIM Record Found"
    except:
        return "❌ No DKIM Record Found"

# 🔎 Analyze Email
def analyze_email(email, email_header=None):
    if not is_valid_email(email):
        return "❌ Invalid Email Format!"

    domain = email.split("@")[-1]
    mx_valid = has_valid_mx_records(domain)
    phishing_detected = detect_phishing(email)
    blacklisted = is_blacklisted(domain)
    domain_age, registrar = get_whois_info(domain)

    results = []

    # ✅ Format validation
    if mx_valid:
        results.append("✅ Valid Email Server (MX records found)")
    else:
        results.append("⚠️ No valid email servers found!")

    # 🚨 Phishing check
    if phishing_detected:
        results.append("🚨 Phishing email detected!")

    # ❌ Blacklist check
    if blacklisted:
        results.append("❌ Domain is blacklisted!")

    # 🔍 WHOIS lookup
    if domain_age:
        results.append(f"📅 Domain registered on: {domain_age}")
    if registrar:
        results.append(f"🏛 Registrar: {registrar}")

    # 🛡️ DNS Security Checks
    results.append(check_spf(domain))
    results.append(check_dkim(domain))

    # 🌍 IP Geolocation
    if email_header:
        sender_ip = extract_sender_ip(email_header)
        if sender_ip:
            results.append(f"📡 Sender IP: {sender_ip}")
            results.append(get_ip_geolocation(sender_ip))
        else:
            results.append("⚠️ Could not extract sender IP")

    return "\n".join(results)

# 📩 Read Email Header from File (For testing)
def read_email_header(file_path):
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
        return str(msg)

# 🚀 Run the tool
if __name__ == "__main__":
    user_email = input("Enter an email to analyze: ")
    header_option = input("Do you have an email header file? (y/n): ")

    email_header = None
    if header_option.lower() == "y":
        file_path = input("Enter email header file path: ")
        email_header = read_email_header(file_path)

    result = analyze_email(user_email, email_header)
    print("\n🔍 OSINT Email Analysis Report 🔍")
    print(result)
