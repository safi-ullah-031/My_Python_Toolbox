import re
import dns.resolver
import requests
import whois

# 🚀 Phishing & Spam Indicators
PHISHING_KEYWORDS = ["urgent", "verify your account", "click here", "update payment", "login now"]
BLACKLIST_CHECK_API = "https://openphish.com/feed.txt"  # Example phishing database
BREACH_CHECK_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"  # Needs API key

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

# 🔎 Check if email is in leaked databases (Optional: Requires API Key)
def check_breached_data(email):
    headers = {"hibp-api-key": "YOUR_API_KEY"}  # Replace with valid API key
    try:
        response = requests.get(BREACH_CHECK_API.format(email), headers=headers)
        if response.status_code == 200:
            return "⚠️ Email found in data breaches!"
    except:
        pass
    return "✅ No breaches found."

# 🎯 Analyze Email
def analyze_email(email):
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

    # 🛑 Data breach check
    breach_status = check_breached_data(email)
    results.append(breach_status)

    return "\n".join(results)

# 🚀 Run the tool
if __name__ == "__main__":
    user_email = input("Enter an email to analyze: ")
    result = analyze_email(user_email)
    print("\n🔍 OSINT Email Analysis Report 🔍")
    print(result)
