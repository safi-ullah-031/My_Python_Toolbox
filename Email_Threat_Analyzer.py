import re
import dns.resolver

# 🚀 Common phishing keywords
PHISHING_KEYWORDS = ["urgent", "verify your account", "click here", "update payment", "login now"]

# ✅ Email format validation using regex
def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

# 🔍 Check if the email domain has valid MX records
def has_valid_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return len(mx_records) > 0
    except:
        return False

# 🛑 Detect phishing patterns
def detect_phishing(email):
    for keyword in PHISHING_KEYWORDS:
        if keyword in email.lower():
            return True
    return False

# 🎯 Main function to analyze email
def analyze_email(email):
    if not is_valid_email(email):
        return "❌ Invalid Email Format!"
    
    domain = email.split("@")[-1]

    if not has_valid_mx_records(domain):
        return "⚠️ Suspicious Email! No valid mail servers found."

    if detect_phishing(email):
        return "🚨 Phishing Email Detected!"

    return "✅ Email looks safe!"

# 🚀 Test the tool
if __name__ == "__main__":
    user_email = input("Enter an email to analyze: ")
    result = analyze_email(user_email)
    print(result)
