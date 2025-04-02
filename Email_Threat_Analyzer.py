import validators
import dns.resolver
import whois
import requests

# HIBP API Key (Replace with your own key)
HIBP_API_KEY = "your_api_key_here"

DISPOSABLE_PROVIDERS = ["tempmail.com", "mailinator.com", "10minutemail.com"]
SUSPICIOUS_PATTERNS = ["admin@", "support@", "secure@", "banking@", "verify@", "paypal@"]
TRUSTED_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com"]
BLACKLISTED_DOMAINS = ["spam.com", "fraudsite.com"]
BUSINESS_DOMAINS = ["ibm.com", "microsoft.com", "apple.com"]

def is_valid_email(email):
    return validators.email(email)

def is_disposable_email(email):
    domain = email.split('@')[-1]
    return domain in DISPOSABLE_PROVIDERS

def is_phishing_email(email):
    domain = email.split('@')[-1]
    return any(pattern in email for pattern in SUSPICIOUS_PATTERNS) and domain not in TRUSTED_DOMAINS

def has_valid_mx_record(email):
    domain = email.split('@')[-1]
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return len(records) > 0
    except:
        return False

def is_blacklisted(email):
    domain = email.split('@')[-1]
    return domain in BLACKLISTED_DOMAINS

def is_business_email(email):
    domain = email.split('@')[-1]
    return domain in BUSINESS_DOMAINS

def fetch_whois_info(email):
    domain = email.split('@')[-1]
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except:
        return "WHOIS lookup failed or domain is private."

def check_data_breach(email):
    """Check if the email was found in a data breach using Have I Been Pwned API."""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": HIBP_API_KEY, "User-Agent": "EmailOSINTTool"}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()  # List of breaches
        elif response.status_code == 404:
            return "No breaches found."
        else:
            return f"Error: {response.status_code}"
    except:
        return "Failed to connect to Have I Been Pwned API."

def analyze_email(email):
    results = {
        "Valid Format": is_valid_email(email),
        "Disposable": is_disposable_email(email),
        "Phishing": is_phishing_email(email),
        "Valid MX Record": has_valid_mx_record(email),
        "Blacklisted": is_blacklisted(email),
        "Business Email": is_business_email(email),
        "WHOIS Info": fetch_whois_info(email),
        "Data Breach Check": check_data_breach(email),
    }
    return results

email = input("Enter an email to analyze: ")
analysis = analyze_email(email)

print("\n📊 Email OSINT Analysis Report:")
for key, value in analysis.items():
    if key == "WHOIS Info" or key == "Data Breach Check":
        print(f"\n🔍 {key}:\n{value}")
    else:
        print(f"{key}: {'✅ Yes' if value else '❌ No'}")
