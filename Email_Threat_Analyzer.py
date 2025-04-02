import validators
import dns.resolver
import whois

# List of known disposable email providers
DISPOSABLE_PROVIDERS = ["tempmail.com", "mailinator.com", "10minutemail.com", "throwawaymail.com"]

# List of phishing-related keywords in email addresses
SUSPICIOUS_PATTERNS = ["admin@", "support@", "secure@", "banking@", "verify@", "paypal@"]

# Trusted domains for legitimate free email providers
TRUSTED_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com"]

# Blacklisted domains (example list)
BLACKLISTED_DOMAINS = ["spam.com", "fraudsite.com", "scamdomain.net"]

# List of known business email providers
BUSINESS_DOMAINS = ["ibm.com", "microsoft.com", "apple.com", "amazon.com", "oracle.com"]


def is_valid_email(email):
    """Check if the email follows a valid format."""
    return validators.email(email)


def is_disposable_email(email):
    """Check if the email belongs to a disposable email provider."""
    domain = email.split('@')[-1]
    return domain in DISPOSABLE_PROVIDERS


def is_phishing_email(email):
    """Detect phishing attempts based on suspicious patterns."""
    domain = email.split('@')[-1]
    if any(pattern in email for pattern in SUSPICIOUS_PATTERNS) and domain not in TRUSTED_DOMAINS:
        return True
    return False


def has_valid_mx_record(email):
    """Check if the email domain has a valid MX (mail exchange) record."""
    domain = email.split('@')[-1]
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return len(records) > 0
    except:
        return False


def is_blacklisted(email):
    """Check if the domain is in a blacklist."""
    domain = email.split('@')[-1]
    return domain in BLACKLISTED_DOMAINS


def is_business_email(email):
    """Check if the email belongs to a known business domain."""
    domain = email.split('@')[-1]
    return domain in BUSINESS_DOMAINS


def fetch_whois_info(email):
    """Fetch WHOIS domain information."""
    domain = email.split('@')[-1]
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except:
        return "WHOIS lookup failed or domain is private."


def analyze_email(email):
    """Perform full email OSINT analysis."""
    results = {
        "Valid Format": is_valid_email(email),
        "Disposable": is_disposable_email(email),
        "Phishing": is_phishing_email(email),
        "Valid MX Record": has_valid_mx_record(email),
        "Blacklisted": is_blacklisted(email),
        "Business Email": is_business_email(email),
        "WHOIS Info": fetch_whois_info(email)
    }

    return results


# Input from user
email = input("Enter an email to analyze: ")
analysis = analyze_email(email)

# Display results
print("\n📊 Email OSINT Analysis Report:")
for key, value in analysis.items():
    if key == "WHOIS Info":
        print(f"\n🔍 WHOIS Info:\n{value}")
    else:
        print(f"{key}: {'✅ Yes' if value else '❌ No'}")
