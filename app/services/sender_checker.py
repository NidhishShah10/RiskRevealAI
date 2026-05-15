import re
import dns.resolver
from Levenshtein import distance

KNOWN_BRANDS = [
    "paypal.com", "amazon.com", "apple.com", "microsoft.com",
    "google.com", "netflix.com", "instagram.com", "facebook.com",
    "chase.com", "wellsfargo.com", "linkedin.com", "twitter.com",
    "dropbox.com", "ebay.com", "bankofamerica.com"
]

def extract_sender_domain(email_text):
    # Try From: header first
    match = re.search(r'from:\s*.*?@([\w\.-]+)', email_text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    # Fallback — any email address in text
    match = re.search(r'[\w\.-]+@([\w\.-]+)', email_text)
    if match:
        return match.group(1).lower()
    return None

def check_spf_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for record in answers:
            if 'spf' in str(record).lower():
                return True
    except:
        pass
    return False

def check_brand_spoofing(domain):
    for brand in KNOWN_BRANDS:
        brand_name = brand.split('.')[0]
        domain_name = domain.split('.')[0]
        # Exact brand name inside suspicious domain
        if brand_name in domain and domain != brand:
            return brand
        # Typosquatting check
        if distance(domain_name, brand_name) <= 2 and domain != brand:
            return brand
    return None

def check_sender(email_text):
    domain = extract_sender_domain(email_text)
    flags = []
    score = 0

    if not domain:
        return {
            "domain": None,
            "flags": ["No sender domain found"],
            "sender_score": 0
        }

    # Check brand spoofing
    spoofed = check_brand_spoofing(domain)
    if spoofed:
        flags.append(f"Domain spoofs known brand: '{spoofed}'")
        score += 40

    # Check SPF record
    spf = check_spf_record(domain)
    if not spf:
        flags.append("No SPF record — email authentication missing")
        score += 20

    # Check for suspicious domain patterns
    hyphen_count = domain.count('-')
    if hyphen_count >= 2:
        flags.append(f"Suspicious sender domain — {hyphen_count} hyphens")
        score += 20

    # Check for long domain
    if len(domain) > 30:
        flags.append("Unusually long sender domain")
        score += 15

    if not flags:
        flags.append("Sender domain appears legitimate")

    return {
        "domain": domain,
        "flags": flags,
        "sender_score": min(score, 100)
    }