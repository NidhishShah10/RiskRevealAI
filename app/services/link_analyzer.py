import re

SUSPICIOUS_EXTENSIONS = [".exe", ".zip", ".rar", ".bat", ".cmd", ".scr"]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "confirm", "banking", "signin", "password", "free",
    "reactivate", "suspend", "hold", "billing", "payment",
    "recover", "restore", "validate", "authenticate", "access",
    "click", "redirect", "token", "session", "credential"
]

SHORT_URL_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "rb.gy", "shorturl.at"
]

def extract_urls(message):
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(pattern, message)

def is_shortened_url(url):
    return any(domain in url for domain in SHORT_URL_DOMAINS)

def has_suspicious_extension(url):
    return any(url.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)

def has_suspicious_keywords(url):
    url_lower = url.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

def has_ip_address(url):
    return bool(re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url))

def check_domain_structure(url):
    flags = []
    score = 0
    domain_match = re.findall(r'https?://([^/]+)', url)
    if domain_match:
        domain = domain_match[0]

        # Check for multiple hyphens
        hyphen_count = domain.count('-')
        if hyphen_count >= 2:
            flags.append(f"Suspicious domain — {hyphen_count} hyphens detected")
            score += 25

        # Check for excessive subdomains
        parts = domain.split('.')
        if len(parts) >= 4:
            flags.append("Excessive subdomains detected")
            score += 20

        # Check for long domain name
        if len(domain) > 40:
            flags.append("Unusually long domain name")
            score += 15

    return flags, score

def analyze_links(message):
    urls = extract_urls(message)

    if not urls:
        return {
            "urls_found": [],
            "url_count": 0,
            "link_score": 0,
            "link_flags": []
        }

    results = []
    total_score = 0

    for url in urls:
        flags = []
        score = 0

        if has_ip_address(url):
            flags.append("IP-based URL detected")
            score += 30

        if is_shortened_url(url):
            flags.append("Shortened URL detected")
            score += 20

        if has_suspicious_extension(url):
            flags.append("Suspicious file extension")
            score += 25

        keywords_found = has_suspicious_keywords(url)
        if keywords_found:
            flags.append(f"Suspicious keywords: {', '.join(keywords_found)}")
            score += len(keywords_found) * 20

        # Check domain structure
        domain_flags, domain_score = check_domain_structure(url)
        flags.extend(domain_flags)
        score += domain_score

        results.append({
            "url": url,
            "flags": flags,
            "url_score": min(score, 100)
        })

        total_score += score

    return {
        "urls_found": results,
        "url_count": len(urls),
        "link_score": min(total_score, 100),
        "link_flags": [flag for r in results for flag in r["flags"]]
    }