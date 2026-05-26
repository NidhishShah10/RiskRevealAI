import re
import dns.resolver
from Levenshtein import distance

KNOWN_BRANDS = [

    "paypal.com",
    "amazon.com",
    "apple.com",
    "microsoft.com",
    "google.com",
    "netflix.com",
    "instagram.com",
    "facebook.com",
    "linkedin.com",
    "twitter.com",
    "dropbox.com",
    "ebay.com",
    "bankofamerica.com",
    "chase.com",
    "wellsfargo.com",
    "citibank.com",
    "americanexpress.com",
    "capitalone.com",
    "ups.com",
    "fedex.com",
    "usps.com",
    "dhl.com",
    "venmo.com",
    "cashapp.com",
    "zellepay.com",
    "stripe.com",
    "coinbase.com",
    "binance.com",
    "shopify.com",
    "spotify.com",
    "verizon.com",
    "att.com",
    "irs.gov"
]


def extract_sender_domain(email_text):

    match = re.search(
        r'from:\s*.*?@([\w\.-]+)',
        email_text,
        re.IGNORECASE
    )

    if match:
        return match.group(1).lower()

    match = re.search(
        r'[\w\.-]+@([\w\.-]+)',
        email_text
    )

    if match:
        return match.group(1).lower()

    return None


def check_spf_record(domain):

    try:

        answers = dns.resolver.resolve(
            domain,
            'TXT'
        )

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

        if (
            brand_name in domain_name
            and domain != brand
        ):
            return brand


        if (
            distance(domain_name, brand_name) <= 2
            and domain != brand
        ):
            return brand

    return None


def check_sender(email_text):

    domain = extract_sender_domain(
        email_text
    )

    flags = []

    score = 0

    if not domain:

        return {
            "domain": None,
            "flags": [
                "No sender domain found"
            ],
            "sender_score": 0
        }


    spoofed = check_brand_spoofing(
        domain
    )

    if spoofed:

        flags.append(
            f"Possible spoofing of trusted brand '{spoofed}'"
        )

        score += 45


    spf = check_spf_record(domain)

    if not spf:

        flags.append(
            "Missing SPF email authentication"
        )

        score += 20


    hyphen_count = domain.count('-')

    if hyphen_count >= 1:

        flags.append(
            f"Suspicious sender domain structure ({hyphen_count} hyphen)"
        )

        score += 15


    if len(domain) > 30:

        flags.append(
            "Unusually long sender domain"
        )

        score += 10


    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".gq",
        ".tk"
    ]

    for tld in suspicious_tlds:

        if domain.endswith(tld):

            flags.append(
                f"Suspicious top-level domain '{tld}'"
            )

            score += 20


    if domain.count('.') >= 3:

        flags.append(
            "Excessive subdomains detected"
        )

        score += 10


    if not flags:

        flags.append(
            "Sender domain appears legitimate"
        )

    return {

        "domain": domain,

        "flags": flags,

        "sender_score": min(score, 100)
    }