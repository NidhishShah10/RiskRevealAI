import re
from urllib.parse import urlparse


TRUSTED_DOMAINS = [

    "paypal.com",
    "amazon.com",
    "apple.com",
    "google.com",
    "microsoft.com",
    "venmo.com",
    "shopify.com",
    "stripe.com",
    "netflix.com",
    "linkedin.com",
    "dropbox.com",
    "facebook.com",
    "instagram.com",
    "spotify.com",
    "bankofamerica.com",
    "chase.com",
    "wellsfargo.com",
    "costco.com",
    "walmart.com",
    "target.com",
    "bestbuy.com",
    "ebay.com",
    "airbnb.com",
    "uber.com",
    "lyft.com"
]


SUSPICIOUS_KEYWORDS = [

    "verify",
    "confirm",
    "secure",
    "login",
    "password",
    "wallet",
    "bank",
    "billing",
    "payment",
    "refund",
    "claim",
    "suspended",
    "limited",
    "urgent",
    "update"
]


SUSPICIOUS_TLDS = [

    ".xyz",
    ".top",
    ".click",
    ".gq",
    ".tk",
    ".ru"
]


def is_trusted_domain(domain):

    for trusted in TRUSTED_DOMAINS:

        if domain == trusted:
            return True

        if domain.endswith("." + trusted):
            return True

    return False


def extract_urls(text):

    return re.findall(
        r'https?://[^\s]+',
        text
    )


def analyze_links(text):

    urls = extract_urls(text)

    url_results = []

    link_flags = []

    total_score = 0

    suspicious_count = 0


    for url in urls:

        flags = []

        score = 0

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        trusted = is_trusted_domain(domain)


        if not url.startswith("https://"):

            flags.append(
                "Non-HTTPS link"
            )

            score += 20


        for tld in SUSPICIOUS_TLDS:

            if domain.endswith(tld):

                flags.append(
                    f"Suspicious top-level domain '{tld}'"
                )

                score += 30


        hyphen_count = domain.count("-")

        if hyphen_count >= 1 and not trusted:

            flags.append(
                f"Suspicious domain structure ({hyphen_count} hyphen)"
            )

            score += 20

        if not trusted:

            for keyword in SUSPICIOUS_KEYWORDS:

                if keyword in parsed.path.lower():

                    flags.append(
                        f"High-risk keyword: {keyword}"
                    )

                    score += 10


        if domain.count(".") >= 3 and not trusted:

            flags.append(
                "Excessive subdomains detected"
            )

            score += 15

        is_suspicious = score >= 15

        if is_suspicious:
            suspicious_count += 1

        total_score += score

        url_results.append({

            "url": url,

            "flags": flags,

            "is_suspicious": is_suspicious
        })

        link_flags.extend(flags)


    if len(urls) == 0:

        final_link_score = 0

    else:

        avg_score = total_score / len(urls)

        final_link_score = min(
            int(avg_score),
            100
        )

    if (
        len(urls) >= 2
        and
        suspicious_count == len(urls) 
    ):
        final_link_score = 100

    return {

        "urls_found": url_results,

        "url_count": len(urls),

        "link_flags": link_flags,

        "link_score": final_link_score
    }