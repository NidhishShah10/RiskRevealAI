import re

SHORT_URL_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly"
]

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".gq",
    ".tk"
]

HIGH_RISK_KEYWORDS = [
    "login",
    "verify",
    "confirm",
    "secure",
    "update",
    "payment",
    "billing",
    "password",
    "account",
    "banking"
]

NORMAL_RISK_KEYWORDS = [
    "hold",
    "delivery",
    "fee",
    "refund",
    "claim",
    "transaction"
]


def extract_urls(message):

    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'

    return re.findall(pattern, message)


def is_shortened_url(url):

    return any(
        domain in url
        for domain in SHORT_URL_DOMAINS
    )


def has_ip_address(url):

    return bool(
        re.match(
            r'https?://(\d{1,3}\.){3}\d{1,3}',
            url
        )
    )


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

        domain_match = re.findall(
            r'https?://([^/]+)',
            url
        )

        domain = domain_match[0] if domain_match else ""


        if is_shortened_url(url):

            flags.append(
                "Shortened URL detected"
            )

            score += 25


        if has_ip_address(url):

            flags.append(
                "IP-based URL detected"
            )

            score += 35

        high_hits = []

        for keyword in HIGH_RISK_KEYWORDS:

            if keyword in url.lower():

                high_hits.append(keyword)

        if high_hits:

            flags.append(
                f"High-risk keywords: {', '.join(high_hits)}"
            )

            score += len(high_hits) * 20


        normal_hits = []

        for keyword in NORMAL_RISK_KEYWORDS:

            if keyword in url.lower():

                normal_hits.append(keyword)

        if normal_hits:

            flags.append(
                f"Suspicious keywords: {', '.join(normal_hits)}"
            )

            score += len(normal_hits) * 10


        hyphen_count = domain.count("-")

        if hyphen_count >= 1:

            flags.append(
                f"Suspicious domain structure ({hyphen_count} hyphen)"
            )

            score += 15

        # =====================================
        # SUSPICIOUS TLD
        # =====================================

        for tld in SUSPICIOUS_TLDS:

            if domain.endswith(tld):

                flags.append(
                    f"Suspicious top-level domain '{tld}'"
                )

                score += 35


        if domain.count(".") >= 3:

            flags.append(
                "Excessive subdomains detected"
            )

            score += 20


        if len(domain) > 35:

            flags.append(
                "Unusually long domain"
            )

            score += 15


        final_url_score = min(score, 100)

        results.append({

            "url":
                url,

            "flags":
                flags,

            "url_score":
                final_url_score
        })

        total_score += final_url_score


    suspicious_urls = sum(

        1 for r in results

        if len(r["flags"]) > 0
    )

    if suspicious_urls >= 2:
        total_score += 15

    if suspicious_urls >= 3:
        total_score += 20


    all_links_suspicious = all(

        len(r["flags"]) > 0

        for r in results
    )

    final_link_score = min(
        total_score,
        100
    )

    if (
        len(results) >= 2
        and
        all_links_suspicious
    ):
        final_link_score = 100

    return {

        "urls_found":
            results,

        "url_count":
            len(urls),

        "link_score":
            final_link_score,

        "link_flags": [

            flag

            for r in results

            for flag in r["flags"]
        ]
    }