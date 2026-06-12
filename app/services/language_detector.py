from transformers import DistilBertTokenizerFast
from transformers import DistilBertForSequenceClassification

import torch


MODEL_PATH = "app/models/phishing_model"

tokenizer = DistilBertTokenizerFast.from_pretrained(
    MODEL_PATH
)

model = DistilBertForSequenceClassification.from_pretrained(
    MODEL_PATH
)

model.eval()

LEGIT_CONTEXT = [
    "transaction receipt",
    "membership renewal",
    "renewal notice",
    "renewal confirmation",
    "payment confirmation",
    "member services",
    "wholesale",
    "order confirmation",
    "transaction id",
    "receipt",
    "invoice",
    "support",
    "customer",
    "thank you",
    "view order",
    "download receipt",
    "account statement",
    "transaction details",
    "store received",
    "new order",
    "items",
    "total",
    "your order",
    "billing statement",
    "purchase receipt",
    "payment receipt",
    "subscription",
    "monthly statement",
    "delivery update",
    "tracking number",
    "view invoice",
    "manage account",
    "customer support",
    "shopify notifications",
    "thanks for using venmo",
    "paypal receipt",
    "amazon order",
    "google account activity",
    "microsoft invoice",
    "payment completed",
    "payment successful",
    "download pdf",
    "view statement",
    "receipt attached",
    "official receipt",
    "order shipped",
    "delivery confirmation"
]


TRUSTED_BRANDS = [

    "venmo",
    "shopify",
    "paypal",
    "amazon",
    "apple",
    "google",
    "microsoft",
    "netflix",
    "linkedin",
    "stripe",
    "dropbox",
    "facebook",
    "instagram",
    "spotify",
    "bank of america",
    "chase",
    "wells fargo",
    "american express",
    "capital one",
    "fedex",
    "ups",
    "usps",
    "dhl",
    "costco",
    "walmart",
    "target",
    "best buy",
    "ebay",
    "airbnb",
    "uber",
    "lyft",
    "walgreens"
]


VERY_TRUSTED_BRANDS = [

    "costco",
    "amazon",
    "paypal",
    "venmo",
    "shopify",
    "microsoft",
    "google",
    "apple",
    "netflix",
    "linkedin",
    "stripe",
    "walmart",
    "target",
    "best buy",
    "ebay",
    "airbnb",
    "uber",
    "lyft",
    "walgreens"
]


LEGIT_SECURITY_CONTEXT = [

    "unusual sign-in activity",
    "new sign-in",
    "recent activity",
    "security team",
    "if this was you",
    "no further action is needed",
    "review your recent activity",
    "account security tips",
    "sign-in details"
]


BUSINESS_EMAIL_SIGNALS = [

    "membership",
    "membership #",
    "membership plan",
    "renewal amount",
    "member account",
    "renewal",
    "membership number",
    "order number",
    "invoice number",
    "transaction id",
    "customer service",
    "member services",
    "contact support",
    "contact member services",
    "renew automatically",
    "gold star membership",
    "billing statement",
    "account statement",
    "purchase receipt",
    "official notification",
    "prescription",
    "prescription ready",
    "prescription history",
    "medication",
    "pharmacy",
    "refill",
    "pickup",
    "pickup location",
    "available for pickup",
    "walgreens pharmacy"
]

HIGH_RISK_PHRASES = [

    "verify your account",
    "verify your identity",
    "confirm your identity",
    "click below",
    "urgent action required",
    "your account has been suspended",
    "reset your password",
    "payment failed",
    "claim your money",
    "send money back",
    "confirm your payment",
    "you have won",
    "login immediately",
    "security alert",
    "unauthorized login",
    "update billing",
    "verify now",
    "confirm now",
    "act now",
    "limited time",
    "within 24 hours",
    "within 48 hours",
    "expire if not claimed",
    "avoid suspension",
    "delivery failed",
    "failed delivery",
    "customs fee",
    "shipping fee"
]


def detect_suspicious_language(text):

    text_lower = text.lower()


    inputs = tokenizer(

        text,

        return_tensors="pt",

        truncation=True,

        padding=True,

        max_length=512
    )

    with torch.no_grad():

        outputs = model(**inputs)

        probs = torch.softmax(
            outputs.logits,
            dim=1
        )

        phishing_prob = probs[0][1].item()


    # Adjusted confidence zones
    if phishing_prob < 0.60:

        score = int(phishing_prob * 20)

    elif phishing_prob < 0.80:

        score = int(phishing_prob * 40)

    else:

        score = int(phishing_prob * 100)


    legit_hits = 0

    for phrase in LEGIT_CONTEXT:

        if phrase in text_lower:
            legit_hits += 1

    score -= legit_hits * 6


    trusted_hits = 0

    for brand in TRUSTED_BRANDS:

        if brand in text_lower:
            trusted_hits += 1

    score -= trusted_hits * 4


    legit_indicators = [

        "https://",
        ".pdf",
        "customer",
        "thank you",
        "support",
        "receipt",
        "statement",
        "notifications",
        "transaction id",
        "date:",
        "items:",
        "total:"
    ]

    legit_indicator_hits = 0

    for item in legit_indicators:

        if item in text_lower:
            legit_indicator_hits += 1

    score -= legit_indicator_hits * 3


    business_hits = 0

    for phrase in BUSINESS_EMAIL_SIGNALS:

        if phrase in text_lower:
            business_hits += 1

    score -= business_hits * 4


    security_context_hits = 0

    for phrase in LEGIT_SECURITY_CONTEXT:

        if phrase in text_lower:
            security_context_hits += 1

    score -= security_context_hits * 5


    phishing_hits = 0

    for phrase in HIGH_RISK_PHRASES:

        if phrase in text_lower:
            phishing_hits += 1

    score += phishing_hits * 12

    severe_signals = [

        "verify your account",
        "verify your identity",
        "confirm your identity",
        "urgent action required",
        "payment failed",
        "login immediately"
    ]

    severe_hits = 0

    for phrase in severe_signals:

        if phrase in text_lower:
            severe_hits += 1

    if severe_hits >= 2:
        score = max(score, 75)

    if severe_hits >= 3:
        score = max(score, 90)


    trusted_brand_found = any(
        brand in text_lower
        for brand in VERY_TRUSTED_BRANDS
    )

    if (
        trusted_brand_found
        and phishing_hits == 0
        and security_context_hits == 0
    ):
        score = min(score, 20)


    score = max(score, 0)

    score = min(score, 100)

    # Fixed: Added 'category' field back for generate_explanation
    detected_patterns = []

    for phrase in HIGH_RISK_PHRASES:
        if phrase in text_lower:
            detected_patterns.append({
                "phrase": phrase,
                "category": "High Risk Phrase"
            })

    if score >= 75:

        verdict = "Highly Suspicious"

    elif score >= 40:

        verdict = "Suspicious"

    else:

        verdict = "Likely Safe"

    return {

        "risk_score": score,

        "verdict": verdict,

        "detected_patterns": detected_patterns
    }