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
    "dhl"
]


HIGH_RISK_PHRASES = [

    "verify your account",
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


    if phishing_prob < 0.50:

        score = int(phishing_prob * 25)

    elif phishing_prob < 0.75:

        score = int(phishing_prob * 40)

    else:

        score = int(phishing_prob * 100)


    legit_hits = 0

    for phrase in LEGIT_CONTEXT:

        if phrase in text_lower:
            legit_hits += 1

    score -= legit_hits * 5


    trusted_hits = 0

    for brand in TRUSTED_BRANDS:

        if brand in text_lower:
            trusted_hits += 1

    score -= trusted_hits * 3


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

    score -= legit_indicator_hits * 2

    phishing_hits = 0

    for phrase in HIGH_RISK_PHRASES:

        if phrase in text_lower:
            phishing_hits += 1

    score += phishing_hits * 8

    severe_signals = [

        "verify your account",
        "reset your password",
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

    score = max(score, 0)

    score = min(score, 100)

    if score >= 75:

        verdict = "Highly Suspicious"

    elif score >= 40:

        verdict = "Suspicious"

    else:

        verdict = "Likely Safe"

    return {

        "risk_score": score,

        "verdict": verdict,

        "detected_patterns": []
    }