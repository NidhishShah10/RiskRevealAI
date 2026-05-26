def detect_suspicious_language(message):

    original_message = message
    message = message.lower()

    patterns = {

        "urgency": [
            "urgent",
            "immediately",
            "act now",
            "within 24 hours",
            "within 48 hours",
            "within 72 hours",
            "update within",
            "expires soon",
            "expire if not claimed",
            "limited time",
            "asap",
            "respond now",
            "time sensitive"
        ],

        "credentials": [
            "verify",
            "confirm",
            "login",
            "password",
            "submit your",
            "sign in",
            "authenticate",
            "verification",
            "verify your account",
            "confirm your identity",
            "confirm your delivery address"
        ],

        "payments": [
            "payment",
            "fee",
            "billing",
            "refund",
            "shipping fee",
            "claim your money",
            "claim payment",
            "transaction",
            "transaction details",
            "wire transfer",
            "bank transfer",
            "invoice",
            "crypto",
            "bitcoin",
            "received $",
            "send money back"
        ],

        "financial_brands": [
            "paypal",
            "venmo",
            "zelle",
            "cash app",
            "apple pay",
            "google pay"
        ],
        "delivery_scam": [
            "sorting facility",
            "delivery delay",
            "package on hold",
            "held at our facility",
            "track your package",
            "delivery problem",
            "shipping issue",
            "delivery issue",
            "failed delivery",
            "release your package"
        ],

        "account_threats": [
            "account suspended",
            "account locked",
            "security alert",
            "unauthorized login",
            "unusual activity",
            "restricted access",
            "your account has been limited",
            "account disabled",
            "account compromised"
        ],

        "rewards": [
            "you won",
            "gift card",
            "free reward",
            "claim reward",
            "selected winner",
            "congratulations",
            "prize",
            "lottery"
        ]
    }

    category_scores = {
        "urgency": 10,
        "credentials": 20,
        "payments": 18,
        "financial_brands": 5,
        "delivery_scam": 12,
        "account_threats": 18,
        "rewards": 14
    }

    detected_patterns = []

    risk_score = 0

    triggered_categories = set()
    for category, words in patterns.items():

        for word in words:

            if word in message:

                detected_patterns.append({
                    "category": category.upper(),
                    "phrase": word
                })

                # Prevent duplicate inflation
                if category not in triggered_categories:

                    risk_score += category_scores[category]

                    triggered_categories.add(category)

    if (
        "credentials" in triggered_categories and
        "urgency" in triggered_categories
    ):
        risk_score += 12

    if (
        "payments" in triggered_categories and
        "urgency" in triggered_categories
    ):
        risk_score += 10

    if (
        "payments" in triggered_categories and
        "credentials" in triggered_categories
    ):
        risk_score += 15

    if (
        "delivery_scam" in triggered_categories and
        "credentials" in triggered_categories
    ):
        risk_score += 10

    if (
        "account_threats" in triggered_categories and
        "credentials" in triggered_categories
    ):
        risk_score += 12

    if (
        "financial_brands" in triggered_categories and
        "payments" in triggered_categories and
        "urgency" in triggered_categories
    ):
        risk_score += 12

    if len(triggered_categories) >= 4:
        risk_score += 10

    if len(triggered_categories) >= 5:
        risk_score += 15


    if message.count("!") >= 3:
        risk_score += 5

    uppercase_words = [
        word for word in original_message.split()
        if word.isupper() and len(word) > 3
    ]

    if len(uppercase_words) >= 4:
        risk_score += 8

    # Multiple URLs inside message
    if message.count("http://") + message.count("https://") >= 3:
        risk_score += 10

   
    risk_score = min(risk_score, 100)


    print("LANGUAGE SCORE:", risk_score)

    print("TRIGGERED CATEGORIES:", triggered_categories)

    print("DETECTED PATTERNS:", detected_patterns)

    return {
        "risk_score": risk_score,
        "detected_patterns": detected_patterns,
        "message_length": len(original_message)
    }