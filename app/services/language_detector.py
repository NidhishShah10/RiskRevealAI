def detect_suspicious_language(message):

    original_message = message
    message = message.lower()

    patterns = {
        "urgency": [
            "urgent", "immediately", "act now", "limited time",
            "expires soon", "last chance", "don't delay",
            "respond now", "time sensitive", "within 24 hours", "asap"
        ],

        "impersonation": [
            "dear customer", "dear user", "dear account holder",
            "paypal", "amazon", "apple", "microsoft",
            "google", "irs", "fbi", "bank of america",
            "chase", "wells fargo"
        ],

        "threats": [
            "suspended", "account locked", "will be closed",
            "unauthorized access", "unusual activity",
            "compromised", "blocked", "restricted",
            "terminated", "deactivated"
        ],

        "credentials": [
            "verify", "confirm", "update your information",
            "enter your password", "login details",
            "click here", "click now", "submit your",
            "provide your"
        ],

        "rewards": [
            "winner", "you have won", "congratulations",
            "free", "prize", "reward", "claim now",
            "selected", "lucky", "gift card"
        ]
    }

    detected_patterns = []

    category_scores = {
        "urgency": 10,
        "impersonation": 15,
        "threats": 20,
        "credentials": 25,
        "rewards": 10
    }

    risk_score = 0

    for category, words in patterns.items():

        for word in words:

            if word in message:

                detected_patterns.append({
                    "category": category,
                    "phrase": word
                })

                risk_score += category_scores[category]

    risk_score = min(risk_score, 100)

    return {
        "risk_score": risk_score,
        "detected_patterns": detected_patterns,
        "message_length": len(original_message)
    }