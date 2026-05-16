import re

def highlight_suspicious(message, detected_patterns):
    highlighted = message

    # Collect all suspicious phrases
    phrases = [p["phrase"] for p in detected_patterns]

    # Sort by length so longer phrases get highlighted first
    phrases = sorted(phrases, key=len, reverse=True)

    for phrase in phrases:
        pattern = re.compile(re.escape(phrase), re.IGNORECASE)
        highlighted = pattern.sub(
            f'<mark class="highlight">{phrase}</mark>',
            highlighted
        )

    return highlighted