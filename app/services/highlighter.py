import re


def highlight_suspicious(
    message,
    detected_patterns
):

    highlighted = message

    phrases = [

        p["phrase"]

        for p in detected_patterns
    ]

    # Longer phrases first
    phrases = sorted(
        phrases,
        key=len,
        reverse=True
    )

    already_done = set()

    for phrase in phrases:

        lower_phrase = phrase.lower()

        if lower_phrase in already_done:
            continue

        already_done.add(lower_phrase)

        pattern = re.compile(
            re.escape(phrase),
            re.IGNORECASE
        )

        highlighted = pattern.sub(

            lambda m:
                f'<mark class="highlight">{m.group(0)}</mark>',

            highlighted
        )

    return highlighted