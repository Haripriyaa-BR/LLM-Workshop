"""URL and keyword detection utilities for phishing email analysis."""

import re
from typing import List, Tuple

# Common phishing indicators and suspicious keywords
PHISHING_KEYWORDS = [
    "urgent", "verify", "suspended", "compromised", "immediately",
    "confirm", "account", "password", "secure", "login", "click here",
    "act now", "limited time", "winner", "congratulations", "prize",
    "verify your identity", "suspended account", "unusual activity",
    "reset password", "update information", "expired", "overdue",
    "dear customer", "dear user", "dear member", "paypal", "bank",
]


def extract_urls(text: str) -> List[str]:
    """Extract all URLs from text."""
    url_pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+|'
        r'www\.[^\s<>"{}|\\^`\[\]]+',
        re.IGNORECASE
    )
    return list(set(url_pattern.findall(text)))


def detect_suspicious_keywords(text: str) -> List[Tuple[str, int]]:
    """
    Find phishing-related keywords in text.
    Returns list of (keyword, position) tuples.
    """
    text_lower = text.lower()
    found = []
    for keyword in PHISHING_KEYWORDS:
        start = 0
        while True:
            pos = text_lower.find(keyword, start)
            if pos == -1:
                break
            found.append((keyword, pos))
            start = pos + 1
    return found


def analyze_text(text: str) -> dict:
    """
    Run URL and keyword detection on email text.
    Returns dict with urls, suspicious_keywords, and counts.
    """
    urls = extract_urls(text)
    keywords = detect_suspicious_keywords(text)
    unique_keywords = list(dict.fromkeys(kw for kw, _ in keywords))
    return {
        "urls": urls,
        "suspicious_keywords": unique_keywords,
        "url_count": len(urls),
        "keyword_count": len(unique_keywords),
    }
