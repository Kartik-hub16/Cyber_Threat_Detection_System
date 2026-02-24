import re

SUSPICIOUS_WORDS = [
    "urgent", "verify", "password", "otp",
    "click here", "account suspended",
    "limited time", "confirm now"
]

def analyze_txt(content):
    score = 0
    reasons = []
    text = content.lower()

    # 1. Suspicious keywords
    for word in SUSPICIOUS_WORDS:
        if word in text:
            score += 1
            reasons.append(f"Suspicious phrase detected: '{word}'")

    # 2. Embedded URLs
    if re.search(r"http[s]?://", text):
        score += 2
        reasons.append("Embedded URL detected")

    # 3. Excessive uppercase (social engineering)
    upper_ratio = sum(1 for c in content if c.isupper()) / max(len(content), 1)
    if upper_ratio > 0.3:
        score += 1
        reasons.append("Excessive uppercase usage")

    return score, reasons

from PyPDF2 import PdfReader

def analyze_pdf(file_path):
    score = 0
    reasons = []

    reader = PdfReader(file_path)

    # 1. JavaScript inside PDF
    if "/JavaScript" in str(reader.metadata):
        score += 4
        reasons.append("JavaScript detected inside PDF")

    # 2. Auto-open actions
    if "/OpenAction" in str(reader.metadata):
        score += 3
        reasons.append("Auto-open action detected")

    # 3. Extract text & scan
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""

    # 4. Embedded URLs
    if re.search(r"http[s]?://", text):
        score += 2
        reasons.append("Embedded URL found in PDF")

    # 5. Phishing keywords
    for word in SUSPICIOUS_WORDS:
        if word in text.lower():
            score += 1
            reasons.append(f"Suspicious phrase detected: '{word}'")

    return score, reasons

def classify_file(score):
    if score >= 7:
        return "Malicious", "High Risk File"
    elif score >= 4:
        return "Suspicious", "Potentially Unsafe File"
    else:
        return "Safe", "No Threat Detected"

def file_confidence(score):
    return min(100, score * 12)
