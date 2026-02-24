# utils/password_analyzer.py

import re
import math

class PasswordAnalyzer:
    """
    Analyzes password strength using complexity rules and entropy.
    """

    COMMON_PASSWORDS = {
        "password", "123456", "123456789",
        "admin", "qwerty", "letmein",
        "welcome", "abc123"
    }

    @classmethod
    def analyze_password(cls, password):
        score = 0
        feedback = []

        length = len(password)

        # -----------------------
        # Length Check
        # -----------------------
        if length >= 12:
            score += 3
        elif length >= 8:
            score += 2
        else:
            score += 0
            feedback.append("Password is too short (minimum 8 characters recommended)")

        # -----------------------
        # Character Diversity
        # -----------------------
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Add uppercase letters")

        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Add lowercase letters")

        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("Add numbers")

        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 2
        else:
            feedback.append("Add special characters")

        # -----------------------
        # Common Password Check
        # -----------------------
        if password.lower() in cls.COMMON_PASSWORDS:
            score = 0
            feedback.append("This is a commonly used password")

        # -----------------------
        # Entropy Calculation
        # -----------------------
        charset = 0
        if re.search(r"[a-z]", password):
            charset += 26
        if re.search(r"[A-Z]", password):
            charset += 26
        if re.search(r"\d", password):
            charset += 10
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            charset += 32

        if charset > 0:
            entropy = round(length * math.log2(charset), 2)
        else:
            entropy = 0

        # -----------------------
        # Strength Classification
        # -----------------------
        if score <= 2:
            strength = "VERY WEAK"
        elif score <= 4:
            strength = "WEAK"
        elif score <= 6:
            strength = "MODERATE"
        elif score <= 8:
            strength = "STRONG"
        else:
            strength = "VERY STRONG"

        return {
            "strength": strength,
            "score": score,
            "entropy": entropy,
            "feedback": feedback if feedback else ["Strong password structure detected"]
        }
