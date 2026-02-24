# utils/log_analyzer.py

import re
from collections import Counter

class LogAnalyzer:
    """
    Static Log Analyzer
    Detects suspicious patterns in system/application logs
    """

    # -----------------------------
    # Suspicious patterns dictionary
    # -----------------------------
    SUSPICIOUS_PATTERNS = {
        "Brute Force Login Attempts": [
            "failed password",
            "authentication failure",
            "login failed",
            "invalid credentials"
        ],
        "Unauthorized Access": [
            "access denied",
            "permission denied",
            "403 forbidden",
            "unauthorized access"
        ],
        "Privilege Escalation": [
            "sudo",
            "root login",
            "admin login",
            "elevated privileges"
        ],
        "Suspicious Network Activity": [
            "unknown ip",
            "unrecognized ip",
            "connection refused"
        ]
    }

    @classmethod
    def analyze_log(cls, log_content):
        """
        Analyze log content and return threat assessment
        """

        log_lines = log_content.lower().splitlines()
        findings = []
        score = 0

        pattern_counter = Counter()

        # -----------------------------
        # Pattern matching
        # -----------------------------
        for category, patterns in cls.SUSPICIOUS_PATTERNS.items():
            count = 0
            for line in log_lines:
                for pattern in patterns:
                    if pattern in line:
                        count += 1
                        pattern_counter[category] += 1

            if count > 0:
                findings.append(f"{category} detected ({count} times)")
                score += count

        # -----------------------------
        # Threat classification
        # -----------------------------
        if score >= 10:
            threat_status = "THREAT"
            threat_level = "HIGH"
        elif score >= 4:
            threat_status = "SUSPICIOUS"
            threat_level = "MEDIUM"
        else:
            threat_status = "SAFE"
            threat_level = "LOW"

        return {
            "threat_status": threat_status,
            "threat_level": threat_level,
            "threat_type": "Log Anomaly Detection",
            "score": score,
            "details": " | ".join(findings) if findings else "No suspicious patterns detected",
            "pattern_summary": dict(pattern_counter)
        }
