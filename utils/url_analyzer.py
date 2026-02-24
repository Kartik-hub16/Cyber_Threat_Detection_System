import re
import difflib
from urllib.parse import urlparse, unquote

class URLAnalyzer:
    """
    URL Analyzer with:
    - Heuristic scoring (likelihood)
    - CVSS-inspired severity scoring (impact)
    - Final risk confidence calculation
    """

    # -----------------------------
    # Configuration
    # -----------------------------

    PHISHING_KEYWORDS = (
        'verify', 'confirm', 'update', 'login', 'signin',
        'validate', 'authenticate', 'secure', 'urgent',
        'action', 'click', 'alert', 'warning',
        'payment', 'account', 'suspended', 'kyc', 'bank',
        'support', 'service', 'billing'
    )

    PHISHING_DOMAINS = {
        'paypa1.com': 'PayPal copy',
        'amaz0n.com': 'Amazon copy',
        'go0gle.com': 'Google copy',
        'facebook-security.com': 'Facebook copy'
    }

    MALICIOUS_DOMAINS = {
        'malware-site.com': 'Malware',
        'botnet-c2.ru': 'Botnet',
        'ransomware-pay.net': 'Ransomware'
    }

    PROTECTED_DOMAINS = (
        'google', 'amazon', 'paypal', 'facebook', 'microsoft',
        'apple', 'netflix', 'twitter', 'linkedin', 'instagram',
        'github', 'gmail', 'yahoo', 'outlook'
    )

    # CVSS mapping based on threat type (impact)
    CVSS_MAPPING = {
        'Known Malicious Domain': 9.8,
        'Phishing Domain': 9.0,
        'Homograph Attack': 8.2,
        'Typosquatting': 7.8,
        'Phishing Pattern': 7.5,
        'IP Address URL': 6.5,
        'Invalid URL Format': 6.0,
        'No Significant Threat Detected': 0.0
    }

    # -----------------------------
    # Utility Methods
    # -----------------------------

    def is_valid_url(url):
        """Check if URL format is valid"""
        # Improved regex for better coverage
        url_pattern = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$'
        return bool(re.match(url_pattern, url, re.IGNORECASE))

    @staticmethod
    def parse_url(url):
        """Parse URL into components"""
        parsed = urlparse(url)
        return {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'path': parsed.path,
            'query': parsed.query,
            'fragment': parsed.fragment
        }

    # -----------------------------
    # Heuristic Detection Methods
    # -----------------------------

    @classmethod
    def detect_homograph_attack(cls, domain):
        suspicious_patterns = {
            'i': ['1'],
            'o': ['0'],
            's': ['5', '$']
        }

        # Check all parts except the TLD
        parts = domain.split('.')
        test_parts = parts[:-1] if len(parts) > 1 else parts

        for part in test_parts:
            if len(part) <= 2: continue # skip 'co', 'in' etc
            for char, replacements in suspicious_patterns.items():
                for r in replacements:
                    if r in part:
                        return True, f"Homograph substitution detected ({r} → {char})"
        return False, ""

    @classmethod
    def detect_typosquatting(cls, domain):
        """Detect visually similar domains (Typosquatting)"""
        # Check all parts except the TLD
        parts = domain.split('.')
        test_parts = parts[:-1] if len(parts) > 1 else parts

        for sld in test_parts:
            if len(sld) <= 3: continue
            sld_lower = sld.lower()
            for protected in cls.PROTECTED_DOMAINS:
                if sld_lower == protected:
                    continue
                
                # Use similarity ratio string comparison
                similarity = difflib.SequenceMatcher(None, sld_lower, protected).ratio()
                # 0.8 is a high confidence threshold for look-alikes
                if similarity >= 0.8:
                    return True, f"Typosquatting detected (visually similar to '{protected}')"
        return False, ""

    @classmethod
    def check_phishing_keywords(cls, url):
        found = []
        url_lower = url.lower()
        for keyword in cls.PHISHING_KEYWORDS:
            # Use regex for word boundary or specific inclusion in domain
            if re.search(rf'[-._]{keyword}|{keyword}[-._]|/{keyword}', url_lower) or keyword in url_lower:
                found.append(keyword)
        return found

    # -----------------------------
    # Main URL Analysis
    # -----------------------------

    @classmethod
    def analyze_url(cls, url):
        """
        Main URL analysis function
        Returns heuristic score, CVSS score, and final confidence
        """

        result = {
            'url': url,
            'is_valid': False,
            'threat_status': 'SAFE',
            'threat_level': 'LOW',
            'threat_type': 'No Significant Threat Detected',
            'heuristic_score': 0,
            'cvss_score': 0.0,
            'confidence': 0.0,
            'details': [],
            'components': {}
        }

        # -----------------------------
        # Step 1: Validate URL
        # -----------------------------
        if not cls.is_valid_url(url):
            result['threat_status'] = 'THREAT'
            result['threat_level'] = 'HIGH'
            result['threat_type'] = 'Invalid URL Format'
            result['heuristic_score'] = 4
            result['details'].append("Malformed or invalid URL format")
            result['cvss_score'] = cls.CVSS_MAPPING['Invalid URL Format']
            result['confidence'] = cls.calculate_confidence(
                result['heuristic_score'], result['cvss_score']
            )
            result['details'] = ' | '.join(result['details'])
            return result

        result['is_valid'] = True
        components = cls.parse_url(url)
        result['components'] = components
        domain = components['domain'].lower()
        scheme = components['scheme'].lower()

        heuristic_score = 0

        # -----------------------------
        # Step 2: Known malicious/phishing domain (handles subdomains)
        # -----------------------------
        base_domain = domain
        parts = domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])

        if domain in cls.MALICIOUS_DOMAINS or base_domain in cls.MALICIOUS_DOMAINS:
            target_domain = domain if domain in cls.MALICIOUS_DOMAINS else base_domain
            heuristic_score += 5
            result['threat_status'] = 'THREAT'
            result['threat_level'] = 'CRITICAL'
            result['threat_type'] = 'Known Malicious Domain'
            result['details'].append(
                f"Domain blacklisted ({cls.MALICIOUS_DOMAINS[target_domain]})"
            )

        elif domain in cls.PHISHING_DOMAINS or base_domain in cls.PHISHING_DOMAINS:
            target_domain = domain if domain in cls.PHISHING_DOMAINS else base_domain
            heuristic_score += 4
            result['threat_status'] = 'THREAT'
            result['threat_level'] = 'CRITICAL'
            result['threat_type'] = 'Phishing Domain'
            result['details'].append(
                f"Phishing domain detected ({cls.PHISHING_DOMAINS[target_domain]})"
            )

        # -----------------------------
        # Step 4: Homograph & Typosquatting detection
        # -----------------------------
        is_homograph, msg_h = cls.detect_homograph_attack(domain)
        is_typo, msg_t = cls.detect_typosquatting(domain)

        if is_homograph:
            heuristic_score += 4
            result['threat_status'] = 'THREAT'
            result['threat_level'] = 'HIGH'
            result['threat_type'] = 'Homograph Attack'
            result['details'].append(msg_h)
        
        elif is_typo:
            heuristic_score += 4
            result['threat_status'] = 'THREAT'
            result['threat_level'] = 'HIGH'
            result['threat_type'] = 'Typosquatting'
            result['details'].append(msg_t)

        # -----------------------------
        # Step 5: Phishing keywords & Domain Suspicion
        # -----------------------------
        keywords = cls.check_phishing_keywords(url)
        
        # Check if domain itself looks like a phishing domain (hyphens + keywords)
        domain_phish = False
        if any(kw in domain for kw in cls.PHISHING_KEYWORDS) or domain.count('-') >= 2:
            domain_phish = True

        if keywords or domain_phish:
            heuristic_score += 3
            if result['threat_status'] == 'SAFE':
                result['threat_status'] = 'SUSPICIOUS'
            
            # Upgrade threat level/type if not already higher
            if result['threat_level'] in ['LOW', 'MEDIUM']:
                result['threat_level'] = 'HIGH' if domain_phish else 'MEDIUM'
                result['threat_type'] = 'Phishing Pattern'
                
            if keywords:
                result['details'].append(f"Phishing keywords found: {', '.join(keywords)}")
            if domain_phish:
                result['details'].append("Suspicious domain pattern (keywords/excessive hyphens)")

        # -----------------------------
        # Step 6: Protocol analysis
        # -----------------------------
        if scheme not in ['http', 'https']:
            heuristic_score += 2
            result['details'].append(f"Non-standard protocol used: {scheme}")

        # -----------------------------
        # Step 7: IP-based URL
        # -----------------------------
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}', domain):
            heuristic_score += 2
            if result['threat_status'] == 'SAFE':
                result['threat_status'] = 'SUSPICIOUS'
            result['threat_type'] = 'IP Address URL'
            result['details'].append("IP address used instead of domain")

        # -----------------------------
        # Step 8: URL encoding check
        # -----------------------------
        decoded_url = unquote(url)
        if decoded_url != url:
            heuristic_score += 1
            result['details'].append("Encoded characters detected in URL")

        # -----------------------------
        # Final scoring
        # -----------------------------
        result['heuristic_score'] = heuristic_score

        result['cvss_score'] = cls.CVSS_MAPPING.get(
            result['threat_type'], 0.0
        )

        result['confidence'] = cls.calculate_confidence(
            heuristic_score, result['cvss_score']
        )

        if not result['details']:
            result['details'].append("URL appears safe")

        if isinstance(result['details'], list):
            result['details'] = ' | '.join(result['details'])

        return result

    # -----------------------------
    # Risk Calculation
    # -----------------------------

    @staticmethod
    def calculate_confidence(heuristic_score, cvss_score):
        """
        Final Risk Confidence:
        - Heuristic score = likelihood
        - CVSS score = impact
        """
        heuristic_pct = min(100, heuristic_score * 10)
        cvss_pct = cvss_score * 10
        final_confidence = (0.6 * heuristic_pct) + (0.4 * cvss_pct)
        return round(final_confidence, 2)

    # -----------------------------
    # Batch Analysis
    # -----------------------------

    @classmethod
    def batch_analyze_urls(cls, urls):
        return [cls.analyze_url(url) for url in urls]
