# phone analyzer - checks phone numbers

import re

class PhoneAnalyzer:
    # analyzes phone numbers for threats
    
    COUNTRY_CODES = {
        '+1': {'country': 'USA/Canada', 'length': 10, 'pattern': r'^\+1\d{10}$'},
        '+44': {'country': 'UK', 'length': 10, 'pattern': r'^\+44\d{10}$'},
        '+91': {'country': 'India', 'length': 10, 'pattern': r'^\+91\d{10}$'},
        '+86': {'country': 'China', 'length': 11, 'pattern': r'^\+86\d{11}$'},
        '+81': {'country': 'Japan', 'length': 10, 'pattern': r'^\+81\d{10}$'},
        '+33': {'country': 'France', 'length': 9, 'pattern': r'^\+33\d{9}$'},
        '+49': {'country': 'Germany', 'length': 11, 'pattern': r'^\+49\d{11}$'},
        '+39': {'country': 'Italy', 'length': 10, 'pattern': r'^\+39\d{10}$'},
        '+61': {'country': 'Australia', 'length': 9, 'pattern': r'^\+61\d{9}$'},
    }
    
    SPAM_PREFIXES = {
        '0800': 'Toll-free',
        '0900': 'Premium rate',
        '0901': 'Premium rate',
        '555': 'Fictional',
    }
    
    BLACKLIST = [
        '+14155552671',
        '+441234567890',
        '+919876543210',
    ]
    
    @staticmethod
    def is_valid_phone_format(phone_number):
        # check if phone number looks ok
        phone_number = phone_number.strip()
        
        if not phone_number:
            return False, "Empty"
        
        clean_phone = re.sub(r'[\s\-\(\)\.]+', '', phone_number)
        
        digits = re.findall(r'\d', clean_phone)
        if len(digits) < 7:
            return False, "Not enough digits"
        
        digit_ratio = len(digits) / len(clean_phone)
        if digit_ratio < 0.5:
            return False, "Bad format"
        
        if clean_phone[0] not in ['+', '0'] and not clean_phone[0].isdigit():
            return False, "Bad format"
        
        return True, "OK"
    
    @staticmethod
    def normalize_phone_number(phone_number):
        # make phone number standard format
        normalized = re.sub(r'[^\d+]', '', phone_number.strip())
        return normalized
    
    @staticmethod
    def extract_country_code(phone_number):
        # get country code
        normalized = PhoneAnalyzer.normalize_phone_number(phone_number)
        
        # Try to match country codes
        for code, info in PhoneAnalyzer.COUNTRY_CODES.items():
            if normalized.startswith(code):
                return code, info['country']
        
        # If starts with 0, likely domestic
        if normalized.startswith('0'):
            return 'UNKNOWN', 'Domestic (Unknown country)'
        
        return 'INVALID', 'Invalid country code'
    
    @classmethod
    def detect_spam_patterns(cls, phone_number):
        # detect spam patterns
        result = {
            'is_spam': False,
            'spam_type': '',
            'threat_level': 'LOW',
            'details': ''
        }
        
        normalized = cls.normalize_phone_number(phone_number)
        
        if normalized in cls.BLACKLIST:
            result['is_spam'] = True
            result['spam_type'] = 'Blacklisted Number'
            result['threat_level'] = 'HIGH'
            result['details'] = 'Number is in spam/fraud blacklist'
            return result
        
        # Check for spam prefixes
        for prefix, description in cls.SPAM_PREFIXES.items():
            if normalized.endswith(prefix) or normalized.startswith(prefix):
                result['is_spam'] = True
                result['spam_type'] = 'Spam Prefix Detected'
                result['threat_level'] = 'MEDIUM'
                result['details'] = description
                return result
        
        # Pattern: Sequential digits (555-1234)
        if re.search(r'555', normalized):
            result['is_spam'] = True
            result['spam_type'] = 'Fictional Pattern'
            result['threat_level'] = 'MEDIUM'
            result['details'] = 'Contains fictional number pattern (555)'
            return result
        
        # Pattern: Repeated digits (111-1111)
        if re.search(r'(\d)\1{4,}', normalized):
            result['is_spam'] = True
            result['spam_type'] = 'Repeated Digits'
            result['threat_level'] = 'MEDIUM'
            result['details'] = 'Contains repeated digit pattern'
            return result
        
        # Pattern: All sequential (123456789)
        digits_only = re.findall(r'\d', normalized)
        if len(digits_only) >= 5:
            digits_str = ''.join(digits_only)
            is_sequential = all(
                int(digits_str[i]) - int(digits_str[i-1]) == 1 
                for i in range(1, min(5, len(digits_str)))
            )
            if is_sequential:
                result['is_spam'] = True
                result['spam_type'] = 'Sequential Pattern'
                result['threat_level'] = 'MEDIUM'
                result['details'] = 'Contains sequential digit pattern'
        
        return result
    
    @classmethod
    def check_country_validity(cls, phone_number):
        # check if phone is valid for country
        result = {
            'country_code': '',
            'country': '',
            'is_valid_for_country': False,
            'details': ''
        }
        
        normalized = cls.normalize_phone_number(phone_number)
        country_code, country = cls.extract_country_code(phone_number)
        
        result['country_code'] = country_code
        result['country'] = country
        
        if country_code not in cls.COUNTRY_CODES:
            result['details'] = f"Unknown country code: {country_code}"
            return result
        
        pattern = cls.COUNTRY_CODES[country_code]['pattern']
        expected_length = cls.COUNTRY_CODES[country_code]['length']
        
        if re.match(pattern, normalized):
            result['is_valid_for_country'] = True
            result['details'] = f"Valid format for {country}"
        else:
            result['details'] = f"Invalid format for {country} (expected {expected_length} digits)"
        
        return result
    
    @classmethod
    @classmethod
    def analyze_phone_number(cls, phone_number):
        # analyze phone number for threats
        result = {
            'phone_number': phone_number,
            'normalized': '',
            'is_valid': False,
            'threat_status': 'SAFE',
            'threat_level': 'LOW',
            'threat_type': 'None',
            'country': '',
            'country_code': '',
            'details': []
        }
        
        try:
            # Threat 1: Check format validity
            is_valid, reason = cls.is_valid_phone_format(phone_number)
            if not is_valid:
                result['threat_status'] = 'THREAT'
                result['threat_level'] = 'MEDIUM'
                result['threat_type'] = 'Invalid Format'
                result['details'].append(f"Format error: {reason}")
                return result
            
            result['is_valid'] = True
            normalized = cls.normalize_phone_number(phone_number)
            result['normalized'] = normalized
            
            # Threat 2: Detect spam patterns
            spam_check = cls.detect_spam_patterns(phone_number)
            if spam_check['is_spam']:
                result['threat_status'] = 'THREAT'
                result['threat_level'] = spam_check['threat_level']
                result['threat_type'] = spam_check['spam_type']
                result['details'].append(spam_check['details'])
            
            # Threat 3: Verify country validity
            country_check = cls.check_country_validity(phone_number)
            result['country'] = country_check['country']
            result['country_code'] = country_check['country_code']
            
            if not country_check['is_valid_for_country']:
                if result['threat_status'] == 'SAFE':
                    result['threat_status'] = 'SUSPICIOUS'
                    result['threat_level'] = 'MEDIUM'
                    result['threat_type'] = 'Invalid Country Format'
                result['details'].append(country_check['details'])
            
            # Threat 4: Check for suspicious patterns
            # Very short numbers
            digits_only = re.findall(r'\d', normalized)
            if len(digits_only) < 7:
                result['details'].append("Unusually short number")
            
            # Finalize result
            if result['threat_status'] == 'SAFE':
                result['threat_level'] = 'LOW'
                if not result['details']:
                    result['details'].append('Phone number appears safe')
            
            if isinstance(result['details'], list):
                result['details'] = ' | '.join(result['details'])
            
            # Ensure threat_type is string
            if not isinstance(result['threat_type'], str):
                 result['threat_type'] = str(result['threat_type'])

            return result
        
        except Exception as e:
            result['threat_status'] = 'ERROR'
            result['details'] = str(e)
            return result
    
    @classmethod
    def batch_analyze_phone_numbers(cls, phone_numbers):
        # analyze multiple phone numbers
        results = []
        for phone_number in phone_numbers:
            result = cls.analyze_phone_number(phone_number)
            results.append(result)
        return results


# Testing
if __name__ == "__main__":
    print("Phone Analyzer Test:")
    print("-" * 50)
    
    test_numbers = [
        "+1-555-123-4567",
        "+441234567890",
        "+919876543210"
    ]
    
    for test_number in test_numbers:
        result = PhoneAnalyzer.analyze_phone_number(test_number)
        print(f"\nPhone: {result['phone_number']}")
        print(f"Status: {result['threat_status']}")
        print(f"Type: {result['threat_type']}")
        print(f"Country: {result['country']}")
