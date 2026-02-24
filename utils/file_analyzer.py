# file analyzer - checks files for threats
# Integrated with content analysis from file_intel.py

import os
import hashlib
import re
from pathlib import Path

try:
    from PyPDF2 import PdfReader
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

class FileAnalyzer:
    # analyzes files for bad stuff with integrated content analysis
    
    # Suspicious keywords for phishing and social engineering detection
    SUSPICIOUS_WORDS = [
        "urgent", "verify", "password", "otp",
        "click here", "account suspended",
        "limited time", "confirm now"
    ]
    
    DANGEROUS_EXTENSIONS = {
        '.exe': 'CRITICAL',
        '.bat': 'CRITICAL',
        '.cmd': 'CRITICAL',
        '.scr': 'CRITICAL',
        '.vbs': 'CRITICAL',
        '.js': 'HIGH',
        '.jar': 'HIGH',
        '.zip': 'MEDIUM',
        '.ps1': 'CRITICAL',
        '.sh': 'HIGH',
        '.py': 'MEDIUM',
        '.pl': 'MEDIUM',
        '.docm': 'HIGH',
        '.xlsm': 'HIGH',
        '.pptm': 'HIGH',
        '.sys': 'CRITICAL',
        '.dll': 'HIGH',
        '.cab': 'MEDIUM'
    }
    
    SAFE_EXTENSIONS = ('.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.csv', '.json', '.xml', '.html')
    
    MALWARE_HASHES = {
        'd41d8cd98f00b204e9800998ecf8427e': 'Empty file',
        'da39a3ee5e6b4b0d3255bfef95601890afd80709': 'Suspicious hash',
        '5d41402abc4b2a76b9719d911017c592': 'Known malware'
    }
    
    @staticmethod
    def calculate_file_hash(file_path, algorithm='md5'):
        # calculate file hash
        try:
            if algorithm == 'md5':
                hasher = hashlib.md5()
            elif algorithm == 'sha256':
                hasher = hashlib.sha256()
            elif algorithm == 'sha1':
                hasher = hashlib.sha1()
            else:
                return ""
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            
            return hasher.hexdigest()
        except (FileNotFoundError, IOError) as e:
            return f"Error: {str(e)}"
    
    @staticmethod
    def get_file_extension(filename: str) -> str:
        """
        Extract file extension safely.
        
        Chapter 4: Immutable Data Structures (using pathlib)
        """
        return Path(filename).suffix.lower()
    
    @staticmethod
    def analyze_txt(content):
        """
        Analyze text content for phishing and social engineering threats.
        Returns score and list of detected threats.
        """
        score = 0
        reasons = []
        text = content.lower()
        
        # 1. Suspicious keywords
        for word in FileAnalyzer.SUSPICIOUS_WORDS:
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
    
    @staticmethod
    def analyze_pdf(file_path):
        """
        Analyze PDF file for malicious content and threats.
        Returns score and list of detected threats.
        """
        if not PDF_SUPPORT:
            return 0, ["PDF analysis not available (PyPDF2 not installed)"]
        
        score = 0
        reasons = []
        
        try:
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
            text_lower = text.lower()
            for word in FileAnalyzer.SUSPICIOUS_WORDS:
                if word in text_lower:
                    score += 1
                    reasons.append(f"Suspicious phrase detected: '{word}'")
        
        except Exception as e:
            reasons.append(f"Error analyzing PDF: {str(e)}")
        
        return score, reasons
    
    @staticmethod
    def classify_file_by_score(score):
        """
        Classify file threat level based on content analysis score.
        """
        if score >= 7:
            return "Malicious", "High Risk File"
        elif score >= 4:
            return "Suspicious", "Potentially Unsafe File"
        else:
            return "Safe", "No Threat Detected"
    
    @staticmethod
    def calculate_confidence(score):
        """
        Calculate confidence percentage based on threat score.
        """
        return min(100, score * 12)
    
    @classmethod
    def analyze_file(cls, file_path):
        """
        Comprehensive file analysis combining structural and content-based threat detection.
        Returns detailed threat assessment.
        """
        result = {
            'filename': os.path.basename(file_path),
            'file_path': file_path,
            'file_size': 0,
            'file_extension': '',
            'file_hash': '',
            'threat_status': 'SAFE',
            'threat_level': 'LOW',
            'threat_type': [],
            'details': [],
            'content_score': 0,
            'confidence': 0
        }
        
        try:
            # Check if file exists (Chapter 6: File operations)
            if not os.path.isfile(file_path):
                result['threat_status'] = 'ERROR'
                result['details'].append('File not found')
                return result
            
            # Get file information
            file_size = os.path.getsize(file_path)
            result['file_size'] = file_size
            
            extension = cls.get_file_extension(file_path)
            result['file_extension'] = extension
            
            # Calculate file hash
            file_hash = cls.calculate_file_hash(file_path, 'md5')
            result['file_hash'] = file_hash
            
            # ========== STRUCTURAL THREAT ANALYSIS ==========
            
            # Threat 1: Check against known malware hashes
            if file_hash in cls.MALWARE_HASHES:
                result['threat_status'] = 'THREAT'
                result['threat_level'] = 'CRITICAL'
                result['threat_type'].append('Known Malware')
                result['details'].append(f"File hash matches: {cls.MALWARE_HASHES[file_hash]}")
                result['confidence'] = 100
                return result
            
            # Threat 2: Check dangerous extensions
            if extension in cls.DANGEROUS_EXTENSIONS:
                result['threat_status'] = 'THREAT'
                result['threat_level'] = cls.DANGEROUS_EXTENSIONS[extension]
                result['threat_type'].append('Dangerous Extension')
                result['details'].append(f"Extension {extension} is flagged as {result['threat_level']}")
                result['confidence'] = 95
                return result
            
            # Threat 3: Check for double extensions (e.g., file.txt.exe)
            filename_without_ext = Path(file_path).stem
            if '.' in filename_without_ext:
                second_ext = '.' + filename_without_ext.split('.')[-1]
                if second_ext in cls.DANGEROUS_EXTENSIONS:
                    result['threat_status'] = 'THREAT'
                    result['threat_level'] = 'HIGH'
                    result['threat_type'].append('Double Extension Spoofing')
                    result['details'].append(f"File uses double extension masking: {second_ext}")
                    result['confidence'] = 90
                    return result
            
            # Threat 4: Suspicious file size
            if file_size == 0:
                result['threat_status'] = 'SUSPICIOUS'
                result['threat_level'] = 'MEDIUM'
                result['threat_type'].append('Empty File')
                result['details'].append("File is empty")
            elif file_size > 1000 * 1024 * 1024:  # > 1GB
                result['threat_status'] = 'SUSPICIOUS'
                result['threat_level'] = 'MEDIUM'
                result['threat_type'].append('Unusually Large File')
                result['details'].append(f"File size: {file_size / (1024*1024):.2f} MB")
            
            # ========== CONTENT ANALYSIS FOR TEXT & PDF ==========
            
            content_score = 0
            content_reasons = []
            
            # Analyze text files
            if extension == '.txt':
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    content_score, content_reasons = cls.analyze_txt(content)
                except Exception as e:
                    content_reasons.append(f"Error analyzing text content: {str(e)}")
            
            # Analyze PDF files
            elif extension == '.pdf':
                content_score, content_reasons = cls.analyze_pdf(file_path)
            
            result['content_score'] = content_score
            result['details'].extend(content_reasons)
            
            # ========== COMBINED THREAT ASSESSMENT ==========
            
            # If content analysis found threats
            if content_score > 0:
                classification, description = cls.classify_file_by_score(content_score)
                if classification == "Malicious" and result['threat_status'] != 'THREAT':
                    result['threat_status'] = 'THREAT'
                    result['threat_level'] = 'CRITICAL'
                    result['threat_type'].append('Malicious Content')
                elif classification == "Suspicious" and result['threat_status'] == 'SAFE':
                    result['threat_status'] = 'SUSPICIOUS'
                    result['threat_level'] = 'MEDIUM'
                    result['threat_type'].append('Suspicious Content')
                
                result['confidence'] = cls.calculate_confidence(content_score)
            
            # Default to safe if no threats found
            if result['threat_status'] == 'SAFE':
                result['threat_level'] = 'LOW'
                result['details'].append('File appears safe')
                result['confidence'] = 95
            
            # Ensure threat_type is never empty
            if not result['threat_type']:
                result['threat_type'] = ['No specific threat detected']
            
            # Convert lists to strings for database compatibility
            if isinstance(result['threat_type'], list):
                result['threat_type'] = ', '.join(result['threat_type'])
                
            if isinstance(result['details'], list):
                result['details'] = ' | '.join(result['details'])
            
            return result
        
        except Exception as e:
            result['threat_status'] = 'ERROR'
            result['details'].append(str(e))
            return result
    
    @staticmethod
    def validate_file_integrity(file_path: str, expected_hash: str) -> bool:
        """
        Verify file hasn't been modified by comparing hashes.
        
        Chapter 6: File validation
        """
        actual_hash = FileAnalyzer.calculate_file_hash(file_path, 'sha256')
        return actual_hash == expected_hash
    
    @classmethod
    def batch_analyze_files(cls, file_paths):
        # analyze multiple files
        results = []
        for file_path in file_paths:
            result = cls.analyze_file(file_path)
            results.append(result)
        return results
    
    @staticmethod
    def get_file_metadata(file_path):
        # get file info
        try:
            stat_info = os.stat(file_path)
            return {
                'size': stat_info.st_size,
                'modified_time': stat_info.st_mtime,
                'created_time': stat_info.st_ctime,
                'is_hidden': os.path.basename(file_path).startswith('.')
            }
        except Exception as e:
            return {'error': str(e)}


# Testing and demonstration
if __name__ == "__main__":
    print("File Analyzer Test:")
    print("-" * 50)
    
    # Example analysis
    test_file = "sample.txt"
    if os.path.exists(test_file):
        result = FileAnalyzer.analyze_file(test_file)
        print(f"File: {result['filename']}")
        print(f"Status: {result['threat_status']}")
        print(f"Level: {result['threat_level']}")
