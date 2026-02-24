import sys
import os

# Add current directory to path
sys.path.append(os.getcwd())

from utils.url_analyzer import URLAnalyzer

def test_url(url):
    print(f"\nAnalyzing: {url}")
    result = URLAnalyzer.analyze_url(url)
    print(f"Status: {result['threat_status']}")
    print(f"Level:  {result['threat_level']}")
    print(f"Type:   {result['threat_type']}")
    
    # Clean details for Windows console printing
    details = result['details']
    if isinstance(details, str):
        details = details.encode('ascii', 'replace').decode('ascii')
    print(f"Details: {details}")
    
    print(f"Confidence: {result['confidence']}%")
    return result

if __name__ == "__main__":
    urls = [
        "https://www.go0gle.com",
        "https://go0gle.com",
        "https://www.google.com",
        "https://www.googla.com",
        "https://amaz0n.co.uk",
        "https://paypa1.com/login"
    ]
    
    for url in urls:
        test_url(url)
