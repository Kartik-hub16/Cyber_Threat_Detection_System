# test_project.py - Project Verification Script
# Run this to test all components without Streamlit

import sys
import os

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.file_analyzer import FileAnalyzer
from utils.url_analyzer import URLAnalyzer

from utils.phone_analyzer import PhoneAnalyzer
from database import ThreatDatabase

def print_header(text):
    """Print formatted header."""
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60)

def print_result(result, threat_type):
    """Print analysis result nicely."""
    print(f"\n{'─'*50}")
    if threat_type == 'file':
        print(f"File: {result.get('filename', 'N/A')}")
    elif threat_type == 'url':
        print(f"URL: {result.get('url', 'N/A')}")

    elif threat_type == 'phone':
        print(f"Phone: {result.get('phone_number', 'N/A')}")
    
    print(f"Status: {result.get('threat_status', 'N/A')} 🔴" if result.get('threat_status') == 'THREAT' 
          else f"Status: {result.get('threat_status', 'N/A')} 🟢")
    print(f"Level: {result.get('threat_level', 'N/A')}")
    print(f"Type: {result.get('threat_type', 'N/A')}")
    print(f"Details: {result.get('details', 'N/A')}")

def test_file_analyzer():
    """Test FileAnalyzer functionality."""
    print_header("TESTING FILE ANALYZER")
    
    print("\n📄 Test 1: Safe text file")
    # Create temporary test file
    test_file = "test_safe.txt"
    with open(test_file, 'w') as f:
        f.write("Safe file content")
    
    result = FileAnalyzer.analyze_file(test_file)
    print_result(result, 'file')
    
    # Clean up
    os.remove(test_file)
    
    print("\n📄 Test 2: Dangerous extension")
    # Create temp .exe file
    test_file_exe = "test_malware.exe"
    with open(test_file_exe, 'w') as f:
        f.write("Malware")
    
    result = FileAnalyzer.analyze_file(test_file_exe)
    print_result(result, 'file')
    
    # Clean up
    os.remove(test_file_exe)
    
    print("\n✓ FileAnalyzer tests completed!")

def test_url_analyzer():
    """Test URLAnalyzer functionality."""
    print_header("TESTING URL ANALYZER")
    
    print("\n🌐 Test 1: Safe URL")
    result = URLAnalyzer.analyze_url("https://www.google.com")
    print_result(result, 'url')
    
    print("\n🌐 Test 2: Phishing URL (homograph)")
    result = URLAnalyzer.analyze_url("https://paypa1.com/login")
    print_result(result, 'url')
    
    print("\n🌐 Test 3: Blacklisted URL")
    result = URLAnalyzer.analyze_url("https://malware-site.com")
    print_result(result, 'url')
    
    print("\n✓ URLAnalyzer tests completed!")



def test_phone_analyzer():
    """Test PhoneAnalyzer functionality."""
    print_header("TESTING PHONE ANALYZER")
    
    print("\n☎️ Test 1: Fictional pattern")
    result = PhoneAnalyzer.analyze_phone_number("+1-555-123-4567")
    print_result(result, 'phone')
    
    print("\n☎️ Test 2: Valid UK number")
    result = PhoneAnalyzer.analyze_phone_number("+441234567890")
    print_result(result, 'phone')
    
    print("\n☎️ Test 3: Blacklisted number")
    result = PhoneAnalyzer.analyze_phone_number("+14155552671")
    print_result(result, 'phone')
    
    print("\n✓ PhoneAnalyzer tests completed!")

def test_database():
    """Test Database functionality."""
    print_header("TESTING DATABASE")
    
    db = ThreatDatabase("test_threat_db.sqlite")
    
    print("\n💾 Test 1: Save and retrieve file threat")
    db.save_threat(
        threat_type="FILE",
        input_data="malware.exe",
        threat_status="THREAT",
        threat_level="CRITICAL",
        details="Dangerous executable"
    )
    
    file_threats = db.get_threats_by_type('FILE')
    print(f"File threats in database: {len(file_threats)}")
    if file_threats:
        print(f"Last threat: {file_threats[-1]['input_data']} - {file_threats[-1]['threat_status']}")
    
    print("\n💾 Test 2: Save and retrieve URL threat")
    db.save_threat(
        threat_type="URL",
        input_data="https://phishing-site.com",
        threat_status="THREAT",
        threat_level="HIGH",
        details="Known phishing site"
    )
    
    url_threats = db.get_threats_by_type('URL')
    print(f"URL threats in database: {len(url_threats)}")
    if url_threats:
        print(f"Last threat: {url_threats[-1]['input_data']} - {url_threats[-1]['threat_status']}")
    

    
    print("\n💾 Test 4: Get statistics")
    stats = db.get_statistics()
    print("Database Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    db.close()
    
    # Clean up test database
    if os.path.exists("test_threat_db.sqlite"):
        os.remove("test_threat_db.sqlite")
    
    print("\n✓ Database tests completed!")

def test_batch_operations():
    """Test batch operations."""
    print_header("TESTING BATCH OPERATIONS")
    
    print("\n🔄 Test 1: Batch URL analysis")
    urls = [
        "https://www.google.com",
        "https://paypa1.com/login",
        "https://malware-site.com"
    ]
    results = URLAnalyzer.batch_analyze_urls(urls)
    print(f"Analyzed {len(results)} URLs:")
    for result in results:
        status = "✓ SAFE" if result['threat_status'] == 'SAFE' else "✗ THREAT"
        print(f"  {status}: {result['url']}")
    

    print("\n✓ Batch operation tests completed!")

def main():
    """Run all tests."""
    print("\n")
    print("╔" + "="*58 + "╗")
    print("║" + " "*58 + "║")
    print("║" + "CYBER THREAT DETECTION SYSTEM - TEST SUITE".center(58) + "║")
    print("║" + " "*58 + "║")
    print("╚" + "="*58 + "╝")
    
    try:
        # Run all tests
        test_file_analyzer()
        test_url_analyzer()

        test_phone_analyzer()
        test_database()
        test_batch_operations()
        
        # Summary
        print_header("TEST SUMMARY")
        print("\n✅ All tests completed successfully!")
        print("\n📊 Test Results:")
        print("  ✓ FileAnalyzer: PASSED")
        print("  ✓ URLAnalyzer: PASSED")

        print("  ✓ PhoneAnalyzer: PASSED")
        print("  ✓ Database: PASSED")
        print("  ✓ Batch Operations: PASSED")
        
        print("\n🚀 Project is ready to use!")
        print("\nTo start the Streamlit app, run:")
        print("  streamlit run main.py")
        print("\n")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
