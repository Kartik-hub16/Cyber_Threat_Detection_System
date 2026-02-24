# main.py - the main app

import streamlit as st
import pandas as pd
from pathlib import Path
import os
from datetime import datetime
from utils.password_analyzer import PasswordAnalyzer
from utils.file_analyzer import FileAnalyzer
from utils.url_analyzer import URLAnalyzer

from database import ThreatDatabase
from utils.integrity_analyzer import IntegrityAnalyzer
from utils.log_analyzer import LogAnalyzer
from utils.phone_analyzer import PhoneAnalyzer


# Page config
st.set_page_config(
    page_title="Cyber Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS for styling
st.markdown("""
    <style>
    .threat-safe { color: #2ecc71; font-weight: bold; }
    .threat-suspicious { color: #f39c12; font-weight: bold; }
    .threat-threat { color: #e74c3c; font-weight: bold; }
    .threat-error { color: #95a5a6; font-weight: bold; }
    
    .metric-box {
        background-color: #f8f9fa;
        padding: 15px;
        border-radius: 5px;
        border-left: 4px solid #3498db;
    }
    </style>
""", unsafe_allow_html=True)
# Initialize session state
# Always re-initialize DB to pick up hotfixes
if 'db' in st.session_state:
    try:
        st.session_state.db.close()
    except:
        pass
    del st.session_state.db

if 'db' not in st.session_state:
    st.session_state.db = ThreatDatabase()
if 'file_history' not in st.session_state:
    st.session_state.file_history = []
if 'url_history' not in st.session_state:
    st.session_state.url_history = []

def get_threat_color(threat_status):
    # return emoji for threat status
    colors = {
        'SAFE': '🟢',
        'SUSPICIOUS': '🟡',
        'THREAT': '🔴',
        'ERROR': '⚫'
    }
    return colors.get(threat_status, '⚪')


def display_threat_result(result, threat_type):
    # display the results nicely
    col1, col2, col3 = st.columns(3)
    
    status_icon = get_threat_color(result['threat_status'])
    
    with col1:
        st.metric("Status", f"{status_icon} {result['threat_status']}")
    
    with col2:
        st.metric("Threat Level", result['threat_level'])
    
    with col3:
        threat_type_val = result['threat_type']
        if isinstance(threat_type_val, list):
            threat_type_val = ", ".join(threat_type_val)
        st.metric("Type", threat_type_val)
    
    with st.expander("View Details"):
        if threat_type == 'file':
            st.write(f"**Filename:** {result.get('filename', 'N/A')}")
            st.write(f"**Size:** {result.get('file_size', 0)} bytes")
            st.write(f"**Extension:** {result.get('file_extension', 'N/A')}")
            st.write(f"**Hash:** `{result.get('file_hash', 'N/A')}`")
        
        elif threat_type == 'url':
            st.write(f"**URL:** {result.get('url', 'N/A')}")
            components = result.get('components', {})
            st.write(f"**Domain:** {components.get('domain', 'N/A')}")
            st.write(f"**Scheme:** {components.get('scheme', 'N/A')}")
        

        
        st.write(f"**Details:** {result.get('details', 'N/A')}")


def save_to_database(result, threat_type):
    # save result to database
    db = st.session_state.db
    
    try:
        if threat_type == 'file':
            input_data = result['filename']
            extra_data = {
                'filename': result.get('filename', ''),
                'file_size': result.get('file_size', 0),
                'file_extension': result.get('file_extension', ''),
                'file_hash': result.get('file_hash', '')
            }
        elif threat_type == 'url':
            input_data = result['url']
            components = result.get('components', {})
            extra_data = {
                'domain': components.get('domain', ''),
                'scheme': components.get('scheme', '')
            }
        
        elif threat_type == 'phone':
            input_data = result['phone_number']
            extra_data = {
                'country': result.get('country', ''),
                'country_code': result.get('country_code', '')
            }

        else:
            input_data = str(result)
            extra_data = None
        
        success = db.save_threat(
            threat_type=threat_type.upper(),
            input_data=input_data,
            threat_status=result['threat_status'],
            threat_level=result['threat_level'],
            details=result['details'],
            extra_data=extra_data
        )
        
        if success:
            st.success(f"✓ {threat_type.upper()} threat saved to database!")
        else:
            st.error(f"Failed to save {threat_type} to database")
    
    except Exception as e:
        st.error(f"Database error: {str(e)}")


# Main app
def main():
    # entry point
    
    st.markdown('<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; margin-bottom: 20px;"><h1 style="color: white; margin: 0;">🛡️ Cyber Threat Detection System</h1><p style="color: white; margin: 5px 0 0 0;">Advanced threat analysis platform</p></div>', unsafe_allow_html=True)
    
    page = st.sidebar.radio(
    "Select Analysis Type:",
    [
        "📊 Dashboard",
        "📄 File Analysis",
        "🔐 File Integrity Check",
        "🌐 URL Analysis",
        "📞 Phone Analysis",
        "🧾 Log Tracker",
        "🔑 Password Strength Checker",
        "📈 Statistics",
        "💾 Database"
    ]
)


    if page == "📊 Dashboard":
        dashboard_page()
    
    elif page == "📄 File Analysis":
        file_analysis_page()

    elif page == "🔐 File Integrity Check":
         file_integrity_page()

    elif page == "🌐 URL Analysis":
        url_analysis_page()

    elif page == "📞 Phone Analysis":
        phone_analysis_page()



    elif page == "🧾 Log Tracker":
        log_analysis_page()
        
    elif page == "🔑 Password Strength Checker":
        password_analysis_page()

    
    elif page == "📈 Statistics":
        statistics_page()
    
    elif page == "💾 Database":
        database_management_page()
    

def dashboard_page():
    # Modern minimal dashboard

    db = st.session_state.db
    stats = db.get_statistics()
    all_threats = db.get_all_threats()

    total_scans = stats.get('FILEs', 0) + stats.get('URLs', 0) + stats.get('PHONEs', 0)
    total_threats = len([t for t in all_threats if t['threat_status'] == 'THREAT'])
    total_safe = len([t for t in all_threats if t['threat_status'] == 'SAFE'])
    total_suspicious = len([t for t in all_threats if t['threat_status'] == 'SUSPICIOUS'])

    # Dashboard CSS
    st.markdown("""
    <style>
    .dash-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 16px;
        padding: 28px 24px;
        text-align: center;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .dash-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 8px 30px rgba(0,0,0,0.3);
    }
    .dash-card .icon { font-size: 2.2rem; margin-bottom: 8px; }
    .dash-card .value {
        font-size: 2.6rem;
        font-weight: 700;
        color: #ffffff;
        margin: 4px 0;
        letter-spacing: -1px;
    }
    .dash-card .label {
        font-size: 0.85rem;
        color: rgba(255,255,255,0.5);
        text-transform: uppercase;
        letter-spacing: 1.5px;
        font-weight: 500;
    }
    .dash-card.blue   { border-left: 4px solid #667eea; }
    .dash-card.green  { border-left: 4px solid #2ecc71; }
    .dash-card.red    { border-left: 4px solid #e74c3c; }
    .dash-card.yellow { border-left: 4px solid #f39c12; }

    .recent-item {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 12px;
        padding: 14px 18px;
        margin-bottom: 8px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .recent-item .ri-left { display: flex; align-items: center; gap: 12px; }
    .recent-item .ri-name { color: #e0e0e0; font-size: 0.92rem; }
    .recent-item .ri-time { color: rgba(255,255,255,0.35); font-size: 0.78rem; }
    .badge {
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .badge.safe       { background: rgba(46,204,113,0.15); color: #2ecc71; }
    .badge.threat     { background: rgba(231,76,60,0.15);  color: #e74c3c; }
    .badge.suspicious { background: rgba(243,156,18,0.15); color: #f39c12; }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("")

    # --- Stat Cards ---
    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.markdown(f"""
        <div class="dash-card blue">
            <div class="icon">�</div>
            <div class="value">{total_scans}</div>
            <div class="label">Total Scans</div>
        </div>""", unsafe_allow_html=True)

    with c2:
        st.markdown(f"""
        <div class="dash-card green">
            <div class="icon">✅</div>
            <div class="value">{total_safe}</div>
            <div class="label">Safe</div>
        </div>""", unsafe_allow_html=True)

    with c3:
        st.markdown(f"""
        <div class="dash-card yellow">
            <div class="icon">⚠️</div>
            <div class="value">{total_suspicious}</div>
            <div class="label">Suspicious</div>
        </div>""", unsafe_allow_html=True)

    with c4:
        st.markdown(f"""
        <div class="dash-card red">
            <div class="icon">🚨</div>
            <div class="value">{total_threats}</div>
            <div class="label">Threats</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # --- Scan Breakdown ---
    st.markdown("##### Scan Breakdown")
    b1, b2, b3 = st.columns(3)
    with b1:
        st.metric("📄 Files", stats.get('FILEs', 0))
    with b2:
        st.metric("🌐 URLs", stats.get('URLs', 0))
    with b3:
        st.metric("📞 Phones", stats.get('PHONEs', 0))

    st.markdown("<br>", unsafe_allow_html=True)

    # --- Recent Activity ---
    st.markdown("##### Recent Activity")

    recent = all_threats[:5]
    if recent:
        for item in recent:
            status = item['threat_status']
            badge_cls = 'safe' if status == 'SAFE' else ('threat' if status == 'THREAT' else 'suspicious')
            icon = '📄' if item['threat_type'] == 'FILE' else ('🌐' if item['threat_type'] == 'URL' else '📞')
            name = item.get('input_data', 'Unknown')
            if len(name) > 45:
                name = name[:42] + '...'
            ts = item.get('timestamp', '')
            if ts:
                ts = ts[5:16].replace('T', ' · ')

            st.markdown(f"""
            <div class="recent-item">
                <div class="ri-left">
                    <span style="font-size:1.3rem">{icon}</span>
                    <div>
                        <div class="ri-name">{name}</div>
                        <div class="ri-time">{ts}</div>
                    </div>
                </div>
                <span class="badge {badge_cls}">{status}</span>
            </div>""", unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="text-align:center; padding:40px 0; color:rgba(255,255,255,0.3);">
            <div style="font-size:2.5rem; margin-bottom:8px;">�</div>
            <div>No scans yet — start analyzing to see results here</div>
        </div>""", unsafe_allow_html=True)


def file_analysis_page():
    # analyze files
    
    st.header("📄 File Threat Analysis")
    st.markdown("Upload or select files to scan for malware and suspicious content")
    st.divider()
    
    uploaded_file = st.file_uploader("📤 Upload file:", key="file_upload")
    
    if uploaded_file:
        temp_path = f"temp_{uploaded_file.name}"
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        st.success(f"✅ Analyzing: **{uploaded_file.name}**")
        
        result = FileAnalyzer.analyze_file(temp_path)
        
        st.markdown("### 📋 Results")
        display_threat_result(result, 'file')
        
        if st.button("Save to DB", key="save_file"):
            save_to_database(result, 'file')
            st.success("✓ Saved to database!")
        
        os.remove(temp_path)
    
    st.divider()
    st.subheader("📁 Or enter file path:")
    
    file_path = st.text_input("File path:", placeholder="C:/path/file.exe")
    
    if file_path and st.button("🔍 Analyze", key="manual_file"):
        if os.path.exists(file_path):
            result = FileAnalyzer.analyze_file(file_path)
            st.markdown("### 📋 Results")
            display_threat_result(result, 'file')
            
            if st.button("Save to DB", key="save_manual_file"):
                save_to_database(result, 'file')
                st.success("✓ Saved!")
        else:
            st.error("❌ File not found!")
def file_integrity_page():
    """
    File Integrity Verification Page
    User uploads a file + provides original hash (key)
    System recalculates hash and verifies integrity
    """

    st.header("🔐 File Integrity Verification")
    st.markdown(
        "Verify whether a file has been **tampered or altered** by "
        "matching its cryptographic hash with a provided key."
    )
    st.divider()

    uploaded_file = st.file_uploader(
        "📤 Upload file for integrity check",
        key="integrity_file"
    )

    hash_algorithm = st.selectbox(
        "Select Hash Algorithm",
        ["md5", "sha1", "sha256"]
    )

    user_hash = st.text_input(
        "Enter Original Hash (Key)",
        placeholder="Paste the trusted hash value here"
    )

    if uploaded_file and user_hash and st.button("🔍 Verify Integrity"):
        temp_path = f"integrity_{uploaded_file.name}"

        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        try:
            result = IntegrityAnalyzer.verify_integrity(
                temp_path,
                user_hash,
                hash_algorithm
            )

            st.markdown("### 📋 Integrity Result")

            if result["integrity_status"] == "SAFE":
                st.success("✅ File is SAFE — integrity verified")
            else:
                st.error("❌ File is TAMPERED — integrity violation detected")

            st.markdown("### 🔐 Hash Comparison")
            st.code(
                f"Algorithm      : {hash_algorithm.upper()}\n"
                f"Provided Hash  : {user_hash}\n"
                f"Computed Hash  : {result['computed_hash']}"
            )

        except Exception as e:
            st.error(f"Integrity check failed: {str(e)}")

        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    st.divider()

    st.info(
        "💡 **Security Note:** This feature verifies file integrity using "
        "cryptographic hashes, ensuring the file has not been modified "
        "during transfer or storage."
    )

def log_analysis_page():
    """
    Log Tracker Page
    """

    st.header("🧾 Log Tracker")
    st.markdown(
        "Analyze system or application logs to detect suspicious "
        "activities such as brute-force attacks and unauthorized access."
    )
    st.divider()

    uploaded_log = st.file_uploader(
        "📤 Upload Log File",
        type=["log", "txt"]
    )

    if uploaded_log:
        try:
            log_content = uploaded_log.read().decode("utf-8", errors="ignore")

            result = LogAnalyzer.analyze_log(log_content)

            st.markdown("### 📋 Analysis Result")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Status", result["threat_status"])

            with col2:
                st.metric("Threat Level", result["threat_level"])

            with col3:
                st.metric("Suspicion Score", result["score"])

            st.markdown("### 🔍 Findings")
            st.write(result["details"])

            st.markdown("### 📊 Pattern Summary")
            if result["pattern_summary"]:
                st.json(result["pattern_summary"])
            else:
                st.info("No suspicious activity found")

        except Exception as e:
            st.error(f"Failed to analyze log file: {str(e)}")

    st.divider()
    st.info(
        "💡 Logs are analyzed statically. No commands are executed "
        "and no external connections are made."
    )

# ==================== URL ANALYSIS PAGE ====================
def url_analysis_page():
    # analyze urls with heuristic + CVSS scoring

    st.header("🌐 URL Threat Detection")
    st.markdown(
        "Check URLs for phishing, malware, homograph attacks, "
        "and view risk using heuristic and CVSS-based scoring."
    )
    st.divider()

    # -------------------------
    # Single URL Analysis
    # -------------------------
    url = st.text_input(
        "Enter URL:",
        placeholder="https://example.com"
    )

    if url and st.button("🔍 Analyze URL"):
        result = URLAnalyzer.analyze_url(url)
        st.session_state.url_result = result

    # Display result if it exists in session state
    if 'url_result' in st.session_state and st.session_state.url_result:
        result = st.session_state.url_result

        st.markdown("### 📋 Analysis Result")
        display_threat_result(result, 'url')

        st.markdown("### 📊 Risk Assessment")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                "Heuristic Score",
                result.get("heuristic_score", 0),
                help="Likelihood of malicious behavior based on URL characteristics"
            )

        with col2:
            st.metric(
                "CVSS Score",
                result.get("cvss_score", 0.0),
                help="Impact severity score based on CVSS-inspired mapping"
            )

        with col3:
            st.metric(
                "Final Confidence (%)",
                f"{result.get('confidence', 0)}%",
                help="Combined likelihood and impact risk score"
            )

        # Save single result
        if st.button("💾 Save to Database", key="save_url"):
            save_to_database(result, 'url')
            st.success("✓ URL analysis saved successfully")

    st.divider()

    # -------------------------
    # Batch URL Analysis
    # -------------------------
    st.subheader("📋 Batch URL Analysis")

    urls_text = st.text_area(
        "Enter URLs (one per line):",
        placeholder="https://example1.com\nhttps://example2.com",
        height=120
    )

    if urls_text and st.button("🔍 Analyze Multiple URLs"):
        urls = [u.strip() for u in urls_text.split('\n') if u.strip()]
        results = URLAnalyzer.batch_analyze_urls(urls)
        st.session_state.url_batch_results = results

    if 'url_batch_results' in st.session_state and st.session_state.url_batch_results:
        results = st.session_state.url_batch_results

        st.markdown("### 📊 Batch Results")

        df_data = []
        for result in results:
            df_data.append({
                'URL': result['url'],
                'Status': result['threat_status'],
                'Threat Level': result['threat_level'],
                'Heuristic Score': result.get('heuristic_score', 0),
                'CVSS Score': result.get('cvss_score', 0.0),
                'Confidence (%)': result.get('confidence', 0.0)
            })

        st.dataframe(df_data, use_container_width=True)

        if st.button("💾 Save All to Database", key="save_batch_url"):
            for result in results:
                save_to_database(result, 'url')
            st.success(f"✓ {len(results)} URL results saved successfully")


def phone_analysis_page():
    # analyze phone numbers
    
    st.header("📞 Phone Number Analysis")
    st.markdown("Analyze phone numbers for spam, fraud, and validity")
    st.divider()
    
    # Single Analysis
    phone = st.text_input("Enter Phone Number:", placeholder="+1-555-123-4567")
    
    if phone and st.button("🔍 Analyze Phone"):
        result = PhoneAnalyzer.analyze_phone_number(phone)
        st.session_state.phone_result = result

    if 'phone_result' in st.session_state and st.session_state.phone_result:
        result = st.session_state.phone_result

        st.markdown("### 📋 Results")
        display_threat_result(result, 'phone')
        
        if result['is_valid']:
            st.info(f"📍 Country: **{result['country']}** ({result['country_code']})")
        
        if st.button("Save to DB", key="save_phone"):
            save_to_database(result, 'phone')
            st.success("✓ Saved to database!")
            
    st.divider()
    
    # Batch Analysis
    st.subheader("📋 Batch Phone Analysis")
    phones_text = st.text_area("Enter Phone Numbers (one per line):", height=100)
    
    if phones_text and st.button("🔍 Analyze Multiple Numbers"):
        phones = [p.strip() for p in phones_text.split('\n') if p.strip()]
        results = PhoneAnalyzer.batch_analyze_phone_numbers(phones)
        st.session_state.phone_batch_results = results

    if 'phone_batch_results' in st.session_state and st.session_state.phone_batch_results:
        results = st.session_state.phone_batch_results

        st.markdown("### 📊 Batch Results")
        
        df_data = []
        for res in results:
            df_data.append({
                'Phone': res['phone_number'],
                'Status': res['threat_status'],
                'Type': res['threat_type'],
                'Country': res['country']
            })
        
        st.dataframe(df_data, use_container_width=True)
        
        if st.button("Save All to DB", key="save_batch_phone"):
            for res in results:
                save_to_database(res, 'phone')
            st.success(f"✓ {len(results)} phone results saved!")


def password_analysis_page():
    st.header("🔑 Password Strength Analyzer")
    st.markdown("Check how strong your password is against brute-force and guessing attacks.")
    st.divider()

    password = st.text_input("Enter Password", type="password")

    if password and st.button("🔍 Analyze Password"):
        result = PasswordAnalyzer.analyze_password(password)

        st.markdown("### 📊 Strength Result")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Strength", result["strength"])

        with col2:
            st.metric("Score", result["score"])

        with col3:
            st.metric("Entropy (bits)", result["entropy"])

        st.markdown("### 💡 Feedback")
        for item in result["feedback"]:
            st.write(f"- {item}")

def statistics_page():
    # show stats from database
    
    st.header("📈 Threat Statistics")
    st.markdown("Detailed analysis and reporting of all threats")
    st.divider()
    
    db = st.session_state.db
    
    tab1, tab2, tab3, tab4 = st.tabs(
        ["📊 Overview", "📄 Files", "🌐 URLs", "📞 Phones"]
    )
    
    with tab1:
        st.subheader("Global Statistics")
        stats = db.get_statistics()
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("📄 Files", stats.get('FILEs', 0))
        with col2:
            st.metric("🌐 URLs", stats.get('URLs', 0))
        with col3:
            st.metric("📞 Phones", stats.get('PHONEs', 0))

    
    with tab2:
        st.subheader("📄 File Threats")
        file_threats = db.get_threats_by_type('FILE')
        
        if file_threats:
            df = pd.DataFrame(file_threats)
            st.dataframe(df, use_container_width=True)
            
            threat_count = len([t for t in file_threats if t['threat_status'] == 'THREAT'])
            st.metric(f"Threats Found", f"{threat_count}/{len(file_threats)}")
        else:
            st.info("No file threats yet.")
    
    with tab3:
        st.subheader("🌐 URL Threats")
        url_threats = db.get_threats_by_type('URL')
        
        if url_threats:
            df = pd.DataFrame(url_threats)
            st.dataframe(df, use_container_width=True)
            
            threat_count = len([t for t in url_threats if t['threat_status'] == 'THREAT'])
            st.metric(f"Threats Found", f"{threat_count}/{len(url_threats)}")
        else:
            st.info("No URL threats yet.")
    
    with tab4:
        st.subheader("📞 Phone Threats")
        phone_threats = db.get_threats_by_type('PHONE')
        
        if phone_threats:
            df = pd.DataFrame(phone_threats)
            st.dataframe(df, use_container_width=True)
            
            threat_count = len([t for t in phone_threats if t['threat_status'] == 'THREAT'])
            st.metric(f"Threats Found", f"{threat_count}/{len(phone_threats)}")
        else:
            st.info("No Phone threats yet.")
    



def database_management_page():
    # manage the database
    
    st.header("💾 Database Management")
    st.warning("⚠️ Be careful with these operations!")
    st.divider()
    
    db = st.session_state.db
    
    st.subheader("📊 Database Size")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        file_threats = db.get_threats_by_type('FILE')
        st.metric("📄 Files", len(file_threats))
    
    with col2:
        url_threats = db.get_threats_by_type('URL')
        st.metric("🌐 URLs", len(url_threats))
    
    with col3:
        phone_threats = db.get_threats_by_type('PHONE')
        st.metric("📞 Phones", len(phone_threats))
    

    
    st.divider()
    st.subheader("🔧 Operations")
    
    confirm_delete = st.checkbox("✓ I confirm I want to delete all data")
    if st.button("🗑️ Clear All Data"):
        if confirm_delete:
            if db.delete_all():
                st.success("✓ Database cleared!")
                st.rerun()
            else:
                st.error("✗ Failed to clear database!")
        else:
            st.warning("⚠️ Please check the confirmation box first.")
    
    st.divider()
    st.info("📁 Database file: `data/threat_db.sqlite`")


if __name__ == "__main__":
    main()
