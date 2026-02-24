# 🛡️ Cyber Threat Detection System

An advanced, multi-layered threat analysis platform built with Python, Streamlit, and SQLite. This system provides a comprehensive suite of tools for detecting and analyzing various cyber threats, from malicious files and phishing URLs to suspicious logs and weak passwords.

## 🚀 Key Features

### 📄 File Analysis
- **Standard Scan:** Detects potential malware and suspicious file types.
- **Integrity Check:** Verifies file integrity using cryptographic hashes (MD5, SHA1, SHA256) to detect tampering.
- **Details:** Extracts file size, extension, and hash for database tracking.

### 🌐 URL Analysis
- **Heuristic Engine:** Analyzes URL structure for phishing and homograph attacks.
- **CVSS Scoring:** Provides impact severity scoring based on CVSS-inspired mapping.
- **Batch Processing:** Analyze multiple URLs simultaneously.

### 📞 Phone Number Analysis
- **Validation:** Verifies phone number formats and identifies country of origin.
- **Spam Detection:** Heuristic scoring for potential spam or fraud.
- **Batch Processing:** Support for scanning lists of phone numbers.

### 🧾 Log Tracker
- **Static Analysis:** Scans system and application logs for suspicious patterns (e.g., brute-force attempts).
- **Security Scoping:** Identifies unauthorized access patterns without executing any code.

### 🔑 Password Strength Checker
- **Entropy Calculation:** Measures the cryptographic strength of passwords.
- **Feedback System:** Provides actionable advice to improve password security.

### 📈 Statistics & Monitoring
- **Real-time Dashboard:** Visual overview of scan history and detected threats.
- **Global Stats:** Aggregated metrics for files, URLs, and phone numbers.

## 🛠️ Technology Stack

- **Frontend:** [Streamlit](https://streamlit.io/) (Interactive Web Interface)
- **Backend:** Python 3.x
- **Database:** SQLite (Relational storage via `sqlite3`)
- **Data Analysis:** Pandas
- **Standard Libraries:** `hashlib`, `pathlib`, `json`, `os`, `re`

## 📂 Project Structure

```text
CyberThreatProject/
├── data/                   # Database storage (SQLite)
├── utils/                  # Core analysis logic
│   ├── file_analyzer.py      # File & Malware analysis
│   ├── url_analyzer.py       # Phishing & URL heuristics
│   ├── phone_analyzer.py     # Phone spam & validation
│   ├── log_analyzer.py       # Log pattern detection
│   ├── password_analyzer.py  # Password entropy logic
│   └── integrity_analyzer.py # File integrity hashing
├── main.py                 # Streamlit application entry point
├── database.py             # Database management (SQLite wrapper)
├── database_setup.py       # Database initialization script
├── DATABASE_LOGIC.md       # Detailed technical documentation
└── test_project.py         # Automated test suite
```

## ⚙️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/cyber-threat-detector.git
   cd cyber-threat-detector
   ```

2. **Install dependencies:**
   ```bash
   pip install streamlit pandas
   ```

3. **Initialize the database:**
   ```bash
   python database_setup.py
   ```

4. **Run the application:**
   ```bash
   streamlit run main.py
   ```

## 💾 Database Logic

The system uses a relational schema with SQLite to persist results across three main tables:
- `file_threats`: Tracks filenames, hashes, and threat levels.
- `url_threats`: Stores analyzed URLs, domains, and CVSS scores.
- `phone_threats`: Logs phone numbers, countries, and spam status.

Refer to [DATABASE_LOGIC.md](CyberThreatProject/DATABASE_LOGIC.md) for full technical details on threading and connection handling.

---
*Developed for advanced threat intelligence and security research.*
