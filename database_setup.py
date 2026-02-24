
import sqlite3
import os
from pathlib import Path

# Define database path
DB_DIR = Path("data")
DB_NAME = "threat_db.sqlite"
DB_PATH = DB_DIR / DB_NAME

def create_connection():
    """Create a database connection to the SQLite database."""
    if not DB_DIR.exists():
        DB_DIR.mkdir()
    
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        print(f"Connected to {DB_PATH}")
        return conn
    except sqlite3.Error as e:
        print(e)
    return None

def create_table(conn, create_table_sql):
    """Create a table from the create_table_sql statement."""
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
        print("Table created successfully")
    except sqlite3.Error as e:
        print(e)

def setup_database():
    """Create the database and tables."""
    
    # Remove existing database if it exists (fresh start)
    if DB_PATH.exists():
        try:
            os.remove(DB_PATH)
            print(f"Removed existing database: {DB_PATH}")
        except Exception as e:
            print(f"Error removing existing database: {e}")

    conn = create_connection()

    if conn is not None:
        # Create tables
        
        # 1. Files Table
        create_files_table = """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            filename TEXT,
            file_path TEXT,
            file_size INTEGER,
            file_extension TEXT,
            file_hash TEXT,
            threat_status TEXT,
            threat_level TEXT,
            threat_type TEXT,
            details TEXT,
            content_score INTEGER,
            confidence REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        # 3. Integrity Checks Table
        create_integrity_table = """
        CREATE TABLE IF NOT EXISTS integrity_checks (
            id INTEGER PRIMARY KEY,
            file_path TEXT,
            integrity_status TEXT,
            computed_hash TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        # 4. Logs Table
        create_logs_table = """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY,
            log_source TEXT,
            threat_status TEXT,
            threat_level TEXT,
            threat_type TEXT,
            score INTEGER,
            details TEXT,
            pattern_summary TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        conn.close()
        print("Database setup complete.")
    else:
        print("Error! cannot create the database connection.")

if __name__ == '__main__':
    setup_database()
