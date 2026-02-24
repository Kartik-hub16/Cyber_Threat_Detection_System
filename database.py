# database.py - stores threat detection results

import sqlite3
import os

class ThreatDatabase:
    # simple database for storing threat detection stuff
    
    def __init__(self, db_path="data/threat_db.sqlite"):
        self.db_path = db_path
        self.connection = None
        self.cursor = None
        self._connect()
    
    def _connect(self):
        # connect to database
        try:
            # create data folder if it doesn't exist
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                print(f"Created directory: {db_dir}")
            
            # Allow multi-threading with SQLite
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.isolation_level = None  # autocommit mode
            self.cursor = self.connection.cursor()
            self._create_table()
            print(f"Database connected: {self.db_path}")
        except Exception as e:
            print(f"Error connecting: {e}")
            raise
    
    def _create_table(self):
        # create separate tables for each threat type
        
        # File threats table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_threats (
                id INTEGER PRIMARY KEY,
                filename TEXT,
                file_size INTEGER,
                file_extension TEXT,
                file_hash TEXT,
                threat_status TEXT,
                threat_level TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # URL threats table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS url_threats (
                id INTEGER PRIMARY KEY,
                url TEXT,
                domain TEXT,
                scheme TEXT,
                threat_status TEXT,
                threat_level TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Phone threats table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS phone_threats (
                id INTEGER PRIMARY KEY,
                phone_number TEXT,
                country TEXT,
                country_code TEXT,
                threat_status TEXT,
                threat_level TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        

        self.connection.commit()
        print("[OK] All tables created/verified")
    
    def save_threat(self, threat_type, input_data, threat_status, threat_level, details, extra_data=None):
        # save threat to appropriate table based on type
        try:
            # Defensive conversion: Ensure lists are converted to strings
            if isinstance(details, list):
                details = " | ".join(details)
            
            # Ensure threat_type is a string (though it's an argument, it might come from a dict)
            # The argument 'threat_type' is used for table selection (FILE, URL etc), 
            # but the actual THREAT TYPE (e.g. Malware) is inside the extra_data or implicit?
            # actually checking the SQL, 'threat_type' argument selects the table, 
            # but there is no 'threat_type' COLUMN in the tables?
            # Wait, let's check the schema in database.py _create_table again.
            pass
            
            if threat_type == "FILE":
                self.cursor.execute('''
                    INSERT INTO file_threats 
                    (filename, file_size, file_extension, file_hash, threat_status, threat_level, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    extra_data.get('filename', input_data) if extra_data else input_data,
                    extra_data.get('file_size', 0) if extra_data else 0,
                    extra_data.get('file_extension', '') if extra_data else '',
                    extra_data.get('file_hash', '') if extra_data else '',
                    threat_status,
                    threat_level,
                    details
                ))
                table_name = "file_threats"
            
            elif threat_type == "URL":
                self.cursor.execute('''
                    INSERT INTO url_threats 
                    (url, domain, scheme, threat_status, threat_level, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    input_data,
                    extra_data.get('domain', '') if extra_data else '',
                    extra_data.get('scheme', '') if extra_data else '',
                    threat_status,
                    threat_level,
                    details
                ))
                table_name = "url_threats"
            
            
            elif threat_type == "PHONE":
                self.cursor.execute('''
                    INSERT INTO phone_threats 
                    (phone_number, country, country_code, threat_status, threat_level, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    input_data,
                    extra_data.get('country', '') if extra_data else '',
                    extra_data.get('country_code', '') if extra_data else '',
                    threat_status,
                    threat_level,
                    details
                ))
                table_name = "phone_threats"
            

            else:
                print(f"Unknown threat type: {threat_type}")
                return False
            
            self.connection.commit()
            saved_id = self.cursor.lastrowid
            print(f"[OK] {threat_type} threat saved to {table_name} (ID: {saved_id})")
            return True
            
        except Exception as e:
            print(f"Error saving threat: {e}")
            self.connection.rollback()
            return False
    
    def get_all_threats(self):
        # get all threats from all tables
        try:
            all_results = []
            
            # Get file threats
            self.cursor.execute('SELECT id, filename as input_data, threat_status, threat_level, details, timestamp FROM file_threats ORDER BY timestamp DESC')
            for row in self.cursor.fetchall():
                all_results.append({
                    'id': row[0],
                    'threat_type': 'FILE',
                    'input_data': row[1],
                    'threat_status': row[2],
                    'threat_level': row[3],
                    'details': row[4],
                    'timestamp': row[5]
                })
            
            # Get URL threats
            self.cursor.execute('SELECT id, url as input_data, threat_status, threat_level, details, timestamp FROM url_threats ORDER BY timestamp DESC')
            for row in self.cursor.fetchall():
                all_results.append({
                    'id': row[0],
                    'threat_type': 'URL',
                    'input_data': row[1],
                    'threat_status': row[2],
                    'threat_level': row[3],
                    'details': row[4],
                    'timestamp': row[5]
                })
            
            
            # Get phone threats
            self.cursor.execute('SELECT id, phone_number as input_data, threat_status, threat_level, details, timestamp FROM phone_threats ORDER BY timestamp DESC')
            for row in self.cursor.fetchall():
                all_results.append({
                    'id': row[0],
                    'threat_type': 'PHONE',
                    'input_data': row[1],
                    'threat_status': row[2],
                    'threat_level': row[3],
                    'details': row[4],
                    'timestamp': row[5]
                })
            

            # Sort by timestamp
            all_results.sort(key=lambda x: x['timestamp'], reverse=True)
            return all_results
            
        except Exception as e:
            print(f"Error: {e}")
            return []
    
    def get_threats_by_type(self, threat_type):
        # get threats by type from specific table
        try:
            if threat_type == 'FILE':
                self.cursor.execute('SELECT id, filename as input_data, threat_status, threat_level, details, timestamp FROM file_threats ORDER BY timestamp DESC')
                results = []
                for row in self.cursor.fetchall():
                    results.append({
                        'id': row[0],
                        'threat_type': 'FILE',
                        'input_data': row[1],
                        'threat_status': row[2],
                        'threat_level': row[3],
                        'details': row[4],
                        'timestamp': row[5]
                    })
            
            elif threat_type == 'URL':
                self.cursor.execute('SELECT id, url as input_data, threat_status, threat_level, details, timestamp FROM url_threats ORDER BY timestamp DESC')
                results = []
                for row in self.cursor.fetchall():
                    results.append({
                        'id': row[0],
                        'threat_type': 'URL',
                        'input_data': row[1],
                        'threat_status': row[2],
                        'threat_level': row[3],
                        'details': row[4],
                        'timestamp': row[5]
                    })
            
            
            elif threat_type == 'PHONE':
                self.cursor.execute('SELECT id, phone_number as input_data, threat_status, threat_level, details, timestamp FROM phone_threats ORDER BY timestamp DESC')
                results = []
                for row in self.cursor.fetchall():
                    results.append({
                        'id': row[0],
                        'threat_type': 'PHONE',
                        'input_data': row[1],
                        'threat_status': row[2],
                        'threat_level': row[3],
                        'details': row[4],
                        'timestamp': row[5]
                    })
            

            else:
                print(f"Unknown threat type: {threat_type}")
                results = []
            
            return results
        except Exception as e:
            print(f"Error: {e}")
            return []
    
    def get_statistics(self):
        # get stats from all tables
        try:
            # Count total records
            self.cursor.execute('SELECT COUNT(*) FROM file_threats')
            file_count = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM url_threats')
            url_count = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM phone_threats')
            phone_count = self.cursor.fetchone()[0]
            
            stats = {
                'FILEs': file_count,
                'URLs': url_count,
                'PHONEs': phone_count
            }
            
            return stats
        except Exception as e:
            print(f"Error: {e}")
            return {}
    
    def delete_all(self):
        # delete all records from all tables
        try:
            self.cursor.execute('DELETE FROM file_threats')
            self.cursor.execute('DELETE FROM url_threats')
            self.cursor.execute('DELETE FROM file_threats')
            self.cursor.execute('DELETE FROM url_threats')

            self.cursor.execute('DELETE FROM phone_threats')

            self.connection.commit()
            print("[OK] All records deleted from all tables")
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
    
    def close(self):
        # close connection
        if self.connection:
            self.connection.close()
            print("Database closed")
    
    def verify_data(self):
        # check if data exists in database
        try:
            self.cursor.execute('SELECT COUNT(*) FROM file_threats')
            file_count = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM url_threats')
            url_count = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM phone_threats')
            phone_count = self.cursor.fetchone()[0]
            
            total = file_count + url_count + phone_count
            print(f"  Total: {total} records")
            return total
        except Exception as e:
            print(f"Error verifying data: {e}")
            return 0


# test stuff
if __name__ == "__main__":
    db = ThreatDatabase()
    
    # Test saving to each table
    db.save_threat("FILE", "malware.exe", "THREAT", "CRITICAL", "Bad file", 
                   {'filename': 'malware.exe', 'file_size': 5000, 'file_extension': 'exe'})
    
    db.save_threat("URL", "https://phishing.com", "THREAT", "HIGH", "Bad site",
                   {'domain': 'phishing.com', 'scheme': 'https'})
    

    
    print("\n" + "="*50)
    print("STATISTICS:")
    print("="*50)
    stats = db.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n" + "="*50)
    print("DATA VERIFICATION:")
    print("="*50)
    db.verify_data()
    
    db.close()
