# database/db.py

import sqlite3
import os
from datetime import datetime

# Database file path (stored in project root)
DB_FILE = os.path. join(os.path.dirname(os. path.dirname(__file__)), "antivirus.db")


def get_connection():
    """
    Create and return a database connection.
    
    Returns:
        sqlite3.Connection: Database connection object
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3. Row  # Enable column access by name
        return conn
    except sqlite3.Error as e:
        print(f"[ERROR] Database connection failed: {e}")
        return None


def init_db():
    """
    Initialize the database by creating all required tables.
    Call this function when the application starts. 
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        conn = get_connection()
        if not conn:
            return False
        
        cursor = conn.cursor()
        
        # =================================================================
        # TABLE 1: SCAN_LOGS
        # Stores history of all scans performed
        # =================================================================
        cursor. execute('''
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_files INTEGER DEFAULT 0,
                files_scanned INTEGER DEFAULT 0,
                files_clean INTEGER DEFAULT 0,
                files_infected INTEGER DEFAULT 0,
                files_skipped INTEGER DEFAULT 0,
                files_errors INTEGER DEFAULT 0,
                scan_duration_seconds REAL DEFAULT 0,
                locations_scanned TEXT,
                status TEXT DEFAULT 'completed'
            )
        ''')
        
        # =================================================================
        # TABLE 2: THREAT_RECORDS
        # Stores details of all threats/infections found
        # =================================================================
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                file_path TEXT NOT NULL,
                file_name TEXT,
                virus_name TEXT,
                threat_type TEXT DEFAULT 'malware',
                detection_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action_taken TEXT DEFAULT 'detected',
                quarantined INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scan_logs(id)
            )
        ''')
        
        # =================================================================
        # TABLE 3: QUARANTINE_RECORDS
        # Stores information about quarantined files
        # =================================================================
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                quarantine_name TEXT UNIQUE NOT NULL,
                original_name TEXT NOT NULL,
                original_path TEXT NOT NULL,
                virus_name TEXT,
                file_size INTEGER DEFAULT 0,
                quarantine_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                restored INTEGER DEFAULT 0,
                restored_date TIMESTAMP,
                deleted INTEGER DEFAULT 0,
                deleted_date TIMESTAMP
            )
        ''')
        
        # =================================================================
        # TABLE 4: USER_SETTINGS
        # Stores user preferences and configuration
        # =================================================================
        cursor. execute('''
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE NOT NULL,
                setting_value TEXT,
                setting_type TEXT DEFAULT 'string',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # =================================================================
        # TABLE 5: REALTIME_EVENTS
        # Stores real-time monitoring events (USB, Downloads)
        # =================================================================
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS realtime_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                event_source TEXT,
                file_path TEXT,
                event_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        ''')
        
        # =================================================================
        # INSERT DEFAULT SETTINGS
        # =================================================================
        default_settings = [
            ('realtime_protection', 'true', 'boolean'),
            ('auto_quarantine', 'true', 'boolean'),
            ('scan_archives', 'true', 'boolean'),
            ('max_file_size_mb', '50', 'integer'),
            ('show_notifications', 'true', 'boolean'),
            ('monitor_downloads', 'true', 'boolean'),
            ('monitor_usb', 'true', 'boolean'),
            ('theme', 'light', 'string'),
            ('last_scan_date', '', 'string'),
            ('last_update_date', '', 'string'),
        ]
        
        for key, value, type_ in default_settings:
            cursor.execute('''
                INSERT OR IGNORE INTO user_settings (setting_key, setting_value, setting_type)
                VALUES (?, ?, ?)
            ''', (key, value, type_))
        
        conn.commit()
        conn.close()
        
        print(f"[INFO] Database initialized: {DB_FILE}")
        return True
        
    except sqlite3.Error as e:
        print(f"[ERROR] Database initialization failed: {e}")
        return False


def reset_db():
    """
    Reset the database by dropping all tables and reinitializing. 
    WARNING: This will delete all data!
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        conn = get_connection()
        if not conn:
            return False
        
        cursor = conn.cursor()
        
        # Drop all tables
        tables = ['scan_logs', 'threat_records', 'quarantine_records', 
                  'user_settings', 'realtime_events']
        
        for table in tables:
            cursor.execute(f'DROP TABLE IF EXISTS {table}')
        
        conn.commit()
        conn.close()
        
        # Reinitialize
        return init_db()
        
    except sqlite3.Error as e:
        print(f"[ERROR] Database reset failed: {e}")
        return False


def get_db_info():
    """
    Get database information and statistics.
    
    Returns:
        dict: Database statistics
    """
    try:
        conn = get_connection()
        if not conn:
            return None
        
        cursor = conn.cursor()
        
        info = {
            "db_path": DB_FILE,
            "db_exists": os.path. exists(DB_FILE),
            "db_size_mb": round(os.path. getsize(DB_FILE) / (1024 * 1024), 2) if os.path. exists(DB_FILE) else 0,
            "tables": {}
        }
        
        # Get row counts for each table
        tables = ['scan_logs', 'threat_records', 'quarantine_records', 
                  'user_settings', 'realtime_events']
        
        for table in tables:
            try:
                cursor. execute(f'SELECT COUNT(*) FROM {table}')
                count = cursor.fetchone()[0]
                info["tables"][table] = count
            except:
                info["tables"][table] = 0
        
        conn.close()
        return info
        
    except Exception as e:
        print(f"[ERROR] Unable to get database info: {e}")
        return None