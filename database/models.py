# database/models.py

import sqlite3
from datetime import datetime
from database.db import get_connection


# =============================================================================
# SCAN LOGS
# =============================================================================

def save_scan_log(scan_type, total_files=0, files_scanned=0, files_clean=0,
                  files_infected=0, files_skipped=0, files_errors=0,
                  scan_duration=0, locations=None, status="completed"):
    """
    Save a scan log entry to the database.
    
    Args:
        scan_type: Type of scan (quick, full, file, folder)
        total_files: Total number of files found
        files_scanned: Number of files actually scanned
        files_clean: Number of clean files
        files_infected: Number of infected files
        files_skipped: Number of skipped files
        files_errors: Number of files with errors
        scan_duration: Scan duration in seconds
        locations: List of locations scanned
        status: Scan status (completed, cancelled, error)
    
    Returns:
        int: ID of the inserted record, or None if failed
    """
    try:
        conn = get_connection()
        if not conn:
            return None
        
        cursor = conn. cursor()
        
        # Convert locations list to string
        locations_str = ", ".join(locations) if locations else ""
        
        cursor.execute('''
            INSERT INTO scan_logs 
            (scan_type, total_files, files_scanned, files_clean, files_infected,
             files_skipped, files_errors, scan_duration_seconds, locations_scanned, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (scan_type, total_files, files_scanned, files_clean, files_infected,
              files_skipped, files_errors, scan_duration, locations_str, status))
        
        scan_id = cursor. lastrowid
        conn.commit()
        conn.close()
        
        return scan_id
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to save scan log: {e}")
        return None


def get_scan_history(limit=50):
    """
    Get scan history from the database.
    
    Args:
        limit: Maximum number of records to return
    
    Returns:
        list: List of scan log dictionaries
    """
    try:
        conn = get_connection()
        if not conn:
            return []
        
        cursor = conn.cursor()
        cursor. execute('''
            SELECT * FROM scan_logs 
            ORDER BY scan_date DESC 
            LIMIT ? 
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn. close()
        
        return [dict(row) for row in rows]
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to get scan history: {e}")
        return []


def get_scan_by_id(scan_id):
    """
    Get a specific scan log by ID.
    
    Args:
        scan_id: ID of the scan log
    
    Returns:
        dict: Scan log dictionary or None
    """
    try:
        conn = get_connection()
        if not conn:
            return None
        
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scan_logs WHERE id = ? ', (scan_id,))
        
        row = cursor. fetchone()
        conn.close()
        
        return dict(row) if row else None
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to get scan by ID: {e}")
        return None


def get_scan_statistics():
    """
    Get overall scan statistics.
    
    Returns:
        dict: Scan statistics
    """
    try:
        conn = get_connection()
        if not conn:
            return None
        
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total_scans,
                SUM(files_scanned) as total_files_scanned,
                SUM(files_infected) as total_threats_found,
                AVG(scan_duration_seconds) as avg_scan_duration
            FROM scan_logs
        ''')
        
        row = cursor.fetchone()
        conn. close()
        
        return {
            "total_scans": row[0] or 0,
            "total_files_scanned": row[1] or 0,
            "total_threats_found": row[2] or 0,
            "avg_scan_duration": round(row[3] or 0, 2)
        }
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to get scan statistics: {e}")
        return None


# =============================================================================
# THREAT RECORDS
# =============================================================================

def save_threat_record(file_path, virus_name, scan_id=None, threat_type="malware",
                       action_taken="detected", quarantined=False):
    """
    Save a threat/infection record to the database.
    
    Args:
        file_path: Path to the infected file
        virus_name: Name of the detected virus
        scan_id: ID of the scan that found this threat
        threat_type: Type of threat (malware, pup, adware, etc.)
        action_taken: Action taken (detected, quarantined, deleted)
        quarantined: Whether the file was quarantined
    
    Returns:
        int: ID of the inserted record, or None if failed
    """
    try:
        conn = get_connection()
        if not conn:
            return None
        
        cursor = conn.cursor()
        
        import os
        file_name = os. path.basename(file_path)
        
        cursor.execute('''
            INSERT INTO threat_records 
            (scan_id, file_path, file_name, virus_name, threat_type, action_taken, quarantined)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, file_path, file_name, virus_name, threat_type, 
              action_taken, 1 if quarantined else 0))
        
        threat_id = cursor. lastrowid
        conn.commit()
        conn.close()
        
        return threat_id
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to save threat record: {e}")
        return None


def get_threat_history(limit=100):
    """
    Get threat detection history. 
    
    Args:
        limit: Maximum number of records to return
    
    Returns:
        list: List of threat record dictionaries
    """
    try:
        conn = get_connection()
        if not conn:
            return []
        
        cursor = conn. cursor()
        cursor.execute('''
            SELECT * FROM threat_records 
            ORDER BY detection_date DESC 
            LIMIT ? 
        ''', (limit,))
        
        rows = cursor. fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to get threat history: {e}")
        return []


def get_threats_by_scan_id(scan_id):
    """
    Get all threats found in a specific scan. 
    
    Args:
        scan_id: ID of the scan
    
    Returns:
        list: List of threat record dictionaries
    """
    try:
        conn = get_connection()
        if not conn:
            return []
        
        cursor = conn. cursor()
        cursor.execute('''
            SELECT * FROM threat_records 
            WHERE scan_id = ?
            ORDER BY detection_date DESC
        ''', (scan_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to get threats by scan ID: {e}")
        return []


# =============================================================================
# QUARANTINE RECORDS
# =============================================================================

def save_quarantine_record(quarantine_name, original_name, original_path,
                           virus_name, file_size=0):
    """
    Save a quarantine record to the database. 
    
    Args:
        quarantine_name: Name of the file in quarantine folder
        original_name: Original file name
        original_path: Original file path
        virus_name: Name of the detected virus
        file_size: Size of the file in bytes
    
    Returns:
        int: ID of the inserted record, or None if failed
    """
    try:
        conn = get_connection()
        if not conn:
            return None
        
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO quarantine_records 
            (quarantine_name, original_name, original_path, virus_name, file_size)
            VALUES (?, ?, ?, ?, ?)
        ''', (quarantine_name, original_name, original_path, virus_name, file_size))
        
        record_id = cursor. lastrowid
        conn.commit()
        conn.close()
        
        return record_id
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to save quarantine record: {e}")
        return None


def get_quarantine_records():
    """
    Get all quarantine records from the database.
    
    Returns:
        list: List of quarantine record dictionaries
    """
    try:
        conn = get_connection()
        if not conn:
            return []
        
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM quarantine_records 
            WHERE deleted = 0
            ORDER BY quarantine_date DESC
        ''')
        
        rows = cursor.fetchall()
        conn. close()
        
        return [dict(row) for row in rows]
        
    except sqlite3. Error as e:
        print(f"[ERROR] Failed to get quarantine records: {e}")
        return []


def mark_quarantine_restored(quarantine_name):
    """
    Mark a quarantine record as restored.
    
    Args:
        quarantine_name: Name of the file in quarantine folder
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        conn = get_connection()
        if not conn:
            return False
        
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE quarantine_records 
            SET restored = 1, restored_date = ? 
            WHERE quarantine_name = ? 
        ''', (datetime.now(). strftime("%Y-%m-%d %H:%M:%S"), quarantine_name))
        
        conn. commit()
        conn.close()
        
        return True
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to mark quarantine as restored: {e}")
        return False


def mark_quarantine_deleted(quarantine_name):
    """
    Mark a quarantine record as deleted. 
    
    Args:
        quarantine_name: Name of the file in quarantine folder
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        conn = get_connection()
        if not conn:
            return False
        
        cursor = conn.cursor()
        cursor. execute('''
            UPDATE quarantine_records 
            SET deleted = 1, deleted_date = ? 
            WHERE quarantine_name = ?
        ''', (datetime. now().strftime("%Y-%m-%d %H:%M:%S"), quarantine_name))
        
        conn.commit()
        conn.close()
        
        return True
        
    except sqlite3. Error as e:
        print(f"[ERROR] Failed to mark quarantine as deleted: {e}")
        return False


# =============================================================================
# USER SETTINGS
# =============================================================================

def save_setting(key, value, setting_type="string"):
    """
    Save or update a user setting. 
    
    Args:
        key: Setting key/name
        value: Setting value
        setting_type: Type of setting (string, integer, boolean)
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        conn = get_connection()
        if not conn:
            return False
        
        cursor = conn.cursor()
        
        # Convert value to string for storage
        str_value = str(value). lower() if setting_type == "boolean" else str(value)
        
        cursor.execute('''
            INSERT OR REPLACE INTO user_settings 
            (setting_key, setting_value, setting_type, updated_at)
            VALUES (?, ?, ?, ?)
        ''', (key, str_value, setting_type, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        
        conn.commit()
        conn.close()
        
        return True
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to save setting: {e}")
        return False


def get_setting(key, default=None):
    """
    Get a user setting by key.
    
    Args:
        key: Setting key/name
        default: Default value if setting not found
    
    Returns:
        Setting value (converted to appropriate type) or default
    """
    try:
        conn = get_connection()
        if not conn:
            return default
        
        cursor = conn. cursor()
        cursor.execute('''
            SELECT setting_value, setting_type FROM user_settings 
            WHERE setting_key = ?
        ''', (key,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return default
        
        value, setting_type = row[0], row[1]
        
        # Convert to appropriate type
        if setting_type == "boolean":
            return value. lower() in ("true", "1", "yes")
        elif setting_type == "integer":
            return int(value)
        elif setting_type == "float":
            return float(value)
        else:
            return value
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to get setting: {e}")
        return default


def get_all_settings():
    """
    Get all user settings. 
    
    Returns:
        dict: Dictionary of all settings
    """
    try:
        conn = get_connection()
        if not conn:
            return {}
        
        cursor = conn.cursor()
        cursor. execute('SELECT setting_key, setting_value, setting_type FROM user_settings')
        
        rows = cursor.fetchall()
        conn. close()
        
        settings = {}
        for row in rows:
            key, value, setting_type = row[0], row[1], row[2]
            
            # Convert to appropriate type
            if setting_type == "boolean":
                settings[key] = value. lower() in ("true", "1", "yes")
            elif setting_type == "integer":
                settings[key] = int(value)
            elif setting_type == "float":
                settings[key] = float(value)
            else:
                settings[key] = value
        
        return settings
        
    except sqlite3. Error as e:
        print(f"[ERROR] Failed to get all settings: {e}")
        return {}


# =============================================================================
# REAL-TIME EVENTS
# =============================================================================

def save_realtime_event(event_type, event_source=None, file_path=None, details=None):
    """
    Save a real-time monitoring event. 
    
    Args:
        event_type: Type of event (usb_detected, file_created, file_modified)
        event_source: Source of event (usb, downloads, etc.)
        file_path: Path to the related file
        details: Additional event details
    
    Returns:
        int: ID of the inserted record, or None if failed
    """
    try:
        conn = get_connection()
        if not conn:
            return None
        
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO realtime_events 
            (event_type, event_source, file_path, details)
            VALUES (?, ?, ?, ?)
        ''', (event_type, event_source, file_path, details))
        
        event_id = cursor. lastrowid
        conn.commit()
        conn.close()
        
        return event_id
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to save realtime event: {e}")
        return None


def get_realtime_events(limit=100, event_type=None):
    """
    Get real-time monitoring events.
    
    Args:
        limit: Maximum number of records to return
        event_type: Filter by event type (optional)
    
    Returns:
        list: List of event dictionaries
    """
    try:
        conn = get_connection()
        if not conn:
            return []
        
        cursor = conn.cursor()
        
        if event_type:
            cursor.execute('''
                SELECT * FROM realtime_events 
                WHERE event_type = ? 
                ORDER BY event_date DESC 
                LIMIT ? 
            ''', (event_type, limit))
        else:
            cursor.execute('''
                SELECT * FROM realtime_events 
                ORDER BY event_date DESC 
                LIMIT ? 
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
        
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to get realtime events: {e}")
        return []


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def clear_old_logs(days=30):
    """
    Clear scan logs older than specified days.
    
    Args:
        days: Number of days to keep
    
    Returns:
        int: Number of records deleted
    """
    try:
        conn = get_connection()
        if not conn:
            return 0
        
        cursor = conn. cursor()
        
        cursor.execute('''
            DELETE FROM scan_logs 
            WHERE scan_date < datetime('now', ?  || ' days')
        ''', (f'-{days}',))
        
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return deleted
        
    except sqlite3. Error as e:
        print(f"[ERROR] Failed to clear old logs: {e}")
        return 0