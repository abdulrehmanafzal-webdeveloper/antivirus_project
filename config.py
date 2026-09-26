import os
import string
import platform


def get_all_drives():
    """Get all available drives on Windows."""
    drives = []
    if platform.system() == "Windows":
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)
    elif platform.system() == "Darwin":  # macOS
        drives = ["/Users", "/Applications"]
    else:   # Linux
        drives = [os.path.expanduser("~"), "/tmp"]
    return drives


def get_user_critical_paths():
    """
    Get critical user paths for real-time monitoring.
    
    NOTE:  Temp folder is excluded by default because: 
    - It generates excessive noise (hundreds of . tmp files per minute)
    - Most . tmp files are locked by system processes (permission denied)
    - Malware in Temp is caught when it's executed or moved elsewhere
    
    To include Temp folder, use get_user_critical_paths_with_temp()
    """
    user_home = os.path. expanduser("~")
    
    paths = [
        os.path.join(user_home, "Downloads"),
        os.path.join(user_home, "Desktop"),
        os.path.join(user_home, "Documents"),
    ]
    
    # Filter only existing paths
    return [p for p in paths if os.path.exists(p)]


def get_user_critical_paths_with_temp():
    """
    Get critical user paths INCLUDING Temp folder. 
    Use this only if you need to monitor temporary files.
    Warning: This will generate more scan events and potential permission errors.
    """
    user_home = os.path.expanduser("~")
    
    paths = [
        os. path.join(user_home, "Downloads"),
        os.path.join(user_home, "Desktop"),
        os.path.join(user_home, "Documents"),
    ]
    
    if platform.system() == "Windows":
        paths.append(os.path. join(user_home, "AppData", "Local", "Temp"))
    
    # Filter only existing paths
    return [p for p in paths if os.path.exists(p)]


# =============================================================================
# CONFIGURATION SETTINGS
# =============================================================================

# Quarantine folder
QUARANTINE_DIR = os.path. join(os.getcwd(), "quarantine")

# Signature database file (optional JSON)
SIGNATURE_FILE = "virus_signatures.json"

# Hash algorithm
HASH_ALGORITHM = "sha256"

# Maximum file size to scan (in MB)
MAX_FILE_SIZE = 50

# =============================================================================
# REAL-TIME MONITORING PATHS
# =============================================================================

# ✅ FIX: Monitor only critical user folders (event-driven, low CPU)
# This follows modern antivirus best practices: 
# - Only watches high-risk directories where new files typically appear
# - Does NOT enumerate entire drives at startup
# - Scans files only when created, modified, or moved
# - Excludes Temp folder to reduce noise and permission errors

# Option 1: Monitor only Downloads folder (Minimal CPU)
# WATCH_PATHS = [os.path.join(os.path.expanduser("~"), "Downloads")]

# Option 2: Monitor critical user folders WITHOUT Temp (Recommended) ✅ ACTIVE
WATCH_PATHS = get_user_critical_paths()

# Option 3: Monitor critical folders WITH Temp (More comprehensive, but noisy)
# WATCH_PATHS = get_user_critical_paths_with_temp()

# Option 4: Monitor ALL drives (High CPU) - Use only for manual full scans
# WATCH_PATHS = get_all_drives()

# Legacy support - keep DOWNLOADS_DIR for backward compatibility
DOWNLOADS_DIR = os.path.join(os. path.expanduser("~"), "Downloads")

# =============================================================================
# REAL-TIME MONITORING SETTINGS
# =============================================================================

# Seconds between USB checks
REALTIME_CHECK_INTERVAL = 2

# Seconds to wait before scanning new files (let downloads complete)
SCAN_DELAY = 1

# Enable/disable monitoring modes
MONITOR_ALL_DRIVES = False  # ✅ FIX: Set to False - full system via manual scan only
MONITOR_USB_DRIVES = True   # Auto-scan and watch USB drives when inserted

# =============================================================================
# REAL-TIME SCAN FILTERING (NEW)
# =============================================================================

# Minimum seconds between scanning the same file (prevents duplicates)
DUPLICATE_SCAN_THRESHOLD = 5

# File patterns to always skip in real-time monitoring
SKIP_PATTERNS = [
    '. tmp', '.temp', '.cache', '. part', '.crdownload', '.download',
    '.lock', '.log', '~$',  # Office temp files
]

# Directories to skip within watched paths
SKIP_DIRECTORIES = [
    '$recycle.bin', 'system volume information', 'windows',
    'program files', 'programdata', 'quarantine',
]