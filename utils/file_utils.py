# utils/file_utils.py

import hashlib
import os
from config import HASH_ALGORITHM, MAX_FILE_SIZE


# =============================================================================
# CORE UTILITIES
# =============================================================================

def get_file_hash(file_path):
    """
    Calculate SHA256 hash of a file. 
    
    Args:
        file_path:  Path to the file
    
    Returns:
        str:  Hexadecimal hash string, or None if error
    """
    try: 
        hasher = hashlib.new(HASH_ALGORITHM)
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files efficiently
            while True:
                chunk = f. read(8192)
                if not chunk: 
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except PermissionError:
        print(f"[ERROR] Permission denied: {file_path}")
        return None
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return None
    except Exception as e:
        print(f"[ERROR] Unable to hash file: {file_path} -> {e}")
        return None


def is_file_safe_size(file_path):
    """
    Check if file size is within scannable limits.
    
    Args:
        file_path: Path to the file
    
    Returns:
        bool: True if file size <= MAX_FILE_SIZE (MB)
    """
    try: 
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        return size_mb <= MAX_FILE_SIZE
    except FileNotFoundError:
        return False
    except PermissionError:
        return False
    except Exception as e: 
        print(f"[ERROR] Unable to check file size: {file_path} -> {e}")
        return False


# =============================================================================
# FILE TYPE DETECTION (Security-Enhanced)
# =============================================================================

def get_file_extension(file_path):
    """
    Safely extract file extension. 
    
    Args:
        file_path: Path to the file
    
    Returns:
        str:  Lowercase file extension (e.g., ". exe")
    """
    try: 
        return os.path.splitext(file_path)[1].lower()
    except Exception: 
        return ""


def is_executable(file_path):
    """
    ⚠️ CRITICAL:  Identify executable files for PRIORITY scanning.
    
    This function flags HIGH-RISK file types that are common malware vectors.
    These files should be scanned with HIGHEST priority, NEVER skipped! 
    
    Args:
        file_path: Path to the file
    
    Returns:
        bool: True if file is an executable type
    """
    try: 
        ext = get_file_extension(file_path)
        
        # High-risk executable extensions
        executable_extensions = {
            # Windows executables
            ". exe",   # Executable program
            ".dll",   # Dynamic Link Library
            ".sys",   # System driver
            ".drv",   # Device driver
            
            # Scripts (Very dangerous!)
            ".bat",   # Batch script
            ".cmd",   # Command script
            ".vbs",   # Visual Basic Script
            ".vbe",   # Encrypted VBScript
            ".js",    # JavaScript
            ".jse",   # Encrypted JavaScript
            ".ps1",   # PowerShell script
            ".psm1",  # PowerShell module
            ".wsf",   # Windows Script File
            ".wsh",   # Windows Script Host
            
            # Shortcuts & screensavers (Common malware vectors)
            ".scr",   # Screensaver (often malware)
            ".pif",   # Program Information File
            ".lnk",   # Windows shortcut
            
            # Installers
            ".msi",   # Windows Installer package
            ".msp",   # Windows Installer patch
            
            # Other Windows executables
            ".com",   # Command file
            ".cpl",   # Control Panel item
            ".hta",   # HTML Application
            
            # macOS/Linux
            ".app",   # macOS application bundle
            ".sh",    # Shell script
            ". bash",  # Bash script
            ".run",   # Linux executable
            ". bin",   # Binary executable
            
            # Cross-platform
            ".jar",   # Java Archive
            ".py",    # Python script (can be malicious)
            ".pyc",   # Compiled Python
            ".pl",    # Perl script
            ".rb",    # Ruby script
        }
        
        return ext in executable_extensions
        
    except Exception as e: 
        print(f"[ERROR] Unable to check executable status: {file_path} -> {e}")
        # Default to True (safer to scan than skip)
        return True


def is_document(file_path):
    """
    Check if file is a document type (can contain macro viruses/exploits).
    
    Args:
        file_path: Path to the file
    
    Returns: 
        bool: True if file is a document
    """
    try:
        ext = get_file_extension(file_path)
        
        document_extensions = {
            # Microsoft Office
            ".doc",   # Word document (old format - macros!)
            ".docx",  # Word document (new format)
            ". docm",  # Word macro-enabled document
            ".xls",   # Excel spreadsheet (old format - macros!)
            ".xlsx",  # Excel spreadsheet (new format)
            ".xlsm",  # Excel macro-enabled spreadsheet
            ". ppt",   # PowerPoint presentation (old format)
            ".pptx",  # PowerPoint presentation (new format)
            ".pptm",  # PowerPoint macro-enabled presentation
            
            # PDF
            ".pdf",   # PDF document (can have exploits)
            
            # Rich Text & Others
            ".rtf",   # Rich Text Format
            ".odt",   # OpenDocument Text
            ".ods",   # OpenDocument Spreadsheet
            ".odp",   # OpenDocument Presentation
        }
        
        return ext in document_extensions
        
    except Exception: 
        return False


def is_archive(file_path):
    """
    Check if file is a compressed archive (needs unpacking to scan contents).
    
    Args:
        file_path: Path to the file
    
    Returns: 
        bool: True if file is an archive
    """
    try: 
        ext = get_file_extension(file_path)
        
        archive_extensions = {
            ". zip",   # ZIP archive
            ".rar",   # RAR archive
            ".7z",    # 7-Zip archive
            ".tar",   # TAR archive
            ".gz",    # GZIP compressed
            ".bz2",   # BZIP2 compressed
            ".xz",    # XZ compressed
            ".iso",   # ISO disk image
            ".cab",   # Cabinet archive
            ".arj",   # ARJ archive
        }
        
        return ext in archive_extensions
        
    except Exception:
        return False


def is_media_file(file_path):
    """
    Check if file is a media file (usually low-risk).
    
    Args:
        file_path: Path to the file
    
    Returns:
        bool: True if file is a media file
    """
    try: 
        ext = get_file_extension(file_path)
        
        media_extensions = {
            # Images
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico",
            
            # Audio
            ".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a",
            
            # Video
            ".mp4", ". avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
        }
        
        return ext in media_extensions
        
    except Exception:
        return False


# =============================================================================
# SCAN PRIORITY SYSTEM
# =============================================================================

def get_scan_priority(file_path):
    """
    Determine scan priority for a file based on risk level.
    
    Priority Levels:
        0 = SKIP (non-file or too large)
        1 = LOW (media files, text files)
        2 = MEDIUM (documents with potential macros)
        3 = HIGH (archives that could contain executables)
        4 = CRITICAL (executables and scripts)
    
    Args:
        file_path: Path to the file
    
    Returns: 
        int: Priority level (0-4)
    """
    try:
        # Pre-checks
        if not os.path.isfile(file_path):
            return 0  # Skip non-files
        
        if not is_file_safe_size(file_path):
            return 0  # Skip extremely large files
        
        # Priority classification
        if is_executable(file_path):
            return 4  # CRITICAL - Executables MUST be scanned! 
        
        if is_archive(file_path):
            return 3  # HIGH - Could contain hidden executables
        
        if is_document(file_path):
            return 2  # MEDIUM - Macro viruses possible
        
        if is_media_file(file_path):
            return 1  # LOW - Usually safe, but still scan
        
        # Default: scan all other files
        return 1  # LOW priority, but still scan
        
    except Exception as e:
        print(f"[ERROR] Unable to determine scan priority:  {file_path} -> {e}")
        return 1  # Default to scanning


def should_scan_file(file_path):
    """
    Determine if a file should be scanned. 
    
    Args:
        file_path: Path to the file
    
    Returns:
        tuple: (should_scan:  bool, reason: str, priority: int)
    """
    try:
        # Check if file exists
        if not os. path.isfile(file_path):
            return (False, "Not a regular file", 0)
        
        # Check file size
        if not is_file_safe_size(file_path):
            return (False, f"File exceeds {MAX_FILE_SIZE}MB limit", 0)
        
        # Get priority level
        priority = get_scan_priority(file_path)
        
        # Determine reason
        if priority == 4: 
            reason = "Executable file - CRITICAL priority"
        elif priority == 3:
            reason = "Archive file - HIGH priority"
        elif priority == 2:
            reason = "Document file - MEDIUM priority"
        elif priority == 1:
            reason = "Regular file - LOW priority"
        else:
            reason = "Skipped"
        
        should_scan = (priority > 0)
        return (should_scan, reason, priority)
        
    except PermissionError:
        return (False, "Permission denied", 0)
    except Exception as e: 
        return (False, f"Error:  {e}", 0)


# =============================================================================
# FILE METADATA UTILITIES
# =============================================================================

def get_file_size_mb(file_path):
    """
    Get file size in megabytes.
    
    Args:
        file_path: Path to the file
    
    Returns:
        float: File size in MB, or 0.0 if error
    """
    try:
        size_bytes = os.path.getsize(file_path)
        return size_bytes / (1024 * 1024)
    except Exception:
        return 0.0


def format_file_size(size_bytes):
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
    
    Returns: 
        str:  Formatted size string (e.g., "1.5 MB")
    """
    try: 
        size_bytes = float(size_bytes)
        
        if size_bytes < 1024:
            return f"{size_bytes:. 0f} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
    except Exception:
        return "Unknown"