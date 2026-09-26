# core/quarantine. py

import os
import shutil
import json
import time
from datetime import datetime
from config import QUARANTINE_DIR


# =============================================================================
# QUARANTINE METADATA FILE
# =============================================================================
# We store metadata about quarantined files in a JSON file
# This helps us restore files to their original locations

METADATA_FILE = os.path.join(QUARANTINE_DIR, ". quarantine_metadata. json")


def _load_metadata():
    """Load quarantine metadata from JSON file."""
    try:
        if os.path.exists(METADATA_FILE):
            with open(METADATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print(f"[ERROR] Unable to load quarantine metadata: {e}")
    return {}


def _save_metadata(metadata):
    """Save quarantine metadata to JSON file."""
    try:
        with open(METADATA_FILE, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[ERROR] Unable to save quarantine metadata: {e}")
        return False


# =============================================================================
# QUARANTINE FOLDER MANAGEMENT
# =============================================================================

def create_quarantine_folder():
    """
    Create the quarantine folder if it doesn't exist. 
    
    Returns:
        bool: True if folder exists or was created successfully, False otherwise
    """
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os. makedirs(QUARANTINE_DIR)
            print(f"[INFO] Quarantine folder created: {QUARANTINE_DIR}")
        
        # Create metadata file if it doesn't exist
        if not os. path.exists(METADATA_FILE):
            _save_metadata({})
            
        return True
    except Exception as e:
        print(f"[ERROR] Unable to create quarantine folder: {e}")
        return False


def get_quarantine_path():
    """
    Get the quarantine folder path.
    
    Returns:
        str: Path to quarantine folder
    """
    return QUARANTINE_DIR


# =============================================================================
# QUARANTINE FILE OPERATIONS
# =============================================================================

def quarantine_file(file_path, virus_name="Unknown Threat"):
    """
    Move an infected file to the quarantine folder. 
    The file is renamed with a . quarantine extension to prevent execution.
    
    Args:
        file_path: Path to the infected file
        virus_name: Name of the detected virus/threat
    
    Returns:
        dict: Result with status and details
    """
    try:
        # Ensure quarantine folder exists
        if not create_quarantine_folder():
            return {
                "status": "error",
                "message": "Unable to create quarantine folder"
            }
        
        # Check if file exists
        if not os. path.exists(file_path):
            return {
                "status": "error",
                "message": "File does not exist"
            }
        
        # Get file info
        file_name = os.path. basename(file_path)
        original_path = os.path.abspath(file_path)
        file_size = os. path.getsize(file_path)
        
        # Generate unique quarantine name (timestamp + original name + . quarantine)
        timestamp = int(time. time() * 1000)  # Milliseconds for uniqueness
        quarantine_name = f"{timestamp}_{file_name}.quarantine"
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)
        
        # Move file to quarantine
        shutil.move(file_path, quarantine_path)
        
        # Save metadata
        metadata = _load_metadata()
        metadata[quarantine_name] = {
            "original_name": file_name,
            "original_path": original_path,
            "quarantine_path": quarantine_path,
            "virus_name": virus_name,
            "file_size": file_size,
            "quarantine_date": datetime.now(). strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": timestamp
        }
        _save_metadata(metadata)
        
        print(f"[INFO] File quarantined: {file_name} -> {quarantine_name}")
        
        return {
            "status": "success",
            "message": "File quarantined successfully",
            "original_path": original_path,
            "quarantine_name": quarantine_name,
            "quarantine_path": quarantine_path,
            "virus_name": virus_name
        }
        
    except PermissionError:
        return {
            "status": "error",
            "message": "Permission denied.  Run as administrator."
        }
    except Exception as e:
        print(f"[ERROR] Unable to quarantine file: {file_path} -> {e}")
        return {
            "status": "error",
            "message": str(e)
        }


def restore_file(quarantine_name, restore_path=None):
    """
    Restore a file from quarantine to its original location. 
    
    Args:
        quarantine_name: Name of the file in quarantine folder
        restore_path: Optional custom restore path.  If None, restores to original location. 
    
    Returns:
        dict: Result with status and details
    """
    try:
        # Load metadata
        metadata = _load_metadata()
        
        # Check if file exists in metadata
        if quarantine_name not in metadata:
            return {
                "status": "error",
                "message": "File not found in quarantine records"
            }
        
        file_info = metadata[quarantine_name]
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)
        
        # Check if quarantined file exists
        if not os.path.exists(quarantine_path):
            # Clean up metadata if file doesn't exist
            del metadata[quarantine_name]
            _save_metadata(metadata)
            return {
                "status": "error",
                "message": "Quarantined file no longer exists"
            }
        
        # Determine restore location
        if restore_path:
            target_path = restore_path
        else:
            target_path = file_info["original_path"]
        
        # Check if original directory exists, create if not
        target_dir = os. path.dirname(target_path)
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
        
        # Handle if file already exists at target location
        if os.path.exists(target_path):
            base, ext = os.path.splitext(target_path)
            target_path = f"{base}_restored_{int(time.time())}{ext}"
        
        # Move file back
        shutil.move(quarantine_path, target_path)
        
        # Remove from metadata
        del metadata[quarantine_name]
        _save_metadata(metadata)
        
        print(f"[INFO] File restored: {quarantine_name} -> {target_path}")
        
        return {
            "status": "success",
            "message": "File restored successfully",
            "restored_path": target_path,
            "original_name": file_info["original_name"]
        }
        
    except PermissionError:
        return {
            "status": "error",
            "message": "Permission denied.  Run as administrator."
        }
    except Exception as e:
        print(f"[ERROR] Unable to restore file: {quarantine_name} -> {e}")
        return {
            "status": "error",
            "message": str(e)
        }


def delete_file(quarantine_name):
    """
    Permanently delete a file from quarantine.
    
    Args:
        quarantine_name: Name of the file in quarantine folder
    
    Returns:
        dict: Result with status and details
    """
    try:
        # Load metadata
        metadata = _load_metadata()
        
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)
        
        # Check if file exists
        if not os.path.exists(quarantine_path):
            # Clean up metadata if exists
            if quarantine_name in metadata:
                del metadata[quarantine_name]
                _save_metadata(metadata)
            return {
                "status": "error",
                "message": "File not found in quarantine"
            }
        
        # Get file info before deletion
        file_info = metadata. get(quarantine_name, {})
        original_name = file_info. get("original_name", quarantine_name)
        
        # Delete the file
        os. remove(quarantine_path)
        
        # Remove from metadata
        if quarantine_name in metadata:
            del metadata[quarantine_name]
            _save_metadata(metadata)
        
        print(f"[INFO] File permanently deleted: {quarantine_name}")
        
        return {
            "status": "success",
            "message": "File permanently deleted",
            "deleted_file": original_name
        }
        
    except PermissionError:
        return {
            "status": "error",
            "message": "Permission denied.  Run as administrator."
        }
    except Exception as e:
        print(f"[ERROR] Unable to delete file: {quarantine_name} -> {e}")
        return {
            "status": "error",
            "message": str(e)
        }


def delete_all_files():
    """
    Permanently delete ALL files from quarantine. 
    
    Returns:
        dict: Result with status and details
    """
    try:
        metadata = _load_metadata()
        deleted_count = 0
        errors = []
        
        # Get list of quarantine names before iterating
        quarantine_names = list(metadata.keys())
        
        for quarantine_name in quarantine_names:
            result = delete_file(quarantine_name)
            if result["status"] == "success":
                deleted_count += 1
            else:
                errors.append(quarantine_name)
        
        # Also delete any orphaned files (files without metadata)
        if os.path.exists(QUARANTINE_DIR):
            for file_name in os.listdir(QUARANTINE_DIR):
                if file_name. startswith(". "):  # Skip metadata file
                    continue
                file_path = os. path.join(QUARANTINE_DIR, file_name)
                if os.path.isfile(file_path):
                    try:
                        os.remove(file_path)
                        deleted_count += 1
                    except:
                        errors. append(file_name)
        
        return {
            "status": "success",
            "message": f"Deleted {deleted_count} files",
            "deleted_count": deleted_count,
            "errors": errors
        }
        
    except Exception as e:
        print(f"[ERROR] Unable to delete all files: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


# =============================================================================
# QUARANTINE LISTING & INFO
# =============================================================================

def list_quarantined_files():
    """
    Get a list of all quarantined files with their details.
    
    Returns:
        list: List of dictionaries containing file information
    """
    try:
        # Ensure quarantine folder exists
        create_quarantine_folder()
        
        metadata = _load_metadata()
        quarantined_files = []
        
        for quarantine_name, file_info in metadata.items():
            quarantine_path = os. path.join(QUARANTINE_DIR, quarantine_name)
            
            # Check if file still exists
            exists = os.path. exists(quarantine_path)
            
            quarantined_files. append({
                "quarantine_name": quarantine_name,
                "original_name": file_info. get("original_name", "Unknown"),
                "original_path": file_info.get("original_path", "Unknown"),
                "virus_name": file_info.get("virus_name", "Unknown"),
                "file_size": file_info.get("file_size", 0),
                "quarantine_date": file_info.get("quarantine_date", "Unknown"),
                "exists": exists
            })
        
        # Sort by quarantine date (newest first)
        quarantined_files.sort(key=lambda x: x. get("quarantine_date", ""), reverse=True)
        
        return quarantined_files
        
    except Exception as e:
        print(f"[ERROR] Unable to list quarantined files: {e}")
        return []


def get_quarantine_info(quarantine_name):
    """
    Get detailed information about a specific quarantined file. 
    
    Args:
        quarantine_name: Name of the file in quarantine folder
    
    Returns:
        dict: File information or None if not found
    """
    try:
        metadata = _load_metadata()
        
        if quarantine_name in metadata:
            file_info = metadata[quarantine_name]. copy()
            file_info["quarantine_name"] = quarantine_name
            
            # Check if file exists
            quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)
            file_info["exists"] = os.path.exists(quarantine_path)
            
            return file_info
        
        return None
        
    except Exception as e:
        print(f"[ERROR] Unable to get quarantine info: {e}")
        return None


def get_quarantine_stats():
    """
    Get statistics about the quarantine folder.
    
    Returns:
        dict: Quarantine statistics
    """
    try:
        create_quarantine_folder()
        
        metadata = _load_metadata()
        total_files = len(metadata)
        total_size = 0
        
        for file_info in metadata. values():
            total_size += file_info. get("file_size", 0)
        
        return {
            "total_files": total_files,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "quarantine_path": QUARANTINE_DIR
        }
        
    except Exception as e:
        print(f"[ERROR] Unable to get quarantine stats: {e}")
        return {
            "total_files": 0,
            "total_size_bytes": 0,
            "total_size_mb": 0,
            "quarantine_path": QUARANTINE_DIR
        }


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def cleanup_metadata():
    """
    Clean up metadata by removing entries for files that no longer exist. 
    
    Returns:
        int: Number of entries cleaned up
    """
    try:
        metadata = _load_metadata()
        cleaned = 0
        
        names_to_remove = []
        for quarantine_name in metadata. keys():
            quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)
            if not os.path.exists(quarantine_path):
                names_to_remove.append(quarantine_name)
        
        for name in names_to_remove:
            del metadata[name]
            cleaned += 1
        
        if cleaned > 0:
            _save_metadata(metadata)
            print(f"[INFO] Cleaned up {cleaned} orphaned metadata entries")
        
        return cleaned
        
    except Exception as e:
        print(f"[ERROR] Unable to cleanup metadata: {e}")
        return 0



def format_file_size(size_in_bytes):
    """
    Convert file size from bytes to human-readable format.
    
    Args:
        size_in_bytes:  File size in bytes (integer)
    
    Returns:
        str:  Formatted size string (e.g., "1.50 MB", "256. 00 KB")
    """
    try:
        if size_in_bytes is None or size_in_bytes == 0:
            return "0 B"
        
        # Define size units
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        
        size = float(size_in_bytes)
        unit_index = 0
        
        # Keep dividing by 1024 until we get a reasonable number
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        # Format with appropriate decimal places
        if unit_index == 0:  # Bytes - no decimal
            return f"{int(size)} {units[unit_index]}"
        else:  # KB, MB, GB, TB - 2 decimal places
            return f"{size:.2f} {units[unit_index]}"
            
    except Exception as e:
        print(f"[ERROR] Unable to format file size: {e}")
        return "Unknown"