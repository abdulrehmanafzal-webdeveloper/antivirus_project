# core/scanner.py

import os
import platform
from utils.file_utils import (
    get_file_hash, 
    is_file_safe_size, 
    is_executable,
    should_scan_file,
    get_scan_priority
)
from core.signatures import KNOWN_SIGNATURES


# =============================================================================
# CORE SCAN FUNCTIONS (Enhanced)
# =============================================================================

def scan_file(file_path, progress_callback=None):
    """
    Scan a single file for malware signatures.
    
    Args:
        file_path: Path to the file to scan
        progress_callback: Optional callback function
    
    Returns:
        dict: Scan result with status, file path, and threat info
    """
    try: 
        # Pre-scan validation
        should_scan, reason, priority = should_scan_file(file_path)
        
        if not should_scan:
            return {
                "status": "skipped",
                "message": reason,
                "file": file_path,
                "priority": priority
            }
        
        # Calculate file hash
        file_hash = get_file_hash(file_path)
        
        if not file_hash:
            return {
                "status": "error",
                "message": "Unable to calculate file hash",
                "file": file_path,
                "priority": priority
            }
        
        # Check against signature database
        if file_hash in KNOWN_SIGNATURES:
            return {
                "status": "infected",
                "file": file_path,
                "virus_name": KNOWN_SIGNATURES[file_hash],
                "file_hash": file_hash,
                "is_executable": is_executable(file_path),
                "priority": priority,
                "severity": "CRITICAL" if priority == 4 else "HIGH"
            }
        
        # File is clean
        return {
            "status": "clean",
            "file": file_path,
            "file_hash": file_hash,
            "is_executable": is_executable(file_path),
            "priority":  priority
        }
        
    except PermissionError:
        return {
            "status": "error",
            "message": "Permission denied",
            "file": file_path
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "message": "File not found",
            "file": file_path
        }
    except Exception as e:
        print(f"[ERROR] Unable to scan file: {file_path} -> {e}")
        return {
            "status": "error",
            "message": str(e),
            "file":  file_path
        }


def scan_folder(folder_path, progress_callback=None):
    """
    Scan all files in a folder recursively.
    
    Args:
        folder_path: Path to the folder to scan
        progress_callback: Optional callback for progress updates
    
    Returns: 
        list: List of scan results
    """
    try:
        results = []
        scan_cancelled = False
        
        # Count total files
        total_files = 0
        for root, dirs, files in os.walk(folder_path):
            total_files += len(files)
        
        scanned_count = 0
        
        # Scan all files
        for root, dirs, files in os.walk(folder_path):
            if scan_cancelled:
                break
            
            for file in files: 
                if scan_cancelled:
                    break
                
                full_path = os.path.join(root, file)
                result = scan_file(full_path)
                result["file"] = full_path
                results.append(result)
                
                scanned_count += 1
                
                # Progress callback with cancellation support
                if progress_callback:
                    should_continue = progress_callback(
                        current_file=full_path,
                        scanned=scanned_count,
                        total=total_files
                    )
                    if should_continue is False: 
                        scan_cancelled = True
                        break
        
        return results
        
    except PermissionError:
        print(f"[ERROR] Permission denied: {folder_path}")
        return []
    except Exception as e:
        print(f"[ERROR] Unable to scan folder: {folder_path} -> {e}")
        return []


# =============================================================================
# SYSTEM SCAN LOCATIONS
# =============================================================================

def get_quick_scan_locations():
    """
    Get critical system locations for quick scan.
    
    These are high-risk areas where malware commonly hides.
    
    Returns:
        list: List of folder paths to scan
    """
    try:
        user_home = os.path.expanduser("~")
        locations = []
        
        # Common user directories (cross-platform)
        common_locations = [
            os. path.join(user_home, "Downloads"),
            os.path. join(user_home, "Desktop"),
            os.path.join(user_home, "Documents"),
        ]
        
        # OS-specific high-risk locations
        if platform.system() == "Windows":
            locations.extend([
                # User temp folders
                os.path.join(user_home, "AppData", "Local", "Temp"),
                
                # Startup folder (auto-run programs)
                os.path. join(user_home, "AppData", "Roaming", "Microsoft", 
                            "Windows", "Start Menu", "Programs", "Startup"),
                
                # System temp
                os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "Temp"),
            ])
        
        elif platform.system() == "Darwin":  # macOS
            locations. extend([
                os.path.join(user_home, "Library", "Caches"),
                os.path.join(user_home, "Library", "Application Support"),
                os. path.join(user_home, ". Trash"),
            ])
        
        else:  # Linux/Unix
            locations.extend([
                "/tmp",
                os.path.join(user_home, ".cache"),
                os.path.join(user_home, ".local", "share"),
                os.path.join(user_home, ".config"),
            ])
        
        # Add common locations
        locations.extend(common_locations)
        
        # Filter out non-existent locations
        valid_locations = [loc for loc in locations if os. path.exists(loc)]
        
        return valid_locations
        
    except Exception as e:
        print(f"[ERROR] Unable to get quick scan locations: {e}")
        return []


def get_full_scan_locations():
    """
    Get root locations for full system scan.
    
    Returns:
        list: List of root paths to scan
    """
    try:
        if platform.system() == "Windows":
            # Scan all available drives
            drives = []
            for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
                drive = f"{letter}:\\"
                if os.path. exists(drive):
                    drives.append(drive)
            return drives if drives else ["C:\\"]
        
        elif platform.system() == "Darwin":  # macOS
            return ["/Users", "/Applications", "/Library"]
        
        else:  # Linux/Unix
            # Scan user home and common system directories
            return [
                os.path.expanduser("~"),
                "/tmp",
                "/var/tmp",
                "/opt"
            ]
    
    except Exception as e: 
        print(f"[ERROR] Unable to get full scan locations: {e}")
        return []


# =============================================================================
# QUICK SCAN & FULL SCAN (Production-Ready)
# =============================================================================

def quick_scan(progress_callback=None):
    """
    Perform quick scan of critical system locations. 
    
    Args:
        progress_callback: Function called for each file scanned. 
                          Should return False to cancel scan.
    
    Returns:
        dict: Comprehensive scan summary
    """
    try:
        locations = get_quick_scan_locations()
        all_results = []
        total_files = 0
        total_scanned = 0
        threats_found = []
        scan_cancelled = False
        
        # Phase 1: Count all files
        for location in locations: 
            if not os.path.exists(location):
                continue
            try:
                for root, dirs, files in os. walk(location):
                    total_files += len(files)
            except PermissionError:
                continue
        
        # Phase 2: Scan all files
        for location in locations:
            if not os. path.exists(location):
                continue
            
            if scan_cancelled:
                break
            
            try:
                for root, dirs, files in os. walk(location):
                    if scan_cancelled:
                        break
                    
                    for file in files:
                        if scan_cancelled:
                            break
                        
                        full_path = os.path.join(root, file)
                        
                        # Scan file
                        result = scan_file(full_path)
                        result["file"] = full_path
                        result["location"] = location
                        all_results.append(result)
                        
                        total_scanned += 1
                        
                        # Track threats
                        if result. get("status") == "infected":
                            threats_found.append(result)
                        
                        # Progress callback with cancellation
                        if progress_callback: 
                            should_continue = progress_callback(
                                current_file=full_path,
                                scanned=total_scanned,
                                total=total_files,
                                location=location
                            )
                            if should_continue is False: 
                                scan_cancelled = True
                                break
            
            except PermissionError: 
                continue
        
        # Return summary
        return {
            "scan_type": "quick",
            "locations_scanned": locations,
            "total_files":  total_files,
            "files_scanned": total_scanned,
            "threats_found": len(threats_found),
            "threats": threats_found,
            "results": all_results,
            "cancelled": scan_cancelled
        }
        
    except Exception as e: 
        print(f"[ERROR] Quick scan failed: {e}")
        return {
            "scan_type": "quick",
            "locations_scanned": [],
            "total_files": 0,
            "files_scanned": 0,
            "threats_found": 0,
            "threats": [],
            "results": [],
            "cancelled": False
        }


def full_scan(target_path=None, progress_callback=None):
    """
    Perform full system scan or scan specific path.
    
    Args:
        target_path: Optional specific path to scan
        progress_callback: Function called for each file scanned.
                          Should return False to cancel scan.
    
    Returns:
        dict: Comprehensive scan summary
    """
    try: 
        # Determine scan locations
        if target_path and os.path.exists(target_path):
            locations = [target_path]
        else:
            locations = get_full_scan_locations()
        
        all_results = []
        total_files = 0
        total_scanned = 0
        threats_found = []
        skipped_files = 0
        error_files = 0
        scan_cancelled = False
        
        # Phase 1: Count all files
        for location in locations: 
            if not os.path.exists(location):
                continue
            try:
                for root, dirs, files in os.walk(location):
                    total_files += len(files)
            except PermissionError:
                continue
        
        # Phase 2: Scan all files
        for location in locations:
            if not os.path.exists(location):
                continue
            
            if scan_cancelled:
                break
            
            try:
                for root, dirs, files in os.walk(location):
                    if scan_cancelled:
                        break
                    
                    for file in files:
                        if scan_cancelled:
                            break
                        
                        full_path = os.path.join(root, file)
                        
                        # Scan file
                        try:
                            result = scan_file(full_path)
                            result["file"] = full_path
                            result["location"] = location
                            all_results.append(result)
                            
                            # Track by status
                            if result.get("status") == "infected":
                                threats_found.append(result)
                            elif result.get("status") == "skipped":
                                skipped_files += 1
                            elif result.get("status") == "error":
                                error_files += 1
                        
                        except PermissionError:
                            error_files += 1
                            all_results.append({
                                "status": "error",
                                "file": full_path,
                                "message": "Permission denied"
                            })
                        
                        total_scanned += 1
                        
                        # Progress callback with cancellation
                        if progress_callback: 
                            should_continue = progress_callback(
                                current_file=full_path,
                                scanned=total_scanned,
                                total=total_files,
                                location=location
                            )
                            if should_continue is False:
                                scan_cancelled = True
                                break
            
            except PermissionError:
                continue
        
        # Return summary
        return {
            "scan_type": "full",
            "locations_scanned": locations,
            "total_files": total_files,
            "files_scanned": total_scanned,
            "files_skipped": skipped_files,
            "files_with_errors": error_files,
            "threats_found": len(threats_found),
            "threats": threats_found,
            "results": all_results,
            "cancelled": scan_cancelled
        }
        
    except Exception as e:
        print(f"[ERROR] Full scan failed: {e}")
        return {
            "scan_type": "full",
            "locations_scanned":  [],
            "total_files":  0,
            "files_scanned": 0,
            "files_skipped": 0,
            "files_with_errors": 0,
            "threats_found": 0,
            "threats": [],
            "results": [],
            "cancelled":  False
        }


# =============================================================================
# SCAN SUMMARY UTILITIES
# =============================================================================

def get_scan_summary(results):
    """
    Generate summary statistics from scan results.
    
    Args:
        results: List of scan result dictionaries
    
    Returns: 
        dict: Summary with statistics and threat list
    """
    try:
        summary = {
            "total":  len(results),
            "clean": 0,
            "infected": 0,
            "skipped": 0,
            "errors": 0,
            "threats": [],
            "executables_scanned": 0,
            "high_priority_files": 0
        }
        
        for result in results:
            status = result.get("status", "error")
            
            if status == "clean":
                summary["clean"] += 1
            elif status == "infected":
                summary["infected"] += 1
                summary["threats"].append({
                    "file": result. get("file", "Unknown"),
                    "virus_name": result.get("virus_name", "Unknown Threat"),
                    "severity": result.get("severity", "HIGH")
                })
            elif status == "skipped":
                summary["skipped"] += 1
            else:
                summary["errors"] += 1
            
            # Track executables and high-priority files
            if result.get("is_executable"):
                summary["executables_scanned"] += 1
            
            if result.get("priority", 0) >= 3:
                summary["high_priority_files"] += 1
        
        return summary
        
    except Exception as e:
        print(f"[ERROR] Unable to generate scan summary: {e}")
        return {
            "total": 0,
            "clean": 0,
            "infected": 0,
            "skipped": 0,
            "errors": 0,
            "threats": [],
            "executables_scanned": 0,
            "high_priority_files":  0
        }