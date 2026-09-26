import os
import time
from threading import Thread, Event, Lock
from datetime import datetime

# Import watchdog for file system monitoring
try: 
    from watchdog. observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("[WARNING] watchdog library not installed.  Run: pip install watchdog")

from config import (
    WATCH_PATHS, DOWNLOADS_DIR, MONITOR_USB_DRIVES,
    DUPLICATE_SCAN_THRESHOLD, SKIP_PATTERNS, SKIP_DIRECTORIES
)
from core.scanner import scan_file
from core.quarantine import quarantine_file
from utils.usb_utils import get_usb_detector
from database.models import save_realtime_event, get_setting
from utils.file_utils import is_file_safe_size


# =============================================================================
# FILE SYSTEM EVENT HANDLER (IMPROVED)
# =============================================================================

if WATCHDOG_AVAILABLE:
    class AntivirusEventHandler(FileSystemEventHandler):
        """
        Handles file system events for real-time scanning.
        Automatically scans new, modified, and moved files.
        
        IMPROVEMENTS:
        - Better duplicate prevention with file-level locking
        - Enhanced . tmp file filtering
        - Reduced log noise for permission errors
        - Prevents duplicate quarantine attempts
        """

        def __init__(self, monitor):
            """
            Initialize event handler with reference to monitor. 

            Args:
                monitor: RealtimeMonitor instance for callback access
            """
            super().__init__()
            self.monitor = monitor
            self._recently_scanned = {}  # {file_path: timestamp}
            self._currently_scanning = set()  # Files being scanned right now
            self._quarantined_files = set()  # Files already quarantined
            self._scan_lock = Lock()
            self._cleanup_interval = 30
            self._last_cleanup = time.time()

        def _cleanup_caches(self):
            """Remove old entries from caches."""
            now = time.time()
            if now - self._last_cleanup > self._cleanup_interval: 
                with self._scan_lock:
                    # Clean recently scanned cache
                    expired = [
                        path for path, timestamp in self._recently_scanned. items()
                        if now - timestamp > DUPLICATE_SCAN_THRESHOLD * 2
                    ]
                    for path in expired: 
                        del self._recently_scanned[path]
                    
                    # Clean quarantined files cache (keep for 60 seconds)
                    # This is a simple set, so we'll just clear old entries periodically
                    if len(self._quarantined_files) > 100:
                        self._quarantined_files.clear()
                    
                    self._last_cleanup = now

        def _should_skip_file(self, file_path):
            """
            Quick check if file should be skipped entirely.
            
            Args:
                file_path: Path to file
                
            Returns:
                tuple: (should_skip:  bool, reason: str)
            """
            try:
                file_name = os.path. basename(file_path).lower()
                file_path_lower = file_path.lower()
                
                # Skip if doesn't exist
                if not os.path.exists(file_path):
                    return (True, "File does not exist")
                
                # Skip directories
                if os. path.isdir(file_path):
                    return (True, "Is a directory")
                
                # Skip hidden files
                if file_name.startswith('.') or file_name. startswith('~'):
                    return (True, "Hidden or temp file")
                
                # Skip based on patterns (includes . tmp files)
                for pattern in SKIP_PATTERNS:
                    if pattern in file_name: 
                        return (True, f"Matches skip pattern: {pattern}")
                
                # Skip system/quarantine folders
                for folder in SKIP_DIRECTORIES:
                    if folder in file_path_lower: 
                        return (True, f"In skip directory: {folder}")
                
                # Skip files that are too large
                if not is_file_safe_size(file_path):
                    return (True, "File too large")
                
                return (False, "")
                
            except Exception as e:
                return (True, f"Error checking file: {e}")

        def _can_scan_file(self, file_path):
            """
            Check if file can be scanned (not recently scanned, not currently scanning).
            
            Args:
                file_path: Path to file
                
            Returns:
                bool: True if file can be scanned
            """
            now = time.time()
            
            with self._scan_lock:
                # Check if already being scanned
                if file_path in self._currently_scanning:
                    return False
                
                # Check if recently scanned
                if file_path in self._recently_scanned: 
                    if now - self._recently_scanned[file_path] < DUPLICATE_SCAN_THRESHOLD:
                        return False
                
                # Check if already quarantined
                if file_path in self._quarantined_files:
                    return False
                
                # Mark as currently scanning
                self._currently_scanning.add(file_path)
                return True

        def _finish_scanning(self, file_path):
            """Mark file as finished scanning."""
            with self._scan_lock:
                self._currently_scanning.discard(file_path)
                self._recently_scanned[file_path] = time.time()

        def _mark_quarantined(self, file_path):
            """Mark file as quarantined to prevent duplicate attempts."""
            with self._scan_lock:
                self._quarantined_files. add(file_path)

        def _is_file_stable(self, file_path, stability_time=1.5):
            """
            Check if file has stopped growing (download/copy complete).

            Args:
                file_path: Path to file
                stability_time:  Seconds to wait for size stability

            Returns:
                bool: True if file size is stable
            """
            try:
                if not os.path. exists(file_path):
                    return False

                initial_size = os.path.getsize(file_path)
                time. sleep(stability_time)

                if not os.path.exists(file_path):
                    return False

                final_size = os. path.getsize(file_path)
                return initial_size == final_size

            except (OSError, PermissionError):
                return False

        def _scan_file_safely(self, file_path, event_type):
            """
            Scan file with proper error handling and callbacks. 

            Args:
                file_path: Path to file to scan
                event_type: Type of filesystem event
            """
            try: 
                # Cleanup old cache entries
                self._cleanup_caches()

                # Quick skip check
                should_skip, skip_reason = self._should_skip_file(file_path)
                if should_skip:
                    return
                
                # Check if we can scan (not duplicate, not currently scanning)
                if not self._can_scan_file(file_path):
                    return

                try:
                    # Wait for file to be stable (download/copy complete)
                    if not self._is_file_stable(file_path):
                        return

                    # Double-check file still exists after waiting
                    if not os.path.exists(file_path):
                        return

                    # Perform scan
                    print(f"[REALTIME] Scanning: {file_path}")
                    result = scan_file(file_path)

                    # Save event to database (silently fail if error)
                    try:
                        save_realtime_event(
                            event_type=event_type,
                            event_source="filesystem_watcher",
                            file_path=file_path,
                            details=f"Status: {result. get('status', 'unknown')}"
                        )
                    except Exception: 
                        pass  # Don't spam logs with database errors

                    # Safe callback execution
                    if self. monitor. on_file_scanned: 
                        try:
                            self.monitor.on_file_scanned(file_path, result)
                        except Exception:
                            pass

                    # Handle infected files
                    if result.get('status') == 'infected':
                        virus_name = result.get('virus_name', 'Unknown Threat')
                        print(f"[ALERT] Real-time threat detected: {virus_name} in {file_path}")

                        # Mark as quarantined BEFORE attempting quarantine
                        # This prevents duplicate quarantine attempts
                        self._mark_quarantined(file_path)

                        # Safe threat callback
                        if self.monitor.on_threat_found:
                            try:
                                self.monitor.on_threat_found(file_path, result)
                            except Exception:
                                pass

                        # Auto-quarantine if enabled
                        try:
                            auto_quarantine = get_setting('auto_quarantine', True)
                            if auto_quarantine: 
                                q_result = quarantine_file(file_path, virus_name)
                                if q_result.get('status') == 'success':
                                    print(f"[REALTIME] Auto-quarantined: {q_result.get('message')}")
                                # Don't log errors for already-quarantined files
                        except Exception:
                            pass

                finally:
                    # Always mark as finished scanning
                    self._finish_scanning(file_path)

            except Exception as e:
                # Only log unexpected errors, not permission/file-not-found
                if not isinstance(e, (PermissionError, FileNotFoundError)):
                    print(f"[REALTIME] Scan error for {file_path}:  {e}")

        def on_created(self, event):
            """Handle file creation events."""
            if not event.is_directory:
                file_path = event. src_path
                Thread(
                    target=self._scan_file_safely,
                    args=(file_path, "file_created"),
                    daemon=True,
                    name=f"Scan-{os.path.basename(file_path)[: 20]}"
                ).start()

        def on_modified(self, event):
            """Handle file modification events (covers downloads completing)."""
            if not event.is_directory:
                file_path = event. src_path
                Thread(
                    target=self._scan_file_safely,
                    args=(file_path, "file_modified"),
                    daemon=True,
                    name=f"Scan-{os.path.basename(file_path)[:20]}"
                ).start()

        def on_moved(self, event):
            """Handle file move events (covers downloads from temp folders)."""
            if not event.is_directory:
                file_path = event. dest_path
                Thread(
                    target=self._scan_file_safely,
                    args=(file_path, "file_moved"),
                    daemon=True,
                    name=f"Scan-{os.path. basename(file_path)[:20]}"
                ).start()


# =============================================================================
# REAL-TIME MONITOR CLASS
# =============================================================================

class RealtimeMonitor:
    """
    Production-ready real-time monitoring controller. 
    Manages filesystem watching and USB monitoring.
    """

    def __init__(self):
        self.running = False
        self.stop_event = Event()

        # Callbacks (set by GUI)
        self.on_threat_found = None
        self.on_file_scanned = None
        self. on_usb_inserted = None
        self.on_usb_removed = None
        self.on_usb_scan_complete = None

        # Watchdog components
        self._observer = None
        self._event_handler = None

        # USB detector
        self._usb_detector = get_usb_detector()

        # Monitored paths
        self._watched_paths = []
        self._watch_lock = Lock()

        # Track USB drives being watched
        self._usb_watches = {}  # {drive_path: watch_object}

    def _handle_usb_insert(self, drive_path):
        """Handle USB drive insertion."""
        print(f"[REALTIME] USB detected: {drive_path}")

        try:
            save_realtime_event(
                event_type="usb_inserted",
                event_source="usb_monitor",
                file_path=drive_path,
                details="USB drive connected"
            )
        except Exception:
            pass

        if self.on_usb_inserted: 
            try:
                self. on_usb_inserted(drive_path)
            except Exception:
                pass

        # Add USB drive to real-time monitoring
        if MONITOR_USB_DRIVES:
            self._add_usb_watch(drive_path)

        # Auto-scan USB drive
        monitor_usb = get_setting('monitor_usb', True)
        if monitor_usb: 
            Thread(
                target=self._scan_usb_drive,
                args=(drive_path,),
                daemon=True,
                name=f"USBScan-{drive_path}"
            ).start()

    def _handle_usb_remove(self, drive_path):
        """Handle USB drive removal."""
        print(f"[REALTIME] USB removed: {drive_path}")

        # Remove USB drive from real-time monitoring
        self._remove_usb_watch(drive_path)

        try:
            save_realtime_event(
                event_type="usb_removed",
                event_source="usb_monitor",
                file_path=drive_path,
                details="USB drive disconnected"
            )
        except Exception: 
            pass

        if self.on_usb_removed: 
            try:
                self.on_usb_removed(drive_path)
            except Exception:
                pass

    def _add_usb_watch(self, drive_path):
        """
        Add USB drive to real-time file monitoring.
        
        Args:
            drive_path: Path to USB drive
        """
        if not self. running or not self._observer:
            return False

        if not os.path.exists(drive_path):
            return False

        with self._watch_lock:
            if drive_path in self._usb_watches:
                return True

            try:
                watch = self._observer.schedule(
                    self._event_handler,
                    drive_path,
                    recursive=True
                )
                self._usb_watches[drive_path] = watch
                self._watched_paths.append(drive_path)
                print(f"[REALTIME] ✅ Now watching USB:  {drive_path}")
                return True
            except Exception as e:
                print(f"[REALTIME] Failed to watch USB {drive_path}: {e}")
                return False

    def _remove_usb_watch(self, drive_path):
        """
        Remove USB drive from real-time file monitoring.
        
        Args: 
            drive_path:  Path to USB drive
        """
        with self._watch_lock:
            if drive_path in self._usb_watches:
                try:
                    watch = self._usb_watches[drive_path]
                    if self._observer:
                        self._observer. unschedule(watch)
                    del self._usb_watches[drive_path]
                    if drive_path in self._watched_paths:
                        self._watched_paths.remove(drive_path)
                    print(f"[REALTIME] Stopped watching USB: {drive_path}")
                except Exception: 
                    pass

    def _scan_usb_drive(self, drive_path):
        """Scan USB drive for threats."""
        print(f"[REALTIME] Auto-scanning USB: {drive_path}")

        threats_found = []
        scanned_count = 0

        try:
            for root, dirs, files in os.walk(drive_path):
                # Skip system folders
                dirs[:] = [d for d in dirs if not d.startswith('.') and
                          d. lower() not in ['system volume information', '$recycle.bin']]

                for file in files:
                    full_path = os. path.join(root, file)

                    try:
                        result = scan_file(full_path)
                        scanned_count += 1

                        if result.get('status') == 'infected':
                            virus_name = result. get('virus_name', 'Unknown')
                            threats_found.append({
                                'file':  full_path,
                                'virus_name': virus_name
                            })

                            print(f"[ALERT] USB threat:  {virus_name} in {full_path}")

                            if self.on_threat_found:
                                try:
                                    self.on_threat_found(full_path, result)
                                except Exception:
                                    pass

                            auto_quarantine = get_setting('auto_quarantine', True)
                            if auto_quarantine: 
                                try:
                                    quarantine_file(full_path, virus_name)
                                except Exception:
                                    pass

                    except Exception: 
                        pass

            try:
                save_realtime_event(
                    event_type="usb_scan_complete",
                    event_source="usb_monitor",
                    file_path=drive_path,
                    details=f"Scanned {scanned_count} files, found {len(threats_found)} threats"
                )
            except Exception:
                pass

            if self.on_usb_scan_complete: 
                try: 
                    self.on_usb_scan_complete(drive_path, scanned_count, threats_found)
                except Exception:
                    pass

            print(f"[REALTIME] USB scan complete: {scanned_count} files, {len(threats_found)} threats")

        except Exception as e:
            print(f"[REALTIME] USB scan failed: {e}")

    def add_watch_path(self, path):
        """Add a path to monitoring."""
        if not os.path.exists(path):
            print(f"[REALTIME] Path does not exist: {path}")
            return False

        with self._watch_lock:
            if path not in self._watched_paths:
                self._watched_paths. append(path)
                print(f"[REALTIME] Added watch path: {path}")

                if self. running and self._observer:
                    try: 
                        self._observer.schedule(
                            self._event_handler,
                            path,
                            recursive=True
                        )
                        print(f"[REALTIME] Now watching: {path}")
                    except Exception as e: 
                        print(f"[REALTIME] Failed to watch {path}: {e}")
                        return False

                return True
        return False

    def remove_watch_path(self, path):
        """Remove a path from monitoring."""
        with self._watch_lock:
            if path in self._watched_paths: 
                self._watched_paths. remove(path)
                print(f"[REALTIME] Removed watch path:  {path}")
                return True
        return False

    def start(self):
        """Start real-time monitoring."""
        if self.running:
            print("[REALTIME] Already running")
            return True

        if not WATCHDOG_AVAILABLE:
            print("[ERROR] watchdog not available.  Install:  pip install watchdog")
            return False

        try:
            self. running = True
            self. stop_event.clear()

            # Add all paths from WATCH_PATHS config
            with self._watch_lock:
                for path in WATCH_PATHS:
                    if os.path.exists(path) and path not in self._watched_paths:
                        self._watched_paths.append(path)

                # Also add Downloads folder for backward compatibility
                if DOWNLOADS_DIR and os.path.exists(DOWNLOADS_DIR):
                    if DOWNLOADS_DIR not in self._watched_paths:
                        self._watched_paths. append(DOWNLOADS_DIR)

            # Create event handler with monitor reference
            self._event_handler = AntivirusEventHandler(self)

            # Create and start observer
            self._observer = Observer()

            for path in self._watched_paths:
                if os.path.exists(path):
                    try:
                        self._observer.schedule(
                            self._event_handler,
                            path,
                            recursive=True
                        )
                        print(f"[REALTIME] Watching: {path}")
                    except Exception as e:
                        print(f"[REALTIME] Failed to watch {path}: {e}")

            self._observer. start()

            # Start USB monitoring
            try:
                self._usb_detector.on_insert(self._handle_usb_insert)
                self._usb_detector.on_remove(self._handle_usb_remove)
                self._usb_detector.start()
            except Exception as e:
                print(f"[REALTIME] USB monitoring error: {e}")

            print("[REALTIME] 🛡️ Protection ACTIVE")
            print(f"[REALTIME] Monitoring {len(self._watched_paths)} paths")
            return True

        except Exception as e:
            print(f"[REALTIME] Start failed: {e}")
            self.running = False
            return False

    def stop(self):
        """Stop real-time monitoring."""
        if not self. running:
            return

        print("[REALTIME] Stopping...")
        self.running = False
        self.stop_event.set()

        # Clear USB watches
        self._usb_watches.clear()

        # Stop observer
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:
                pass
            finally:
                self._observer = None

        # Stop USB monitoring
        try:
            self._usb_detector.stop()
        except Exception: 
            pass

        print("[REALTIME] Stopped")

    def is_running(self):
        """Check if monitoring is active."""
        return self.running

    def get_status(self):
        """Get monitoring status."""
        with self._watch_lock:
            return {
                "running": self.running,
                "watched_paths": self._watched_paths. copy(),
                "usb_watches":  list(self._usb_watches.keys()),
                "usb_monitoring":  self._usb_detector.is_running() if self._usb_detector else False,
                "watchdog_available": WATCHDOG_AVAILABLE
            }


# =============================================================================
# GLOBAL CONVENIENCE FUNCTIONS
# =============================================================================

_monitor = None


def get_realtime_monitor():
    """Get or create global monitor instance."""
    global _monitor
    if _monitor is None: 
        _monitor = RealtimeMonitor()
    return _monitor


def start_realtime_monitoring(on_threat_found=None, on_file_scanned=None,
                               on_usb_inserted=None, on_usb_removed=None,
                               on_threats_batch=None):
    """
    Start real-time protection with GUI callbacks. 

    Args:
        on_threat_found: Callback(file_path, result) when threat detected
        on_file_scanned: Callback(file_path, result) after file scanned
        on_usb_inserted: Callback(drive_path) when USB inserted
        on_usb_removed:  Callback(drive_path) when USB removed
        on_threats_batch: Callback(threats_list) for batched threat notifications

    Returns:
        bool: True if started successfully
    """
    monitor = get_realtime_monitor()

    # Set callbacks BEFORE starting
    if on_threat_found:
        monitor.on_threat_found = on_threat_found
    if on_file_scanned:
        monitor.on_file_scanned = on_file_scanned
    if on_usb_inserted: 
        monitor.on_usb_inserted = on_usb_inserted
    if on_usb_removed:
        monitor.on_usb_removed = on_usb_removed

    return monitor.start()


def stop_realtime_monitoring():
    """Stop real-time protection."""
    monitor = get_realtime_monitor()
    monitor.stop()


def add_watch_folder(folder_path):
    """Add folder to real-time monitoring."""
    monitor = get_realtime_monitor()
    return monitor.add_watch_path(folder_path)


def remove_watch_folder(folder_path):
    """Remove folder from monitoring."""
    monitor = get_realtime_monitor()
    return monitor.remove_watch_path(folder_path)


def get_monitoring_status():
    """Get current monitoring status."""
    monitor = get_realtime_monitor()
    return monitor.get_status()


def is_realtime_protection_enabled():
    """Check if real-time protection is enabled."""
    return get_setting('realtime_protection', True)