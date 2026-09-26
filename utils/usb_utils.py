# utils/usb_utils.py

import os
import platform
import time
import string
from threading import Thread, Event


class USBDetector: 
    """
    Cross-platform USB drive detection utility.
    Detects when USB drives are inserted or removed. 
    """

    def __init__(self):
        self.running = False
        self.stop_event = Event()
        self.known_drives = set()
        self.callbacks = {
            'on_insert': [],
            'on_remove': []
        }
        self._thread = None
        self._system = platform.system()

    def _get_windows_drives(self):
        """Get list of available removable drives on Windows."""
        drives = set()
        try:
            import ctypes
            for letter in string.ascii_uppercase:
                drive_path = f"{letter}:\\"
                if os. path.exists(drive_path):
                    try:
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                        # 2 = DRIVE_REMOVABLE (USB drives)
                        if drive_type == 2:
                            drives.add(drive_path)
                    except Exception:
                        # Fallback:  include all drives except C:\
                        if letter != 'C': 
                            drives. add(drive_path)
        except ImportError:
            # ctypes not available, use fallback
            for letter in string.ascii_uppercase:
                if letter != 'C': 
                    drive_path = f"{letter}:\\"
                    if os. path.exists(drive_path):
                        drives.add(drive_path)
        return drives

    def _get_linux_drives(self):
        """Get list of mounted USB drives on Linux."""
        drives = set()
        user = os.environ.get('USER', '')

        # Check common USB mount points
        mount_points = [
            f"/media/{user}",
            f"/run/media/{user}",
            "/mnt"
        ]

        for mount_point in mount_points: 
            if os.path.exists(mount_point):
                try:
                    for item in os.listdir(mount_point):
                        full_path = os. path.join(mount_point, item)
                        if os.path.ismount(full_path):
                            drives.add(full_path)
                except PermissionError: 
                    pass

        return drives

    def _get_macos_drives(self):
        """Get list of mounted USB drives on macOS."""
        drives = set()
        volumes_path = "/Volumes"

        if os.path.exists(volumes_path):
            try:
                for item in os.listdir(volumes_path):
                    # Skip the main Macintosh HD
                    if item == "Macintosh HD":
                        continue
                    full_path = os. path.join(volumes_path, item)
                    if os.path.ismount(full_path):
                        drives.add(full_path)
            except PermissionError: 
                pass

        return drives

    def get_removable_drives(self):
        """
        Get list of currently connected removable drives. 
        Works on Windows, Linux, and macOS. 

        Returns:
            set: Set of drive paths
        """
        try:
            if self._system == "Windows":
                return self._get_windows_drives()
            elif self._system == "Linux":
                return self._get_linux_drives()
            elif self._system == "Darwin":  # macOS
                return self._get_macos_drives()
            else: 
                return set()
        except Exception as e:
            print(f"[USB] Failed to get removable drives: {e}")
            return set()

    def on_insert(self, callback):
        """
        Register a callback for USB insertion events. 

        Args:
            callback: Function to call when USB is inserted. 
                     Receives drive_path as argument.
        """
        if callback not in self.callbacks['on_insert']: 
            self.callbacks['on_insert']. append(callback)

    def on_remove(self, callback):
        """
        Register a callback for USB removal events.

        Args:
            callback: Function to call when USB is removed. 
                     Receives drive_path as argument. 
        """
        if callback not in self.callbacks['on_remove']:
            self.callbacks['on_remove'].append(callback)

    def _monitor_loop(self, check_interval=2):
        """Main monitoring loop."""
        # Initialize known drives
        self.known_drives = self. get_removable_drives()
        print(f"[USB] Initial drives detected: {self.known_drives}")

        while not self.stop_event.is_set():
            try: 
                current_drives = self. get_removable_drives()

                # Check for new drives (inserted)
                new_drives = current_drives - self.known_drives
                for drive in new_drives: 
                    print(f"[USB] 🔌 Drive inserted: {drive}")
                    for callback in self.callbacks['on_insert']: 
                        try:
                            callback(drive)
                        except Exception as e:
                            print(f"[USB] Insert callback error: {e}")

                # Check for removed drives
                removed_drives = self.known_drives - current_drives
                for drive in removed_drives:
                    print(f"[USB] ⏏️ Drive removed:  {drive}")
                    for callback in self.callbacks['on_remove']:
                        try:
                            callback(drive)
                        except Exception as e:
                            print(f"[USB] Remove callback error: {e}")

                # Update known drives
                self.known_drives = current_drives

            except Exception as e: 
                print(f"[USB] Monitoring error: {e}")

            # Wait before next check
            self.stop_event. wait(check_interval)

    def start(self, check_interval=2):
        """
        Start USB monitoring in a background thread.

        Args:
            check_interval:  Seconds between checks (default: 2)
        """
        if self.running:
            print("[USB] Monitoring already running")
            return

        self.running = True
        self. stop_event.clear()

        self._thread = Thread(
            target=self._monitor_loop,
            args=(check_interval,),
            daemon=True,
            name="USBMonitor"
        )
        self._thread.start()
        print("[USB] 🔍 Monitoring started")

    def stop(self):
        """Stop USB monitoring."""
        if not self.running:
            return

        self.stop_event.set()
        self. running = False

        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

        print("[USB] Monitoring stopped")

    def is_running(self):
        """Check if monitoring is active."""
        return self.running

    def clear_callbacks(self):
        """Clear all registered callbacks."""
        self.callbacks = {
            'on_insert': [],
            'on_remove': []
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

_detector = None


def get_usb_detector():
    """Get or create the global USB detector instance."""
    global _detector
    if _detector is None:
        _detector = USBDetector()
    return _detector


def detect_usb_drives():
    """
    Get list of currently connected USB drives. 

    Returns:
        list: List of drive paths
    """
    detector = get_usb_detector()
    return list(detector.get_removable_drives())


def start_usb_monitoring(on_insert=None, on_remove=None, check_interval=2):
    """
    Start USB monitoring with callbacks.

    Args:
        on_insert: Callback function for USB insertion
        on_remove:  Callback function for USB removal
        check_interval: Seconds between checks
    """
    detector = get_usb_detector()

    if on_insert: 
        detector.on_insert(on_insert)
    if on_remove: 
        detector.on_remove(on_remove)

    detector.start(check_interval)


def stop_usb_monitoring():
    """Stop USB monitoring."""
    detector = get_usb_detector()
    detector.stop()