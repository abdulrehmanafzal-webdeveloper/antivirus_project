# main.py

import sys
import os

from core.signatures import load_signatures

# Load signatures at startup
load_signatures()

# Add project root to path for imports
sys.path.insert(0, os. path.dirname(os.path.abspath(__file__)))


def run_cli():
    """Run command-line interface."""
    import time
    from core.scanner import scan_file, scan_folder, quick_scan, full_scan, get_scan_summary
    from core. quarantine import (
        create_quarantine_folder,
        quarantine_file,
        restore_file,
        delete_file,
        list_quarantined_files,
        get_quarantine_stats,
        format_file_size
    )
    from database.db import init_db, get_db_info
    from database.models import (
        save_scan_log,
        get_scan_history,
        get_scan_statistics,
        get_all_settings
    )
    from core.realtime import (
        start_realtime_monitoring,
        stop_realtime_monitoring,
        get_monitoring_status
    )
    
    print("=" * 60)
    print("       ANTIVIRUS SCANNER (CLI)")
    print("=" * 60)
    
    init_db()
    create_quarantine_folder()
    
    # CLI menu loop... 
    print("\nCLI mode - Use GUI for full experience")
    print("Run: python main.py --gui")


def run_gui():
    """Run graphical user interface."""
    from ui.gui import run_gui as start_gui
    start_gui()


def main():
    """Main entry point."""
    # Check for command-line arguments
    if len(sys. argv) > 1:
        if sys.argv[1] in ["--cli", "-c"]:
            run_cli()
            return
        elif sys.argv[1] in ["--help", "-h"]:
            print("Antivirus Scanner")
            print("=" * 40)
            print("\nUsage:")
            print("  python main.py          Run GUI (default)")
            print("  python main. py --gui    Run GUI")
            print("  python main.py --cli    Run CLI")
            print("  python main.py --help   Show this help")
            return
    
    # Default: Run GUI
    run_gui()


if __name__ == "__main__":
    main()