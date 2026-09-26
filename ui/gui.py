# ui/gui.py

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import time
import os
from datetime import datetime


class AntivirusGUI:
    """
    Main Antivirus GUI Application using Tkinter.   
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Antivirus Scanner")
        self.root.geometry("920x800")
        self.root.minsize(820, 650)
        self.root.configure(bg="#f5f5f5")
        
        # Scan state variables
        self.is_scanning = False
        self.cancel_requested = False
        self. current_scan_thread = None
        self.scan_results = []
        
        # ✅ NEW: Track if scan has actually started processing files
        self.scan_started = False
        
        # Progress variables
        self.progress_var = tk.DoubleVar(value=0)
        self.status_var = tk.StringVar(value="Ready")
        self.current_file_var = tk.StringVar(value="No scan in progress")
        self.files_scanned_var = tk.StringVar(value="0 / 0 files")
        
        # Real-time protection status
        self.realtime_status_var = tk.StringVar(value="🟢 Active")
        
        # Build the GUI with scrollable container
        self._create_styles()
        self._create_scrollable_container()
        self._create_header()
        self._create_scan_options()
        self._create_progress_section()
        self._create_status_section()
        self._create_additional_sections()
        self._create_footer()
        
        # Update scroll region after all widgets are created
        self.root.after(100, self._update_scroll_region)
        
        # Initialize backend components
        self._initialize_backend()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def _create_scrollable_container(self):
        """Create a scrollable container for all content."""
        # Create main container frame
        self.main_container = tk.Frame(self.root, bg="#f5f5f5")
        self.main_container. pack(fill=tk.BOTH, expand=True)
        
        # Create canvas for scrolling
        self.canvas = tk.Canvas(self.main_container, bg="#f5f5f5", highlightthickness=0)
        
        # Create vertical scrollbar
        self.scrollbar = ttk.Scrollbar(self. main_container, orient=tk.VERTICAL, command=self.canvas.yview)
        
        # Create scrollable frame inside canvas
        self.scrollable_frame = tk.Frame(self. canvas, bg="#f5f5f5")
        
        # Configure canvas scrolling
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        # Create window inside canvas
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        
        # Configure canvas to expand with window
        self.canvas.configure(yscrollcommand=self. scrollbar.set)
        
        # Bind canvas resize to adjust scrollable frame width
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        
        # Pack scrollbar and canvas
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Bind mousewheel for scrolling
        self._bind_mousewheel()
    
    def _on_canvas_configure(self, event):
        """Adjust the scrollable frame width when canvas is resized."""
        self.canvas.itemconfig(self. canvas_window, width=event.width)
    
    def _update_scroll_region(self):
        """Update the scroll region after widgets are created."""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    
    def _bind_mousewheel(self):
        """Bind mousewheel events for scrolling."""
        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
        def _bind_to_mousewheel(event):
            self.canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        def _unbind_from_mousewheel(event):
            self.canvas.unbind_all("<MouseWheel>")
        
        # Bind when mouse enters/leaves the canvas
        self.canvas.bind("<Enter>", _bind_to_mousewheel)
        self.canvas.bind("<Leave>", _unbind_from_mousewheel)
    
    def _create_styles(self):
        """Create custom styles for widgets."""
        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')
        except:
            pass
        
        # Enhanced progressbar style
        self.style.configure("Custom. Horizontal.TProgressbar",
                           troughcolor='#e0e0e0',
                           background='#4CAF50',
                           borderwidth=0,
                           thickness=22)
    
    def _create_header(self):
        """Create the header section."""
        # Gradient-like header with subtle shadow effect
        header_frame = tk. Frame(self.scrollable_frame, bg="#1976D2", height=90)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        # Title with better spacing
        title_label = tk. Label(
            header_frame,
            text="🛡️ Antivirus Protection Suite",
            font=("Segoe UI", 24, "bold"),
            bg="#1976D2",
            fg="white"
        )
        title_label.pack(side=tk.LEFT, padx=25, pady=20)
        
        # Real-time protection status with modern badge style
        rt_frame = tk.Frame(header_frame, bg="#1976D2")
        rt_frame.pack(side=tk.RIGHT, padx=25, pady=20)
        
        rt_label = tk.Label(
            rt_frame,
            text="Real-Time Protection:",
            font=("Segoe UI", 11),
            bg="#1976D2",
            fg="#E3F2FD"
        )
        rt_label.pack(side=tk.LEFT, padx=(0, 8))
        
        self.rt_status_label = tk.Label(
            rt_frame,
            textvariable=self.realtime_status_var,
            font=("Segoe UI", 11, "bold"),
            bg="#1976D2",
            fg="white"
        )
        self.rt_status_label.pack(side=tk.LEFT)
    
    def _create_scan_options(self):
        """Create the scan options section."""
        section_frame = tk.LabelFrame(
            self.scrollable_frame,
            text=" Scan Options ",
            font=("Segoe UI", 13, "bold"),
            bg="#ffffff",
            fg="#1976D2",
            padx=20,
            pady=20,
            relief=tk.FLAT,
            borderwidth=2
        )
        section_frame.pack(fill=tk.X, padx=25, pady=(25, 12))
        
        buttons_frame = tk.Frame(section_frame, bg="#ffffff")
        buttons_frame.pack(expand=True)
        
        # Modern button style with hover effects
        button_config = {
            "font": ("Segoe UI", 11, "bold"),
            "fg": "white",
            "width": 19,
            "height": 2,
            "cursor": "hand2",
            "relief": tk.FLAT,
            "borderwidth": 0
        }
        
        # Row 1: Quick Scan and Full Scan
        row1_frame = tk.Frame(buttons_frame, bg="#ffffff")
        row1_frame.pack(pady=(0, 12))
        
        self.quick_scan_btn = tk.Button(
            row1_frame,
            text="⚡ Quick Scan",
            bg="#43A047",
            activebackground="#388E3C",
            command=self._start_quick_scan,
            **button_config
        )
        self.quick_scan_btn. pack(side=tk.LEFT, padx=10)
        
        self.full_scan_btn = tk.Button(
            row1_frame,
            text="🔍 Full Scan",
            bg="#1976D2",
            activebackground="#1565C0",
            command=self._start_full_scan,
            **button_config
        )
        self.full_scan_btn.pack(side=tk. LEFT, padx=10)
        
        # Row 2: Scan File and Scan Folder
        row2_frame = tk.Frame(buttons_frame, bg="#ffffff")
        row2_frame.pack(pady=(0, 5))
        
        self.scan_file_btn = tk.Button(
            row2_frame,
            text="📄 Scan File",
            bg="#FB8C00",
            activebackground="#F57C00",
            command=self._start_file_scan,
            **button_config
        )
        self.scan_file_btn.pack(side=tk.LEFT, padx=10)
        
        self.scan_folder_btn = tk.Button(
            row2_frame,
            text="📁 Scan Folder",
            bg="#8E24AA",
            activebackground="#7B1FA2",
            command=self._start_folder_scan,
            **button_config
        )
        self.scan_folder_btn.pack(side=tk.LEFT, padx=10)
    
    def _create_progress_section(self):
        """Create the progress bar section."""
        section_frame = tk.LabelFrame(
            self.scrollable_frame,
            text=" Scan Progress ",
            font=("Segoe UI", 13, "bold"),
            bg="#ffffff",
            fg="#1976D2",
            padx=20,
            pady=20,
            relief=tk.FLAT,
            borderwidth=2
        )
        section_frame.pack(fill=tk.X, padx=25, pady=12)
        
        # Enhanced progress bar
        self.progress_bar = ttk.Progressbar(
            section_frame,
            variable=self.progress_var,
            maximum=100,
            length=400,
            mode='determinate',
            style="Custom.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(fill=tk.X, pady=(0, 18))
        
        self.progress_percent_label = tk.Label(
            section_frame,
            text="0%",
            font=("Segoe UI", 16, "bold"),
            bg="#ffffff",
            fg="#43A047"
        )
        self.progress_percent_label. pack(pady=(0, 12))
        
        info_frame = tk.Frame(section_frame, bg="#ffffff")
        info_frame.pack(fill=tk.X, pady=(0, 18))
        
        # Status
        status_row = tk.Frame(info_frame, bg="#ffffff")
        status_row.pack(fill=tk.X, pady=3)
        tk.Label(
            status_row,
            text="Status:",
            font=("Segoe UI", 10, "bold"),
            bg="#ffffff",
            fg="#424242",
            width=12,
            anchor="w"
        ).pack(side=tk.LEFT)
        tk.Label(
            status_row,
            textvariable=self.status_var,
            font=("Segoe UI", 10),
            bg="#ffffff",
            fg="#757575",
            anchor="w"
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Current file
        file_row = tk.Frame(info_frame, bg="#ffffff")
        file_row.pack(fill=tk.X, pady=3)
        tk.Label(
            file_row,
            text="Current File:",
            font=("Segoe UI", 10, "bold"),
            bg="#ffffff",
            fg="#424242",
            width=12,
            anchor="w"
        ).pack(side=tk.LEFT)
        tk.Label(
            file_row,
            textvariable=self.current_file_var,
            font=("Segoe UI", 9),
            bg="#ffffff",
            fg="#757575",
            anchor="w"
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Files scanned
        count_row = tk.Frame(info_frame, bg="#ffffff")
        count_row.pack(fill=tk.X, pady=3)
        tk.Label(
            count_row,
            text="Progress:",
            font=("Segoe UI", 10, "bold"),
            bg="#ffffff",
            fg="#424242",
            width=12,
            anchor="w"
        ).pack(side=tk.LEFT)
        tk.Label(
            count_row,
            textvariable=self.files_scanned_var,
            font=("Segoe UI", 10),
            bg="#ffffff",
            fg="#757575",
            anchor="w"
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Control button (Cancel only)
        control_frame = tk.Frame(section_frame, bg="#ffffff")
        control_frame.pack(pady=(12, 0))
        
        self.cancel_btn = tk. Button(
            control_frame,
            text="❌ Cancel Scan",
            font=("Segoe UI", 11, "bold"),
            bg="#D32F2F",
            fg="white",
            activebackground="#C62828",
            width=18,
            height=1,
            cursor="hand2",
            relief=tk.FLAT,
            state=tk.DISABLED,
            command=self._cancel_scan
        )
        self.cancel_btn.pack()
    
    def _create_status_section(self):
        """Create the status messages section."""
        section_frame = tk.LabelFrame(
            self.scrollable_frame,
            text=" Activity Log ",
            font=("Segoe UI", 13, "bold"),
            bg="#ffffff",
            fg="#1976D2",
            padx=15,
            pady=15,
            relief=tk.FLAT,
            borderwidth=2
        )
        section_frame.pack(fill=tk.X, padx=25, pady=12)
        
        text_frame = tk.Frame(section_frame, bg="#ffffff")
        text_frame.pack(fill=tk.X)
        
        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.status_text = tk.Text(
            text_frame,
            font=("Consolas", 9),
            bg="#263238",
            fg="#00E676",
            height=6,
            wrap=tk.WORD,
            state=tk.DISABLED,
            yscrollcommand=scrollbar.set,
            relief=tk.FLAT,
            padx=8,
            pady=8
        )
        self.status_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        scrollbar.config(command=self. status_text.yview)
        
        self.status_text.tag_configure("info", foreground="#29B6F6")
        self.status_text.tag_configure("success", foreground="#00E676")
        self.status_text.tag_configure("warning", foreground="#FFD600")
        self.status_text.tag_configure("error", foreground="#FF5252")
        self.status_text.tag_configure("threat", foreground="#FF1744", font=("Consolas", 9, "bold"))
    
    def _create_additional_sections(self):
        """Create additional navigation buttons."""
        section_frame = tk.LabelFrame(
            self.scrollable_frame,
            text=" Quick Actions ",
            font=("Segoe UI", 13, "bold"),
            bg="#ffffff",
            fg="#1976D2",
            padx=25,
            pady=20,
            relief=tk. FLAT,
            borderwidth=2
        )
        section_frame.pack(fill=tk.X, padx=25, pady=(12, 18))
        
        nav_container = tk.Frame(section_frame, bg="#ffffff")
        nav_container.pack(expand=True, pady=12)
        
        action_button_config = {
            "font": ("Segoe UI", 11, "bold"),
            "fg": "white",
            "width": 15,
            "height": 2,
            "cursor": "hand2",
            "relief": tk.FLAT
        }
        
        tk.Button(
            nav_container,
            text="🗑️ Quarantine",
            bg="#E91E63",
            activebackground="#C2185B",
            command=self._show_quarantine,
            **action_button_config
        ).pack(side=tk.LEFT, padx=8)
        
        tk.Button(
            nav_container,
            text="📜 History",
            bg="#3F51B5",
            activebackground="#303F9F",
            command=self._show_history,
            **action_button_config
        ).pack(side=tk.LEFT, padx=8)
        
        tk.Button(
            nav_container,
            text="📊 Statistics",
            bg="#00897B",
            activebackground="#00796B",
            command=self._show_statistics,
            **action_button_config
        ).pack(side=tk.LEFT, padx=8)
        
        tk.Button(
            nav_container,
            text="⚙️ Settings",
            bg="#546E7A",
            activebackground="#455A64",
            command=self._show_settings,
            **action_button_config
        ).pack(side=tk.LEFT, padx=8)
    
    def _create_footer(self):
        """Create the footer section."""
        footer_frame = tk.Frame(self.scrollable_frame, bg="#ECEFF1", height=35)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        footer_label = tk.Label(
            footer_frame,
            text="© 2025 Antivirus Protection Suite | University Project",
            font=("Segoe UI", 9),
            bg="#ECEFF1",
            fg="#546E7A"
        )
        footer_label.pack(pady=8)

    # =========================================================================
    # BACKEND INITIALIZATION
    # =========================================================================
    
    def _initialize_backend(self):
        """Initialize backend components."""
        try:
            from database.db import init_db
            from core.quarantine import create_quarantine_folder
            from core.realtime import start_realtime_monitoring, get_monitoring_status
            
            init_db()
            self._log_message("Database initialized", "info")
            
            create_quarantine_folder()
            self._log_message("Quarantine folder ready", "info")
            
            start_realtime_monitoring(
                on_threat_found=self._on_threat_found,
                on_file_scanned=self._on_file_scanned_realtime,
                on_usb_inserted=self._on_usb_inserted,
                on_usb_removed=self._on_usb_removed
            )
            self._log_message("Real-time protection started", "success")
            self. realtime_status_var.set("🟢 Active")
            
        except Exception as e: 
            self._log_message(f"Initialization warning: {e}", "warning")
            self.realtime_status_var.set("🔴 Inactive")
    
    # =========================================================================
    # LOGGING
    # =========================================================================
    
    def _log_message(self, message, msg_type="info"):
        """Add a message to the status text widget."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.status_text.config(state=tk.NORMAL)
        self.status_text. insert(tk.END, f"[{timestamp}] ", "info")
        self.status_text.insert(tk.END, f"{message}\n", msg_type)
        self.status_text.see(tk.END)
        self.status_text.config(state=tk.DISABLED)
    
    # =========================================================================
    # SCAN METHODS
    # =========================================================================
    
    def _update_button_states(self, scanning=False):
        """Update button states based on scan status."""
        if scanning:
            self.quick_scan_btn.config(state=tk. DISABLED)
            self.full_scan_btn.config(state=tk.DISABLED)
            self.scan_file_btn.config(state=tk.DISABLED)
            self.scan_folder_btn.config(state=tk. DISABLED)
            # ✅ Cancel button is handled separately in _update_progress_ui
        else:
            self. quick_scan_btn.config(state=tk.NORMAL)
            self.full_scan_btn.config(state=tk. NORMAL)
            self.scan_file_btn.config(state=tk.NORMAL)
            self.scan_folder_btn.config(state=tk.NORMAL)
            self. cancel_btn.config(state=tk.DISABLED)
    
    def _show_scan_started_dialog(self, scan_type):
        """Show scan started modal dialog."""
        messagebox.showinfo(
            "Scan Started",
            f"{scan_type} has been initiated.\n\nPlease wait while the scan is in progress.. .",
        )
    
    def _show_scan_completed_dialog(self, scan_type, total_files, threats_found):
        """Show scan completed modal dialog."""
        if threats_found > 0:
            messagebox. showwarning(
                "Scan Completed",
                f"{scan_type} Completed!\n\n"
                f"📁 Total Files Scanned: {total_files}\n"
                f"⚠️ Threats Found:  {threats_found}\n\n"
                f"Infected files have been quarantined.\nCheck the Quarantine section for details."
            )
        else:
            messagebox.showinfo(
                "Scan Completed",
                f"{scan_type} Completed Successfully!\n\n"
                f"📁 Total Files Scanned: {total_files}\n"
                f"✅ No threats detected!\n\n"
                f"Your system is clean and secure."
            )
    
    def _progress_callback(self, current_file, scanned, total, location=None):
        """Callback for scan progress updates."""
        if self.cancel_requested:
            return False
        
        # Avoid division by zero
        percent = (scanned / total * 100) if total > 0 else 0
        self.root.after(0, lambda: self._update_progress_ui(percent, current_file, scanned, total))
        return True
    
    def _update_progress_ui(self, percent, current_file, scanned, total):
        """Update progress UI elements."""
        self.progress_var.set(percent)
        self.progress_percent_label.config(text=f"{percent:.1f}%")
        self.current_file_var.set(self._truncate_path(current_file, 60))
        self.files_scanned_var.set(f"{scanned} / {total} files")
        
        # ✅ FIX: Enable cancel button only when progress > 0
        if percent > 0 and not self.scan_started:
            self.scan_started = True
            self. cancel_btn.config(state=tk.NORMAL)
            self.status_var.set("Scanning...")
    
    def _truncate_path(self, path, max_length):
        """Truncate file path for display."""
        if len(path) <= max_length:
            return path
        return "..." + path[-(max_length - 3):]
    
    def _start_quick_scan(self):
        """Start quick scan."""
        self._log_message("Starting Quick Scan.. .", "info")
        self._show_scan_started_dialog("Quick Scan")
        self._start_scan_thread("quick")
    
    def _start_full_scan(self):
        """Start full scan."""
        self._log_message("Starting Full System Scan...", "info")
        self._show_scan_started_dialog("Full Scan")
        self._start_scan_thread("full")
    
    def _start_file_scan(self):
        """Start file scan with file chooser."""
        file_path = filedialog.askopenfilename(
            title="Select File to Scan",
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            self._log_message(f"Scanning file: {file_path}", "info")
            self._start_scan_thread("file", target=file_path)
    
    def _start_folder_scan(self):
        """Start folder scan with folder chooser."""
        folder_path = filedialog.askdirectory(title="Select Folder to Scan")
        if folder_path:
            self._log_message(f"Scanning folder: {folder_path}", "info")
            self._show_scan_started_dialog("Folder Scan")
            self._start_scan_thread("folder", target=folder_path)
    
    def _start_scan_thread(self, scan_type, target=None):
        """Start scan in a background thread."""
        self.is_scanning = True
        self. cancel_requested = False
        self.scan_started = False  # ✅ Reset scan started flag
        self. scan_results = []
        
        self._update_button_states(scanning=True)
        # ✅ Set initializing status
        self.status_var.set("Initializing scan...")
        
        # ✅ Reset UI to clean state
        self._reset_progress_ui()
        
        self. current_scan_thread = threading.Thread(
            target=self._run_scan,
            args=(scan_type, target),
            daemon=True
        )
        self.current_scan_thread.start()
    
    def _reset_progress_ui(self):
        """Reset progress UI to default state."""
        self.progress_var.set(0)
        self.progress_percent_label. config(text="0%")
        self.current_file_var.set("Preparing scan...")
        self.files_scanned_var.set("0 / 0 files")
        self.cancel_btn.config(state=tk.DISABLED)  # ✅ Disable until progress starts
    
    def _run_scan(self, scan_type, target=None):
        """Run the scan (executed in background thread)."""
        try:
            from core.scanner import scan_file, scan_folder, quick_scan, full_scan
            from database.models import save_scan_log, save_threat_record
            from core.quarantine import quarantine_file
            
            start_time = time.time()
            threats_found = []
            total_files = 0
            files_scanned = 0
            
            if scan_type == "quick":
                result = quick_scan(progress_callback=self._progress_callback)
                total_files = result. get('total_files', 0)
                files_scanned = result.get('files_scanned', 0)
                threats_found = result.get('threats', [])
                
            elif scan_type == "full": 
                result = full_scan(target_path=target, progress_callback=self._progress_callback)
                total_files = result.get('total_files', 0)
                files_scanned = result. get('files_scanned', 0)
                threats_found = result.get('threats', [])
                
            elif scan_type == "file":
                # ✅ Enable cancel immediately for single file scan
                self.root.after(0, lambda: self. cancel_btn.config(state=tk.NORMAL))
                self.scan_started = True
                
                result = scan_file(target)
                total_files = 1
                files_scanned = 1
                if result. get('status') == 'infected':
                    result['file'] = target
                    threats_found = [result]
                self.root.after(0, lambda: self._update_progress_ui(100, target, 1, 1))
                
            elif scan_type == "folder":
                result = self._scan_folder_with_progress(target)
                total_files = result.get('total', 0)
                files_scanned = result.get('scanned', 0)
                threats_found = result.get('threats', [])
            
            duration = time.time() - start_time
            
            # Check if scan was cancelled
            if self.cancel_requested:
                self.root.after(0, lambda: self._scan_cancelled(
                    scan_type, files_scanned, total_files, threats_found
                ))
                return
            
            # Process threats
            for threat in threats_found:
                file_path = threat.get("file", "")
                virus_name = threat.get("virus_name", "Unknown")

                self.root.after(
                    0,
                    lambda f=file_path, v=virus_name: self._log_message(
                        f"⚠️ THREAT DETECTED: {v} in {f}", "threat"
                    ),
                )

                # REMOVED: Individual popup for each threat

                try:
                    quarantine_file(file_path, virus_name)
                    self.root.after(
                        0,
                        lambda f=file_path: self._log_message(
                            f"File quarantined: {f}", "warning"
                        ),
                    )
                except Exception as e:
                    self.root.after(
                        0,
                        lambda e=e: self._log_message(
                            f"Quarantine failed: {e}", "error"
                        ),
                    )

            # ✅ ADDED: Show SINGLE consolidated popup after all threats processed
            if threats_found:
                self.root.after(
                    0,
                    lambda: self._show_threats_summary_popup(
                        threats_found, scan_type
                    ),
                )

            
            # Save scan log
            try:
                save_scan_log(
                    scan_type=scan_type,
                    total_files=total_files,
                    files_scanned=files_scanned,
                    files_infected=len(threats_found),
                    scan_duration=duration
                )
            except Exception as e:
                print(f"Failed to save scan log: {e}")
            
            # Complete the scan
            self.root.after(0, lambda: self._scan_completed(
                scan_type, total_files, len(threats_found), duration
            ))
            
        except Exception as e:
            self. root.after(0, lambda: self._scan_error(str(e)))
    
    def _scan_folder_with_progress(self, folder_path):
        """Scan folder with detailed progress tracking."""
        from core.scanner import scan_file
        
        results = []
        threats = []
        
        total_files = 0
        for root, dirs, files in os. walk(folder_path):
            total_files += len(files)
        
        scanned = 0
        
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if self.cancel_requested:
                    break
                    
                full_path = os.path.join(root, file)
                result = scan_file(full_path)
                results.append(result)
                
                if result.get('status') == 'infected':
                    result['file'] = full_path
                    threats.append(result)
                
                scanned += 1
                
                if not self._progress_callback(full_path, scanned, total_files):
                    break
            
            if self.cancel_requested:
                break
        
        return {
            'total': total_files,
            'scanned': scanned,
            'threats': threats,
            'results':  results
        }
    
    def _scan_completed(self, scan_type, total_files, threats_found, duration):
        """Handle scan completion."""
        # ✅ CRITICAL: Reset ALL state flags
        self.is_scanning = False
        self.cancel_requested = False
        self.scan_started = False
        
        self._update_button_states(scanning=False)
        self. status_var.set("Ready")  # ✅ Reset to default
        
        # ✅ Reset progress UI to clean state
        self. progress_var.set(0)
        self.progress_percent_label.config(text="0%")
        self.current_file_var.set("No scan in progress")
        self.files_scanned_var.set("0 / 0 files")
        self.cancel_btn.config(state=tk.DISABLED)
        
        self._log_message(
            f"Scan completed:  {total_files} files scanned, {threats_found} threats found, Duration: {duration:. 1f}s",
            "success" if threats_found == 0 else "warning"
        )
        
        scan_type_display = {
            "quick": "Quick Scan",
            "full": "Full Scan",
            "file": "File Scan",
            "folder": "Folder Scan"
        }.get(scan_type, "Scan")
        
        self._show_scan_completed_dialog(scan_type_display, total_files, threats_found)
    
    def _scan_cancelled(self, scan_type, files_scanned, total_files, threats_found):
        """Handle scan cancellation."""
        # ✅ CRITICAL: Reset ALL state flags
        self.is_scanning = False
        self.cancel_requested = False
        self.scan_started = False
        
        self._update_button_states(scanning=False)
        self.status_var. set("Ready")  # ✅ Reset to default
        
        # ✅ Reset progress UI to clean state
        self.progress_var.set(0)
        self.progress_percent_label.config(text="0%")
        self.current_file_var. set("No scan in progress")
        self.files_scanned_var.set("0 / 0 files")
        self.cancel_btn.config(state=tk.DISABLED)
        
        self._log_message(
            f"Scan cancelled: {files_scanned}/{total_files} files scanned, {len(threats_found)} threats found",
            "warning"
        )
        
        messagebox.showinfo(
            "Scan Cancelled",
            f"The scan was cancelled by user.\n\n"
            f"Files Scanned: {files_scanned} / {total_files}\n"
            f"Threats Found:  {len(threats_found)}\n\n"
            f"You can start a new scan anytime."
        )
    
    def _scan_error(self, error_message):
        """Handle scan error."""
        # ✅ CRITICAL: Reset ALL state flags
        self.is_scanning = False
        self. cancel_requested = False
        self.scan_started = False
        
        self._update_button_states(scanning=False)
        self.status_var.set("Ready")  # ✅ Reset to default
        
        # ✅ Reset progress UI
        self._reset_progress_ui()
        self.current_file_var.set("No scan in progress")
        
        self._log_message(f"Scan error: {error_message}", "error")
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n\n{error_message}")

    def _show_threats_summary_popup(self, threats_list, scan_type):
        """Show single consolidated popup for all threats found in scan."""
        threat_count = len(threats_list)

        # Build threat details (show max 10, then summarize rest)
        threat_details = "\n".join([
            f"• {os.path.basename(t.get('file', 'Unknown'))}: {t.get('virus_name', 'Unknown')}"
            for t in threats_list[:10]
        ])

        if threat_count > 10:
            threat_details += f"\n... and {threat_count - 10} more"

        scan_type_display = scan_type.upper() if scan_type else "SCAN"

        messagebox.showwarning(
            "⚠️ Threats Detected",
            f"{scan_type_display} found {threat_count} threat(s)!\n\n"
            f"{threat_details}\n\n"
            f"✅ All infected files have been quarantined.\n"
            f"Check Quarantine section to manage them."
        )
    
    def _cancel_scan(self):
        """Cancel the current scan."""
        if self.is_scanning and self.scan_started:
            self.cancel_requested = True
            self.status_var.set("Cancelling scan...")
            self._log_message("Cancellation requested by user.. .", "warning")
            self. cancel_btn.config(state=tk.DISABLED)
    
    # =========================================================================
    # REAL-TIME MONITORING CALLBACKS
    # =========================================================================
    
    def _on_threat_found(self, file_path, result):
        """Callback when threat is detected by real-time monitoring."""
        virus_name = result.get('virus_name', 'Unknown Threat')
        self. root.after(0, lambda: self._log_message(
            f"🚨 REAL-TIME THREAT:  {virus_name} detected in {file_path}", "threat"
        ))
        self.root.after(0, lambda: messagebox.showwarning(
            "Threat Detected! ",
            f"Real-time protection detected a threat!\n\n"
            f"File: {file_path}\n"
            f"Threat: {virus_name}\n\n"
            f"The file has been automatically quarantined."
        ))
    
    def _on_file_scanned_realtime(self, file_path, result):
        """Callback when file is scanned by real-time monitoring."""
        if result.get('status') == 'clean':
            filename = os.path.basename(file_path)
            self.root.after(0, lambda: self._log_message(
                f"Real-time scan:  {filename} - Clean", "success"
            ))
    
    def _on_usb_inserted(self, drive_path):
        """Callback when USB is inserted."""
        self.root. after(0, lambda: self._log_message(
            f"USB device detected: {drive_path} - Auto-scanning initiated.. .", "info"
        ))
        self.root.after(0, lambda: messagebox.showinfo(
            "USB Device Detected",
            f"USB drive detected: {drive_path}\n\nAutomatic security scan started..."
        ))
    
    def _on_usb_removed(self, drive_path):
        """Callback when USB is removed."""
        self.root.after(0, lambda: self._log_message(
            f"USB device removed: {drive_path}", "info"
        ))
    
    # =========================================================================
    # ADDITIONAL SECTIONS
    # =========================================================================
    
    def _show_quarantine(self):
        """Show quarantine management window."""
        QuarantineWindow(self.root, self._log_message)
    
    def _show_history(self):
        """Show scan history window."""
        HistoryWindow(self.root)
    
    def _show_statistics(self):
        """Show statistics window."""
        StatisticsWindow(self.root)
    
    def _show_settings(self):
        """Show settings window."""
        SettingsWindow(self.root, self._update_realtime_status)
    
    def _update_realtime_status(self, is_active):
        """Update real-time protection status display."""
        if is_active:
            self. realtime_status_var.set("🟢 Active")
        else:
            self.realtime_status_var.set("🔴 Inactive")
    
    # =========================================================================
    # WINDOW MANAGEMENT
    # =========================================================================
    
    def _on_closing(self):
        """Handle window close event."""
        # ✅ CRITICAL: Check BOTH flags
        if self.is_scanning and self.scan_started and not self.cancel_requested:
            response = messagebox.askyesnocancel(
                "Scan In Progress",
                "A scan is currently in progress.\n\nDo you want to cancel the scan and exit?"
            )
            if response is None:  # User clicked Cancel
                return
            elif response:   # User clicked Yes
                self. cancel_requested = True
                # Give the thread a moment to acknowledge cancellation
                self.root.after(500, self._force_close)
                return
            else:  # User clicked No
                return
        
        # No scan in progress or already cancelled - safe to close
        try:
            from core.realtime import stop_realtime_monitoring
            stop_realtime_monitoring()
        except:
            pass
        
        self.root.destroy()
    
    def _force_close(self):
        """Force close after giving thread time to cancel."""
        try:
            from core.realtime import stop_realtime_monitoring
            stop_realtime_monitoring()
        except:
            pass
        self.root.destroy()


# =============================================================================
# ADDITIONAL WINDOWS (QuarantineWindow, HistoryWindow, StatisticsWindow, SettingsWindow)
# =============================================================================

class QuarantineWindow: 
    """Quarantine management window."""
    
    def __init__(self, parent, log_callback=None):
        self.window = tk.Toplevel(parent)
        self.window.title("🗑️ Quarantine Management")
        self.window.geometry("750x550")
        self.window.configure(bg="#f5f5f5")
        self.log_callback = log_callback
        
        self._create_widgets()
        self._load_quarantine_list()
    
    def _create_widgets(self):
        """Create quarantine window widgets."""
        title_label = tk.Label(
            self.window, text="🗑️ Quarantine Management",
            font=("Segoe UI", 18, "bold"), bg="#f5f5f5", fg="#1976D2"
        )
        title_label.pack(pady=20)
        
        # Move buttons to BOTTOM first so they don't get squeezed by the list
        btn_frame = tk.Frame(self.window, bg="#f5f5f5")
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=25, pady=15)
        
        tk.Button(btn_frame, text="🗑️ Delete All", font=("Segoe UI", 10, "bold"),
                  bg="#C62828", fg="white", width=15, relief=tk.FLAT,
                  activebackground="#B71C1C", cursor="hand2",
                  command=self._delete_all).pack(side=tk.RIGHT, padx=5)
        
        tk.Button(btn_frame, text="🗑️ Delete", font=("Segoe UI", 10, "bold"),
                  bg="#D32F2F", fg="white", width=15, relief=tk.FLAT,
                  activebackground="#C62828", cursor="hand2",
                  command=self._delete_selected).pack(side=tk.RIGHT, padx=5)
        
        tk.Button(btn_frame, text="♻️ Restore", font=("Segoe UI", 10, "bold"),
                  bg="#43A047", fg="white", width=15, relief=tk. FLAT,
                  activebackground="#388E3C", cursor="hand2",
                  command=self._restore_selected).pack(side=tk.RIGHT, padx=5)
        
        tk.Button(btn_frame, text="🔄 Refresh", font=("Segoe UI", 10, "bold"),
                  bg="#546E7A", fg="white", width=15, relief=tk. FLAT,
                  activebackground="#455A64", cursor="hand2",
                  command=self._load_quarantine_list).pack(side=tk.RIGHT, padx=5)

        # Container for List (takes remaining space)
        list_frame = tk.Frame(self.window, bg="#ffffff", relief=tk.FLAT, borderwidth=2)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=(5, 10))

        columns = ("Name", "Virus", "Date", "Size")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        self.tree.heading("Name", text="File Name")
        self.tree.heading("Virus", text="Virus Name")
        self.tree.heading("Date", text="Quarantine Date")
        self.tree.heading("Size", text="Size")
        
        self.tree.column("Name", width=220)
        self.tree.column("Virus", width=170)
        self.tree.column("Date", width=170)
        self.tree.column("Size", width=100)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree. pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk. LEFT, fill=tk.Y, pady=5, padx=(0, 5))
    
    def _load_quarantine_list(self):
        for item in self.tree.get_children():
            self.tree. delete(item)
        try:
            from core.quarantine import list_quarantined_files, format_file_size
            files = list_quarantined_files()
            for file in files: 
                self.tree.insert("", tk.END, values=(
                    file. get('original_name', 'Unknown'),
                    file.get('virus_name', 'Unknown'),
                    file.get('quarantine_date', 'Unknown'),
                    format_file_size(file.get('file_size', 0))
                ), tags=(file.get('quarantine_name'),))
        except Exception as e: 
            messagebox.showerror("Error", f"Failed to load quarantine list:\n{e}")
    
    def _restore_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Restore", "Please select a file to restore.")
            return
        item = self.tree.item(selected[0])
        quarantine_name = item['tags'][0] if item['tags'] else None
        if quarantine_name: 
            if messagebox.askyesno("Restore File", f"Restore '{item['values'][0]}'?\n\nWarning: Only restore if you're certain the file is safe. "):
                try:
                    from core.quarantine import restore_file
                    result = restore_file(quarantine_name)
                    if result. get('status') == 'success':  
                        messagebox.showinfo("Success", "File restored successfully!")
                        if self.log_callback:
                            self.log_callback(f"File restored: {item['values'][0]}", "success")
                        self._load_quarantine_list()
                    else:
                        messagebox. showerror("Error", result.get('message', 'Restore failed'))
                except Exception as e:  
                    messagebox.showerror("Error", f"Restore failed:\n{e}")
    
    def _delete_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox. showinfo("Delete", "Please select a file to delete.")
            return
        item = self.tree. item(selected[0])
        quarantine_name = item['tags'][0] if item['tags'] else None
        if quarantine_name:  
            if messagebox.askyesno("Confirm Deletion", f"Permanently delete '{item['values'][0]}'?\n\nThis action cannot be undone."):
                try:  
                    from core.quarantine import delete_file
                    result = delete_file(quarantine_name)
                    if result.get('status') == 'success': 
                        messagebox.showinfo("Deleted", "File permanently deleted!")
                        if self. log_callback:
                            self.log_callback(f"File deleted: {item['values'][0]}", "warning")
                        self._load_quarantine_list()
                    else:
                        messagebox.showerror("Error", result.get('message', 'Delete failed'))
                except Exception as e:
                    messagebox.showerror("Error", f"Delete failed:\n{e}")
    
    def _delete_all(self):
        if messagebox.askyesno("Confirm Delete All", "Permanently delete ALL quarantined files?\n\nThis action cannot be undone."):
            try: 
                from core.quarantine import delete_all_files
                result = delete_all_files()
                messagebox.showinfo("Deleted", f"Successfully deleted {result.get('deleted_count', 0)} file(s).")
                if self.log_callback:  
                    self.log_callback("All quarantined files deleted", "warning")
                self._load_quarantine_list()
            except Exception as e:
                messagebox. showerror("Error", f"Delete operation failed:\n{e}")


class HistoryWindow:  
    """Scan history window."""
    
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("📜 Scan History")
        self.window.geometry("850x550")
        self.window.configure(bg="#f5f5f5")
        self._create_widgets()
        self._load_history()
    
    def _create_widgets(self):
        title_label = tk.Label(
            self.window, text="📜 Scan History",
            font=("Segoe UI", 18, "bold"), bg="#f5f5f5", fg="#1976D2"
        )
        title_label.pack(pady=20)
        
        list_frame = tk.Frame(self.window, bg="#ffffff", relief=tk.FLAT, borderwidth=2)
        list_frame.pack(fill=tk. BOTH, expand=True, padx=25, pady=(5, 25))
        
        columns = ("ID", "Type", "Date", "Files", "Threats", "Duration")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=18)
        
        self.tree.heading("ID", text="ID")
        self.tree.heading("Type", text="Scan Type")
        self.tree.heading("Date", text="Date & Time")
        self.tree.heading("Files", text="Files Scanned")
        self.tree.heading("Threats", text="Threats")
        self.tree.heading("Duration", text="Duration")
        
        self.tree.column("ID", width=60)
        self.tree.column("Type", width=120)
        self.tree.column("Date", width=200)
        self.tree.column("Files", width=130)
        self.tree.column("Threats", width=100)
        self.tree.column("Duration", width=120)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk. VERTICAL, command=self.tree. yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y, pady=5, padx=(0, 5))
    
    def _load_history(self):
        """Load scan history from database."""
        try:
            from database.models import get_scan_history
            
            history = get_scan_history(limit=50)
            
            for scan in history:
                # Safe duration formatting
                raw_duration = scan.get('scan_duration_seconds')
                
                try:
                    if raw_duration is None:
                        duration_val = 0.0
                    else:
                        duration_val = float(raw_duration)
                except (ValueError, TypeError):
                    duration_val = 0.0
                
                duration = f"{duration_val:.1f}s"

                self.tree.insert("", tk.END, values=(
                    scan.get('id', ''),
                    str(scan.get('scan_type', '') or 'Unknown').upper(),
                    scan.get('scan_date', ''),
                    scan.get('files_scanned', 0),
                    scan.get('files_infected', 0),
                    duration
                ))
                
        except Exception as e: 
            print(f"History Error Details: {e}")
            messagebox.showerror("Error", f"Failed to load scan history:\n{e}")


class StatisticsWindow: 
    """Statistics dashboard window."""
    
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("📊 Statistics")
        self.window.geometry("650x550")
        self.window.configure(bg="#f5f5f5")
        self._create_widgets()
    
    def _create_widgets(self):
        title_label = tk.Label(
            self. window, text="📊 Antivirus Statistics",
            font=("Segoe UI", 18, "bold"), bg="#f5f5f5", fg="#1976D2"
        )
        title_label.pack(pady=25)
        
        stats_frame = tk.Frame(self.window, bg="#ffffff", padx=40, pady=35, relief=tk.FLAT, borderwidth=2)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(5, 30))
        
        try:
            from database.models import get_scan_statistics
            from core.quarantine import get_quarantine_stats
            
            scan_stats = get_scan_statistics() or {}
            quarantine_stats = get_quarantine_stats() or {}
            
            stats = [
                ("Total Scans Performed", scan_stats.get('total_scans', 0)),
                ("Total Files Scanned", scan_stats.get('total_files_scanned', 0)),
                ("Total Threats Found", scan_stats.get('total_threats_found', 0)),
                ("Average Scan Duration", f"{scan_stats.get('avg_scan_duration', 0):.1f}s"),
                ("", ""),
                ("Files in Quarantine", quarantine_stats.get('total_files', 0)),
                ("Quarantine Size", f"{quarantine_stats. get('total_size_mb', 0):.2f} MB"),
            ]
            
            for label, value in stats:
                if label == "":  
                    tk.Label(stats_frame, text="", bg="#ffffff", height=1).pack()
                    continue
                row = tk.Frame(stats_frame, bg="#ffffff")
                row.pack(fill=tk.X, pady=10)
                tk.Label(row, text=label + ":", font=("Segoe UI", 12, "bold"),
                         bg="#ffffff", fg="#424242", anchor="w", width=30).pack(side=tk.LEFT)
                tk.Label(row, text=str(value), font=("Segoe UI", 12),
                         bg="#ffffff", fg="#1976D2", anchor="e").pack(side=tk.RIGHT)
        except Exception as e:
            tk.Label(stats_frame, text=f"Error loading statistics:\n{e}",
                     font=("Segoe UI", 11), bg="#ffffff", fg="#D32F2F").pack(pady=20)


class SettingsWindow:
    """Settings window."""
    
    def __init__(self, parent, realtime_callback=None):
        self.window = tk.Toplevel(parent)
        self.window.title("⚙️ Settings")
        self.window.geometry("650x650")
        self.window.configure(bg="#f5f5f5")
        self.realtime_callback = realtime_callback
        self._create_widgets()
        self._load_settings()
    
    def _create_widgets(self):
        title_label = tk.Label(
            self. window, text="⚙️ Application Settings",
            font=("Segoe UI", 18, "bold"), bg="#f5f5f5", fg="#1976D2"
        )
        title_label.pack(pady=25)
        
        settings_frame = tk.Frame(self.window, bg="#ffffff", padx=40, pady=30, relief=tk.FLAT, borderwidth=2)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(5, 20))
        
        self. realtime_var = tk.BooleanVar()
        ttk.Checkbutton(settings_frame, text="Enable Real-Time Protection",
                        variable=self.realtime_var, command=self._toggle_realtime).pack(anchor="w", pady=12, fill=tk.X)
        
        self.auto_quarantine_var = tk.BooleanVar()
        ttk.Checkbutton(settings_frame, text="Auto-Quarantine Infected Files",
                        variable=self.auto_quarantine_var).pack(anchor="w", pady=12, fill=tk.X)
        
        self.monitor_downloads_var = tk.BooleanVar()
        ttk.Checkbutton(settings_frame, text="Monitor Downloads Folder",
                        variable=self. monitor_downloads_var).pack(anchor="w", pady=12, fill=tk.X)
        
        self.monitor_usb_var = tk.BooleanVar()
        ttk.Checkbutton(settings_frame, text="Auto-Scan USB Drives",
                        variable=self. monitor_usb_var).pack(anchor="w", pady=12, fill=tk.X)
        
        self.notifications_var = tk.BooleanVar()
        ttk.Checkbutton(settings_frame, text="Show Notifications",
                        variable=self.notifications_var).pack(anchor="w", pady=12, fill=tk.X)
        
        tk.Label(settings_frame, text="", bg="#ffffff", height=1).pack()
        
        size_frame = tk.Frame(settings_frame, bg="#ffffff")
        size_frame.pack(anchor="w", pady=15, fill=tk.X)
        tk.Label(size_frame, text="Max File Size to Scan (MB):",
                 bg="#ffffff", font=("Segoe UI", 11, "bold"), fg="#424242").pack(side=tk.LEFT)
        self.max_size_var = tk.StringVar(value="50")
        ttk.Entry(size_frame, textvariable=self.max_size_var, width=12, font=("Segoe UI", 11)).pack(side=tk.LEFT, padx=15)
        
        tk.Button(settings_frame, text="💾 Save Settings", font=("Segoe UI", 12, "bold"),
                  bg="#43A047", fg="white", width=22, height=2, relief=tk.FLAT,
                  activebackground="#388E3C", cursor="hand2",
                  command=self._save_settings).pack(pady=35)
    
    def _load_settings(self):
        try:
            from database.models import get_all_settings
            settings = get_all_settings()
            self.realtime_var.set(settings.get('realtime_protection', True))
            self.auto_quarantine_var.set(settings. get('auto_quarantine', True))
            self.monitor_downloads_var.set(settings.get('monitor_downloads', True))
            self.monitor_usb_var.set(settings.get('monitor_usb', True))
            self.notifications_var.set(settings.get('show_notifications', True))
            self.max_size_var.set(str(settings.get('max_file_size_mb', 50)))
        except Exception as e: 
            print(f"Failed to load settings: {e}")
    
    def _save_settings(self):
        try: 
            from database.models import save_setting
            save_setting('realtime_protection', self.realtime_var.get(), 'boolean')
            save_setting('auto_quarantine', self.auto_quarantine_var.get(), 'boolean')
            save_setting('monitor_downloads', self.monitor_downloads_var.get(), 'boolean')
            save_setting('monitor_usb', self. monitor_usb_var.get(), 'boolean')
            save_setting('show_notifications', self.notifications_var.get(), 'boolean')
            save_setting('max_file_size_mb', self.max_size_var.get(), 'integer')
            messagebox.showinfo("Success", "Settings saved successfully!")
        except Exception as e:
            messagebox. showerror("Error", f"Failed to save settings:\n{e}")
    
    def _toggle_realtime(self):
        try:
            from core.realtime import start_realtime_monitoring, stop_realtime_monitoring
            if self.realtime_var. get():
                start_realtime_monitoring()
                if self.realtime_callback:  
                    self.realtime_callback(True)
            else:
                stop_realtime_monitoring()
                if self.realtime_callback: 
                    self.realtime_callback(False)
        except Exception as e:  
            print(f"Failed to toggle real-time protection: {e}")


# =============================================================================
# MAIN APPLICATION ENTRY
# =============================================================================

def run_gui():
    """Run the GUI application."""
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()


if __name__ == "__main__": 
    run_gui()