# Install via: pip install pyperclip ttkbootstrap
# On Linux/WSL: sudo apt install xclip (for pyperclip functionality)
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import pyperclip
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import subprocess
from datetime import datetime
import threading
import queue
import os
import json
import platform
import logging
from functools import partial

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class UnifiedCommandTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Unified Command & VirtualEnv Tool")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Apply dark theme
        self.style = ttk.Style(theme="cyborg")
        self.style.configure("danger.TButton", foreground="white")
        
        # Setup command queue
        self.command_queue = queue.Queue()
        self.root.after(100, self.process_queue)
        
        # Initialize threat feeds
        self.threat_feeds = {}
        
        # VirtualEnv configuration
        self.show_popups = True
        self.terminal_output = None
        self.terminal_input_entry = None
        
        # Main container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Header
        self.create_header()
        
        # Main content area with tabs
        self.create_tab_interface()
        
        # Status bar
        self.create_status_bar()
        
        # Start monitoring
        self.start_threat_monitor()
    
    def create_header(self):
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill='x', pady=(0, 10))
        
        # App title
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(side='left', padx=15, pady=10)
        
        ttk.Label(
            title_frame, 
            text="🛡️ Unified Command & VirtualEnv Tool", 
            font=("Segoe UI", 18, "bold")
        ).pack(side='left')
        
        # Threat level indicator
        self.threat_level = ttk.Label(
            header_frame,
            text="🟢 THREAT LEVEL: NORMAL",
            foreground="green",
            font=("Segoe UI", 12, "bold")
        )
        self.threat_level.pack(side='right', padx=15)
        
        # Search functionality
        search_frame = ttk.Frame(header_frame)
        search_frame.pack(side='right', padx=15, pady=10)
        
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(
            search_frame,
            textvariable=self.search_var,
            width=30
        )
        search_entry.pack(side='left', padx=5)
        search_entry.insert(0, "Search commands...")
        
        ttk.Button(
            search_frame,
            text="Search",
            command=self.search_commands
        ).pack(side='left')

    def search_commands(self):
        """Placeholder for search functionality"""
        query = self.search_var.get()
        messagebox.showinfo(
            "Search", 
            f"Would search for: {query}\n(Search functionality to be implemented)",
            parent=self.root
        )

    def create_tab_interface(self):
        """Create the notebook with tabs"""
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill='both', expand=True)
        
        # Create merged Windows & CyberSec tab
        self.create_windows_cybersec_tab()
        
        # Create other tab frames
        self.linux_frame = ttk.Frame(self.notebook)
        self.venv_frame = ttk.Frame(self.notebook)
        
        # Add tabs to notebook
        self.notebook.add(self.linux_frame, text="🐧 Linux/WSL")
        self.notebook.add(self.venv_frame, text="🐍 VirtualEnv")
        
        # Populate tabs
        self.create_linux_ui()
        self.create_venv_ui()

    def create_windows_cybersec_tab(self):
        """Create merged Windows & CyberSec tab"""
        self.windows_cybersec_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.windows_cybersec_frame, text="🪟 Windows & CyberSec")
        
        # Main paned window
        paned = ttk.PanedWindow(self.windows_cybersec_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # Left pane - Windows Commands
        left_pane = ttk.Frame(paned)
        paned.add(left_pane, weight=1)
        
        # Windows Commands section
        cmd_frame = ttk.LabelFrame(left_pane, text="🪟 Windows Commands", padding=10)
        cmd_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create scrollable area for commands
        canvas = tk.Canvas(cmd_frame)
        scrollbar = ttk.Scrollbar(cmd_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Command categories
        categories = [
            {
                "name": "📂 File Operations",
                "commands": [
                    ("List Files", "Get-ChildItem", "List items in current directory"),
                    ("List Files (Detailed)", "Get-ChildItem | Format-Table", "Detailed list with properties"),
                    ("Create Directory", "New-Item -ItemType Directory -Name 'FolderName'", "Make new folder"),
                    ("Delete File", "Remove-Item 'FileName'", "Permanently delete a file"),
                    ("Show File Content", "Get-Content 'FileName'", "Display file contents")
                ]
            },
            {
                "name": "🌐 Network",
                "commands": [
                    ("Show IP Config", "ipconfig", "Display network configuration"),
                    ("Test Connection", "Test-NetConnection google.com", "Check internet connectivity"),
                    ("Flush DNS", "Clear-DnsClientCache", "Clear DNS resolver cache"),
                    ("Show Active Connections", "Get-NetTCPConnection", "List all TCP connections")
                ]
            },
            {
                "name": "🔧 System",
                "commands": [
                    ("Show Running Processes", "Get-Process", "List all running processes"),
                    ("Stop Process", "Stop-Process -Name 'ProcessName'", "Terminate a process"),
                    ("Show Services", "Get-Service", "List all services"),
                    ("Start Service", "Start-Service -Name 'ServiceName'", "Start a service"),
                    ("Show System Info", "Get-ComputerInfo", "Display system information")
                ]
            }
        ]
        
        # Create category sections
        for category in categories:
            frame = ttk.LabelFrame(
                scrollable_frame,
                text=category["name"],
                padding=10
            )
            frame.pack(fill='x', padx=5, pady=5, ipady=5)
            
            for cmd_name, cmd, description in category["commands"]:
                self.create_command_button(frame, cmd_name, cmd, description)
        
        # Right pane - CyberSec Dashboard
        right_pane = ttk.Frame(paned)
        paned.add(right_pane, weight=1)
        
        # Network Activity
        net_frame = ttk.LabelFrame(right_pane, text="🌐 Network Activity", padding=10)
        net_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.net_activity = scrolledtext.ScrolledText(
            net_frame,
            height=10,
            wrap=tk.WORD,
            bg='black',
            fg='lime',
            font=("Consolas", 9)
        )
        self.net_activity.pack(fill=tk.BOTH)
        self.net_activity.insert(tk.END, "Initializing network monitor...\n")
        
        btn_frame = ttk.Frame(net_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            btn_frame,
            text="Refresh",
            command=self.refresh_connections,
            style='info.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        # Clear Terminal button
        ttk.Button(
            btn_frame,
            text="Clear Terminal",
            command=self.clear_network_activity,
            style='warning.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        # Quick Actions
        action_frame = ttk.LabelFrame(right_pane, text="⚡ Quick Actions", padding=10)
        action_frame.pack(fill=tk.BOTH, padx=5, pady=5)
        
        actions = [
            ("Port Scan", self.run_port_scan),
            ("Process Audit", self.analyze_processes),
            ("Check Firewall", self.check_firewall),
            ("Security Scan", self.run_security_scan),
            ("Update Signatures", self.update_signatures)
        ]
        
        for text, cmd in actions:
            ttk.Button(
                action_frame,
                text=text,
                command=cmd,
                style='info.TButton',
                width=15
            ).pack(fill=tk.X, pady=2)

    def clear_network_activity(self):
        """Clear the network activity terminal"""
        self.net_activity.delete(1.0, tk.END)
        self.net_activity.insert(tk.END, "Network activity cleared.\n")

    def refresh_connections(self):
        """Refresh network connections"""
        def _run():
            try:
                result = subprocess.run(
                    ["powershell", "Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State | Format-Table"],
                    capture_output=True,
                    text=True
                )
                output = result.stdout if result.returncode == 0 else result.stderr
                self.command_queue.put((
                    self._update_net_activity,
                    output
                ))
            except Exception as e:
                self.command_queue.put((
                    self._show_error,
                    f"Connection refresh failed: {str(e)}"
                ))
        
        threading.Thread(target=_run, daemon=True).start()

    def _update_net_activity(self, text):
        """Update network activity display"""
        self.net_activity.delete(1.0, tk.END)
        self.net_activity.insert(tk.END, f"Last updated: {datetime.now().strftime('%H:%M:%S')}\n\n")
        self.net_activity.insert(tk.END, text)
        self.net_activity.see(tk.END)

    def run_port_scan(self):
        """Run port scan"""
        self._run_powershell_command("Test-NetConnection -ComputerName localhost -Port 80", "Port Scan")

    def analyze_processes(self):
        """Analyze running processes"""
        self._run_powershell_command("Get-Process | Sort-Object CPU -Descending | Select-Object -First 10", "Process Audit")

    def check_firewall(self):
        """Check firewall status"""
        self._run_powershell_command("Get-NetFirewallProfile | Format-Table Name, Enabled", "Firewall Check")

    def run_security_scan(self):
        """Run security scan"""
        self._run_powershell_command("Get-MpComputerStatus | Select-Object AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled", "Security Scan")

    def update_signatures(self):
        """Update security signatures"""
        self._run_powershell_command("Update-MpSignature", "Update Signatures")

    def _run_powershell_command(self, command, description):
        """Run PowerShell command and display results"""
        def _run():
            try:
                result = subprocess.run(
                    ["powershell", command],
                    capture_output=True,
                    text=True
                )
                output = result.stdout if result.returncode == 0 else result.stderr
                self.command_queue.put((
                    self._update_net_activity,
                    f"=== {description} ===\n{output}\n"
                ))
            except Exception as e:
                self.command_queue.put((
                    self._show_error,
                    f"{description} failed: {str(e)}"
                ))
        
        threading.Thread(target=_run, daemon=True).start()

    def _show_error(self, message):
        """Show error message"""
        messagebox.showerror("Error", message, parent=self.root)

    def process_queue(self):
        """Process commands from the queue"""
        while not self.command_queue.empty():
            func, arg = self.command_queue.get()
            func(arg)
        self.root.after(100, self.process_queue)

    def create_linux_ui(self):
        """Create Linux commands tab with organized structure and terminal"""
        # Main paned window for Linux tab
        paned = ttk.PanedWindow(self.linux_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # Left pane - Command Reference
        left_pane = ttk.Frame(paned)
        paned.add(left_pane, weight=1)
        
        # Command Reference with notebook
        cmd_notebook = ttk.Notebook(left_pane)
        cmd_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Define command categories
        command_categories = {
            "File Operations": [
                ("List Files", "ls -la", "List files with details"),
                ("Create Directory", "mkdir dirname", "Create new directory"),
                ("Delete File", "rm filename", "Delete a file"),
                ("Show File Content", "cat filename", "Display file contents"),
                ("Find File", "find /path -name filename", "Search for a file"),
                ("Copy File", "cp source dest", "Copy a file"),
                ("Move/Rename File", "mv oldname newname", "Move or rename a file"),
                ("Change Permissions", "chmod 755 file", "Change file permissions"),
                ("Change Owner", "chown user:group file", "Change file owner")
            ],
            "Network": [
                ("Show IP Config", "ip addr show", "Display network configuration"),
                ("Test Connection", "ping google.com", "Check internet connectivity"),
                ("Show Open Ports", "netstat -tuln", "List listening ports"),
                ("Show Active Connections", "ss -tuln", "Show active connections"),
                ("Show Routing Table", "ip route show", "Display routing table"),
                ("Trace Route", "traceroute google.com", "Trace network path"),
                ("Download File", "wget URL", "Download file from URL"),
                ("Show Network Stats", "netstat -s", "Show network statistics")
            ],
            "System": [
                ("Show Running Processes", "ps aux", "List all running processes"),
                ("Stop Process", "kill PID", "Terminate a process by PID"),
                ("Show Disk Usage", "df -h", "Display disk usage"),
                ("Show Memory Usage", "free -h", "Display memory usage"),
                ("Show System Info", "uname -a", "Display system information"),
                ("Show CPU Info", "lscpu", "Display CPU information"),
                ("Show Hardware Info", "lshw", "List hardware configuration"),
                ("Show System Load", "uptime", "Show system load average"),
                ("Show Running Services", "systemctl list-units --type=service", "List all services")
            ],
            "Security": [
                ("Check Firewall Status", "sudo ufw status", "Check UFW firewall status"),
                ("Enable Firewall", "sudo ufw enable", "Enable UFW firewall"),
                ("List Firewall Rules", "sudo ufw status verbose", "Show all firewall rules"),
                ("Block IP Address", "sudo ufw deny from IP", "Block specific IP address"),
                ("Check Open Ports", "sudo netstat -tulpn", "Show all listening ports with processes"),
                ("Show Failed Login Attempts", "sudo grep 'Failed password' /var/log/auth.log", "Check for failed SSH logins"),
                ("Show Active Users", "who", "List currently logged-in users"),
                ("Show Last Logins", "last", "Display recent login history"),
                ("Check System Logs", "sudo journalctl -xe", "View system logs"),
                ("Scan for Rootkits", "sudo rkhunter --check", "Run rootkit scan (requires rkhunter)"),
                ("Check for Malware", "sudo clamscan -r /", "Scan for malware (requires clamav)"),
                ("Update Security Patches", "sudo apt update && sudo apt upgrade -y", "Update system packages"),
                ("Show Listening Services", "sudo lsof -i", "List all open files and internet connections"),
                ("Check SSH Configuration", "sudo sshd -T", "Show SSH server configuration"),
                ("Audit File Permissions", "sudo find / -type f -perm /o=w", "Find world-writable files"),
                ("Check SUID Files", "sudo find / -perm -4000", "Find files with SUID bit set"),
                ("Show User Accounts", "sudo cat /etc/passwd", "List all user accounts"),
                ("Check Password Policy", "sudo chage -l username", "Show password policy for user")
            ]
        }
        
        # Create tabs for each category
        for category_name, commands in command_categories.items():
            tab_frame = ttk.Frame(cmd_notebook)
            cmd_notebook.add(tab_frame, text=category_name)
            
            # Create scrollable area for commands
            canvas = tk.Canvas(tab_frame, bg='#2d2d2d', highlightthickness=0)
            scrollbar = ttk.Scrollbar(tab_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)
            
            scrollable_frame.bind(
                "<Configure>",
                lambda e, canvas=canvas: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Add commands to the tab
            for cmd_name, cmd, description in commands:
                self.create_command_button(scrollable_frame, cmd_name, cmd, description)
        
        # Right pane - Linux Terminal
        right_pane = ttk.Frame(paned)
        paned.add(right_pane, weight=1)
        
        # Terminal section
        terminal_frame = ttk.LabelFrame(right_pane, text="🖥️ Linux Terminal", padding=10)
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Terminal output
        self.linux_terminal_output = scrolledtext.ScrolledText(
            terminal_frame,
            wrap=tk.WORD,
            bg='black',
            fg='#00ff00',
            font=("Consolas", 10),
            height=20
        )
        self.linux_terminal_output.pack(fill=tk.BOTH, expand=True)
        self.linux_terminal_output.insert(tk.END, "Linux Terminal Ready\n")
        self.linux_terminal_output.config(state='disabled')
        
        # Configure tags for terminal text styling
        self.linux_terminal_output.tag_config('normal', foreground='#00ff00')
        self.linux_terminal_output.tag_config('error', foreground='#ff6b6b')
        self.linux_terminal_output.tag_config('command', foreground='#00bfff', font=('Consolas', 10, 'bold'))
        
        # Terminal input section
        input_frame = ttk.Frame(terminal_frame)
        input_frame.pack(fill=tk.X, pady=(5, 0))
        input_frame.columnconfigure(0, weight=1)
        
        # Command input
        self.linux_command_input = ttk.Entry(input_frame)
        self.linux_command_input.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.linux_command_input.bind("<Return>", self.execute_linux_command)
        
        # Placeholder text
        self.linux_command_input.insert(0, "Enter Linux command...")
        self.linux_command_input.bind("<FocusIn>", self._clear_linux_placeholder)
        self.linux_command_input.bind("<FocusOut>", self._add_linux_placeholder)
        
        # Buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=0, column=1, sticky="e")
        
        ttk.Button(
            button_frame,
            text="Execute",
            command=self.execute_linux_command,
            style='success.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            button_frame,
            text="Clear",
            command=self.clear_linux_terminal,
            style='warning.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        # Quick commands section
        quick_frame = ttk.LabelFrame(right_pane, text="⚡ Quick Commands", padding=10)
        quick_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Quick command buttons
        quick_commands = [
            ("System Info", "uname -a"),
            ("Disk Usage", "df -h"),
            ("Memory Usage", "free -h"),
            ("Running Processes", "ps aux | head -20"),
            ("Network Connections", "ss -tuln"),
            ("System Logs", "journalctl -n 20"),
            ("Firewall Status", "sudo ufw status")
        ]
        
        for i, (name, cmd) in enumerate(quick_commands):
            row = i // 3
            col = i % 3
            ttk.Button(
                quick_frame,
                text=name,
                command=lambda c=cmd: self.quick_linux_command(c),
                style='info.TButton',
                width=15
            ).grid(row=row, column=col, padx=2, pady=2, sticky="ew")
        
        # Configure grid weights
        for i in range(3):
            quick_frame.grid_columnconfigure(i, weight=1)

    def _clear_linux_placeholder(self, event):
        """Clear placeholder text from Linux command input"""
        if self.linux_command_input.get() == "Enter Linux command...":
            self.linux_command_input.delete(0, tk.END)

    def _add_linux_placeholder(self, event):
        """Add placeholder text to Linux command input"""
        if not self.linux_command_input.get():
            self.linux_command_input.insert(0, "Enter Linux command...")

    def execute_linux_command(self, event=None):
        """Execute command in Linux terminal"""
        command = self.linux_command_input.get().strip()
        if not command or command == "Enter Linux command...":
            return
        
        self.linux_command_input.delete(0, tk.END)
        self._add_linux_placeholder(None)
        
        # Display command in terminal
        self.linux_terminal_output.config(state='normal')
        self.linux_terminal_output.insert(tk.END, f"$ {command}\n", 'command')
        self.linux_terminal_output.config(state='disabled')
        self.linux_terminal_output.see(tk.END)
        
        # Execute command in thread
        threading.Thread(target=self._run_linux_command, args=(command,), daemon=True).start()

    def quick_linux_command(self, command):
        """Execute a quick command"""
        self.linux_command_input.delete(0, tk.END)
        self.linux_command_input.insert(0, command)
        self.execute_linux_command()

    def _run_linux_command(self, command):
        """Run Linux command and capture output"""
        try:
            # Use shell=True for proper command execution
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                check=False,
                encoding='utf-8',
                errors='replace'
            )
            
            # Process output
            output = ""
            if process.stdout:
                output += process.stdout
            if process.stderr:
                output += process.stderr
            
            # Display output in terminal
            self.root.after(0, lambda: self._update_linux_terminal(output, process.returncode != 0))
            
        except Exception as e:
            error_msg = f"Error executing command: {str(e)}"
            self.root.after(0, lambda: self._update_linux_terminal(error_msg, True))

    def _update_linux_terminal(self, text, is_error=False):
        """Update Linux terminal with command output"""
        self.linux_terminal_output.config(state='normal')
        tag = 'error' if is_error else 'normal'
        self.linux_terminal_output.insert(tk.END, text + "\n", tag)
        self.linux_terminal_output.insert(tk.END, "\n")  # Add space after command output
        self.linux_terminal_output.config(state='disabled')
        self.linux_terminal_output.see(tk.END)

    def clear_linux_terminal(self):
        """Clear the Linux terminal"""
        self.linux_terminal_output.config(state='normal')
        self.linux_terminal_output.delete(1.0, tk.END)
        self.linux_terminal_output.insert(tk.END, "Terminal cleared\n")
        self.linux_terminal_output.config(state='disabled')

    def create_venv_ui(self):
        """Create Python Virtual Environment tab"""
        # Main container
        main_container = ttk.Frame(self.venv_frame)
        main_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Input fields and buttons for paths
        input_frame = ttk.Frame(main_container)
        input_frame.pack(fill='x', pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)
        
        self.env_entry = self._create_input_field(input_frame, "Virtual Env Path:", 0)
        self.script_entry = self._create_input_field(input_frame, "Script Path:", 1)
        self.py_path_entry = self._create_input_field(input_frame, "Python Executable Path:", 2)
        
        # Browse buttons for paths
        ttk.Button(input_frame, text="Browse Dir", command=partial(self.browse_path, self.env_entry, True)).grid(row=0, column=2, padx=5)
        ttk.Button(input_frame, text="Browse File", command=partial(self.browse_path, self.script_entry, False)).grid(row=1, column=2, padx=5)
        ttk.Button(input_frame, text="Browse File", command=partial(self.browse_path, self.py_path_entry, False)).grid(row=2, column=2, padx=5)
        
        # Default paths
        self.env_entry.insert(0, os.path.expanduser(os.path.join("~", "Documents", "Projects", "my_project", "venv")))
        self.script_entry.insert(0, os.path.expanduser(os.path.join("~", "Documents", "Projects", "my_project", "script.py")))
        self.py_path_entry.insert(0, self._get_default_python_path())
        
        # Notebook for command categories
        self.venv_notebook = ttk.Notebook(main_container)
        self.venv_notebook.pack(fill='both', expand=True, pady=(0, 10))
        
        # Commands defined with templates
        self.venv_commands_data = {
            "Basic Commands": [
                ("Create Virtual Environment", "python -m venv {env}"),
                ("Activate (Windows)", "{env}\\Scripts\\activate.ps1"),
                ("Activate (Linux/Mac)", "source {env}/bin/activate"),
                ("Deactivate", "deactivate"),
                ("Install Package", "pip install package"),
                ("Run Script", "{py_path} {script}"),
                ("List Installed Packages", "pip list"),
                ("Freeze Requirements", "pip freeze > requirements.txt")
            ],
            "Advanced Commands": [
                ("List Python Installations", "py --list"),
                ("Create with Python 3.9", "py -3.9 -m venv {env}"),
                ("Create with Specific Python", "\"{py_path}\" -m venv {env}"),
                ("Check Python Version", "python --version"),
                ("Upgrade pip", "python -m pip install --upgrade pip"),
                ("Install dev dependencies", "pip install -e .[dev]")
            ],
            "PowerShell Specific": [
                ("Check Execution Policy", "Get-ExecutionPolicy -List"),
                ("Set Remote Signed Policy", "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"),
                ("Unblock Activate.ps1", "Unblock-File {env}\\Scripts\\Activate.ps1"),
                ("Run PS as Admin", "Start-Process powershell -Verb RunAs")
            ],
            "Troubleshooting": [
                ("Recreate Virtualenv", "rm -rf {env} && python -m venv {env}"),
                ("Clean pip cache", "pip cache purge"),
                ("Fix corrupt packages", "pip install --force-reinstall package"),
                ("Check environment", "python -m pip check")
            ],
            "Make Exe": [
                ("Install PyInstaller", "pip install pyinstaller"),
                ("Build Onefile Executable", "pyinstaller --onefile \"{script}\""),
                ("Build Windowed Executable", "pyinstaller --onefile --windowed \"{script}\""),
                ("Open dist Folder", "OPEN_DIST_FOLDER_SPECIAL_COMMAND")
            ]
        }
        self._create_venv_command_tabs()
        
        # Terminal output section
        terminal_frame = ttk.Frame(main_container)
        terminal_frame.pack(fill='both', expand=True)
        
        terminal_label = ttk.Label(terminal_frame, text="Terminal Output:", font=('Segoe UI', 12, 'bold'))
        terminal_label.pack(side=tk.TOP, anchor=tk.W, pady=(0, 5))
        
        self.terminal_output = scrolledtext.ScrolledText(
            terminal_frame,
            wrap="word",
            bg='#1e1e1e',
            fg='#06d6a0',
            font=('Consolas', 10),
            height=10
        )
        self.terminal_output.pack(fill='both', expand=True)
        
        # Terminal Input Section
        terminal_input_frame = ttk.Frame(terminal_frame)
        terminal_input_frame.pack(fill='x', pady=(5, 0))
        terminal_input_frame.columnconfigure(0, weight=1)
        
        self.terminal_input_entry = ttk.Entry(terminal_input_frame)
        self.terminal_input_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.terminal_input_entry.bind("<Return>", self._execute_terminal_input_command)
        
        # Placeholder text
        self.terminal_input_entry.insert(0, "Type command here and press Enter...")
        self.terminal_input_entry.bind("<FocusIn>", self._clear_placeholder)
        self.terminal_input_entry.bind("<FocusOut>", self._add_placeholder)
        
        ttk.Button(
            terminal_input_frame,
            text="Run",
            command=self._execute_terminal_input_command,
            style='danger.TButton'
        ).grid(row=0, column=1, sticky="e")
        
        # Clear Terminal Button
        ttk.Button(
            terminal_frame,
            text="Clear Terminal",
            command=self._clear_terminal_output,
            style='info.TButton'
        ).pack(side=tk.BOTTOM, pady=5)
        
        # Configure tags for terminal text styling
        self.terminal_output.tag_config('normal', foreground='#06d6a0')
        self.terminal_output.tag_config('error', foreground='#ff6b6b')
        self.terminal_output.tag_config('new_command', foreground='#118ab2', font=('Consolas', 10, 'bold'))
        
        self._log_terminal_output("VirtualEnv terminal ready. Enter your paths and use the commands.", new_command=True)

    def _create_input_field(self, parent, label_text, row):
        """Create a labeled input field"""
        label = ttk.Label(parent, text=label_text)
        label.grid(row=row, column=0, padx=5, pady=5, sticky="w")
        entry = ttk.Entry(parent)
        entry.grid(row=row, column=1, padx=5, pady=5, sticky="ew")
        return entry

    def _get_default_python_path(self):
        """Find default Python executable path"""
        python_exec_name = "python.exe" if platform.system() == "Windows" else "python3"
        
        try:
            command = ["where", python_exec_name] if platform.system() == "Windows" else ["which", python_exec_name]
            result = subprocess.run(command, capture_output=True, text=True, check=True, shell=True)
            if result.stdout.strip():
                return result.stdout.splitlines()[0].strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        if platform.system() == "Windows":
            common_paths = [
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'Python', 'Python312', python_exec_name),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'Python', 'Python311', python_exec_name),
                os.path.join("C:", "Python312", python_exec_name),
                os.path.join("C:", "Python311", python_exec_name)
            ]
        else:
            common_paths = [
                "/usr/bin/python3",
                "/usr/local/bin/python3",
                os.path.expanduser("~/anaconda3/bin/python"),
                os.path.expanduser("~/miniforge3/bin/python")
            ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return "python"

    def _create_venv_command_tabs(self):
        """Create notebook tabs and populate with commands"""
        for tab_name, commands in self.venv_commands_data.items():
            tab_frame = ttk.Frame(self.venv_notebook)
            self.venv_notebook.add(tab_frame, text=tab_name)
            
            # Create a scrollable canvas
            canvas = tk.Canvas(tab_frame, bg='#2d2d2d', highlightthickness=0)
            scrollbar = ttk.Scrollbar(tab_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)
            
            scrollable_frame.bind(
                "<Configure>",
                lambda e, canvas=canvas: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            for i, (desc, cmd_template) in enumerate(commands):
                row_frame = ttk.Frame(scrollable_frame)
                row_frame.pack(fill='x', pady=3, padx=5)
                
                # Command description
                label = ttk.Label(row_frame, text=desc, font=('Consolas', 9), wraplength=300, justify=tk.LEFT)
                label.pack(side=tk.LEFT, padx=5, pady=5)
                
                # Copy button
                ttk.Button(
                    row_frame,
                    text="Copy",
                    command=partial(self.copy_command_with_feedback, cmd_template, label),
                    style='info.TButton',
                    width=8
                ).pack(side=tk.RIGHT, padx=5, pady=5)
                
                # Execute button
                if cmd_template == "OPEN_DIST_FOLDER_SPECIAL_COMMAND":
                    ttk.Button(
                        row_frame,
                        text="Open",
                        command=self._open_dist_folder,
                        style='success.TButton',
                        width=8
                    ).pack(side=tk.RIGHT, padx=5, pady=5)
                else:
                    ttk.Button(
                        row_frame,
                        text="Execute",
                        command=partial(self.execute_command_in_terminal, cmd_template),
                        style='danger.TButton',
                        width=8
                    ).pack(side=tk.RIGHT, padx=5, pady=5)

    def browse_path(self, entry_widget, is_directory=False):
        """Browse for file or directory path"""
        initial_dir = os.path.dirname(entry_widget.get()) if entry_widget.get() and os.path.exists(entry_widget.get()) else os.path.expanduser("~")
        try:
            if is_directory:
                path = filedialog.askdirectory(initialdir=initial_dir)
            else:
                path = filedialog.askopenfilename(initialdir=initial_dir)
            if path:
                entry_widget.delete(0, tk.END)
                entry_widget.insert(0, path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to browse path: {e}")

    def copy_command_with_feedback(self, cmd_template, feedback_label):
        """Copy command to clipboard with visual feedback"""
        cmd = self._format_command(cmd_template)
        if not cmd:
            return
        
        try:
            pyperclip.copy(cmd)
            # Visual feedback
            original_bg = feedback_label.cget('background')
            feedback_label.configure(background='#06d6a0')
            self.root.after(750, lambda: feedback_label.configure(background=original_bg))
            
            if self.show_popups:
                messagebox.showinfo("Copied!", f"Command copied to clipboard:\n{cmd}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard:\n{e}")

    def _format_command(self, cmd_template):
        """Format command template with current paths"""
        if cmd_template == "OPEN_DIST_FOLDER_SPECIAL_COMMAND":
            return cmd_template
        
        env = self.env_entry.get().strip()
        script = self.script_entry.get().strip()
        py_path = self.py_path_entry.get().strip()
        
        # Input validation
        missing_inputs = []
        if "{env}" in cmd_template and not env:
            missing_inputs.append("Virtual Environment Path")
        if "{script}" in cmd_template and not script:
            missing_inputs.append("Script Path")
        if "{py_path}" in cmd_template and not py_path:
            missing_inputs.append("Python Executable Path")
        
        if missing_inputs:
            messagebox.showwarning("Missing Input", f"Please fill in:\n- " + "\n- ".join(missing_inputs))
            return ""
        
        # Normalize paths
        if platform.system() == 'Windows':
            env = os.path.normpath(env)
            script = os.path.normpath(script)
            py_path = os.path.normpath(py_path)
            if "activate.ps1" in cmd_template.lower():
                cmd_template = cmd_template.replace('/', '\\')
        
        try:
            return cmd_template.format(env=env, script=script, py_path=py_path)
        except KeyError as e:
            messagebox.showerror("Formatting Error", f"Missing placeholder '{e}' in template")
            return ""
        except Exception as e:
            messagebox.showerror("Error", f"Formatting error: {e}")
            return ""

    def _execute_terminal_input_command(self, event=None):
        """Execute command from terminal input"""
        command = self.terminal_input_entry.get().strip()
        if not command or command == "Type command here and press Enter...":
            return
        
        self.terminal_input_entry.delete(0, tk.END)
        self._add_placeholder(None)
        
        self._log_terminal_output(f"> {command}", new_command=True)
        threading.Thread(target=self._run_command, args=(command,)).start()

    def execute_command_in_terminal(self, cmd_template):
        """Execute formatted command in terminal"""
        cmd = self._format_command(cmd_template)
        if not cmd:
            return
        
        self._log_terminal_output(f"> {cmd}", new_command=True)
        threading.Thread(target=self._run_command, args=(cmd,)).start()

    def _run_command(self, command):
        """Run command and capture output"""
        use_shell = True
        
        if platform.system() == 'Windows':
            if "activate.ps1" in command.lower() and not command.lower().startswith("powershell.exe"):
                command = f"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"& '{command}'\""
                use_shell = False
        
        try:
            process = subprocess.run(
                command,
                shell=use_shell,
                capture_output=True,
                text=True,
                check=False,
                encoding='utf-8',
                errors='replace'
            )
            
            if process.stdout:
                self._log_terminal_output(process.stdout.strip())
            if process.stderr:
                self._log_terminal_output(process.stderr.strip(), is_error=True)
            
            if process.returncode != 0:
                self._log_terminal_output(f"Command failed with exit code {process.returncode}.", is_error=True)
                if self.show_popups:
                    self.root.after(0, lambda: messagebox.showerror("Command Failed", f"Command failed.\nSee terminal for details."))
        except FileNotFoundError:
            self._log_terminal_output("Error: Command or executable not found.", is_error=True)
            if self.show_popups:
                self.root.after(0, lambda: messagebox.showerror("Error", "Command not found. Check your paths."))
        except Exception as e:
            self._log_terminal_output(f"Error: {e}", is_error=True)
            if self.show_popups:
                self.root.after(0, lambda: messagebox.showerror("Error", f"An error occurred:\n{e}"))

    def _open_dist_folder(self):
        """Open PyInstaller dist folder"""
        script_path = self.script_entry.get().strip()
        if not script_path:
            messagebox.showwarning("Missing Input", "Please provide a Script Path.")
            return
        
        script_dir = os.path.dirname(script_path)
        if not script_dir:
            script_dir = os.getcwd()
        
        dist_path = os.path.join(script_dir, "dist")
        dist_path = os.path.normpath(dist_path)
        
        if not os.path.isdir(dist_path):
            messagebox.showwarning("Folder Not Found", f"The 'dist' folder was not found at:\n{dist_path}")
            return
        
        try:
            if platform.system() == "Windows":
                os.startfile(dist_path)
            elif platform.system() == "Darwin":
                subprocess.run(["open", dist_path], check=True)
            else:
                subprocess.run(["xdg-open", dist_path], check=True)
            self._log_terminal_output(f"Opened folder: {dist_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open folder:\n{e}")

    def _log_terminal_output(self, message, is_error=False, new_command=False):
        """Log message to terminal output"""
        self.root.after(0, lambda: self._update_terminal_text(message, is_error, new_command))

    def _update_terminal_text(self, message, is_error, new_command):
        """Update terminal text widget"""
        self.terminal_output.configure(state='normal')
        
        if new_command:
            self.terminal_output.insert(tk.END, f"\n--- {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n", 'new_command')
        
        tag = 'error' if is_error else 'normal'
        self.terminal_output.insert(tk.END, message + "\n", tag)
        self.terminal_output.see(tk.END)
        self.terminal_output.configure(state='disabled')

    def _clear_terminal_output(self):
        """Clear terminal output"""
        self.terminal_output.configure(state='normal')
        self.terminal_output.delete(1.0, tk.END)
        self.terminal_output.configure(state='disabled')
        self._log_terminal_output("Terminal cleared.", new_command=True)

    def _clear_placeholder(self, event):
        """Clear placeholder text"""
        if self.terminal_input_entry.get() == "Type command here and press Enter...":
            self.terminal_input_entry.delete(0, tk.END)

    def _add_placeholder(self, event):
        """Add placeholder text"""
        if not self.terminal_input_entry.get():
            self.terminal_input_entry.insert(0, "Type command here and press Enter...")

    def create_command_button(self, parent, name, command, description):
        """Create a command button with details"""
        card = ttk.Frame(parent, padding=5)
        card.pack(fill='x', pady=2)
        
        ttk.Label(
            card,
            text=name,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor='w')
        
        ttk.Label(
            card,
            text=description,
            font=("Segoe UI", 8)
        ).pack(anchor='w', pady=(0, 5))
        
        cmd_frame = ttk.Frame(card)
        cmd_frame.pack(fill='x')
        
        cmd_label = ttk.Label(
            cmd_frame,
            text=command,
            font=("Consolas", 9),
            foreground="#00BFFF"
        )
        cmd_label.pack(side='left', fill='x', expand=True)
        
        ttk.Button(
            cmd_frame,
            text="Copy",
            command=lambda c=command: self.copy_command(c),
            width=8
        ).pack(side='right')

    def copy_command(self, command):
        """Copy command to clipboard"""
        try:
            pyperclip.copy(command)
            self.status_var.set(f"Copied: {command[:50]}...")
        except Exception as e:
            self.status_var.set(f"Copy failed: {str(e)}")

    def create_status_bar(self):
        """Create status bar at bottom"""
        status_frame = ttk.Frame(self.main_frame, height=25)
        status_frame.pack(fill='x', pady=(10, 0))
        status_frame.pack_propagate(False)
        
        self.status_var = tk.StringVar(value="Ready")
        
        ttk.Label(
            status_frame,
            textvariable=self.status_var,
            font=("Segoe UI", 8)
        ).pack(side='left', padx=10)
        
        ttk.Label(
            status_frame,
            text="Unified Command Tool v3.0",
            font=("Segoe UI", 8)
        ).pack(side='right', padx=10)

    def start_threat_monitor(self):
        """Start monitoring threat level"""
        self.evaluate_threat_level()
        self.root.after(300000, self.start_threat_monitor)  # Check every 5 minutes

    def evaluate_threat_level(self):
        """Evaluate current threat level"""
        threat_score = 0
        
        # Example checks would go here
        # if self._check_suspicious_activity():
        #     threat_score += 30
        
        if threat_score >= 70:
            self._set_threat_level("🔴 CRITICAL", "red")
        elif threat_score >= 40:
            self._set_threat_level("🟠 HIGH", "orange")
        elif threat_score >= 20:
            self._set_threat_level("🟡 ELEVATED", "yellow")
        else:
            self._set_threat_level("🟢 NORMAL", "green")

    def _set_threat_level(self, text, color):
        """Update threat level display"""
        self.threat_level.config(text=f"THREAT LEVEL: {text}", foreground=color)
        self.status_var.set(f"Threat level: {text}")

if __name__ == "__main__":
    # Initialize the application
    root = ttk.Window()
    root.style.theme_use("cyborg")  # Set the dark theme
    app = UnifiedCommandTool(root)
    root.mainloop()
