import os
import sys
import time
import re
import json
import psutil
import socket
import logging
import argparse
import smtplib
import hashlib
import threading
import datetime
import subprocess
import shutil
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict, deque
import platform
from pathlib import Path
import watchdog.observers
import watchdog.events
from twilio.rest import Client  # Added for Twilio SMS
import random
import getpass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("forensicaguard.log"),
        logging.StreamHandler()
    ]
)

class FileSystemEventHandler(watchdog.events.FileSystemEventHandler):
    """Handler for file system events for real-time monitoring"""
    def __init__(self, forensica_guard):
        self.fg = forensica_guard
        
    def on_modified(self, event):
        if not event.is_directory:
            self.fg.handle_file_event("modified", event.src_path)
            
    def on_created(self, event):
        if not event.is_directory:
            self.fg.handle_file_event("created", event.src_path)
            
    def on_deleted(self, event):
        if not event.is_directory:
            self.fg.handle_file_event("deleted", event.src_path)
            
    def on_moved(self, event):
        if not event.is_directory:
            self.fg.handle_file_event("moved", event.src_path, dest_path=event.dest_path)

class NetworkMonitor(threading.Thread):
    """Thread for monitoring network connections"""
    def __init__(self, forensica_guard):
        threading.Thread.__init__(self)
        self.fg = forensica_guard
        self.daemon = True
        self.running = True
        self.connection_history = defaultdict(lambda: deque(maxlen=60))
          # Store 1 minute of connections by IP
        
    def run(self):
        while self.running:
            try:
                # Get current connections
                connections = psutil.net_connections(kind='inet')
                timestamp = datetime.datetime.now()
                ip_counts = defaultdict(int)
                
                # Count connections by remote IP
                for conn in connections:
                    if conn.raddr and conn.raddr.ip:
                        ip_counts[conn.raddr.ip] += 1
                
                # Store counts in history and check for DoS
                for ip, count in ip_counts.items():
                    self.connection_history[ip].append((timestamp, count))
                    # Calculate connections per minute for this IP
                    total_conns = sum(c for _, c in self.connection_history[ip])
                    if total_conns >= self.fg.alert_thresholds.get("connections_per_minute", 100):
                        self.fg.handle_dos_detection(ip, total_conns)
                
                time.sleep(1)  # Check every second
            except Exception as e:
                logging.error(f"Error in network monitoring: {e}")
                time.sleep(5)  # Wait a bit longer if there's an error

class SystemLogMonitor(threading.Thread):
    """Thread for monitoring system logs"""
    def __init__(self, forensica_guard):
        threading.Thread.__init__(self)
        self.fg = forensica_guard
        self.daemon = True
        self.running = True
        
    def run(self):
        while self.running:
            try:
                for log_name, log_file in self.fg.log_files.items():
                    if os.path.exists(log_file):
                        self.fg.parse_system_logs(log_file, log_name)
                
                time.sleep(self.fg.config.get("log_scan_interval", 30))
            except Exception as e:
                logging.error(f"Error in system log monitoring: {e}")
                time.sleep(10)  # Wait a bit longer if there's an error

class ForensicaGuard:
    def __init__(self, config_file="config.json"):
     self.display_banner()

     self.config = self.load_config(config_file)

   
     self.evidence_dir = self.config.get("evidence_dir", "evidence")
     self.system_info = self.get_system_info()
     self.email_config = {}
     self.prompt_for_email_config()

    # Rest of the init
     self.log_files = self.config.get("log_files", {})
     self.alert_thresholds = self.config.get("alert_thresholds", {})
     self.sms_config = self.config.get("sms_notification", {})
     self.file_checksums = {}
     self.login_attempts = defaultdict(list)
     self.privilege_escalations = defaultdict(list)
     self.system_shutdowns = []
     self.suspicious_processes = []
     self.file_access_events = []
     self.network_connections = defaultdict(int)
     self.dos_alerts = set()
     self.brute_force_alerts = set()
     self.running = True
     self.threads = []
     self.file_observers = []
     self.scan_start_time = datetime.datetime.now()
     self.parse_arguments()

    def prompt_for_email_config(self):
        print("\n--- Email Configuration ---")
        sender = input("Enter sender email address (e.g., your Gmail): ").strip()
        password = getpass.getpass("Enter app-specific password for this email: ").strip()
        recipient = input("Enter recipient email to receive alerts: ").strip()

        self.email_config["enabled"] = True
        self.email_config["smtp_server"] = "smtp.gmail.com"
        self.email_config["smtp_port"] = 587
        self.email_config["username"] = sender
        self.email_config["password"] = password
        self.email_config["recipient"] = recipient


        # Parse command-line arguments
        self.parse_arguments()

        # Create evidence directory if it doesn't exist
        if not os.path.exists(self.evidence_dir):
            os.makedirs(self.evidence_dir)

        # Initialize file integrity checksums
        if "monitored_files" in self.config:
            self.initialize_file_checksums()
            
        # Initialize directory monitoring
        if "monitored_directories" in self.config:
            self.initialize_directory_monitoring()
            
    def display_banner(self):
        banner = r"""
   ______                        _       ______                     _ 
  / ____/___  ________  ____    (_)_____/ ____/_  ______ __________/ /
 / /_  / __ \/ ___/ _ \/ __ \  / / ___/ / __/ / / / __ / ___/ __  / 
/ __/ / /_/ / /  /  __/ / / / / / /__/ /_/ / /_/ / /_/ / /  / /_/ /  
/_/    \____/_/   \___/_/ /_/_/ /\___/\____/\__,_/\__,_/_/   \__,_/   
                          /___/                                      
"""
        print("\033[1;36m" + banner + "\033[0m")  # Print in cyan color
        print("\033[1;33m" + "ForensicGuard - Advanced Security Monitoring Tool v1.2" + "\033[0m")
        print("\033[1;33m" + "Copyright © 2025 ForensicGuard Team" + "\033[0m")
        print("\033[1;33m" + "=" * 80 + "\033[0m\n")

    def parse_arguments(self):
        """Parse command-line arguments"""
        parser = argparse.ArgumentParser(description='ForensicaGuard - Security Monitoring Tool')
        parser.add_argument('-c', '--config', help='Path to configuration file', default='config.json')
        parser.add_argument('-t', '--test', help='Generate test alerts', action='store_true')
        parser.add_argument('-d', '--debug', help='Enable debug logging', action='store_true')
        args = parser.parse_args()
        
        # Apply command-line settings
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug("Debug logging enabled")
            
        if args.test:
            logging.info("Test mode enabled - will generate simulated threats")
            self.test_mode = True
        else:
            self.test_mode = False

    def load_config(self, config_file):
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logging.warning(f"Config file {config_file} not found. Creating default configuration.")
            # Create default configuration
            default_config = {
                "log_files": {
                    "Security.evtx": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                    "System.evtx": "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
                    "auth.log": "/var/log/auth.log" if platform.system() != "Windows" else "",
                    "syslog": "/var/log/syslog" if platform.system() != "Windows" else ""
                },
                "alert_thresholds": {
                    "failed_logins": 5,
                    "connections_per_minute": 100,
                    "file_changes": 1,
                    "privilege_escalations": 3
                },
                "email_notification": {
                    "enabled": False,
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "username": "your-email@gmail.com",
                    "password": "your-app-password",
                    "recipient": "your-email@gmail.com"
                },
                "sms_notification": {
                    "enabled": False,
                    "service": "twilio",
                    "account_sid": "your-twilio-sid",
                    "auth_token": "your-twilio-token",
                    "from_number": "+1234567890",
                    "to_number": "+1234567890"
                },
                "evidence_dir": "evidence",
                "monitored_files": [
                    "C:\\Windows\\System32\\config\\SAM",
                    "C:\\Windows\\System32\\config\\SECURITY",
                    "C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "/etc/passwd" if platform.system() != "Windows" else "",
                    "/etc/shadow" if platform.system() != "Windows" else "",
                    "/etc/hosts" if platform.system() != "Windows" else ""
                ],
                "monitored_directories": [
                    "C:\\Windows\\System32\\config" if platform.system() == "Windows" else "/etc"
                ],
                "scan_interval": 30,  # Default scan interval
                "log_scan_interval": 60  # Log scanning interval
            }
            # Filter out empty paths
            default_config["monitored_files"] = [f for f in default_config["monitored_files"] if f]
            default_config["log_files"] = {k: v for k, v in default_config["log_files"].items() if v}
            
            # Save default configuration
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
            return default_config

    def get_system_info(self):
        """Gather system information"""
        info = {
            "hostname": socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "platform": platform.platform(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "start_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cpu_count": psutil.cpu_count(),
            "memory_total": psutil.virtual_memory().total,
            "disks": []
        }
        
        # Gather disk information
        for disk in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(disk.mountpoint)
                info["disks"].append({
                    "device": disk.device,
                    "mountpoint": disk.mountpoint,
                    "total_size": usage.total,
                    "percent_used": usage.percent
                })
            except:
                pass
        
        logging.info(f"System information: {info}")
        return info

    def initialize_file_checksums(self):
        """Initialize checksums for monitored files"""
        for file_path in self.config.get("monitored_files", []):
            if os.path.exists(file_path):
                try:
                    self.file_checksums[file_path] = self.calculate_file_hash(file_path)
                    logging.info(f"Initialized checksum for {file_path}")
                except Exception as e:
                    logging.error(f"Error calculating checksum for {file_path}: {e}")
            else:
                logging.warning(f"Monitored file does not exist: {file_path}")

    def initialize_directory_monitoring(self):
        """Initialize real-time directory monitoring"""
        for directory in self.config.get("monitored_directories", []):
            if os.path.exists(directory) and os.path.isdir(directory):
                try:
                    event_handler = FileSystemEventHandler(self)
                    observer = watchdog.observers.Observer()
                    observer.schedule(event_handler, directory, recursive=True)
                    observer.start()
                    self.file_observers.append(observer)
                    logging.info(f"Started real-time monitoring for directory: {directory}")
                except Exception as e:
                    logging.error(f"Error setting up directory monitoring for {directory}: {e}")
            else:
                logging.warning(f"Monitored directory does not exist: {directory}")

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            buf = f.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(65536)
        return hasher.hexdigest()

    def sanitize_filename(self, filename):
        """Sanitize a string to be used as a filename"""
        # Replace invalid characters in filenames
        invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        return filename

    def monitor_file_integrity(self):
        """Check for changes in monitored files"""
        modified_files = []
        for file_path, original_hash in self.file_checksums.items():
            if os.path.exists(file_path):
                try:
                    current_hash = self.calculate_file_hash(file_path)
                    if current_hash != original_hash:
                        modified_files.append(file_path)
                        self.file_checksums[file_path] = current_hash
                        logging.warning(f"File modified: {file_path}")
                        self.save_file_evidence(file_path)
                except Exception as e:
                    logging.error(f"Error checking file integrity for {file_path}: {e}")
            else:
                modified_files.append(file_path)
                logging.warning(f"Monitored file has been deleted: {file_path}")

        if modified_files and len(modified_files) >= self.alert_thresholds.get("file_changes", 1):
            self.send_alert(f"File integrity violation detected! Modified files: {', '.join(modified_files)}")

    def handle_file_event(self, event_type, file_path, dest_path=None):
        """Handle file system events from watchdog"""
        timestamp = datetime.datetime.now()
        event_details = {
            "event_type": event_type,
            "file_path": file_path,
            "timestamp": timestamp
        }
        
        if dest_path:
            event_details["dest_path"] = dest_path
            
        self.file_access_events.append(event_details)
        
        # Log the event
        if event_type == "modified":
            logging.warning(f"File modified in real-time: {file_path}")
        elif event_type == "created":
            logging.warning(f"File created in real-time: {file_path}")
        elif event_type == "deleted":
            logging.warning(f"File deleted in real-time: {file_path}")
        elif event_type == "moved":
            logging.warning(f"File moved in real-time from {file_path} to {dest_path}")
            
        # Save evidence
        if event_type != "deleted" and os.path.exists(file_path):
            self.save_file_evidence(file_path, f"{event_type}_{os.path.basename(file_path)}_{timestamp.strftime('%Y%m%d%H%M%S')}")
            
        # Send alert
        self.send_alert(f"File {event_type} detected: {file_path}")

    def parse_system_logs(self, log_file, log_name):
        """Parse various system logs based on their type"""
        if log_name.lower().endswith('.evtx') and platform.system() == "Windows":
            self.parse_windows_event_logs(log_file, log_name)
        else:
            self.parse_unix_logs(log_file, log_name)

    def parse_windows_event_logs(self, log_file, log_name):
        """Parse Windows Event Logs for security events"""
        try:
            # Failed logins (Event ID 4625)
            if "Security" in log_name:
                self.parse_windows_security_log()
                
                # Privilege escalation events (Event ID 4672)
                ps_command = 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4672} -MaxEvents 20 | ForEach-Object { $_.Message }'
                try:
                    output = subprocess.check_output(['powershell', '-Command', ps_command], universal_newlines=True)
                    self.process_privilege_escalation_events(output, "windows")
                except Exception as e:
                    logging.error(f"Error parsing Windows privilege escalation events: {e}")
                
                # System shutdown events (Event ID 1074, 6006, or 6008)
                ps_command = 'Get-WinEvent -FilterHashtable @{LogName="System"; ID=1074,6006,6008} -MaxEvents 5 | ForEach-Object { $_.Message }'
                try:
                    output = subprocess.check_output(['powershell', '-Command', ps_command], universal_newlines=True)
                    self.process_system_shutdown_events(output, "windows")
                except Exception as e:
                    logging.error(f"Error parsing Windows shutdown events: {e}")
                
        except Exception as e:
            logging.error(f"Error parsing Windows event log {log_file}: {e}")

    def parse_unix_logs(self, log_file, log_name):
        """Parse Unix-style log files"""
        if not os.path.exists(log_file):
            logging.warning(f"Log file not found: {log_file}")
            return
            
        try:
            output = subprocess.check_output(['tail', '-n', '100', log_file], universal_newlines=True)
            
            # Check for authentication failures
            if "auth.log" in log_name.lower() or "secure" in log_name.lower():
                self.process_failed_login_events(output, "unix")
                self.process_privilege_escalation_events(output, "unix")
                
            # Check for system shutdown events
            if "syslog" in log_name.lower() or "messages" in log_name.lower():
                self.process_system_shutdown_events(output, "unix")
                
        except Exception as e:
            logging.error(f"Error parsing Unix log {log_file}: {e}")

    def process_failed_login_events(self, log_content, system_type):
        """Process failed login events from logs"""
        failed_logins = defaultdict(list)
        
        if system_type == "unix":
            for line in log_content.splitlines():
                if "Failed password" in line or "authentication failure" in line:
                    user_match = re.search(r'user=(\w+)', line)
                    ip_match = re.search(r'from=([0-9.]+)', line) or re.search(r'rhost=([0-9.]+)', line)
                    username = user_match.group(1) if user_match else "unknown"
                    ip = ip_match.group(1) if ip_match else "unknown"
                    key = f"{username}@{ip}"
                    timestamp = datetime.datetime.now()
                    self.login_attempts[key].append(timestamp)
                    recent_attempts = [t for t in self.login_attempts[key] if (timestamp - t).total_seconds() < 300]
                    if len(recent_attempts) >= self.alert_thresholds.get("failed_logins", 5):
                        self.handle_brute_force_detection(username, ip, len(recent_attempts))
                        
    def parse_windows_security_log(self):
        """Parse Windows Security Event Log for failed logins"""
        try:
            ps_command = 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4625} -MaxEvents 50 | ForEach-Object { $_.Message }'
            output = subprocess.check_output(['powershell', '-Command', ps_command], universal_newlines=True)
            for entry in output.split("Security ID:"):
                if "Account Name:" in entry and "Source Network Address:" in entry:
                    username_match = re.search(r'Account Name:\s+(\S+)', entry)
                    ip_match = re.search(r'Source Network Address:\s+(\S+)', entry)
                    username = username_match.group(1) if username_match else "unknown"
                    ip = ip_match.group(1) if ip_match else "unknown"
                    if ip == "-":
                        ip = "local"
                    key = f"{username}@{ip}"
                    timestamp = datetime.datetime.now()
                    self.login_attempts[key].append(timestamp)
                    recent_attempts = [t for t in self.login_attempts[key] if (timestamp - t).total_seconds() < 300]
                    if len(recent_attempts) >= self.alert_thresholds.get("failed_logins", 5):
                        self.handle_brute_force_detection(username, ip, len(recent_attempts))
        except Exception as e:
            logging.error(f"Error parsing Windows security log: {e}")

    def process_privilege_escalation_events(self, log_content, system_type):
        """Process privilege escalation events from logs"""
        timestamp = datetime.datetime.now()
        
        if system_type == "windows":
            # Process Windows special privileges assigned to new logon events
            for entry in log_content.split("Security ID:"):
                if "Special privileges assigned to new logon" in entry:
                    account_match = re.search(r'Account Name:\s+(\S+)', entry)
                    username = account_match.group(1) if account_match else "unknown"
                    self.privilege_escalations[username].append(timestamp)
                    recent_events = [t for t in self.privilege_escalations[username] 
                                    if (timestamp - t).total_seconds() < 600]  # 10 minutes
                    if len(recent_events) >= self.alert_thresholds.get("privilege_escalations", 3):
                        self.handle_privilege_escalation_detection(username, len(recent_events))
                        # Save the event details as evidence
                        self.save_text_evidence(entry, f"privesc_{username}_{timestamp.strftime('%Y%m%d%H%M%S')}")
                        
        elif system_type == "unix":
            # Process sudo/su events in Unix logs
            for line in log_content.splitlines():
                if "sudo:" in line or "su:" in line:
                    user_match = re.search(r'(\w+) : TTY=', line)
                    username = user_match.group(1) if user_match else "unknown"
                    self.privilege_escalations[username].append(timestamp)
                    recent_events = [t for t in self.privilege_escalations[username] 
                                    if (timestamp - t).total_seconds() < 600]  # 10 minutes
                    if len(recent_events) >= self.alert_thresholds.get("privilege_escalations", 3):
                        self.handle_privilege_escalation_detection(username, len(recent_events))
                        # Save the log line as evidence
                        self.save_text_evidence(line, f"privesc_{username}_{timestamp.strftime('%Y%m%d%H%M%S')}")

    def process_system_shutdown_events(self, log_content, system_type):
        """Process system shutdown/reboot events from logs"""
        timestamp = datetime.datetime.now()
        
        if system_type == "windows":
            # Look for shutdown events in Windows logs
            if "The system is shutting down" in log_content or "shutdown" in log_content.lower():
                event = {
                    "timestamp": timestamp,
                    "type": "shutdown",
                    "details": log_content[:200]  # First 200 chars as details
                }
                self.system_shutdowns.append(event)
                logging.info(f"System shutdown event detected: {event}")
                
        elif system_type == "unix":
            # Look for shutdown events in Unix logs
            for line in log_content.splitlines():
                if "shutdown" in line.lower() or "reboot" in line.lower() or "halt" in line.lower():
                    event = {
                        "timestamp": timestamp,
                        "type": "shutdown" if "shutdown" in line.lower() else "reboot",
                        "details": line
                    }
                    self.system_shutdowns.append(event)
                    logging.info(f"System shutdown/reboot event detected: {event}")

    def check_suspicious_processes(self):
        """Check for suspicious processes running on the system"""
        suspicious = []
        timestamp = datetime.datetime.now()
        
        try:
            # Get all running processes
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    # Check CPU and memory usage for abnormal behavior
                    with proc.oneshot():
                        cpu_percent = proc.cpu_percent(interval=None)
                        memory_percent = proc.memory_percent()
                        
                        # Look for potential mining processes or high CPU usage
                        if cpu_percent > 90:
                            suspicious.append({
                                "pid": proc.pid,
                                "name": proc.name(),
                                "username": proc.username(),
                                "cpu_percent": cpu_percent,
                                "memory_percent": memory_percent,
                                "reason": "High CPU usage",
                                "timestamp": timestamp
                            })
                            
                        # Check for known suspicious process names or commands
                        process_name = proc.name().lower()
                        cmdline = " ".join(proc.cmdline()).lower() if proc.cmdline() else ""
                        
                        suspicious_keywords = ["miner", "xmrig", "minerd", "ncrack", "hydra", "hashcat"]
                        for keyword in suspicious_keywords:
                            if keyword in process_name or keyword in cmdline:
                                suspicious.append({
                                    "pid": proc.pid,
                                    "name": proc.name(),
                                    "username": proc.username(),
                                    "cmdline": cmdline[:100],  # Truncate long command lines
                                    "reason": f"Suspicious keyword: {keyword}",
                                    "timestamp": timestamp
                                })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                    
            # Alert on any suspicious processes found
            if suspicious:
                for proc in suspicious:
                    logging.warning(f"Suspicious process detected: {proc}")
                    self.suspicious_processes.append(proc)
                    # Create evidence file with process details
                    evidence = f"PID: {proc['pid']}\nName: {proc['name']}\nUser: {proc['username']}\n"
                    if 'cmdline' in proc:
                        evidence += f"Command: {proc['cmdline']}\n"
                    evidence += f"Reason flagged: {proc['reason']}\nTimestamp: {proc['timestamp']}"
                    self.save_text_evidence(evidence, f"suspicious_process_{proc['pid']}_{timestamp.strftime('%Y%m%d%H%M%S')}")
                
                processes_info = "\n".join([f"{p['name']} (PID: {p['pid']}, Reason: {p['reason']})" for p in suspicious])
                self.send_alert(f"Suspicious processes detected!\n{processes_info}")
                
        except Exception as e:
            logging.error(f"Error checking for suspicious processes: {e}")

    def monitor_network_connections(self):
        """Check for abnormal network connections and potential DoS"""
        try:
            # Use psutil for more accurate network connection monitoring
            connections = psutil.net_connections(kind='inet')
            ip_counts = defaultdict(int)
            port_counts = defaultdict(int)
            
            # Count connections by remote IP and local port
            for conn in connections:
                if conn.raddr:
                    ip_counts[conn.raddr.ip] += 1
                if conn.laddr:
                    port_counts[conn.laddr.port] += 1
            
            timestamp = datetime.datetime.now()
            threshold = self.alert_thresholds.get("connections_per_minute", 100)
            
            # Check for IPs with unusually high connection counts (potential DoS)
            for ip, count in ip_counts.items():
                if count > threshold // 2:  # Alert at half the per-minute threshold for instantaneous counts
                    if ip not in self.dos_alerts:  # Only alert once per IP
                        self.handle_dos_detection(ip, count)
        except Exception as e:
            logging.error(f"Error monitoring network connections: {e}")

    def handle_brute_force_detection(self, username, ip, attempt_count):
        """Handle detected brute force attack"""
        # Create a unique key for this brute force attempt
        key = f"{username}@{ip}"
        if key in self.brute_force_alerts:
            return  # Already alerted on this combination
            
        logging.warning(f"Possible brute force attack detected! {attempt_count} failed login attempts for user {username} from IP {ip}")
        
        evidence = f"Brute force attack detected\nUsername: {username}\nIP Address: {ip}\n"
        evidence += f"Attempt count: {attempt_count}\nTimestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        # Sanitize the IP address for filename
        safe_ip = self.sanitize_filename(ip)
        self.save_text_evidence(evidence, f"brute_force_{username}_{safe_ip}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
        
        self.send_alert(f"Possible brute force attack detected! {attempt_count} failed login attempts for user {username} from IP {ip}")
        self.brute_force_alerts.add(key)  # Mark as alerted

    def handle_dos_detection(self, ip, connection_count):
        """Handle detected DoS attack"""
        if ip in self.dos_alerts:
            return  # Already alerted on this IP
            
        logging.warning(f"Possible DoS attack detected! {connection_count} connections from IP {ip}")
        
        evidence = f"DoS attack detected\nIP Address: {ip}\n"
        evidence += f"Connection count: {connection_count}\nTimestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        # Sanitize the IP address for filename - fix for IPv6 addresses
        safe_ip = self.sanitize_filename(ip)
        self.save_text_evidence(evidence, f"dos_attack_{safe_ip}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
        
        self.send_alert(f"Possible DoS attack detected! {connection_count} connections from IP {ip}")
        self.dos_alerts.add(ip)
        def handle_privilege_escalation_detection(self, username, event_count):
            logging.warning(f"Unusual privilege escalation detected! {event_count} events for user {username}")
            evidence = f"Privilege escalation detected\nUsername: {username}\n"
            evidence += f"Event count: {event_count}\nTimestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            self.save_text_evidence(evidence, f"privilege_escalation_{username}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
            self.send_alert(f"Unusual privilege escalation detected! {event_count} events for user {username}")

    def save_file_evidence(self, file_path, custom_filename=None):
        """Save a copy of a file as evidence"""
        try:
            # Create evidence directory if it doesn't exist
            if not os.path.exists(self.evidence_dir):
                os.makedirs(self.evidence_dir)
            
            # Generate evidence filename
            if custom_filename:
                safe_filename = self.sanitize_filename(custom_filename)
            else:
                timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                basename = os.path.basename(file_path)
                safe_filename = self.sanitize_filename(f"{basename}_{timestamp}")
            
            evidence_path = os.path.join(self.evidence_dir, safe_filename)
            
            # Copy the file to evidence directory
            shutil.copy2(file_path, evidence_path)
            logging.info(f"Saved file evidence to {evidence_path}")
            
            # Calculate and store the hash of the evidence file
            file_hash = self.calculate_file_hash(evidence_path)
            hash_file = f"{evidence_path}.hash"
            with open(hash_file, 'w') as f:
                f.write(f"{file_hash} *{os.path.basename(evidence_path)}")
            
            return evidence_path
        except Exception as e:
            logging.error(f"Error saving file evidence for {file_path}: {e}")
            return None

    def save_text_evidence(self, text_content, filename):
        """Save text content as evidence"""
        try:
            # Create evidence directory if it doesn't exist
            if not os.path.exists(self.evidence_dir):
                os.makedirs(self.evidence_dir)
            
            # Sanitize filename
            safe_filename = self.sanitize_filename(filename)
            if not safe_filename.endswith('.txt'):
                safe_filename += '.txt'
            
            evidence_path = os.path.join(self.evidence_dir, safe_filename)
            
            # Write content to evidence file
            with open(evidence_path, 'w') as f:
                f.write(text_content)
            
            logging.info(f"Saved text evidence to {evidence_path}")
            
            # Calculate and store the hash of the evidence file
            file_hash = self.calculate_file_hash(evidence_path)
            hash_file = f"{evidence_path}.hash"
            with open(hash_file, 'w') as f:
                f.write(f"{file_hash} *{os.path.basename(evidence_path)}")
            
            return evidence_path
        except Exception as e:
            logging.error(f"Error saving text evidence: {e}")
            return None

    def send_alert(self, message):
        """Send alerts via configured channels (email, SMS)"""
        logging.warning(f"ALERT: {message}")
        
        # Send email notification if configured
        if self.email_config.get("enabled", False):
            self.send_email_alert(message)
        
        # Send SMS notification if configured
        if self.sms_config.get("enabled", False):
            self.send_sms_alert(message)

    def send_email_alert(self, message):
        """Send alert via email"""
        try:
            # Configure email
            sender = self.email_config.get("username", "")
            recipient = self.email_config.get("recipient", "")
            smtp_server = self.email_config.get("smtp_server", "")
            smtp_port = self.email_config.get("smtp_port", 587)
            username = self.email_config.get("username", "")
            password = self.email_config.get("password", "")
            
            if not sender or not recipient or not smtp_server or not username or not password:
                logging.error("Email configuration incomplete. Cannot send email alert.")
                return
            
            # Create message
            subject = f"ForensicaGuard Security Alert - {self.system_info['hostname']}"
            body = f"""
            Security Alert from ForensicaGuard
            
            System: {self.system_info['hostname']} ({self.system_info['ip_address']})
            Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            Alert Message:
            {message}
            
            --- 
            This is an automated message from ForensicaGuard.
            """
            
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = recipient
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect to SMTP server and send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(username, password)
            server.sendmail(sender, recipient, msg.as_string())
            server.quit()
            
            logging.info(f"Email alert sent to {recipient}")
        except Exception as e:
            logging.error(f"Error sending email alert: {e}")

    def send_sms_alert(self, message):
        """Send alert via SMS using Twilio"""
        try:
            # Get Twilio configuration
            account_sid = self.sms_config.get("account_sid", "")
            auth_token = self.sms_config.get("auth_token", "")
            from_number = self.sms_config.get("from_number", "")
            to_number = self.sms_config.get("to_number", "")
            
            if not account_sid or not auth_token or not from_number or not to_number:
                logging.error("SMS configuration incomplete. Cannot send SMS alert.")
                return
            
            # Create Twilio client and send SMS
            client = Client(account_sid, auth_token)
            
            # Truncate message if too long
            short_message = f"ForensicaGuard Alert - {self.system_info['hostname']}: "
            remaining_chars = 160 - len(short_message)
            if len(message) > remaining_chars:
                short_message += message[:remaining_chars-3] + "..."
            else:
                short_message += message
            
            message = client.messages.create(
                body=short_message,
                from_=from_number,
                to=to_number
            )
            
            logging.info(f"SMS alert sent to {to_number}")
        except Exception as e:
            logging.error(f"Error sending SMS alert: {e}")

    def generate_test_alerts(self):
        """Generate test alerts to verify system functionality"""
        logging.info("Generating test alerts...")
        
        # Test file integrity alert
        test_file = os.path.join(self.evidence_dir, "test_file.txt")
        with open(test_file, 'w') as f:
            f.write("This is a test file for ForensicaGuard")
        
        self.save_file_evidence(test_file, "test_file_evidence")
        self.send_alert("Test alert: File integrity violation detected")
        
        # Test brute force alert
        self.handle_brute_force_detection("testuser", "192.168.1.100", 10)
        
        # Test DoS alert
        self.handle_dos_detection("10.0.0.1", 500)
        
        # Test privilege escalation alert
        self.handle_privilege_escalation_detection("testadmin", 5)
        
        logging.info("Test alerts generated successfully")

    def run(self):
        """Run the ForensicaGuard monitoring system"""
        try:
            logging.info(f"ForensicaGuard started on {self.system_info['hostname']}")
            logging.info(f"System: {self.system_info['platform']} - Evidence directory: {self.evidence_dir}")
            
            # Print banner
            print("\n" + "="*60)
            print(" ForensicaGuard - Security Monitoring and Forensic Tool ")
            print("="*60)
            print(f" Started on: {self.system_info['hostname']} ({self.system_info['ip_address']})")
            print(f" Platform: {self.system_info['platform']}")
            print(f" Evidence directory: {self.evidence_dir}")
            print("="*60 + "\n")
            
            # Generate test alerts if in test mode
            if self.test_mode:
                self.generate_test_alerts()
            
            # Start monitoring threads
            network_monitor = NetworkMonitor(self)
            network_monitor.start()
            self.threads.append(network_monitor)
            
            log_monitor = SystemLogMonitor(self)
            log_monitor.start()
            self.threads.append(log_monitor)
            
            # Main monitoring loop
            scan_interval = self.config.get("scan_interval", 30)
            
            while self.running:
                # Check file integrity
                self.monitor_file_integrity()
                
                # Check for suspicious processes
                self.check_suspicious_processes()
                
                # Monitor network connections
                self.monitor_network_connections()
                
                # Sleep until next scan
                time.sleep(scan_interval)
                
        except KeyboardInterrupt:
            logging.info("ForensicaGuard stopped by user")
        except Exception as e:
            logging.error(f"Error in ForensicaGuard main loop: {e}")
        finally:
            self.shutdown()
            
    def shutdown(self):
        """Clean shutdown of ForensicaGuard"""
        logging.info("Shutting down ForensicaGuard...")
        
        # Stop running flag
        self.running = False
        
        # Stop file observers
        for observer in self.file_observers:
            observer.stop()
            observer.join()
            
        # Wait for threads to finish
        for thread in self.threads:
            if hasattr(thread, 'running'):
                thread.running = False
            thread.join(timeout=3)
            
        # Generate summary report
        self.generate_summary_report()
        logging.info("ForensicaGuard shutdown complete")

    def generate_summary_report(self):
        """Generate a summary report of all detected events"""
        try:
            report_time = datetime.datetime.now()
            runtime = report_time - self.scan_start_time
            
            report = f"""
            ForensicaGuard Summary Report
            ============================
            
            System: {self.system_info['hostname']} ({self.system_info['ip_address']})
            Platform: {self.system_info['platform']}
            Runtime: {runtime.total_seconds() / 60:.2f} minutes
            Report generated: {report_time.strftime('%Y-%m-%d %H:%M:%S')}
            
            Security Events Summary:
            -----------------------
            Failed login attempts: {sum(len(attempts) for attempts in self.login_attempts.values())}
            Privilege escalation events: {sum(len(events) for events in self.privilege_escalations.values())}
            File access events: {len(self.file_access_events)}
            System shutdowns: {len(self.system_shutdowns)}
            Suspicious processes: {len(self.suspicious_processes)}
            
            Evidence collected: {len(os.listdir(self.evidence_dir)) if os.path.exists(self.evidence_dir) else 0} files
            
            ForensicaGuard completed successfully.
            """
            
            # Save report to file
            report_filename = f"forensicaguard_report_{report_time.strftime('%Y%m%d%H%M%S')}.txt"
            report_path = os.path.join(self.evidence_dir, report_filename)
            
            with open(report_path, 'w') as f:
                f.write(report)
                
            logging.info(f"Summary report generated at {report_path}")
            print("\nSummary report generated:")
            print(report)
            
            return report_path
        except Exception as e:
            logging.error(f"Error generating summary report: {e}")
            return None

if __name__ == "__main__":
    try:
        
        fg = ForensicaGuard()
        fg.run()
    except Exception as e:
        logging.critical(f"Critical error in ForensicaGuard: {e}")
        sys.exit(1)

