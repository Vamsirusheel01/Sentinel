import sys
import os
import re
import itertools

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agent.yara_fallback import YaraFallback
from agent.executor import ActionExecutor
from shared.models import SentinelAction, ActionType
import time
import requests
import subprocess
import logging
from datetime import datetime
BRAIN_URL = "http://localhost:8000/inject"
RULES_PATH = os.path.join(os.path.dirname(__file__), "rules", "base_rules.yar")
SCAN_DIRS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Downloads"),
    "C:\\temp"
]
LOG_FILE = os.path.join(os.path.dirname(__file__), "sentinel_agent.log")

# Unified Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SentinelAgent")

class SentinelWatcher:
    """
    Continually monitors the system for indicators of compromise (IoCs).
    """
    def __init__(self, dry_run: bool = True):
        self.known_processes = set()
        self.startup_keys = self._get_startup_keys()
        self.yara = YaraFallback(RULES_PATH)
        self.executor = ActionExecutor(dry_run=dry_run)
        logger.info(f"Sentinel Agent Initialized. Rules: {RULES_PATH}. DryRun: {dry_run}")
        
    def _get_startup_keys(self):
        """
        Parses HKCU Run keys into a dictionary: {Name: Value}
        """
        keys = {}
        target = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        try:
            output = subprocess.check_output(['reg', 'query', target], stderr=subprocess.STDOUT, shell=True).decode('utf-8', errors='ignore')
            # Lines look like: "    Name    REG_SZ    Value"
            for line in output.splitlines():
                parts = re.split(r'\s{4,}', line.strip())
                if len(parts) >= 3:
                    keys[parts[0]] = parts[2]
            return keys
        except Exception as e:
            return {}

    def scan_processes(self):
        """
        Looks for suspicious command line tools often used by attackers.
        """
        suspicious_terms = ["whoami", "nltest", "net group", "ipconfig /all", "mimikatz", "powershell -enc"]
        
        try:
            # We use tasklist for a simple cross-environment check without needing psutil installed
            # Using errors='replace' to handle non-UTF-8 characters in localized names/titles
            output = subprocess.check_output(['tasklist', '/v', '/fo', 'csv']).decode('utf-8', errors='replace')
            lines = [l for l in output.split('\n') if l.strip()]
            
            # Skip header line safely
            if len(lines) > 1:
                for line in itertools.islice(lines, 1, None):
                    # Check for suspicious process names or window titles
                    for term in suspicious_terms:
                        if term.lower() in line.lower():
                            self.report_threat("PROCESS_MONITOR", f"Suspicious tool usage detected: {term}", "HIGH")
                        
        except Exception as e:
            print(f"Process scan error: {e}")

    def scan_directories(self):
        """
        Scans sensitive directories for files matching YARA rules.
        """
        for directory in SCAN_DIRS:
            if not os.path.exists(directory): continue
            
            try:
                for root, _, files in os.walk(directory):
                    for file in files:
                        if file.endswith(('.txt', '.exe', '.bat', '.ps1')):
                            path = os.path.join(root, file)
                            matches = self.yara.scan_file(path)
                            for m in matches:
                                self.report_threat("YARA_SCANNER", f"File '{file}' matches rule '{m['rule']}'", "CRITICAL")
            except Exception as e:
                print(f"[Watcher] Dir scan error: {e}")

    def scan_registry(self):
        current_keys = self._get_startup_keys()
        
        # Check for new or modified entries
        for name, value in current_keys.items():
            if name not in self.startup_keys or self.startup_keys[name] != value:
                self.report_threat("REGISTRY_WATCHER", f"Unauthorized startup entry: '{name}' -> '{value}'", "CRITICAL")
        
        self.startup_keys = current_keys

    def simulate_yara(self):
        # In a real version, we'd run: yara.compile(source=rules).match(pid=pid)
        # For demo, we simulate a match every now and then if a specific file exists
        if os.path.exists("C:\\temp\\malware.txt"):
            self.report_threat("YARA_SCANNER", "Found signature 'Backdoor.Win32.Sentinel' in C:\\temp\\malware.txt", "CRITICAL")

    def report_threat(self, source, desc, severity):
        print(f"[Watcher] THREAT DETECTED: {source} - {desc} ({severity})")
        try:
            # We use query params as defined in the server's /inject endpoint
            params = {
                "source": source,
                "description": desc,
                "severity": severity
            }
            response = requests.post(f"{BRAIN_URL}", params=params)
            if response.status_code == 200:
                data = response.json()
                print(f"[Watcher] Brain Analysis Received: {data['status']}")
                
                # Execute any actions returned by the brain
                actions = data.get("actions", [])
                for action_data in actions:
                    # Human-in-the-loop: Only execute if already approved (High Confidence)
                    if action_data["status"] == "APPROVED":
                        action = SentinelAction(
                            action_type=ActionType(action_data["type"]),
                            target=action_data["target"],
                            reason=f"AI Approved Countermeasure (Conf: {action_data.get('confidence', 0):.2f})"
                        )
                        self.executor.execute(action)
                    else:
                        print(f"[Watcher] Action {action_data['type']} is PENDING human approval.")
            else:
                print(f"[Watcher] Brain reported error: {response.status_code}")
        except Exception as e:
            print(f"[Watcher] Failed to connect to Brain: {e}")

    def run(self):
        logger.info("Sentinel Resident Watcher started (Loop: 10s)")
        while True:
            try:
                self.scan_processes()
                self.scan_registry()
                self.scan_directories()
            except Exception as e:
                logger.error(f"Scan Loop Error: {e}")
            
            time.sleep(10)

if __name__ == "__main__":
    # Change to dry_run=False to enable real system actions (Requires Admin)
    watcher = SentinelWatcher(dry_run=True)
    watcher.run()
