import requests
import time
import sys
import os

BASE_URL = "http://localhost:8000/inject"

def simulate_threat(source, desc, severity):
    print(f"[*] Simulating threat: {desc} ({severity})")
    try:
        params = {
            "source": source,
            "description": desc,
            "severity": severity
        }
        resp = requests.post(BASE_URL, params=params)
        print(f"[+] Response: {resp.json()}")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    print("=== Sentinel Threat Simulation ===")
    
    # 0. Create a "malicious" file for YARA to find
    print("[*] Creating bait file: C:\\temp\\discovery.txt")
    if not os.path.exists("C:\\temp"):
        os.makedirs("C:\\temp")
    with open("C:\\temp\\discovery.txt", "w") as f:
        f.write("This is a secret note.\nUser discovery: net group \"Domain Admins\"\n")
    
    # 1. Suspicious discovery
    simulate_threat("PROCESS_WATCHER", "User executed 'whoami /all' - potential discovery phase", "medium")
    time.sleep(3)
    
    # 2. Suspicious network
    simulate_threat("NET_WATCHER", "High-frequency outbound traffic to unknown IP 192.168.1.105:4444", "high")
    time.sleep(3)
    
    # 3. Critical Ransomware-like activity
    simulate_threat("YARA", "Signature MATCH: 'Ransomware.LockBit' in C:\\Users\\Public\\Videos", "critical")
    time.sleep(2)
    
    # 4. Final Blow - Rapid Trust Collapse
    simulate_threat("SYSTEM", "Multiple unauthorized admin login attempts detected", "critical")
    time.sleep(2)

    # 5. Registry Persistence (Self-Healing Stage)
    simulate_threat("REGISTRY_WATCHER", "Unauthorized startup entry: 'Backdoor' -> 'C:\\malware.exe'", "critical")
    
    print("\n[!] Simulation complete. Check the Sentinel Dashboard to see the autonomous response.")
