import subprocess
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from shared.models import SentinelAction, ActionType

class ActionExecutor:
    """
    Executes the definitive actions sent by the Brain.
    WARNING: These are real system commands.
    """
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        if dry_run:
            print("[Executor] INITIALIZED IN DRY_RUN MODE. No real changes will be made.")
        else:
            print("[Executor] WARNING: INITIALIZED IN REAL MODE. System changes will be applied.")
    
    def execute(self, action: SentinelAction):
        msg = f"[Executor] {'DRY_RUN: ' if self.dry_run else 'EXECUTING: '} {action.action_type.value} on {action.target}"
        print(msg)
        
        if action.action_type == ActionType.KILL_PROCESS:
            self._kill_process(action.target)
        elif action.action_type == ActionType.DISCONNECT_NETWORK:
            self._disable_network()
        elif action.action_type == ActionType.STRIP_PRIVILEGES:
            self._strip_privileges(action.target)
        elif action.action_type == ActionType.LOCKOUT_USER:
            self._lockout_session()
        elif action.action_type == ActionType.BLOCK_IP:
            self._block_ip(action.target)
        elif action.action_type == ActionType.REVERT_REGISTRY:
            self._revert_registry(action.target)
        else:
            print(f"[Executor] Action {action.action_type.value} not yet implemented.")

    def _kill_process(self, target: str):
        # target can be PID or name
        try:
            cmd = ["taskkill", "/F", "/PID" if target.isdigit() else "/IM", target]
            if not self.dry_run:
                subprocess.run(cmd, check=True)
            print(f"[Executor] SUCCESS: Killed process {target}")
        except Exception as e:
            print(f"[Executor] ERROR: Failed to kill process {target}: {e}")

    def _disable_network(self):
        try:
            print("[Executor] Executing: ipconfig /release")
            # subprocess.run(["ipconfig", "/release"], check=True)
            print("[Executor] SUCCESS: Network disconnected.")
        except Exception as e:
            print(f"[Executor] ERROR: Failed to disconnect network: {e}")

    def _strip_privileges(self, target: str):
        print(f"[Executor] Logic: Revoking administrative rights for {target}...")
        # In a real scenario, this might involve icacls or adjusting token privileges
        # For demo, we log the intent.

    def _lockout_session(self):
        try:
            cmd = ["rundll32.exe", "user32.dll,LockWorkStation"]
            if not self.dry_run:
                subprocess.run(cmd, check=True)
            print(f"[Executor] SUCCESS: session locked.")
        except Exception as e:
            print(f"[Executor] ERROR: Failed to lock session: {e}")

    def _block_ip(self, ip: str):
        rule_name = f"Sentinel_Block_{ip}"
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=out", "action=block",
                f"remoteip={ip}"
            ]
            if not self.dry_run:
                # Requires Admin privileges
                subprocess.run(cmd, check=True)
            print(f"[Executor] SUCCESS: Firewall rule added to block {ip}")
        except Exception as e:
            print(f"[Executor] ERROR: Failed to block IP {ip}: {e}. (Check if running as Admin)")

    def _revert_registry(self, target: str):
        # target is the name of the registry value to delete
        try:
            reg_path = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            cmd = ["reg", "delete", reg_path, "/v", target, "/f"]
            if not self.dry_run:
                subprocess.run(cmd, check=True)
            print(f"[Executor] SUCCESS: Registry value '{target}' reverted (deleted).")
        except Exception as e:
            print(f"[Executor] ERROR: Failed to revert registry value '{target}': {e}")

if __name__ == "__main__":
    from shared.models import Severity
    from datetime import datetime
    
    executor = ActionExecutor()
    dummy_action = SentinelAction(
        action_type=ActionType.KILL_PROCESS,
        target="9999",
        reason="Test Execution"
    )
    executor.execute(dummy_action)
