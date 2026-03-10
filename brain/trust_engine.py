import sys
import os
import re
from datetime import datetime
from typing import List, Tuple
import re

# Add the project root to path so we can import shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from shared.models import SystemEvent, Severity, ActionType, SentinelAction

class TrustEngine:
    def __init__(self):
        self.trust_score = 100.0
        self.min_score = 0.0
        self.max_score = 100.0
        self.event_history: List[SystemEvent] = []
        self.action_history: List[SentinelAction] = []
        self.last_threat_time = datetime.min
        
        # Scoring Weights
        self.weights = {
            Severity.LOW: 2.0,
            Severity.MEDIUM: 10.0,
            Severity.HIGH: 30.0,
            Severity.CRITICAL: 60.0
        }

    def process_event(self, event: SystemEvent) -> List[SentinelAction]:
        """
        Primary entry point for new system events.
        1. Logs the event.
        2. Updates the Trust Score.
        3. Consults the 'ML Brain' for necessary actions.
        """
        self.event_history.append(event)
        
        # 1. Update Trust Score
        previous_score = self.trust_score
        penalty = self.weights.get(event.severity, 0)
        self.trust_score = max(self.min_score, self.trust_score - penalty)
        
        # Track last significant threat time
        if event.severity in [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]:
            self.last_threat_time = datetime.now()

        print(f"[TrustEngine] Score updated: {previous_score} -> {self.trust_score} (Event: {event.description})")
        
        # 2. Evaluate Actions (The ML Logic Proxy)
        actions = self._ml_decision_brain(event)
        
        # De-duplicate: Don't repeat high-level commands if triggered recently
        recent_actions = [a.action_type for a in self.action_history[-15:]]
        unique_actions = []
        for a in actions:
            if a.action_type in [ActionType.DISCONNECT_NETWORK, ActionType.LOCKOUT_USER]:
                if a.action_type not in recent_actions:
                    unique_actions.append(a)
            else:
                unique_actions.append(a)

        for action in unique_actions:
            self.action_history.append(action)
            print(f"[TrustEngine] ACTION TRIGGERED: {action.action_type.value} on {action.target} - Reason: {action.reason}")
            
        return unique_actions

    def recover_trust(self):
        """
        Intelligent Recovery:
        1. Cooldown Period (30s): No recovery right after a threat.
        2. Initial Recovery (30s-60s): Slow recovery (+2.0).
        3. Stable Recovery (>60s): Fast recovery (+5.0).
        """
        if self.trust_score >= self.max_score:
            return

        time_since_threat = (datetime.now() - self.last_threat_time).total_seconds()
        
        recovery_amount = 0
        status_msg = ""

        if time_since_threat < 30:
            status_msg = "TRUST_LOCKED (Cooldown Active)"
        elif time_since_threat < 60:
            recovery_amount = 2.0
            status_msg = "SLOW_RECOVERY (Probing Environment)"
        else:
            recovery_amount = 5.0
            status_msg = "ACCELERATED_RECOVERY (Safe State)"

        if recovery_amount > 0:
            prev = self.trust_score
            self.trust_score = min(self.max_score, self.trust_score + recovery_amount)
            print(f"[TrustEngine] {status_msg}: {prev} -> {self.trust_score}")
        else:
            print(f"[TrustEngine] {status_msg}: Trust at {self.trust_score}")

    def _ml_decision_brain(self, event: SystemEvent) -> List[SentinelAction]:
        """
        This mimics the ML analysis. It looks at the context, the current score,
        and the velocity of score drop.
        """
        actions = []
        
        # Case 1: High Velocity Drop (Critical Threat)
        if self.trust_score < 30 and event.severity == Severity.CRITICAL:
            actions.append(SentinelAction(
                action_type=ActionType.LOCKOUT_USER,
                target="Current Session",
                reason="Rapid trust collapse - potential hostile takeover."
            ))
            
        # Case 2: Network Threat
        source_low = event.source.lower()
        desc_low = event.description.lower()
        is_net_threat = "net" in source_low or any(k in desc_low for k in ["network", "ip", "traffic", "conn", "ping"])

        if is_net_threat:
            # Extract IP if exists
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', event.description)
            if ip_match:
                actions.append(SentinelAction(
                    action_type=ActionType.BLOCK_IP,
                    target=ip_match.group(1),
                    reason=f"Blocking malicious IP detected in: {event.description}"
                ))

            if event.severity in [Severity.HIGH, Severity.CRITICAL]:
                actions.append(SentinelAction(
                    action_type=ActionType.DISCONNECT_NETWORK,
                    target="All Adapters",
                    reason=f"Detected high severity network threat: {event.description}"
                ))
            
        # Case 3: Unauthorized Admin escalation/usage
        if "administrative" in event.description.lower() or "whoami" in event.description.lower():
            actions.append(SentinelAction(
                action_type=ActionType.STRIP_PRIVILEGES,
                target=event.process_name if event.process_name else "System",
                reason="Suspicious administrative command usage."
            ))

        # Case 4: Known Malicious Pattern (YARA)
        if event.source == "yara":
            actions.append(SentinelAction(
                action_type=ActionType.KILL_PROCESS,
                target=str(event.process_id),
                reason=f"YARA signature match: {event.description}"
            ))
            actions.append(SentinelAction(
                action_type=ActionType.BLACKLIST_APP,
                target=event.process_name,
                reason="Matched known malware signature."
            ))

        # Case 5: Registry Reversion (Self-Healing)
        if "registry" in source_low:
            # Entry: 'Name' -> 'Value'
            reg_match = re.search(r"entry:\s+'([^']+)'", event.description)
            if reg_match:
                actions.append(SentinelAction(
                    action_type=ActionType.REVERT_REGISTRY,
                    target=reg_match.group(1),
                    reason=f"Unauthorized registry persistence detected: {reg_match.group(1)}"
                ))

        return actions

if __name__ == "__main__":
    # Quick Test
    engine = TrustEngine()
    
    # Simulate a suspicious network event
    e1 = SystemEvent(
        id="1",
        timestamp=datetime.now(),
        source="network",
        description="Attempted connection to C2 server 8.8.4.4:443",
        severity=Severity.HIGH,
        process_name="cmd.exe"
    )
    
    engine.process_event(e1)
    
    # Simulate a critical YARA match
    e2 = SystemEvent(
        id="2",
        timestamp=datetime.now(),
        source="yara",
        description="CobaltStrike Beacon detected",
        severity=Severity.CRITICAL,
        process_id=1234,
        process_name="malware.exe"
    )
    
    engine.process_event(e2)
