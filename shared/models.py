from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ActionType(Enum):
    LOG_ONLY = "LOG_ONLY"
    DISCONNECT_NETWORK = "DISCONNECT_NETWORK"
    KILL_PROCESS = "KILL_PROCESS"
    STRIP_PRIVILEGES = "STRIP_PRIVILEGES"
    BLACKLIST_APP = "BLACKLIST_APP"
    LOCKOUT_USER = "LOCKOUT_USER"
    BLOCK_IP = "BLOCK_IP"
    REVERT_REGISTRY = "REVERT_REGISTRY"

class ActionStatus(Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"

@dataclass
class SystemEvent:
    id: str
    timestamp: datetime
    source: str  # registry, network, logs, yara
    description: str
    severity: Severity
    metadata: dict = field(default_factory=dict)
    process_id: Optional[int] = None
    process_name: Optional[str] = None

@dataclass
class SentinelAction:
    action_type: ActionType
    target: str
    reason: str
    status: ActionStatus = ActionStatus.APPROVED
    confidence: float = 1.0
    timestamp: datetime = field(default_factory=datetime.now)
    id: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d%H%M%S%f"))
