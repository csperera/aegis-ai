from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime
import uuid


@dataclass
class ThreatEvent:
    # --- Ingestion fields ---
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    features: dict[str, float] = field(default_factory=dict)
    label: str = "Benign"
    attack_family: str = "Benign"
    meta: dict[str, Any] = field(default_factory=dict)

    # --- Prediction Agent fields ---
    risk_score: Optional[float] = None
    is_suspicious: Optional[bool] = None
    model_version: Optional[str] = None

    # --- Triage Agent fields ---
    severity: Optional[str] = None          # CRITICAL/HIGH/MEDIUM/LOW/INFO
    triage_decision: Optional[str] = None   # ESCALATE/MONITOR/IGNORE
    rules_triggered: list[str] = field(default_factory=list)
    attack_hypothesis: Optional[str] = None

    # --- Explanation Agent fields ---
    llm_explanation: Optional[str] = None
    analyst_summary: Optional[str] = None
    recommended_action: Optional[str] = None
    confidence: Optional[float] = None
    reasoning_trace: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)