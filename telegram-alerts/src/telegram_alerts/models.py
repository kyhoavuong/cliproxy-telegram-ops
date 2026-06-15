from dataclasses import dataclass

@dataclass
class Alert:
    alert_id: str
    severity: str
    title: str
    body: str
    fingerprint: str
