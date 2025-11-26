from dataclasses import dataclass


@dataclass
class LogEntry:
    timestamp: str
    severity: str
    source_ip: str
    event_type: str
    details: str


@dataclass
class Incident:
    rule_name: str
    description: str
    first_seen: str
    last_seen: str
    source_ip: str
    extra: dict[str, str]
