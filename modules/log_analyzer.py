from collections import defaultdict
from pathlib import Path
import re
from datetime import datetime, timedelta

from modules.constants import LOG_LINE_RE
from modules.models import Incident, LogEntry


class LogAnalyzer:
    # thresholds
    FAILED_LOGIN_THRESHOLD_IN_SHORT_TIME = 3
    FAILED_LOGIN_TIME_WINDOW_IN_SECONDS = timedelta(seconds=60)

    def __init__(self, path: Path):
        self.path = path
        self.log_line_pattern = re.compile(LOG_LINE_RE, re.VERBOSE)

    def analyze(self):
        entries: list[LogEntry] = self._read_and_parse()
        incidents: list[Incident] = []
        incidents += self._detect_bruteforce(entries)
        print(incidents)

    def _read_and_parse(self) -> list[LogEntry]:
        entries = []
        with open(self.path, encoding="UTF-8") as file:
            for line in file:
                stripped_line = line.strip()
                if not stripped_line:
                    continue
                match = self.log_line_pattern.match(stripped_line)
                if not match:
                    continue

                log_entry = LogEntry(
                    timestamp=match.group("timestamp"),
                    severity=match.group("severity"),
                    source_ip=match.group("source_ip"),
                    event_type=match.group("event_type"),
                    details=match.group("details")
                )
                entries.append(log_entry)
        return entries

    def _detect_bruteforce(self, entries: list[LogEntry]) -> list[Incident]:
        """Brute-Force Detection: Multiple failed login attempts from the same
        IP address within a short timeframe."""
        potential_bruteforce: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in entries:
            if entry.event_type == "FAILED_LOGIN":
                potential_bruteforce[entry.source_ip].append(entry)

        incidents: list[Incident] = []
        for ip, logs in potential_bruteforce.items():
            if len(logs) <= self.FAILED_LOGIN_THRESHOLD_IN_SHORT_TIME:
                continue
            first_seen = datetime.fromisoformat(logs[0].timestamp)
            last_seen = datetime.fromisoformat(logs[-1].timestamp)
            if last_seen - first_seen > self.FAILED_LOGIN_TIME_WINDOW_IN_SECONDS:
                continue

            # it is an incident
            usernames = frozenset(self._extract_key_value(log.details).get("user", "unknown") for log in logs)
            incident = Incident(
                rule_name="Brute-force attempt",
                description=f"{len(logs)} failed login attempts from {ip} (possible brute-force)",
                first_seen=logs[0].timestamp,
                last_seen=logs[-1].timestamp,
                source_ip=ip,
                extra={
                    "failed_count": f"{len(logs)}",
                    "usernames": ", ".join(usernames)
                }
            )
            incidents.append(incident)
        return incidents

    @staticmethod
    def _extract_key_value(details: str) -> dict[str, str]:
        """details='user=testuser'"""
        result = {}
        elements = details.split()
        for element in elements:
            if "=" in element:
                key, value = element.split("=", 1)
                result[key.strip()] = value.strip()
        return result