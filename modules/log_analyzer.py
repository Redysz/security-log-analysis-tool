from pathlib import Path
import re

from modules.constants import LOG_LINE_RE
from modules.models import Incident, LogEntry


class LogAnalyzer:
    def __init__(self, path: Path):
        self.path = path
        self.log_line_pattern = re.compile(LOG_LINE_RE, re.VERBOSE)

    def analyze(self):
        entries = self._read_and_parse()
        for entry in entries:
            print(entry)

    def _read_and_parse(self):
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