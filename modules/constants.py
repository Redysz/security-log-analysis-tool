from enum import Enum

# LINE EXAMPLE: [2025-07-03 10:00:01] INFO 192.168.1.10 GET /index.html 200
LOG_LINE_RE = r"""
^\[(?P<timestamp>[^\]]+)\]\s+   # [2025-07-03 10:00:01]
(?P<severity>\S+)\s+            # INFO
(?P<source_ip>\S+)\s+           # 192.168.1.10
(?P<event_type>\S+)\s+          # GET
(?P<details>.*)$                # /index.html 200
""".strip()


# IMPORTANT EVENTS
class EventType(Enum):
    FAILED_LOGIN = "FAILED_LOGIN"
    SQL_INJECTION_ATTEMPT = "SQL_INJECTION_ATTEMPT"
    UNUSUAL_ACCESS = "UNUSUAL_ACCESS"
    PORT_SCAN_ATTEMPT = "PORT_SCAN_ATTEMPT"