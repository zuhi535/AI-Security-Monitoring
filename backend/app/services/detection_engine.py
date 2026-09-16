import re
from dataclasses import dataclass


@dataclass
class Detection:
    rule_name: str
    severity: str
    title: str
    description: str
    confidence: float


def detect_threats(
    source: str,
    source_ip: str,
    event_type: str,
    username: str | None,
    message: str,
) -> list[Detection]:

    detections: list[Detection] = []

    # ---------------------------------------------------------
    # 1. Brute force / failed authentication
    # ---------------------------------------------------------

    if event_type.lower() in {
        "login_failed",
        "authentication_failed",
        "failed_login",
    }:
        detections.append(
            Detection(
                rule_name="FAILED_LOGIN",
                severity="HIGH",
                title="Failed authentication attempt",
                description=(
                    f"Failed authentication attempt detected "
                    f"from {source_ip}."
                ),
                confidence=0.85,
            )
        )

    # ---------------------------------------------------------
    # 2. Suspicious privileged username
    # ---------------------------------------------------------

    privileged_users = {
        "admin",
        "administrator",
        "root",
        "superuser",
    }

    if username and username.lower() in privileged_users:
        detections.append(
            Detection(
                rule_name="PRIVILEGED_ACCOUNT_TARGET",
                severity="HIGH",
                title="Privileged account targeted",
                description=(
                    f"Suspicious activity targeting privileged "
                    f"account '{username}'."
                ),
                confidence=0.90,
            )
        )

    # ---------------------------------------------------------
    # 3. SQL Injection
    # ---------------------------------------------------------

    sql_patterns = [
        r"(\bor\b|\band\b)\s+[\w'\"=]+\s*=\s*[\w'\"=]+",
        r"union\s+select",
        r"select\s+.*\s+from",
        r"drop\s+table",
        r"insert\s+into",
        r"delete\s+from",
        r"--\s*$",
    ]

    for pattern in sql_patterns:
        if re.search(pattern, message, re.IGNORECASE):
            detections.append(
                Detection(
                    rule_name="SQL_INJECTION",
                    severity="CRITICAL",
                    title="Possible SQL injection attempt",
                    description=(
                        "The security event contains a pattern "
                        "commonly associated with SQL injection."
                    ),
                    confidence=0.95,
                )
            )
            break

    # ---------------------------------------------------------
    # 4. XSS
    # ---------------------------------------------------------

    xss_patterns = [
        r"<script",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<iframe",
    ]

    for pattern in xss_patterns:
        if re.search(pattern, message, re.IGNORECASE):
            detections.append(
                Detection(
                    rule_name="XSS",
                    severity="HIGH",
                    title="Possible XSS attack",
                    description=(
                        "The security event contains a pattern "
                        "associated with cross-site scripting."
                    ),
                    confidence=0.94,
                )
            )
            break

    # ---------------------------------------------------------
    # 5. Path Traversal
    # ---------------------------------------------------------

    path_traversal_patterns = [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"/etc/shadow",
        r"windows\\system32",
    ]

    for pattern in path_traversal_patterns:
        if re.search(pattern, message, re.IGNORECASE):
            detections.append(
                Detection(
                    rule_name="PATH_TRAVERSAL",
                    severity="HIGH",
                    title="Possible path traversal attack",
                    description=(
                        "The security event contains a path traversal "
                        "pattern."
                    ),
                    confidence=0.93,
                )
            )
            break

    # ---------------------------------------------------------
    # 6. Suspicious command
    # ---------------------------------------------------------

    suspicious_commands = [
        "wget ",
        "curl ",
        "powershell",
        "cmd.exe",
        "nc ",
        "netcat",
        "chmod ",
        "base64 ",
    ]

    message_lower = message.lower()

    for command in suspicious_commands:
        if command in message_lower:
            detections.append(
                Detection(
                    rule_name="SUSPICIOUS_COMMAND",
                    severity="MEDIUM",
                    title="Suspicious command detected",
                    description=(
                        f"The event contains a potentially dangerous "
                        f"command or utility: '{command.strip()}'."
                    ),
                    confidence=0.80,
                )
            )
            break

    return detections