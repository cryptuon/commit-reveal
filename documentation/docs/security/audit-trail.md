# Audit Trail

The audit trail system provides tamper-evident logging for all commit-reveal operations. It is enabled by default.

## Overview

```python
from commit_reveal import CommitRevealScheme
from commit_reveal.audit import get_audit_trail

# Audit trail is enabled by default
cr = CommitRevealScheme(enable_audit=True)

# Operations are automatically logged
commitment, salt = cr.commit("secret")   # logged
result = cr.reveal("secret", salt, commitment)  # logged
```

## AuditTrail

```python
from commit_reveal.audit import AuditTrail, get_audit_trail, set_audit_trail
```

### Constructor

```python
AuditTrail(audit_dir: Optional[Path] = None)
```

Default directory: `~/.commit-reveal/audit/`. Stores events in `audit.jsonl` with `0600` permissions.

### Session Context

```python
audit = get_audit_trail()

# Set context for all subsequent operations
session_id = audit.set_session_context(user_id="alice@example.com")

# Get current context
user_id, session_id = audit.get_session_context()
```

### Logging Events

Events are logged automatically during `commit`, `reveal`, and ZKP operations. You can also log custom events:

```python
# Custom event
audit.log_event(
    event_type="custom",
    operation="user_action",
    details={"action": "exported_data"},
    success=True,
)

# Convenience methods
audit.log_commit("my-secret", hash_algorithm="sha256")
audit.log_reveal("my-secret", success=True)
audit.log_zkp_creation("my-secret")
audit.log_zkp_verification("my-secret", verification_result=True)
```

!!! info
    Sensitive values are never logged. The audit trail records only metadata: operation types, timestamps, success/failure, and user context.

### Querying Events

```python
# Get all events
events = audit.get_events()

# Filter by criteria
events = audit.get_events(
    start_time=datetime(2025, 1, 1),
    end_time=datetime(2025, 12, 31),
    event_type="commit",
    user_id="alice@example.com",
    session_id="abc123",
)
```

### Integrity Verification

Each event includes a cryptographic integrity hash. Verify the entire trail:

```python
result = audit.verify_integrity()

print(result["total_events"])       # Total events in the trail
print(result["verified_events"])    # Events that passed verification
print(result["failed_events"])      # List of failed event IDs
print(result["integrity_verified"]) # True if all events are intact
```

### Exporting Reports

```python
from pathlib import Path

audit.export_audit_report(Path("audit_report.json"))
# File created with 0600 permissions
```

The report includes all events, session metadata, and integrity verification results.

## AuditEvent

Individual audit events with integrity verification:

```python
from commit_reveal.audit import AuditEvent

event = AuditEvent(
    event_type="commit",
    operation="create_commitment",
    details={"algorithm": "sha256"},
    success=True,
    user_id="alice",
    session_id="session-123",
)

# Convert to dictionary
event_dict = event.to_dict()

# Verify integrity
assert event.verify_integrity()
```

## Monitoring Example

```python
from datetime import datetime, timedelta

def check_security_events():
    audit = get_audit_trail()

    # Check for recent failures
    recent = audit.get_events(
        start_time=datetime.now() - timedelta(hours=1),
        event_type="security_error",
    )

    if len(recent) > 10:
        print("Alert: high number of security violations")

    # Verify trail integrity
    result = audit.verify_integrity()
    if not result["integrity_verified"]:
        print("Alert: audit trail integrity compromised")
```
