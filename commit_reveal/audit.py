"""
Cryptographic audit trail implementation for commit-reveal operations.

This module provides comprehensive logging and audit capabilities for
security-critical operations in the commit-reveal scheme.
"""

import json
import time
import hashlib
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import uuid

from .validation import sanitize_filename


class AuditEvent:
    """Represents a single audit event."""

    def __init__(
        self,
        event_type: str,
        operation: str,
        details: Dict[str, Any],
        success: bool = True,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        self.event_id = str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc)
        self.event_type = event_type
        self.operation = operation
        self.details = details
        self.success = success
        self.user_id = user_id
        self.session_id = session_id

        # Create integrity hash
        self.integrity_hash = self._compute_integrity_hash()

    def _compute_integrity_hash(self) -> str:
        """Compute integrity hash of the audit event."""
        # Serialize event data in a deterministic way
        event_data = {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "operation": self.operation,
            "details": self.details,
            "success": self.success,
            "user_id": self.user_id,
            "session_id": self.session_id,
        }

        # Create deterministic JSON string
        json_str = json.dumps(event_data, sort_keys=True, separators=(",", ":"))

        # Compute SHA-256 hash
        return hashlib.sha256(json_str.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "operation": self.operation,
            "details": self.details,
            "success": self.success,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "integrity_hash": self.integrity_hash,
        }

    def verify_integrity(self) -> bool:
        """Verify the integrity hash of this event."""
        # Temporarily remove the hash and recompute
        original_hash = self.integrity_hash
        self.integrity_hash = ""
        computed_hash = self._compute_integrity_hash()
        self.integrity_hash = original_hash

        return computed_hash == original_hash


class AuditTrail:
    """
    Cryptographic audit trail for commit-reveal operations.

    Provides tamper-evident logging of all security-critical operations
    with integrity verification and secure storage.
    """

    def __init__(self, audit_dir: Optional[Path] = None):
        """
        Initialize the audit trail.

        Args:
            audit_dir: Directory for audit logs (default: ~/.commit-reveal/audit)
        """
        if audit_dir is None:
            home = Path.home()
            audit_dir = home / ".commit-reveal" / "audit"

        self.audit_dir = audit_dir
        self.audit_dir.mkdir(parents=True, mode=0o700, exist_ok=True)

        # Thread-local storage for session context
        self._local = threading.local()

        # Initialize audit log file
        self.log_file = self.audit_dir / "audit.jsonl"
        self._ensure_log_file()

    def _ensure_log_file(self) -> None:
        """Ensure audit log file exists with proper permissions."""
        if not self.log_file.exists():
            self.log_file.touch(mode=0o600)
        else:
            # Ensure secure permissions
            self.log_file.chmod(0o600)

    def set_session_context(self, user_id: Optional[str] = None) -> str:
        """
        Set session context for audit logging.

        Args:
            user_id: Optional user identifier

        Returns:
            Session ID for this audit session
        """
        session_id = str(uuid.uuid4())
        self._local.session_id = session_id
        self._local.user_id = user_id
        return session_id

    def get_session_context(self) -> tuple[Optional[str], Optional[str]]:
        """Get current session context."""
        user_id = getattr(self._local, "user_id", None)
        session_id = getattr(self._local, "session_id", None)
        return user_id, session_id

    def log_event(
        self,
        event_type: str,
        operation: str,
        details: Dict[str, Any],
        success: bool = True,
    ) -> str:
        """
        Log an audit event.

        Args:
            event_type: Type of event (e.g., 'commit', 'reveal', 'zkp')
            operation: Specific operation performed
            details: Event-specific details (sanitized)
            success: Whether the operation succeeded

        Returns:
            Event ID of the logged event
        """
        user_id, session_id = self.get_session_context()

        # Sanitize details to remove sensitive information
        sanitized_details = self._sanitize_details(details)

        # Create audit event
        event = AuditEvent(
            event_type=event_type,
            operation=operation,
            details=sanitized_details,
            success=success,
            user_id=user_id,
            session_id=session_id,
        )

        # Write to audit log
        self._write_event(event)

        return event.event_id

    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize event details to remove sensitive information.

        Args:
            details: Raw event details

        Returns:
            Sanitized details safe for logging
        """
        sanitized = {}

        for key, value in details.items():
            # Never log sensitive values
            if key.lower() in ("value", "plaintext", "secret", "password"):
                sanitized[key] = "[REDACTED]"
            # Log lengths instead of actual data for bytes/strings
            elif key.lower() in ("salt", "commitment", "signature"):
                if isinstance(value, (bytes, str)):
                    sanitized[f"{key}_length"] = len(value)
                    sanitized[f"{key}_type"] = type(value).__name__
                else:
                    sanitized[key] = str(value)
            # Log hash algorithm names
            elif key.lower() == "hash_algorithm":
                sanitized[key] = str(value)
            # Log boolean flags
            elif isinstance(value, bool):
                sanitized[key] = value
            # Log numeric values
            elif isinstance(value, (int, float)):
                sanitized[key] = value
            # For other types, log type and length if applicable
            else:
                sanitized[f"{key}_type"] = type(value).__name__
                if hasattr(value, "__len__"):
                    sanitized[f"{key}_length"] = len(value)

        return sanitized

    def _write_event(self, event: AuditEvent) -> None:
        """Write an audit event to the log file."""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                json.dump(event.to_dict(), f, separators=(",", ":"))
                f.write("\n")
        except IOError as e:
            # Log to stderr if we can't write to audit log
            import sys

            print(f"AUDIT ERROR: Failed to write audit event: {e}", file=sys.stderr)

    def log_commit(self, commitment_name: str, hash_algorithm: str, success: bool = True) -> str:
        """Log a commit operation."""
        return self.log_event(
            event_type="commit",
            operation="create_commitment",
            details={
                "commitment_name": sanitize_filename(commitment_name),
                "hash_algorithm": hash_algorithm,
            },
            success=success,
        )

    def log_reveal(self, commitment_name: str, success: bool = True) -> str:
        """Log a reveal operation."""
        return self.log_event(
            event_type="reveal",
            operation="reveal_commitment",
            details={
                "commitment_name": sanitize_filename(commitment_name),
            },
            success=success,
        )

    def log_zkp_creation(self, commitment_name: str, success: bool = True) -> str:
        """Log a ZKP proof creation."""
        return self.log_event(
            event_type="zkp",
            operation="create_proof",
            details={
                "commitment_name": sanitize_filename(commitment_name),
            },
            success=success,
        )

    def log_zkp_verification(self, commitment_name: str, verification_result: bool) -> str:
        """Log a ZKP proof verification."""
        return self.log_event(
            event_type="zkp",
            operation="verify_proof",
            details={
                "commitment_name": sanitize_filename(commitment_name),
                "verification_result": verification_result,
            },
            success=True,  # Operation succeeded, result is in details
        )

    def log_migration(self, commitment_name: str, success: bool = True) -> str:
        """Log a data migration operation."""
        return self.log_event(
            event_type="migration",
            operation="migrate_commitment",
            details={
                "commitment_name": sanitize_filename(commitment_name),
            },
            success=success,
        )

    def log_deletion(self, commitment_name: str, success: bool = True) -> str:
        """Log a commitment deletion."""
        return self.log_event(
            event_type="deletion",
            operation="delete_commitment",
            details={
                "commitment_name": sanitize_filename(commitment_name),
            },
            success=success,
        )

    def get_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_type: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit events with optional filtering.

        Args:
            start_time: Filter events after this time
            end_time: Filter events before this time
            event_type: Filter by event type
            user_id: Filter by user ID
            session_id: Filter by session ID

        Returns:
            List of matching audit events
        """
        events = []

        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        event_data = json.loads(line.strip())

                        # Apply filters
                        if start_time:
                            event_time = datetime.fromisoformat(event_data["timestamp"])
                            if event_time < start_time:
                                continue

                        if end_time:
                            event_time = datetime.fromisoformat(event_data["timestamp"])
                            if event_time > end_time:
                                continue

                        if event_type and event_data.get("event_type") != event_type:
                            continue

                        if user_id and event_data.get("user_id") != user_id:
                            continue

                        if session_id and event_data.get("session_id") != session_id:
                            continue

                        events.append(event_data)

                    except (json.JSONDecodeError, KeyError):
                        # Skip malformed log entries
                        continue

        except IOError:
            # Return empty list if log file doesn't exist or can't be read
            pass

        return events

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verify the integrity of all audit events.

        Returns:
            Dictionary with verification results
        """
        total_events = 0
        verified_events = 0
        failed_events = []

        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        event_data = json.loads(line.strip())
                        total_events += 1

                        # Reconstruct event and verify integrity
                        event = AuditEvent(
                            event_type=event_data["event_type"],
                            operation=event_data["operation"],
                            details=event_data["details"],
                            success=event_data["success"],
                            user_id=event_data.get("user_id"),
                            session_id=event_data.get("session_id"),
                        )

                        # Override with stored values
                        event.event_id = event_data["event_id"]
                        event.timestamp = datetime.fromisoformat(event_data["timestamp"])
                        event.integrity_hash = event_data["integrity_hash"]

                        if event.verify_integrity():
                            verified_events += 1
                        else:
                            failed_events.append(
                                {
                                    "line": line_num,
                                    "event_id": event_data["event_id"],
                                    "timestamp": event_data["timestamp"],
                                }
                            )

                    except (json.JSONDecodeError, KeyError) as e:
                        failed_events.append(
                            {"line": line_num, "error": f"Parse error: {e}"}
                        )

        except IOError:
            return {"error": "Could not read audit log file"}

        return {
            "total_events": total_events,
            "verified_events": verified_events,
            "failed_events": failed_events,
            "integrity_verified": len(failed_events) == 0,
        }

    def export_audit_report(self, output_file: Path) -> None:
        """
        Export a comprehensive audit report.

        Args:
            output_file: Path to write the audit report
        """
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "audit_log_file": str(self.log_file),
            "integrity_check": self.verify_integrity(),
            "events": self.get_events(),
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        # Set secure permissions
        output_file.chmod(0o600)


# Global audit trail instance
_audit_trail: Optional[AuditTrail] = None
_audit_lock = threading.Lock()


def get_audit_trail() -> AuditTrail:
    """Get the global audit trail instance."""
    global _audit_trail

    if _audit_trail is None:
        with _audit_lock:
            if _audit_trail is None:
                _audit_trail = AuditTrail()

    return _audit_trail


def set_audit_trail(audit_trail: AuditTrail) -> None:
    """Set the global audit trail instance."""
    global _audit_trail
    with _audit_lock:
        _audit_trail = audit_trail