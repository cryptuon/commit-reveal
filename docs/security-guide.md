# Security Guide

This guide covers security considerations, best practices, and implementation guidance for production deployments of the commit-reveal library.

## Security Model

### Assumptions

The commit-reveal library operates under the following security assumptions:

1. **Trusted Execution Environment**: The library runs in a trusted environment where the underlying OS and hardware are not compromised
2. **Secure Random Number Generation**: Python's `secrets` module provides access to cryptographically secure randomness
3. **Hash Function Security**: The selected hash algorithms (SHA-256, SHA-512, etc.) remain cryptographically secure
4. **Network Security**: When used in distributed systems, secure communication channels (TLS) are used
5. **Key Management**: Any long-term cryptographic keys are managed securely outside this library

### Threat Model

#### Threats We Protect Against

1. **Timing Attacks**: All cryptographic comparisons use constant-time operations
2. **Side-Channel Attacks**: Secure random number generation and careful memory handling
3. **Input Injection**: Comprehensive validation and sanitization of all inputs
4. **Information Leakage**: No plaintext values stored in secure mode
5. **Replay Attacks**: Timestamping and nonce usage in protocols
6. **Commitment Binding**: Cryptographically secure binding prevents commitment changes

#### Threats Outside Scope

1. **Physical Attacks**: Hardware-level attacks on the execution environment
2. **Operating System Compromise**: Kernel-level or root-level system compromise
3. **Network Attacks**: Man-in-the-middle attacks on communication channels
4. **Social Engineering**: Attacks targeting users rather than the cryptographic protocol
5. **Implementation Bugs**: While we follow best practices, formal verification is not provided

## Cryptographic Security

### Hash Algorithm Selection

The library enforces secure hash algorithm selection:

```python
# Secure algorithms (allowed)
SECURE_ALGORITHMS = {
    'sha256',    # Recommended default
    'sha384',    # Higher security margin
    'sha512',    # Highest security
    'sha3_256',  # SHA-3 variant
    'sha3_384',  # SHA-3 variant
    'sha3_512',  # SHA-3 variant
    'blake2b',   # Fast and secure
    'blake2s'    # Fast and secure (smaller output)
}

# Insecure algorithms (rejected)
DEPRECATED_ALGORITHMS = {
    'md5',      # Cryptographically broken
    'sha1',     # Collision attacks known
    'sha224'    # Truncated SHA-256, not recommended
}
```

**Best Practice**: Use SHA-256 (default) unless you have specific requirements for higher security margins.

```python
# Recommended for most applications
cr = CommitRevealScheme(hash_algorithm='sha256')

# For high-security applications
cr = CommitRevealScheme(hash_algorithm='sha512')

# This will raise SecurityError
cr = CommitRevealScheme(hash_algorithm='md5')  # Rejected!
```

### Salt Generation and Management

Salts are generated using cryptographically secure random number generation:

```python
# Automatic secure salt generation (recommended)
commitment, salt = cr.commit("my value")

# Manual salt (ensure it's cryptographically random)
import secrets
secure_salt = secrets.token_bytes(32)  # 256 bits
commitment, salt = cr.commit("my value", salt=secure_salt)
```

**Security Requirements for Salts**:
- Minimum 16 bytes (128 bits)
- Maximum 1024 bytes
- Must have sufficient entropy (not all zeros, not low entropy)
- Should be unique for each commitment

### Zero-Knowledge Proof Security

The ZKP implementation uses industry-standard cryptography:

```python
# Uses secp256k1 elliptic curve (same as Bitcoin)
# Implements Schnorr signature scheme
# Non-interactive via Fiat-Shamir heuristic

cr = CommitRevealScheme(use_zkp=True)
commitment, salt = cr.commit("secret")

# Create proof
public_key, R_compressed, challenge, response = cr.create_zkp_proof(
    "secret", salt, commitment
)

# Verify proof (without knowing the secret)
is_valid = cr.verify_zkp_proof(
    commitment, public_key, R_compressed, challenge, response
)
```

**ZKP Security Considerations**:
- Each proof should only be used once
- Public keys should not be reused across different commitments
- The curve implementation follows NIST standards
- Challenge generation uses cryptographically secure hashing

## Input Validation Security

### Comprehensive Input Sanitization

All inputs are validated to prevent various attack vectors:

```python
from commit_reveal import ValidationError, SecurityError

# String validation
def secure_string_handling():
    try:
        # This will work
        cr.commit("normal string")

        # This will be rejected (contains null bytes)
        cr.commit("string\x00with\x00nulls")

    except SecurityError as e:
        print(f"Security violation: {e}")

# Integer validation
def secure_integer_handling():
    try:
        # This will work
        cr.commit(42)

        # This will be rejected (negative not supported)
        cr.commit(-42)

    except ValidationError as e:
        print(f"Validation error: {e}")

# Size limits
def secure_size_limits():
    try:
        # This will work
        cr.commit("x" * 1000)

        # This will be rejected (too large)
        cr.commit("x" * 20_000_000)  # 20MB

    except ValidationError as e:
        print(f"Size limit exceeded: {e}")
```

### Directory Traversal Prevention

The CLI components prevent directory traversal attacks:

```python
from commit_reveal.validation import sanitize_filename

# Safe filename handling
unsafe_name = "../../../etc/passwd"
safe_name = sanitize_filename(unsafe_name)
print(safe_name)  # "etc_passwd" (sanitized)

# Dangerous patterns are neutralized
dangerous = "con.txt"  # Windows reserved name
safe = sanitize_filename(dangerous)  # "safe_con.txt"
```

## CLI Security

### Secure CLI vs Legacy CLI

**Always use the secure CLI for production**:

```bash
# Secure (recommended)
commit-reveal-secure commit my-secret

# Legacy (deprecated, insecure)
commit-reveal commit my-secret "plaintext value"
```

### Security Features of Secure CLI

1. **No Plaintext Storage**: Values are never written to disk
2. **Secure Input**: Uses `getpass` to prevent echo
3. **File Permissions**: All files created with 0600 (owner-only)
4. **Input Validation**: All CLI inputs are validated
5. **Audit Trail**: All operations are logged securely

```python
# Secure CLI implementation highlights
def prompt_for_value(prompt: str) -> str:
    """Securely prompt for a value without echoing."""
    try:
        # Uses getpass to avoid echoing sensitive values
        value = getpass.getpass(f"{prompt}: ")
        if not value.strip():
            raise ValueError("Value cannot be empty")
        return value
    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        sys.exit(1)

def save_secure_commitment(name: str, commitment: bytes, salt: bytes):
    """Save commitment without storing plaintext value."""
    # File created with 0600 permissions (owner read/write only)
    with open(commitment_file, "w") as f:
        json.dump(secure_data, f, indent=2)
    commitment_file.chmod(0o600)
```

### Migration Security

When migrating from legacy CLI:

```bash
# Check what needs migration
commit-reveal-migrate --list

# Migrate with backups (recommended)
commit-reveal-migrate --all

# Migrate without backups (not recommended)
commit-reveal-migrate --all --no-backup
```

**Migration Security Features**:
- Creates secure backups of old data
- Removes plaintext values from new format
- Sets proper file permissions
- Verifies integrity of migrated data

## Audit Trail Security

### Tamper-Evident Logging

The audit system provides cryptographic integrity verification:

```python
from commit_reveal.audit import get_audit_trail

# Enable audit trail (default)
cr = CommitRevealScheme(enable_audit=True)

# Set user context for audit
audit = get_audit_trail()
session_id = audit.set_session_context(user_id="alice")

# Operations are automatically logged
commitment, salt = cr.commit("secret")  # Logged
result = cr.reveal("secret", salt, commitment)  # Logged

# Verify audit integrity
integrity_check = audit.verify_integrity()
if integrity_check['integrity_verified']:
    print("Audit trail is intact")
else:
    print(f"Audit integrity issues: {integrity_check['failed_events']}")
```

### Audit Data Protection

```python
# Audit events sanitize sensitive data
audit.log_commit(
    commitment_name="user-bid",
    hash_algorithm="sha256",
    success=True
)

# Sensitive values are never logged
# Only metadata like lengths, types, and success/failure
```

## Production Deployment Security

### Environment Security

```python
# Production configuration
class ProductionConfig:
    def __init__(self):
        # Enable all security features
        self.cr = CommitRevealScheme(
            hash_algorithm='sha256',  # Or sha512 for higher security
            use_zkp=True,            # Enable ZKP for sensitive applications
            enable_audit=True        # Enable comprehensive logging
        )

        # Set secure audit context
        audit = get_audit_trail()
        audit.set_session_context(user_id=self.get_authenticated_user())

    def get_authenticated_user(self):
        # Implement proper user authentication
        return "authenticated_user_id"
```

### File System Security

```bash
# Ensure secure permissions for storage directory
chmod 700 ~/.commit-reveal
chmod 600 ~/.commit-reveal/*.json
chmod 700 ~/.commit-reveal/audit
chmod 600 ~/.commit-reveal/audit/audit.jsonl
```

### Network Security

When using in distributed systems:

```python
import ssl
import requests

class SecureDistributedCommitReveal:
    def __init__(self):
        self.cr = CommitRevealScheme(use_zkp=True, enable_audit=True)

        # Configure secure TLS
        self.session = requests.Session()
        self.session.verify = True  # Verify SSL certificates

        # Use TLS 1.2 or higher
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2

    def submit_commitment_to_server(self, commitment):
        # Always use HTTPS
        response = self.session.post(
            "https://secure-server.com/commitments",
            json={"commitment": commitment.hex()},
            headers={"Content-Type": "application/json"}
        )
        return response
```

## Error Handling Security

### Secure Error Handling

```python
def secure_operation_handler(user_input):
    try:
        cr = CommitRevealScheme()
        commitment, salt = cr.commit(user_input)
        return {"success": True, "commitment": commitment.hex()}

    except ValidationError as e:
        # Log security event but don't expose internal details
        audit.log_event("validation_error", "commit_attempt",
                        {"error_type": "validation"}, success=False)
        return {"success": False, "error": "Invalid input format"}

    except SecurityError as e:
        # Log security violation
        audit.log_event("security_error", "commit_attempt",
                        {"error_type": "security"}, success=False)
        return {"success": False, "error": "Security policy violation"}

    except Exception as e:
        # Log unexpected errors without exposing details
        audit.log_event("system_error", "commit_attempt",
                        {"error_type": "system"}, success=False)
        return {"success": False, "error": "Operation failed"}
```

### Information Disclosure Prevention

```python
# Good: Generic error messages
def safe_reveal(value, salt, commitment):
    try:
        result = cr.reveal(value, salt, commitment)
        return {"valid": result}
    except Exception:
        return {"valid": False}  # Don't expose why it failed

# Bad: Detailed error messages that could help attackers
def unsafe_reveal(value, salt, commitment):
    try:
        result = cr.reveal(value, salt, commitment)
        return {"valid": result}
    except ValidationError as e:
        return {"valid": False, "reason": str(e)}  # Too much info!
```

## Memory Security

### Secure Memory Handling

```python
# The library attempts to clear sensitive data
from commit_reveal.validation import SecureString

# Use SecureString for sensitive data
sensitive_value = SecureString("my secret")
str_value = str(sensitive_value)  # Use the value
sensitive_value.clear()  # Explicitly clear when done

# For bytes, the library provides secure wiping attempts
from commit_reveal.validation import secure_wipe_bytes

sensitive_bytes = b"secret data"
# Use the bytes...
secure_wipe_bytes(sensitive_bytes)  # Best effort clearing
```

### Memory Limitations

**Note**: Python's garbage collection and string immutability make true secure memory wiping difficult. For applications requiring guaranteed memory security, consider:

1. Using specialized secure memory libraries
2. Running in secure enclaves
3. Using hardware security modules (HSMs)
4. Implementing at the operating system level

## Compliance and Standards

### Cryptographic Standards Compliance

- **NIST Recommendations**: Follows NIST SP 800-57 for key lengths
- **FIPS 140-2**: Uses FIPS-approved algorithms
- **RFC Standards**: Implements standard cryptographic protocols
- **Industry Best Practices**: Follows OWASP and security guidelines

### Audit Requirements

For compliance environments:

```python
# Enable comprehensive audit logging
cr = CommitRevealScheme(enable_audit=True)

# Set compliance context
audit = get_audit_trail()
audit.set_session_context(
    user_id="compliant_user",
    # session_metadata could include compliance info
)

# All operations are logged with integrity verification
commitment, salt = cr.commit("sensitive_data")

# Export audit reports for compliance
audit.export_audit_report(Path("/secure/audit/report.json"))
```

## Security Testing

### Automated Security Testing

The library includes comprehensive security tests:

```bash
# Run security-focused tests
pytest -m security

# Run timing attack tests
pytest tests/test_security.py::test_timing_consistency -v

# Run input validation tests
pytest tests/test_validation.py -v

# Run property-based security tests
pytest tests/test_properties.py -v
```

### Manual Security Testing

```python
# Test input validation
def test_security_manually():
    cr = CommitRevealScheme()

    # Test dangerous inputs
    dangerous_inputs = [
        "../../../etc/passwd",
        "script><script>alert('xss')</script>",
        "\x00\x01\x02",
        "A" * 100000000,  # Very large input
        -999999999,       # Negative number
    ]

    for dangerous_input in dangerous_inputs:
        try:
            cr.commit(dangerous_input)
            print(f"WARNING: Dangerous input accepted: {dangerous_input}")
        except (ValidationError, SecurityError):
            print(f"Good: Dangerous input rejected: {type(dangerous_input)}")
```

## Incident Response

### Security Incident Handling

1. **Detection**: Monitor audit logs for unusual patterns
2. **Assessment**: Verify audit trail integrity
3. **Containment**: Disable affected components
4. **Recovery**: Restore from secure backups
5. **Lessons Learned**: Update security measures

```python
# Security monitoring example
def monitor_security_events():
    audit = get_audit_trail()

    # Check for security violations
    recent_events = audit.get_events(
        start_time=datetime.now() - timedelta(hours=1),
        event_type="security_error"
    )

    if len(recent_events) > 10:  # Threshold
        alert_security_team("High number of security violations detected")

    # Verify audit integrity
    integrity_check = audit.verify_integrity()
    if not integrity_check['integrity_verified']:
        alert_security_team("Audit trail integrity compromised")
```

### Backup and Recovery

```python
# Secure backup procedures
def create_secure_backup():
    audit = get_audit_trail()
    backup_path = Path("/secure/backups/audit_backup.json")

    # Create encrypted backup
    audit.export_audit_report(backup_path)

    # Set secure permissions
    backup_path.chmod(0o600)

    # Verify backup integrity
    # (implementation would include checksum verification)
```

## Security Updates

### Staying Secure

1. **Monitor Releases**: Subscribe to security advisories
2. **Update Regularly**: Apply security patches promptly
3. **Test Updates**: Verify compatibility before production deployment
4. **Review Changes**: Understand security implications of updates

### Reporting Security Issues

If you discover security vulnerabilities:

1. **DO NOT** create public GitHub issues for security problems
2. **DO** email security issues to the maintainers
3. **DO** provide detailed reproduction steps
4. **DO** follow responsible disclosure practices

See [SECURITY.md](../SECURITY.md) for complete security reporting guidelines.

---

Remember: Security is a process, not a destination. Regularly review and update your security practices as threats evolve and new best practices emerge.