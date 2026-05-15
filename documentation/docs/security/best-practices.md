# Best Practices

## Production Configuration

```python
from commit_reveal import CommitRevealScheme
from commit_reveal.audit import get_audit_trail

# Enable all security features
cr = CommitRevealScheme(
    hash_algorithm='sha256',  # or 'sha512' for higher margin
    use_zkp=True,
    enable_audit=True,
)

# Set audit context
audit = get_audit_trail()
audit.set_session_context(user_id="authenticated_user_id")
```

## CLI Security

!!! tip "Always use the secure CLI"
    ```bash
    # Production
    commit-reveal-secure commit my-secret

    # Never in production (stores plaintext)
    commit-reveal commit my-secret "value"
    ```

## Error Handling

Avoid leaking internal details in error messages:

```python
from commit_reveal import CommitRevealScheme, ValidationError, SecurityError

def safe_commit(user_input):
    try:
        cr = CommitRevealScheme()
        commitment, salt = cr.commit(user_input)
        return {"success": True, "commitment": commitment.hex()}

    except ValidationError:
        # Don't expose validation details to users
        return {"success": False, "error": "Invalid input"}

    except SecurityError:
        return {"success": False, "error": "Operation rejected"}
```

## File System Permissions

```bash
# Ensure secure permissions
chmod 700 ~/.commit-reveal
chmod 600 ~/.commit-reveal/*.json
chmod 700 ~/.commit-reveal/audit
chmod 600 ~/.commit-reveal/audit/audit.jsonl
```

The secure CLI sets these permissions automatically.

## Salt Management

```python
import secrets

# Let the library generate salts (recommended)
commitment, salt = cr.commit("value")

# If you must provide your own salt
custom_salt = secrets.token_bytes(32)  # 256-bit, cryptographically secure
commitment, salt = cr.commit("value", salt=custom_salt)
```

!!! warning
    Never use `random.randbytes()` or any non-cryptographic RNG for salts.

## Memory Handling

```python
from commit_reveal.validation import SecureString, secure_wipe_bytes

# For sensitive string data
sensitive = SecureString("my secret")
# ... use it ...
sensitive.clear()

# For sensitive bytes
secret_bytes = b"key material"
# ... use it ...
secure_wipe_bytes(secret_bytes)
```

!!! note
    Python's garbage collector and string immutability make true secure wiping difficult. For applications requiring guaranteed memory security, consider hardware security modules (HSMs) or secure enclaves.

## Network Security

When transmitting commitments or proofs over a network:

- Always use TLS 1.2+
- Verify server certificates
- Transmit commitments and proofs as hex-encoded strings
- Never transmit salts and values together over insecure channels

## Compliance

The library follows:

- **NIST SP 800-57** for key lengths
- **FIPS 140-2** approved algorithms
- **OWASP** security guidelines

Enable audit trails for compliance environments:

```python
cr = CommitRevealScheme(enable_audit=True)

# Export audit reports for review
audit = get_audit_trail()
audit.export_audit_report(Path("audit_report.json"))
```
