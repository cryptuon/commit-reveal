# Error Handling

## Exception Hierarchy

```
Exception
    ValidationError    # Invalid input
    SecurityError      # Security violation
    ValueError         # ZKP not enabled
```

## ValidationError

Raised for invalid inputs. Common causes:

| Error | Cause |
|-------|-------|
| `"Value must be string, integer, or bytes"` | Unsupported type (list, dict, None) |
| `"Negative integers are not supported"` | Negative integer value |
| `"String value too large (max 10MB)"` | String exceeds 10 MB |
| `"Salt too short (minimum 16 bytes)"` | Salt under 16 bytes |
| `"Salt too long (maximum 1024 bytes)"` | Salt over 1024 bytes |
| `"Commitment cannot be empty"` | Empty bytes for commitment |

```python
from commit_reveal import CommitRevealScheme, ValidationError

cr = CommitRevealScheme()

try:
    cr.commit(-42)
except ValidationError as e:
    print(e)  # "Negative integers are not supported"
```

## SecurityError

Raised when a security policy is violated:

| Error | Cause |
|-------|-------|
| `"Hash algorithm 'md5' is deprecated and insecure"` | Insecure hash algorithm |
| `"Salt has insufficient entropy"` | Low-entropy salt (e.g., all zeros) |
| `"String contains potentially dangerous pattern"` | Null bytes or directory traversal |
| `"Public key coordinates out of field range"` | Invalid EC point |

```python
from commit_reveal import CommitRevealScheme, SecurityError

try:
    cr = CommitRevealScheme(hash_algorithm='md5')
except SecurityError as e:
    print(e)  # Hash algorithm 'md5' is deprecated and insecure
```

## ValueError

Raised when attempting ZKP operations without enabling them:

```python
cr = CommitRevealScheme(use_zkp=False)
commitment, salt = cr.commit("secret")

try:
    cr.create_zkp_proof("secret", salt, commitment)
except ValueError as e:
    print(e)  # "ZKP functionality not enabled. Initialize with use_zkp=True"
```

## Production Error Handling Pattern

```python
from commit_reveal import CommitRevealScheme, ValidationError, SecurityError


def handle_commitment(user_input):
    """Safe commitment with proper error handling."""
    cr = CommitRevealScheme()

    try:
        commitment, salt = cr.commit(user_input)
        return {"ok": True, "commitment": commitment.hex(), "salt": salt.hex()}

    except ValidationError:
        # Log internally, return generic message
        return {"ok": False, "error": "Invalid input"}

    except SecurityError:
        # Log as security event
        return {"ok": False, "error": "Operation rejected"}


def handle_reveal(value, salt_hex, commitment_hex):
    """Safe reveal with proper error handling."""
    cr = CommitRevealScheme()

    try:
        salt = bytes.fromhex(salt_hex)
        commitment = bytes.fromhex(commitment_hex)
        result = cr.reveal(value, salt, commitment)
        return {"ok": True, "valid": result}

    except (ValidationError, SecurityError, ValueError):
        return {"ok": True, "valid": False}
```

!!! tip
    In production, avoid returning detailed error messages to end users. Log the full error internally and return a generic message. This prevents information leakage that could help an attacker.
