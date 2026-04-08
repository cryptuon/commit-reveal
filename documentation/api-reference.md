# API Reference

## CommitRevealScheme

The main class for commit-reveal operations.

```python
from commit_reveal import CommitRevealScheme

scheme = CommitRevealScheme(
    hash_algorithm: str = 'sha256',
    use_zkp: bool = False,
    enable_audit: bool = True
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hash_algorithm` | `str` | `'sha256'` | Hash algorithm. See [supported algorithms](advanced/hash-algorithms.md). |
| `use_zkp` | `bool` | `False` | Enable zero-knowledge proof functionality. |
| `enable_audit` | `bool` | `True` | Enable audit trail logging. |

!!! failure "Raises"
    - **`ValidationError`** -- if `hash_algorithm` is unsupported
    - **`SecurityError`** -- if `hash_algorithm` is insecure (e.g., `md5`, `sha1`)

---

### commit()

```python
def commit(
    self,
    value: Union[str, int, bytes],
    salt: Optional[bytes] = None
) -> Tuple[bytes, bytes]
```

Commit to a value with cryptographic binding.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `value` | `str \| int \| bytes` | The value to commit to |
| `salt` | `bytes \| None` | Optional salt. If `None`, a 32-byte secure random salt is generated. |

**Returns:** `(commitment, salt)` -- the commitment hash and the salt used.

!!! failure "Raises"
    - **`ValidationError`** -- invalid type or value
    - **`SecurityError`** -- dangerous content detected

```python
# Auto-generated salt (recommended)
commitment, salt = scheme.commit("my secret")

# Custom salt
import secrets
commitment, salt = scheme.commit("my secret", salt=secrets.token_bytes(32))
```

---

### reveal()

```python
def reveal(
    self,
    value: Union[str, int, bytes],
    salt: bytes,
    commitment: bytes
) -> bool
```

Reveal a value and verify it matches the commitment. Uses constant-time comparison (`hmac.compare_digest`).

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `value` | `str \| int \| bytes` | The original value |
| `salt` | `bytes` | The salt from the commit phase |
| `commitment` | `bytes` | The commitment to verify against |

**Returns:** `True` if the value and salt produce the given commitment, `False` otherwise.

```python
commitment, salt = scheme.commit("secret value")

scheme.reveal("secret value", salt, commitment)  # True
scheme.reveal("wrong value", salt, commitment)    # False
```

---

### verify()

Alias for [`reveal()`](#reveal). Identical signature and behavior.

---

### create_zkp_proof()

```python
def create_zkp_proof(
    self,
    value: Union[str, int, bytes],
    salt: bytes,
    commitment: bytes
) -> Tuple[Tuple[int, int], bytes, int, int]
```

Create a Schnorr zero-knowledge proof for a commitment.

!!! info "Requires `use_zkp=True`"

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `value` | `str \| int \| bytes` | The original value |
| `salt` | `bytes` | The salt used in the commitment |
| `commitment` | `bytes` | The commitment to prove knowledge of |

**Returns:** `(public_key, R_compressed, challenge, response)`

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | `(int, int)` | Elliptic curve public key (x, y) |
| `R_compressed` | `bytes` | Compressed curve point (33 bytes) |
| `challenge` | `int` | Fiat-Shamir challenge value |
| `response` | `int` | Schnorr response value |

!!! failure "Raises"
    - **`ValueError`** -- ZKP not enabled
    - **`ValidationError`** -- invalid parameters

```python
scheme = CommitRevealScheme(use_zkp=True)
commitment, salt = scheme.commit("secret")

public_key, R_compressed, challenge, response = scheme.create_zkp_proof(
    "secret", salt, commitment
)
```

---

### verify_zkp_proof()

```python
def verify_zkp_proof(
    self,
    commitment: bytes,
    public_key: Tuple[int, int],
    R_compressed: bytes,
    challenge: int,
    response: int
) -> bool
```

Verify a zero-knowledge proof without knowing the original value.

!!! info "Requires `use_zkp=True`"

**Returns:** `True` if the proof is cryptographically valid.

```python
is_valid = scheme.verify_zkp_proof(
    commitment, public_key, R_compressed, challenge, response
)
```

---

### verify_commitment_consistency()

```python
def verify_commitment_consistency(
    self,
    value: Union[str, int, bytes],
    salt: bytes,
    commitment: bytes,
    public_key: Tuple[int, int]
) -> bool
```

After a reveal, verify the revealed value/salt pair is consistent with a ZKP public key.

!!! info "Requires `use_zkp=True`"

**Returns:** `True` if consistent.

```python
is_consistent = scheme.verify_commitment_consistency(
    "secret", salt, commitment, public_key
)
```

---

## Exceptions

### ValidationError

```python
from commit_reveal import ValidationError
```

Raised when input validation fails:

- Invalid data types
- Values exceeding size limits (strings/bytes: 10 MB, integers: ~1.25 KB)
- Malformed parameters
- Salt too short (minimum 16 bytes) or too long (maximum 1024 bytes)

### SecurityError

```python
from commit_reveal import SecurityError
```

Raised when a security violation is detected:

- Insecure hash algorithms (`md5`, `sha1`)
- Dangerous input patterns (null bytes, directory traversal)
- Insufficient salt entropy

---

## Validation Functions

Available from `commit_reveal.validation`:

| Function | Description |
|----------|-------------|
| `validate_hash_algorithm(algorithm)` | Validate and normalize algorithm name |
| `validate_value(value)` | Validate a value for commitment |
| `validate_salt(salt)` | Validate salt bytes (entropy, length) |
| `validate_commitment(commitment)` | Validate commitment hash |
| `validate_zkp_public_key(public_key)` | Validate EC public key coordinates |
| `validate_zkp_challenge(challenge)` | Validate ZKP challenge value |
| `validate_zkp_response(response)` | Validate ZKP response value |
| `validate_zkp_compressed_point(R_compressed)` | Validate compressed EC point (33 bytes) |
| `sanitize_filename(filename)` | Sanitize filename for safe storage |

---

## Audit Trail

See [Audit Trail](security/audit-trail.md) for full documentation.

```python
from commit_reveal.audit import get_audit_trail, AuditTrail, AuditEvent
```

| Class/Function | Description |
|----------------|-------------|
| `get_audit_trail()` | Get the global `AuditTrail` instance |
| `set_audit_trail(trail)` | Set the global `AuditTrail` instance |
| `AuditTrail(audit_dir=None)` | Tamper-evident audit trail (default: `~/.commit-reveal/audit/`) |
| `AuditEvent(...)` | Single audit event with integrity hash |

---

## Module Structure

```
commit_reveal/
    __init__.py          # CommitRevealScheme, ValidationError, SecurityError
    core.py              # CommitRevealScheme implementation
    zkp.py               # Elliptic curve ZKP (secp256k1, Schnorr)
    validation.py        # Input validation and security
    audit.py             # Audit trail system
    cli.py               # Legacy CLI (deprecated)
    secure_cli.py        # Secure CLI
    migrate.py           # Migration utility
```
