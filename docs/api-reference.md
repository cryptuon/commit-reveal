# API Reference

Complete reference for all classes, methods, and functions in the commit-reveal library.

## Core Classes

### CommitRevealScheme

The main class for commit-reveal operations.

```python
class CommitRevealScheme:
    def __init__(
        self,
        hash_algorithm: str = 'sha256',
        use_zkp: bool = False,
        enable_audit: bool = True
    ):
```

#### Parameters

- **hash_algorithm** (`str`, optional): Hash algorithm to use. Default: `'sha256'`
  - Supported: `'sha256'`, `'sha384'`, `'sha512'`, `'sha3_256'`, `'sha3_384'`, `'sha3_512'`, `'blake2b'`, `'blake2s'`
  - Rejected: `'md5'`, `'sha1'` (security reasons)

- **use_zkp** (`bool`, optional): Enable zero-knowledge proof functionality. Default: `False`

- **enable_audit** (`bool`, optional): Enable audit trail logging. Default: `True`

#### Raises

- **ValidationError**: If `hash_algorithm` is invalid or unsupported
- **SecurityError**: If `hash_algorithm` is deprecated/insecure

### Core Methods

#### commit()

```python
def commit(
    self,
    value: Union[str, int, bytes],
    salt: bytes = None
) -> Tuple[bytes, bytes]:
```

Commit to a value with cryptographic binding.

**Parameters:**
- **value** (`str | int | bytes`): The value to commit to
- **salt** (`bytes`, optional): Salt for the commitment. If `None`, a secure random salt is generated.

**Returns:**
- `Tuple[bytes, bytes]`: `(commitment, salt)` where:
  - `commitment`: SHA-256 hash binding the value and salt
  - `salt`: The salt used (either provided or generated)

**Raises:**
- **ValidationError**: If value type is unsupported or invalid
- **SecurityError**: If value contains potentially dangerous content

**Example:**
```python
cr = CommitRevealScheme()

# With auto-generated salt
commitment, salt = cr.commit("my secret")

# With custom salt
custom_salt = secrets.token_bytes(32)
commitment, salt = cr.commit("my secret", salt=custom_salt)
```

#### reveal()

```python
def reveal(
    self,
    value: Union[str, int, bytes],
    salt: bytes,
    commitment: bytes
) -> bool:
```

Reveal a value and verify it matches the commitment.

**Parameters:**
- **value** (`str | int | bytes`): The original value to verify
- **salt** (`bytes`): The salt used in the original commitment
- **commitment** (`bytes`): The original commitment to verify against

**Returns:**
- `bool`: `True` if the value and salt produce the given commitment, `False` otherwise

**Raises:**
- **ValidationError**: If any parameter is invalid
- **SecurityError**: If parameters pose security risks

**Example:**
```python
# Commit phase
commitment, salt = cr.commit("secret value")

# Reveal phase
is_valid = cr.reveal("secret value", salt, commitment)  # True
is_invalid = cr.reveal("wrong value", salt, commitment)  # False
```

#### verify()

```python
def verify(
    self,
    value: Union[str, int, bytes],
    salt: bytes,
    commitment: bytes
) -> bool:
```

Alias for `reveal()`. Identical functionality.

### Zero-Knowledge Proof Methods

#### create_zkp_proof()

```python
def create_zkp_proof(
    self,
    value: Union[str, int, bytes],
    salt: bytes,
    commitment: bytes
) -> Tuple[Tuple[int, int], bytes, int, int]:
```

Create a zero-knowledge proof for a commitment using Schnorr signatures.

**Parameters:**
- **value** (`str | int | bytes`): The original value
- **salt** (`bytes`): The salt used in the commitment
- **commitment** (`bytes`): The commitment to prove knowledge of

**Returns:**
- `Tuple[Tuple[int, int], bytes, int, int]`: `(public_key, R_compressed, challenge, response)` where:
  - `public_key`: Elliptic curve public key (x, y coordinates)
  - `R_compressed`: Compressed elliptic curve point (33 bytes)
  - `challenge`: Challenge value derived via Fiat-Shamir heuristic
  - `response`: Response to the challenge

**Raises:**
- **ValueError**: If ZKP functionality is not enabled
- **ValidationError**: If parameters are invalid
- **RuntimeError**: If ZKP system is not initialized

**Example:**
```python
cr = CommitRevealScheme(use_zkp=True)
commitment, salt = cr.commit("secret data")

# Create proof
public_key, R_compressed, challenge, response = cr.create_zkp_proof(
    "secret data", salt, commitment
)

print(f"Public key: ({public_key[0]}, {public_key[1]})")
print(f"Challenge: {challenge}")
```

#### verify_zkp_proof()

```python
def verify_zkp_proof(
    self,
    commitment: bytes,
    public_key: Tuple[int, int],
    R_compressed: bytes,
    challenge: int,
    response: int
) -> bool:
```

Verify a zero-knowledge proof without knowing the original value.

**Parameters:**
- **commitment** (`bytes`): The commitment
- **public_key** (`Tuple[int, int]`): Public key from the proof (x, y coordinates)
- **R_compressed** (`bytes`): Compressed elliptic curve point (33 bytes)
- **challenge** (`int`): Challenge value from the proof
- **response** (`int`): Response value from the proof

**Returns:**
- `bool`: `True` if the proof is cryptographically valid, `False` otherwise

**Raises:**
- **ValueError**: If ZKP functionality is not enabled
- **ValidationError**: If parameters are invalid

**Example:**
```python
# Verify proof created above
is_valid = cr.verify_zkp_proof(
    commitment, public_key, R_compressed, challenge, response
)
print(f"Proof valid: {is_valid}")  # True
```

#### verify_commitment_consistency()

```python
def verify_commitment_consistency(
    self,
    value: Union[str, int, bytes],
    salt: bytes,
    commitment: bytes,
    public_key: Tuple[int, int]
) -> bool:
```

Verify that a revealed value/salt pair is consistent with a ZKP public key.

**Parameters:**
- **value** (`str | int | bytes`): The revealed value
- **salt** (`bytes`): The revealed salt
- **commitment** (`bytes`): The original commitment
- **public_key** (`Tuple[int, int]`): Public key from ZKP proof

**Returns:**
- `bool`: `True` if the value/salt pair matches the public key, `False` otherwise

**Raises:**
- **ValueError**: If ZKP functionality is not enabled
- **ValidationError**: If parameters are invalid

**Example:**
```python
# After creating proof and later revealing
consistency = cr.verify_commitment_consistency(
    "secret data", salt, commitment, public_key
)
print(f"Consistent: {consistency}")  # True
```

## Exception Classes

### ValidationError

```python
class ValidationError(Exception):
    """Raised when input validation fails."""
```

Thrown when:
- Invalid data types are provided
- Values exceed size limits
- Malformed parameters are detected
- Required parameters are missing

### SecurityError

```python
class SecurityError(Exception):
    """Raised when a security violation is detected."""
```

Thrown when:
- Insecure hash algorithms are used (MD5, SHA-1)
- Values contain dangerous patterns
- Security constraints are violated
- Insufficient entropy is detected

## Validation Functions

### validate_hash_algorithm()

```python
def validate_hash_algorithm(algorithm: str) -> str:
```

Validate and normalize a hash algorithm name.

**Parameters:**
- **algorithm** (`str`): Hash algorithm name to validate

**Returns:**
- `str`: Normalized algorithm name

**Raises:**
- **ValidationError**: If algorithm is unsupported
- **SecurityError**: If algorithm is insecure

### validate_value()

```python
def validate_value(value: Union[str, int, bytes]) -> Union[str, int, bytes]:
```

Validate a value for commitment.

**Parameters:**
- **value** (`str | int | bytes`): Value to validate

**Returns:**
- `str | int | bytes`: Validated value

**Raises:**
- **ValidationError**: If value is invalid
- **SecurityError**: If value poses security risks

### Additional Validation Functions

- `validate_salt(salt: Optional[bytes]) -> Optional[bytes]`
- `validate_commitment(commitment: bytes) -> bytes`
- `validate_zkp_public_key(public_key: tuple) -> tuple`
- `validate_zkp_challenge(challenge: int) -> int`
- `validate_zkp_response(response: int) -> int`
- `validate_zkp_compressed_point(R_compressed: bytes) -> bytes`

## Audit Trail Classes

### AuditTrail

```python
class AuditTrail:
    def __init__(self, audit_dir: Optional[Path] = None):
```

Cryptographic audit trail for commit-reveal operations.

#### Key Methods

```python
def set_session_context(self, user_id: Optional[str] = None) -> str:
def log_event(self, event_type: str, operation: str, details: Dict[str, Any], success: bool = True) -> str:
def verify_integrity(self) -> Dict[str, Any]:
def export_audit_report(self, output_file: Path) -> None:
```

### AuditEvent

```python
class AuditEvent:
    def __init__(self, event_type: str, operation: str, details: Dict[str, Any], ...):
```

Represents a single audit event with integrity verification.

## Elliptic Curve Classes

### EllipticCurve

```python
class EllipticCurve:
    def __init__(self):
```

Secp256k1 elliptic curve implementation for ZKP operations.

#### Key Methods

```python
def point_add(self, P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
def point_multiply(self, k: int, P: Tuple[int, int]) -> Optional[Tuple[int, int]]:
def point_compress(self, point: Optional[Tuple[int, int]]) -> bytes:
def is_valid_point(self, point: Tuple[int, int]) -> bool:
```

### SchnorrZKP

```python
class SchnorrZKP:
    def __init__(self, curve: Optional[EllipticCurve] = None):
```

Schnorr zero-knowledge proof implementation.

#### Key Methods

```python
def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
def create_proof(self, secret: int, public_key: Tuple[int, int], commitment: bytes) -> Tuple[bytes, int, int]:
def verify_proof(self, public_key: Tuple[int, int], commitment: bytes, R_compressed: bytes, challenge: int, response: int) -> bool:
```

## Constants and Configuration

### Supported Hash Algorithms

```python
SECURE_ALGORITHMS = {
    'sha256', 'sha384', 'sha512',
    'sha3_256', 'sha3_384', 'sha3_512',
    'blake2b', 'blake2s'
}

DEPRECATED_ALGORITHMS = {
    'md5', 'sha1', 'sha224'
}
```

### Elliptic Curve Parameters (secp256k1)

```python
# Field prime
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# Curve parameters (y² = x³ + 7)
a = 0
b = 7

# Generator point
gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Group order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

## Type Hints

```python
from typing import Union, Tuple, Optional, Dict, Any, List

# Common type aliases used throughout the library
ValueType = Union[str, int, bytes]
CommitmentTuple = Tuple[bytes, bytes]
ZKPProofTuple = Tuple[Tuple[int, int], bytes, int, int]
PublicKeyType = Tuple[int, int]
```

## Error Codes and Messages

### Common Validation Errors

- `"Value must be string, integer, or bytes"`
- `"Negative integers are not supported"`
- `"String value too large (max 10MB)"`
- `"Salt too short (minimum 16 bytes)"`
- `"Commitment cannot be empty"`

### Common Security Errors

- `"Hash algorithm 'md5' is deprecated and insecure"`
- `"Salt has insufficient entropy"`
- `"String contains potentially dangerous pattern"`
- `"Public key coordinates out of field range"`

### ZKP-Specific Errors

- `"ZKP functionality not enabled. Initialize with use_zkp=True"`
- `"ZKP system not initialized"`
- `"Invalid compressed point prefix"`
- `"Challenge out of valid range"`

## Version Information

```python
import commit_reveal

print(commit_reveal.__version__)  # "1.0.0"
print(commit_reveal.__all__)      # ["CommitRevealScheme", "ValidationError", "SecurityError"]
```

## Module Structure

```
commit_reveal/
├── __init__.py          # Main exports
├── core.py              # CommitRevealScheme class
├── zkp.py               # Zero-knowledge proof implementation
├── validation.py        # Input validation and security
├── audit.py             # Audit trail functionality
├── cli.py               # Legacy CLI (deprecated)
├── secure_cli.py        # Secure CLI implementation
└── migrate.py           # Migration utility
```