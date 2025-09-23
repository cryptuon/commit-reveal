"""
Input validation and security utilities for the commit-reveal library.

This module provides comprehensive validation and sanitization functions
to ensure secure operation of the commit-reveal scheme.
"""

import hashlib
import re
from typing import Union, Any, Optional


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class SecurityError(Exception):
    """Raised when a security violation is detected."""
    pass


def validate_hash_algorithm(algorithm: str) -> str:
    """
    Validate and normalize a hash algorithm name.

    Args:
        algorithm: The hash algorithm name to validate

    Returns:
        The normalized algorithm name

    Raises:
        ValidationError: If the algorithm is not supported or secure
    """
    if not isinstance(algorithm, str):
        raise ValidationError("Hash algorithm must be a string")

    algorithm = algorithm.lower().strip()

    # List of allowed secure hash algorithms
    allowed_algorithms = {
        'sha256', 'sha384', 'sha512',
        'sha3_256', 'sha3_384', 'sha3_512',
        'blake2b', 'blake2s'
    }

    # Deprecated/insecure algorithms
    deprecated_algorithms = {
        'md5', 'sha1', 'sha224'
    }

    if algorithm in deprecated_algorithms:
        raise SecurityError(f"Hash algorithm '{algorithm}' is deprecated and insecure")

    if algorithm not in allowed_algorithms:
        available = ', '.join(sorted(allowed_algorithms))
        raise ValidationError(
            f"Unsupported hash algorithm '{algorithm}'. "
            f"Supported algorithms: {available}"
        )

    # Verify the algorithm is actually available in hashlib
    try:
        getattr(hashlib, algorithm)
    except AttributeError:
        raise ValidationError(f"Hash algorithm '{algorithm}' not available in this Python installation")

    return algorithm


def validate_value(value: Union[str, int, bytes]) -> Union[str, int, bytes]:
    """
    Validate a value for commitment.

    Args:
        value: The value to validate

    Returns:
        The validated value

    Raises:
        ValidationError: If the value is invalid
        SecurityError: If the value poses security risks
    """
    if value is None:
        raise ValidationError("Value cannot be None")

    if isinstance(value, str):
        return validate_string_value(value)
    elif isinstance(value, int):
        return validate_integer_value(value)
    elif isinstance(value, bytes):
        return validate_bytes_value(value)
    else:
        raise ValidationError(
            f"Value must be string, integer, or bytes, got {type(value).__name__}"
        )


def validate_string_value(value: str) -> str:
    """
    Validate a string value.

    Args:
        value: The string value to validate

    Returns:
        The validated string

    Raises:
        ValidationError: If the string is invalid
        SecurityError: If the string poses security risks
    """
    if not isinstance(value, str):
        raise ValidationError("Expected string value")

    # Check for reasonable length limits
    if len(value) > 10_000_000:  # 10MB limit for strings
        raise ValidationError("String value too large (max 10MB)")

    # Check for null bytes which could cause issues
    if '\x00' in value:
        raise SecurityError("String contains null bytes")

    # Check for potential directory traversal attempts
    dangerous_patterns = ['../', '..\\', '~/', '/etc/', '/proc/', '/sys/']
    value_lower = value.lower()
    for pattern in dangerous_patterns:
        if pattern in value_lower:
            raise SecurityError(f"String contains potentially dangerous pattern: {pattern}")

    return value


def validate_integer_value(value: int) -> int:
    """
    Validate an integer value.

    Args:
        value: The integer value to validate

    Returns:
        The validated integer

    Raises:
        ValidationError: If the integer is invalid
    """
    if not isinstance(value, int):
        raise ValidationError("Expected integer value")

    if value < 0:
        raise ValidationError("Negative integers are not supported")

    # Check for reasonable size limits
    if value.bit_length() > 10_000:  # Roughly 1.25KB
        raise ValidationError("Integer value too large (max ~1250 bytes)")

    return value


def validate_bytes_value(value: bytes) -> bytes:
    """
    Validate a bytes value.

    Args:
        value: The bytes value to validate

    Returns:
        The validated bytes

    Raises:
        ValidationError: If the bytes are invalid
    """
    if not isinstance(value, bytes):
        raise ValidationError("Expected bytes value")

    # Check for reasonable length limits
    if len(value) > 10_000_000:  # 10MB limit
        raise ValidationError("Bytes value too large (max 10MB)")

    return value


def validate_salt(salt: Optional[bytes]) -> Optional[bytes]:
    """
    Validate a salt value.

    Args:
        salt: The salt to validate (can be None for auto-generation)

    Returns:
        The validated salt

    Raises:
        ValidationError: If the salt is invalid
        SecurityError: If the salt is insecure
    """
    if salt is None:
        return None

    if not isinstance(salt, bytes):
        raise ValidationError("Salt must be bytes or None")

    if len(salt) < 16:
        raise SecurityError("Salt too short (minimum 16 bytes)")

    if len(salt) > 1024:
        raise ValidationError("Salt too long (maximum 1024 bytes)")

    # Check for obviously bad salts
    if salt == b'\x00' * len(salt):
        raise SecurityError("Salt is all zeros")

    if len(set(salt)) < 4:
        raise SecurityError("Salt has insufficient entropy")

    return salt


def validate_commitment(commitment: bytes) -> bytes:
    """
    Validate a commitment value.

    Args:
        commitment: The commitment to validate

    Returns:
        The validated commitment

    Raises:
        ValidationError: If the commitment is invalid
    """
    if not isinstance(commitment, bytes):
        raise ValidationError("Commitment must be bytes")

    if len(commitment) == 0:
        raise ValidationError("Commitment cannot be empty")

    if len(commitment) > 128:  # Reasonable upper bound for hash outputs
        raise ValidationError("Commitment too long")

    return commitment


def validate_zkp_public_key(public_key: tuple) -> tuple:
    """
    Validate a ZKP public key.

    Args:
        public_key: The public key to validate (x, y coordinates)

    Returns:
        The validated public key

    Raises:
        ValidationError: If the public key is invalid
    """
    if not isinstance(public_key, tuple):
        raise ValidationError("Public key must be a tuple")

    if len(public_key) != 2:
        raise ValidationError("Public key must have exactly 2 coordinates")

    x, y = public_key

    if not isinstance(x, int) or not isinstance(y, int):
        raise ValidationError("Public key coordinates must be integers")

    if x < 0 or y < 0:
        raise ValidationError("Public key coordinates must be non-negative")

    # secp256k1 field prime
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    if x >= p or y >= p:
        raise ValidationError("Public key coordinates out of field range")

    return public_key


def validate_zkp_challenge(challenge: int) -> int:
    """
    Validate a ZKP challenge value.

    Args:
        challenge: The challenge to validate

    Returns:
        The validated challenge

    Raises:
        ValidationError: If the challenge is invalid
    """
    if not isinstance(challenge, int):
        raise ValidationError("Challenge must be an integer")

    if challenge < 0:
        raise ValidationError("Challenge must be non-negative")

    # secp256k1 group order
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    if challenge >= n:
        raise ValidationError("Challenge out of valid range")

    return challenge


def validate_zkp_response(response: int) -> int:
    """
    Validate a ZKP response value.

    Args:
        response: The response to validate

    Returns:
        The validated response

    Raises:
        ValidationError: If the response is invalid
    """
    if not isinstance(response, int):
        raise ValidationError("Response must be an integer")

    if response < 0:
        raise ValidationError("Response must be non-negative")

    # secp256k1 group order
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    if response >= n:
        raise ValidationError("Response out of valid range")

    return response


def validate_zkp_compressed_point(R_compressed: bytes) -> bytes:
    """
    Validate a compressed elliptic curve point.

    Args:
        R_compressed: The compressed point to validate

    Returns:
        The validated compressed point

    Raises:
        ValidationError: If the compressed point is invalid
    """
    if not isinstance(R_compressed, bytes):
        raise ValidationError("Compressed point must be bytes")

    if len(R_compressed) != 33:
        raise ValidationError("Compressed point must be exactly 33 bytes")

    prefix = R_compressed[0]
    if prefix not in (0x02, 0x03, 0x00):
        raise ValidationError("Invalid compressed point prefix")

    return R_compressed


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename for safe storage.

    Args:
        filename: The filename to sanitize

    Returns:
        The sanitized filename

    Raises:
        ValidationError: If the filename cannot be sanitized
    """
    if not isinstance(filename, str):
        raise ValidationError("Filename must be a string")

    if not filename.strip():
        raise ValidationError("Filename cannot be empty")

    # Remove or replace dangerous characters
    # Allow alphanumeric, hyphen, underscore, and dot
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)

    # Remove leading dots and spaces to prevent hidden files
    sanitized = sanitized.lstrip('. ')

    # Ensure it's not too long
    if len(sanitized) > 255:
        sanitized = sanitized[:255]

    # Ensure it's not a reserved name (Windows)
    reserved_names = {
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    }

    if sanitized.upper() in reserved_names:
        sanitized = f"safe_{sanitized}"

    if not sanitized:
        raise ValidationError("Filename became empty after sanitization")

    return sanitized


def secure_wipe_bytes(data: bytes) -> None:
    """
    Attempt to securely wipe bytes from memory.

    Note: This is best-effort in Python due to garbage collection
    and string immutability. For truly secure applications, consider
    using specialized libraries.

    Args:
        data: The bytes to wipe
    """
    if isinstance(data, bytes):
        # In Python, we can't actually overwrite bytes objects
        # but we can at least clear references
        del data


class SecureString:
    """
    A more secure string implementation that attempts to clear
    sensitive data when no longer needed.
    """

    def __init__(self, value: str):
        self._value = value
        self._cleared = False

    def __str__(self) -> str:
        if self._cleared:
            raise SecurityError("Secure string has been cleared")
        return self._value

    def __repr__(self) -> str:
        if self._cleared:
            return "SecureString(cleared)"
        return f"SecureString(length={len(self._value)})"

    def clear(self) -> None:
        """Clear the secure string."""
        self._value = ""
        self._cleared = True

    def __del__(self):
        """Clear on deletion."""
        self.clear()