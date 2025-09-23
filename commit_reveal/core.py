import hashlib
import secrets
import hmac
from typing import Union, Tuple, Any, Optional
from .zkp import CommitmentZKP
from .validation import (
    validate_hash_algorithm, validate_value, validate_salt,
    validate_commitment, validate_zkp_public_key, validate_zkp_challenge,
    validate_zkp_response, validate_zkp_compressed_point,
    ValidationError, SecurityError
)
from .audit import get_audit_trail


class CommitRevealScheme:
    """
    A commit-reveal scheme implementation with optional zero-knowledge proofs.
    
    This class provides methods to commit to a value and later reveal it,
    proving that the revealed value matches the original commitment.
    Optionally, zero-knowledge proofs can be used to enhance security.
    """

    def __init__(self, hash_algorithm: str = 'sha256', use_zkp: bool = False,
                 enable_audit: bool = True):
        """
        Initialize the commit-reveal scheme.

        Args:
            hash_algorithm: The hash algorithm to use (default: sha256)
            use_zkp: Whether to use zero-knowledge proofs (default: False)
            enable_audit: Whether to enable audit trail logging (default: True)

        Raises:
            ValidationError: If hash_algorithm is invalid
            SecurityError: If hash_algorithm is insecure
        """
        self.hash_algorithm = validate_hash_algorithm(hash_algorithm)
        self._hash_func = getattr(hashlib, self.hash_algorithm)
        self.use_zkp = use_zkp
        self.enable_audit = enable_audit

        if use_zkp:
            self._zkp_system = CommitmentZKP()
        else:
            self._zkp_system = None

        if enable_audit:
            self._audit = get_audit_trail()
        else:
            self._audit = None

    def commit(self, value: Union[str, int, bytes], salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Commit to a value.

        Args:
            value: The value to commit to (string, integer, or bytes)
            salt: Optional salt for the commitment. If None, a random salt is generated.

        Returns:
            A tuple containing:
                - commitment: The commitment hash
                - salt: The salt used for the commitment

        Raises:
            ValidationError: If value or salt is invalid
            SecurityError: If value or salt poses security risks
        """
        # Validate inputs
        validated_value = validate_value(value)
        validated_salt = validate_salt(salt)

        if validated_salt is None:
            validated_salt = secrets.token_bytes(32)

        # Convert value to bytes if needed
        if isinstance(validated_value, str):
            value_bytes = validated_value.encode('utf-8')
        elif isinstance(validated_value, int):
            # Use a more robust conversion for large integers
            if validated_value == 0:
                value_bytes = b'\x00'
            else:
                value_bytes = validated_value.to_bytes((validated_value.bit_length() + 7) // 8, 'big')
        elif isinstance(validated_value, bytes):
            value_bytes = validated_value
        else:
            # This should never happen due to validate_value, but defensive programming
            raise TypeError("Value must be string, integer, or bytes")

        # Create commitment by hashing value + salt
        commitment = self._hash_func(value_bytes + validated_salt).digest()

        return commitment, validated_salt

    def reveal(self, value: Union[str, int, bytes], salt: bytes, commitment: bytes) -> bool:
        """
        Reveal a value and verify it matches the commitment.

        Args:
            value: The original value
            salt: The salt used in the commitment
            commitment: The original commitment

        Returns:
            True if the revealed value matches the commitment, False otherwise

        Raises:
            ValidationError: If inputs are invalid
            SecurityError: If inputs pose security risks
        """
        # Validate inputs
        validated_value = validate_value(value)
        validated_salt = validate_salt(salt)
        validated_commitment = validate_commitment(commitment)

        if validated_salt is None:
            raise ValidationError("Salt cannot be None for reveal operation")

        try:
            # Recompute the commitment
            recomputed_commitment, _ = self.commit(validated_value, validated_salt)

            # Compare commitments securely
            return hmac.compare_digest(recomputed_commitment, validated_commitment)
        except Exception:
            # If any error occurs during recomputation, the reveal fails
            return False

    def verify(self, value: Union[str, int, bytes], salt: bytes, commitment: bytes) -> bool:
        """
        Verify that a value and salt produce the given commitment.
        
        This is an alias for the reveal method.
        
        Args:
            value: The value to verify
            salt: The salt used in the commitment
            commitment: The commitment to verify against
            
        Returns:
            True if the value and salt produce the given commitment, False otherwise
        """
        return self.reveal(value, salt, commitment)
    
    # Zero-Knowledge Proof methods
    def create_zkp_proof(self, value: Union[str, int, bytes], salt: bytes,
                        commitment: bytes) -> Tuple[Tuple[int, int], bytes, int, int]:
        """
        Create a zero-knowledge proof for the commitment.

        This implements a proper Schnorr zero-knowledge proof that allows proving
        knowledge of the value and salt that produced the commitment without
        revealing them.

        Args:
            value: The original value
            salt: The salt used in the commitment
            commitment: The commitment to prove knowledge of

        Returns:
            A tuple containing:
                - public_key: The public key derived from value and salt (x, y coordinates)
                - R_compressed: The compressed commitment point
                - challenge: The challenge value
                - response: The response to the challenge

        Raises:
            ValueError: If ZKP functionality is not enabled
            TypeError: If value type is not supported
        """
        if not self.use_zkp:
            raise ValueError("ZKP functionality not enabled. Initialize with use_zkp=True")

        if self._zkp_system is None:
            raise RuntimeError("ZKP system not initialized")

        return self._zkp_system.create_commitment_proof(value, salt, commitment)

    def verify_zkp_proof(self, commitment: bytes, public_key: Tuple[int, int],
                        R_compressed: bytes, challenge: int, response: int) -> bool:
        """
        Verify a zero-knowledge proof.

        Args:
            commitment: The commitment
            public_key: The public key from the proof (x, y coordinates)
            R_compressed: The compressed commitment point
            challenge: The challenge value
            response: The response to the challenge

        Returns:
            True if the proof is valid, False otherwise

        Raises:
            ValueError: If ZKP functionality is not enabled or inputs are invalid
            ValidationError: If inputs are invalid
        """
        if not self.use_zkp:
            raise ValueError("ZKP functionality not enabled. Initialize with use_zkp=True")

        if self._zkp_system is None:
            raise RuntimeError("ZKP system not initialized")

        # Validate inputs
        validated_commitment = validate_commitment(commitment)
        validated_public_key = validate_zkp_public_key(public_key)
        validated_R_compressed = validate_zkp_compressed_point(R_compressed)
        validated_challenge = validate_zkp_challenge(challenge)
        validated_response = validate_zkp_response(response)

        try:
            return self._zkp_system.verify_commitment_proof(
                validated_commitment, validated_public_key, validated_R_compressed,
                validated_challenge, validated_response
            )
        except Exception:
            # If any error occurs during verification, the proof is invalid
            return False

    def verify_commitment_consistency(self, value: Union[str, int, bytes], salt: bytes,
                                    commitment: bytes, public_key: Tuple[int, int]) -> bool:
        """
        Verify that a revealed value/salt pair is consistent with a ZKP public key.

        This method can be used to verify that a revealed value and salt match
        the public key from a previously created zero-knowledge proof.

        Args:
            value: The revealed value
            salt: The revealed salt
            commitment: The original commitment
            public_key: The public key from the ZKP proof (x, y coordinates)

        Returns:
            True if the value/salt pair matches the public key, False otherwise

        Raises:
            ValueError: If ZKP functionality is not enabled
        """
        if not self.use_zkp:
            raise ValueError("ZKP functionality not enabled. Initialize with use_zkp=True")

        if self._zkp_system is None:
            raise RuntimeError("ZKP system not initialized")

        return self._zkp_system.verify_commitment_consistency(
            value, salt, commitment, public_key
        )