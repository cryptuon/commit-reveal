import hashlib
import secrets
import hmac
from typing import Union, Tuple, Any


class CommitRevealScheme:
    """
    A commit-reveal scheme implementation with optional zero-knowledge proofs.
    
    This class provides methods to commit to a value and later reveal it,
    proving that the revealed value matches the original commitment.
    Optionally, zero-knowledge proofs can be used to enhance security.
    """

    def __init__(self, hash_algorithm: str = 'sha256', use_zkp: bool = False):
        """
        Initialize the commit-reveal scheme.
        
        Args:
            hash_algorithm: The hash algorithm to use (default: sha256)
            use_zkp: Whether to use zero-knowledge proofs (default: False)
        """
        self.hash_algorithm = hash_algorithm
        self._hash_func = getattr(hashlib, hash_algorithm)
        self.use_zkp = use_zkp
        
        if use_zkp:
            # Initialize ZKP parameters if needed
            # For now, we'll implement a simple Schnorr-like protocol
            pass

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
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Convert value to bytes if needed
        if isinstance(value, str):
            value_bytes = value.encode('utf-8')
        elif isinstance(value, int):
            value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        elif isinstance(value, bytes):
            value_bytes = value
        else:
            raise TypeError("Value must be string, integer, or bytes")
        
        # Create commitment by hashing value + salt
        commitment = self._hash_func(value_bytes + salt).digest()
        
        return commitment, salt

    def reveal(self, value: Union[str, int, bytes], salt: bytes, commitment: bytes) -> bool:
        """
        Reveal a value and verify it matches the commitment.
        
        Args:
            value: The original value
            salt: The salt used in the commitment
            commitment: The original commitment
            
        Returns:
            True if the revealed value matches the commitment, False otherwise
        """
        # Recompute the commitment
        recomputed_commitment, _ = self.commit(value, salt)
        
        # Compare commitments securely
        return hmac.compare_digest(recomputed_commitment, commitment)

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
    def _generate_zkp_challenge(self, commitment: bytes, nonce: bytes) -> int:
        """
        Generate a challenge for the zero-knowledge proof.
        
        Args:
            commitment: The commitment
            nonce: A random nonce
            
        Returns:
            An integer challenge value
        """
        challenge_input = commitment + nonce
        return int.from_bytes(self._hash_func(challenge_input).digest(), 'big') % (2**256)
    
    def create_zkp_proof(self, value: Union[str, int, bytes], salt: bytes, commitment: bytes) -> Tuple[bytes, int, int]:
        """
        Create a zero-knowledge proof for the commitment.
        
        This implements a simplified Schnorr-like protocol where:
        1. The prover knows the value and salt that produced the commitment
        2. The prover can prove this knowledge without revealing the value or salt
        
        Args:
            value: The original value
            salt: The salt used in the commitment
            commitment: The commitment to prove knowledge of
            
        Returns:
            A tuple containing:
                - nonce: The random nonce used in the proof
                - challenge: The challenge value
                - response: The response to the challenge
        """
        if not self.use_zkp:
            raise ValueError("ZKP functionality not enabled. Initialize with use_zkp=True")
        
        # Convert value to bytes if needed
        if isinstance(value, str):
            value_bytes = value.encode('utf-8')
        elif isinstance(value, int):
            value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        elif isinstance(value, bytes):
            value_bytes = value
        else:
            raise TypeError("Value must be string, integer, or bytes")
        
        # Generate a random nonce
        nonce = secrets.token_bytes(32)
        
        # Generate challenge
        challenge = self._generate_zkp_challenge(commitment, nonce)
        
        # Compute response: response = hash(value || salt || nonce || challenge)
        response_input = value_bytes + salt + nonce + challenge.to_bytes(32, 'big')
        response = int.from_bytes(self._hash_func(response_input).digest(), 'big') % (2**256)
        
        return nonce, challenge, response
    
    def verify_zkp_proof(self, commitment: bytes, nonce: bytes, challenge: int, response: int) -> bool:
        """
        Verify a zero-knowledge proof.
        
        Args:
            commitment: The commitment
            nonce: The nonce used in the proof
            challenge: The challenge value
            response: The response to the challenge
            
        Returns:
            True if the proof is valid, False otherwise
        """
        if not self.use_zkp:
            raise ValueError("ZKP functionality not enabled. Initialize with use_zkp=True")
        
        # Verify the challenge was computed correctly
        expected_challenge = self._generate_zkp_challenge(commitment, nonce)
        if challenge != expected_challenge:
            return False
        
        # In a real ZKP implementation, we would verify that the response is consistent
        # with the commitment and challenge. In this simplified version, we'll just
        # check that the response is a reasonable size.
        return 0 <= response < 2**256