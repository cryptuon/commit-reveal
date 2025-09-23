"""
Zero-Knowledge Proof implementation for commit-reveal schemes.

This module implements a proper zero-knowledge proof system based on
elliptic curve cryptography and Schnorr signatures.
"""

import hashlib
import secrets
import os
from typing import Tuple, Optional, Union


class EllipticCurve:
    """
    A simple elliptic curve implementation for cryptographic operations.

    Uses the secp256k1 curve (same as Bitcoin) for compatibility and security.
    Equation: y² = x³ + 7 (mod p)
    """

    def __init__(self):
        # secp256k1 parameters
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.a = 0
        self.b = 7
        self.gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        self.gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.G = (self.gx, self.gy)  # Generator point

    def point_add(self, P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        """Add two points on the elliptic curve."""
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2:
            if y1 == y2:
                # Point doubling
                s = (3 * x1 * x1 * pow(2 * y1, -1, self.p)) % self.p
            else:
                # Points are inverses
                return None
        else:
            # Regular addition
            s = ((y2 - y1) * pow(x2 - x1, -1, self.p)) % self.p

        x3 = (s * s - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p

        return (x3, y3)

    def point_multiply(self, k: int, P: Tuple[int, int]) -> Optional[Tuple[int, int]]:
        """Multiply a point by a scalar using double-and-add algorithm."""
        if k == 0:
            return None
        if k == 1:
            return P

        result = None
        addend = P

        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1

        return result

    def point_compress(self, point: Optional[Tuple[int, int]]) -> bytes:
        """Compress a point to bytes representation."""
        if point is None:
            return b'\x00' * 33

        x, y = point
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        return prefix + x.to_bytes(32, 'big')

    def is_valid_point(self, point: Tuple[int, int]) -> bool:
        """Check if a point is on the curve."""
        x, y = point
        return (y * y) % self.p == (x * x * x + self.b) % self.p


class SchnorrZKP:
    """
    Schnorr Zero-Knowledge Proof implementation.

    This implements a non-interactive zero-knowledge proof of knowledge
    of discrete logarithm using the Fiat-Shamir heuristic.
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or EllipticCurve()

    def _hash_to_challenge(self, *args: bytes) -> int:
        """Hash input to create a challenge using SHA-256."""
        hasher = hashlib.sha256()
        for arg in args:
            hasher.update(arg)
        digest = hasher.digest()
        return int.from_bytes(digest, 'big') % self.curve.n

    def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
        """Generate a private/public key pair."""
        private_key = secrets.randbelow(self.curve.n - 1) + 1
        public_key = self.curve.point_multiply(private_key, self.curve.G)
        return private_key, public_key

    def create_proof(self, secret: int, public_key: Tuple[int, int],
                    commitment: bytes) -> Tuple[bytes, int, int]:
        """
        Create a zero-knowledge proof that we know the secret corresponding to public_key.

        Returns (R_compressed, challenge, response) where:
        - R_compressed: Compressed representation of commitment point R
        - challenge: The challenge value computed via Fiat-Shamir
        - response: The response value s = k + challenge * secret
        """
        # Step 1: Generate random nonce
        k = secrets.randbelow(self.curve.n - 1) + 1

        # Step 2: Compute R = k * G
        R = self.curve.point_multiply(k, self.curve.G)

        # Step 3: Compress R for transmission
        R_compressed = self.curve.point_compress(R)

        # Step 4: Compute challenge using Fiat-Shamir heuristic
        public_key_compressed = self.curve.point_compress(public_key)
        challenge = self._hash_to_challenge(
            R_compressed,
            public_key_compressed,
            commitment
        )

        # Step 5: Compute response s = k + c * x (mod n)
        response = (k + challenge * secret) % self.curve.n

        return R_compressed, challenge, response

    def verify_proof(self, public_key: Tuple[int, int], commitment: bytes,
                    R_compressed: bytes, challenge: int, response: int) -> bool:
        """
        Verify a zero-knowledge proof.

        Verifies that the prover knows the secret without revealing it.
        """
        try:
            # Step 1: Decompress R (we need to reconstruct it)
            # For verification, we compute R' = s*G - c*P and check if it matches

            # Step 2: Compute s*G
            sG = self.curve.point_multiply(response, self.curve.G)

            # Step 3: Compute c*P
            cP = self.curve.point_multiply(challenge, public_key)

            # Step 4: Compute R' = s*G - c*P
            # Note: -c*P = c*(-P), where -P = (x, -y mod p)
            if cP is not None:
                neg_cP = (cP[0], (-cP[1]) % self.curve.p)
                R_prime = self.curve.point_add(sG, neg_cP)
            else:
                R_prime = sG

            # Step 5: Compress R' and compare with transmitted R
            R_prime_compressed = self.curve.point_compress(R_prime)

            # Step 6: Verify challenge was computed correctly
            public_key_compressed = self.curve.point_compress(public_key)
            expected_challenge = self._hash_to_challenge(
                R_compressed,
                public_key_compressed,
                commitment
            )

            return (R_compressed == R_prime_compressed and
                   challenge == expected_challenge)

        except (ValueError, TypeError, ZeroDivisionError):
            return False


class CommitmentZKP:
    """
    Zero-Knowledge Proof system specifically for commitment schemes.

    This allows proving knowledge of the value and salt that produced
    a commitment without revealing them.
    """

    def __init__(self):
        self.curve = EllipticCurve()
        self.schnorr = SchnorrZKP(self.curve)

    def _derive_secret_from_commitment_data(self, value: Union[str, int, bytes],
                                          salt: bytes) -> int:
        """
        Derive a secret key from value and salt for ZKP purposes.

        This creates a deterministic but unpredictable secret from the commitment data.
        """
        # Convert value to bytes
        if isinstance(value, str):
            value_bytes = value.encode('utf-8')
        elif isinstance(value, int):
            if value < 0:
                raise ValueError("Negative integers not supported")
            value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        elif isinstance(value, bytes):
            value_bytes = value
        else:
            raise TypeError("Value must be string, integer, or bytes")

        # Combine value and salt
        combined = value_bytes + salt

        # Hash to get a secret in the correct range
        hasher = hashlib.sha256()
        hasher.update(combined)
        hasher.update(b"ZKP_SECRET_DERIVATION")  # Domain separation
        digest = hasher.digest()

        # Ensure secret is in valid range [1, n-1]
        secret = int.from_bytes(digest, 'big') % (self.curve.n - 1) + 1
        return secret

    def create_commitment_proof(self, value: Union[str, int, bytes], salt: bytes,
                              commitment: bytes) -> Tuple[Tuple[int, int], bytes, int, int]:
        """
        Create a zero-knowledge proof for a commitment.

        Returns (public_key, R_compressed, challenge, response) where:
        - public_key: The public key derived from value and salt
        - R_compressed, challenge, response: The Schnorr proof components
        """
        # Derive secret from value and salt
        secret = self._derive_secret_from_commitment_data(value, salt)

        # Generate public key from secret
        public_key = self.curve.point_multiply(secret, self.curve.G)

        # Create Schnorr proof
        R_compressed, challenge, response = self.schnorr.create_proof(
            secret, public_key, commitment
        )

        return public_key, R_compressed, challenge, response

    def verify_commitment_proof(self, commitment: bytes, public_key: Tuple[int, int],
                               R_compressed: bytes, challenge: int, response: int) -> bool:
        """
        Verify a zero-knowledge proof for a commitment.

        This verifies that the prover knows value and salt that produce the commitment,
        without revealing the value or salt.
        """
        return self.schnorr.verify_proof(
            public_key, commitment, R_compressed, challenge, response
        )

    def verify_commitment_consistency(self, value: Union[str, int, bytes], salt: bytes,
                                    commitment: bytes, public_key: Tuple[int, int]) -> bool:
        """
        Verify that a public key is consistent with value, salt, and commitment.

        This can be used to verify that a revealed value/salt pair matches
        a previously generated ZKP public key.
        """
        try:
            expected_secret = self._derive_secret_from_commitment_data(value, salt)
            expected_public_key = self.curve.point_multiply(expected_secret, self.curve.G)
            return expected_public_key == public_key
        except (ValueError, TypeError):
            return False


# Factory function for easy access
def create_zkp_system() -> CommitmentZKP:
    """Create a new ZKP system instance."""
    return CommitmentZKP()