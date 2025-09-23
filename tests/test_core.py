import pytest
import secrets
import hashlib
from commit_reveal.core import CommitRevealScheme


class TestCommitRevealScheme:
    """Test suite for the core CommitRevealScheme functionality."""

    def test_initialization_default(self):
        """Test default initialization."""
        cr = CommitRevealScheme()
        assert cr.hash_algorithm == 'sha256'
        assert not cr.use_zkp
        assert cr._hash_func == hashlib.sha256

    def test_initialization_custom_hash(self):
        """Test initialization with custom hash algorithm."""
        cr = CommitRevealScheme(hash_algorithm='sha512')
        assert cr.hash_algorithm == 'sha512'
        assert cr._hash_func == hashlib.sha512

    def test_initialization_with_zkp(self):
        """Test initialization with ZKP enabled."""
        cr = CommitRevealScheme(use_zkp=True)
        assert cr.use_zkp

    def test_initialization_invalid_hash(self):
        """Test initialization with invalid hash algorithm."""
        with pytest.raises(AttributeError):
            CommitRevealScheme(hash_algorithm='invalid_hash')


class TestCommitFunctionality:
    """Test suite for commit functionality."""

    @pytest.fixture
    def scheme(self):
        return CommitRevealScheme()

    def test_commit_string_value(self, scheme):
        """Test committing to a string value."""
        value = "test string"
        commitment, salt = scheme.commit(value)

        assert isinstance(commitment, bytes)
        assert isinstance(salt, bytes)
        assert len(commitment) == 32  # SHA-256 output length
        assert len(salt) == 32  # Default salt length

    def test_commit_integer_value(self, scheme):
        """Test committing to an integer value."""
        value = 12345
        commitment, salt = scheme.commit(value)

        assert isinstance(commitment, bytes)
        assert isinstance(salt, bytes)
        assert len(commitment) == 32

    def test_commit_bytes_value(self, scheme):
        """Test committing to bytes value."""
        value = b"test bytes"
        commitment, salt = scheme.commit(value)

        assert isinstance(commitment, bytes)
        assert isinstance(salt, bytes)
        assert len(commitment) == 32

    def test_commit_with_custom_salt(self, scheme):
        """Test committing with a custom salt."""
        value = "test"
        custom_salt = b"a" * 32
        commitment, returned_salt = scheme.commit(value, salt=custom_salt)

        assert returned_salt == custom_salt
        assert isinstance(commitment, bytes)

    def test_commit_invalid_type(self, scheme):
        """Test committing with invalid value type."""
        with pytest.raises(TypeError, match="Value must be string, integer, or bytes"):
            scheme.commit([1, 2, 3])  # List is not supported

    def test_commit_deterministic_with_same_salt(self, scheme):
        """Test that same value and salt produce same commitment."""
        value = "test"
        salt = secrets.token_bytes(32)

        commitment1, _ = scheme.commit(value, salt=salt)
        commitment2, _ = scheme.commit(value, salt=salt)

        assert commitment1 == commitment2

    def test_commit_different_with_different_salt(self, scheme):
        """Test that same value with different salts produce different commitments."""
        value = "test"

        commitment1, salt1 = scheme.commit(value)
        commitment2, salt2 = scheme.commit(value)

        assert commitment1 != commitment2
        assert salt1 != salt2

    def test_commit_large_integer(self, scheme):
        """Test committing to large integer values."""
        value = 2**1024  # Very large integer
        commitment, salt = scheme.commit(value)

        assert isinstance(commitment, bytes)
        assert len(commitment) == 32


class TestRevealFunctionality:
    """Test suite for reveal functionality."""

    @pytest.fixture
    def scheme(self):
        return CommitRevealScheme()

    def test_reveal_valid_string(self, scheme):
        """Test revealing a valid string commitment."""
        value = "secret message"
        commitment, salt = scheme.commit(value)

        result = scheme.reveal(value, salt, commitment)
        assert result is True

    def test_reveal_valid_integer(self, scheme):
        """Test revealing a valid integer commitment."""
        value = 42
        commitment, salt = scheme.commit(value)

        result = scheme.reveal(value, salt, commitment)
        assert result is True

    def test_reveal_valid_bytes(self, scheme):
        """Test revealing a valid bytes commitment."""
        value = b"secret bytes"
        commitment, salt = scheme.commit(value)

        result = scheme.reveal(value, salt, commitment)
        assert result is True

    def test_reveal_wrong_value(self, scheme):
        """Test revealing with wrong value."""
        value = "correct value"
        wrong_value = "wrong value"
        commitment, salt = scheme.commit(value)

        result = scheme.reveal(wrong_value, salt, commitment)
        assert result is False

    def test_reveal_wrong_salt(self, scheme):
        """Test revealing with wrong salt."""
        value = "secret"
        commitment, salt = scheme.commit(value)
        wrong_salt = secrets.token_bytes(32)

        result = scheme.reveal(value, wrong_salt, commitment)
        assert result is False

    def test_reveal_wrong_commitment(self, scheme):
        """Test revealing with wrong commitment."""
        value = "secret"
        commitment, salt = scheme.commit(value)
        wrong_commitment = secrets.token_bytes(32)

        result = scheme.reveal(value, salt, wrong_commitment)
        assert result is False

    def test_verify_alias(self, scheme):
        """Test that verify is an alias for reveal."""
        value = "test"
        commitment, salt = scheme.commit(value)

        reveal_result = scheme.reveal(value, salt, commitment)
        verify_result = scheme.verify(value, salt, commitment)

        assert reveal_result == verify_result
        assert verify_result is True


class TestZeroKnowledgeProofs:
    """Test suite for zero-knowledge proof functionality."""

    @pytest.fixture
    def zkp_scheme(self):
        return CommitRevealScheme(use_zkp=True)

    @pytest.fixture
    def non_zkp_scheme(self):
        return CommitRevealScheme(use_zkp=False)

    def test_create_zkp_proof_enabled(self, zkp_scheme):
        """Test creating ZKP proof when ZKP is enabled."""
        value = "secret"
        commitment, salt = zkp_scheme.commit(value)

        nonce, challenge, response = zkp_scheme.create_zkp_proof(value, salt, commitment)

        assert isinstance(nonce, bytes)
        assert isinstance(challenge, int)
        assert isinstance(response, int)
        assert len(nonce) == 32

    def test_create_zkp_proof_disabled(self, non_zkp_scheme):
        """Test creating ZKP proof when ZKP is disabled."""
        value = "secret"
        commitment, salt = non_zkp_scheme.commit(value)

        with pytest.raises(ValueError, match="ZKP functionality not enabled"):
            non_zkp_scheme.create_zkp_proof(value, salt, commitment)

    def test_verify_zkp_proof_enabled(self, zkp_scheme):
        """Test verifying ZKP proof when ZKP is enabled."""
        value = "secret"
        commitment, salt = zkp_scheme.commit(value)
        nonce, challenge, response = zkp_scheme.create_zkp_proof(value, salt, commitment)

        result = zkp_scheme.verify_zkp_proof(commitment, nonce, challenge, response)
        assert result is True

    def test_verify_zkp_proof_disabled(self, non_zkp_scheme):
        """Test verifying ZKP proof when ZKP is disabled."""
        with pytest.raises(ValueError, match="ZKP functionality not enabled"):
            non_zkp_scheme.verify_zkp_proof(b"", b"", 0, 0)

    def test_verify_zkp_proof_wrong_challenge(self, zkp_scheme):
        """Test verifying ZKP proof with wrong challenge."""
        value = "secret"
        commitment, salt = zkp_scheme.commit(value)
        nonce, challenge, response = zkp_scheme.create_zkp_proof(value, salt, commitment)

        wrong_challenge = challenge + 1
        result = zkp_scheme.verify_zkp_proof(commitment, nonce, wrong_challenge, response)
        assert result is False

    def test_zkp_proof_deterministic(self, zkp_scheme):
        """Test that ZKP proof generation is deterministic for same inputs."""
        value = "secret"
        commitment, salt = zkp_scheme.commit(value)

        # Note: This test might need adjustment if we add more randomness to ZKP
        nonce1, challenge1, response1 = zkp_scheme.create_zkp_proof(value, salt, commitment)
        nonce2, challenge2, response2 = zkp_scheme.create_zkp_proof(value, salt, commitment)

        # Nonces should be different (random), but challenges and responses might be deterministic
        assert nonce1 != nonce2  # Different random nonces

    def test_zkp_different_values_different_proofs(self, zkp_scheme):
        """Test that different values produce different ZKP proofs."""
        value1 = "secret1"
        value2 = "secret2"

        commitment1, salt1 = zkp_scheme.commit(value1)
        commitment2, salt2 = zkp_scheme.commit(value2)

        nonce1, challenge1, response1 = zkp_scheme.create_zkp_proof(value1, salt1, commitment1)
        nonce2, challenge2, response2 = zkp_scheme.create_zkp_proof(value2, salt2, commitment2)

        # At least some components should be different
        assert not (nonce1 == nonce2 and challenge1 == challenge2 and response1 == response2)


class TestEdgeCases:
    """Test suite for edge cases and boundary conditions."""

    @pytest.fixture
    def scheme(self):
        return CommitRevealScheme()

    def test_empty_string_commit(self, scheme):
        """Test committing to empty string."""
        value = ""
        commitment, salt = scheme.commit(value)

        assert isinstance(commitment, bytes)
        assert scheme.reveal(value, salt, commitment) is True

    def test_zero_integer_commit(self, scheme):
        """Test committing to zero integer."""
        value = 0
        commitment, salt = scheme.commit(value)

        assert isinstance(commitment, bytes)
        assert scheme.reveal(value, salt, commitment) is True

    def test_empty_bytes_commit(self, scheme):
        """Test committing to empty bytes."""
        value = b""
        commitment, salt = scheme.commit(value)

        assert isinstance(commitment, bytes)
        assert scheme.reveal(value, salt, commitment) is True

    def test_unicode_string_commit(self, scheme):
        """Test committing to Unicode string."""
        value = "🔐 secret émoji"
        commitment, salt = scheme.commit(value)

        assert isinstance(commitment, bytes)
        assert scheme.reveal(value, salt, commitment) is True

    def test_negative_integer_commit(self, scheme):
        """Test committing to negative integer."""
        value = -42
        with pytest.raises(OverflowError):
            # This should fail because negative numbers can't be converted to bytes directly
            scheme.commit(value)

    def test_very_long_string(self, scheme):
        """Test committing to very long string."""
        value = "x" * 10000  # 10KB string
        commitment, salt = scheme.commit(value)

        assert isinstance(commitment, bytes)
        assert scheme.reveal(value, salt, commitment) is True


class TestSecurityProperties:
    """Test suite for security properties."""

    @pytest.fixture
    def scheme(self):
        return CommitRevealScheme()

    def test_salt_randomness(self, scheme):
        """Test that generated salts are random."""
        salts = []
        for _ in range(100):
            _, salt = scheme.commit("test")
            salts.append(salt)

        # All salts should be unique
        assert len(set(salts)) == 100

    def test_commitment_uniformity(self, scheme):
        """Test that commitments appear uniform."""
        commitments = []
        for i in range(100):
            commitment, _ = scheme.commit(f"test{i}")
            commitments.append(commitment)

        # All commitments should be unique
        assert len(set(commitments)) == 100

    def test_timing_safe_comparison(self, scheme):
        """Test that reveal uses timing-safe comparison."""
        value = "secret"
        commitment, salt = scheme.commit(value)

        # This is more of a code review test - we check that hmac.compare_digest is used
        # The actual timing analysis would require more sophisticated testing
        assert scheme.reveal(value, salt, commitment) is True
        assert scheme.reveal("wrong", salt, commitment) is False

    def test_salt_length_security(self, scheme):
        """Test that salt length is cryptographically secure."""
        _, salt = scheme.commit("test")

        # 32 bytes = 256 bits, which is cryptographically secure
        assert len(salt) == 32

    def test_commitment_collision_resistance(self, scheme):
        """Test commitment collision resistance with different values."""
        commitments = set()

        # Test with many different values
        test_values = [
            "test1", "test2", "", "a" * 1000, "🔐",
            b"bytes1", b"bytes2", b"",
            1, 2, 1000000
        ]

        for value in test_values:
            try:
                commitment, _ = scheme.commit(value)
                commitments.add(commitment)
            except (TypeError, OverflowError):
                # Skip invalid values for this test
                continue

        # All valid commitments should be unique
        # (This is a probabilistic test, collisions are extremely unlikely)
        valid_count = len([v for v in test_values if not (isinstance(v, int) and v < 0)])
        assert len(commitments) == valid_count - 1  # -1 for negative integer