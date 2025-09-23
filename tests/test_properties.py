"""Property-based tests using hypothesis for robust testing of cryptographic properties."""

import pytest
from hypothesis import given, strategies as st, assume, settings
from hypothesis.stateful import RuleBasedStateMachine, Bundle, rule, initialize
from commit_reveal.core import CommitRevealScheme


# Strategies for generating test data
def safe_integers():
    """Generate non-negative integers that can be converted to bytes."""
    return st.integers(min_value=0, max_value=2**1024)


def safe_text():
    """Generate text that can be safely encoded."""
    return st.text(min_size=0, max_size=1000)


def safe_bytes():
    """Generate byte strings."""
    return st.binary(min_size=0, max_size=1000)


class TestCommitRevealProperties:
    """Property-based tests for commit-reveal scheme properties."""

    @given(safe_text())
    def test_commit_reveal_string_roundtrip(self, value):
        """Property: commit-reveal should always work for any string."""
        scheme = CommitRevealScheme()
        commitment, salt = scheme.commit(value)
        assert scheme.reveal(value, salt, commitment) is True

    @given(safe_integers())
    def test_commit_reveal_integer_roundtrip(self, value):
        """Property: commit-reveal should always work for any non-negative integer."""
        scheme = CommitRevealScheme()
        commitment, salt = scheme.commit(value)
        assert scheme.reveal(value, salt, commitment) is True

    @given(safe_bytes())
    def test_commit_reveal_bytes_roundtrip(self, value):
        """Property: commit-reveal should always work for any bytes."""
        scheme = CommitRevealScheme()
        commitment, salt = scheme.commit(value)
        assert scheme.reveal(value, salt, commitment) is True

    @given(safe_text(), safe_text())
    def test_different_values_different_commitments(self, value1, value2):
        """Property: different values should produce different commitments (with high probability)."""
        assume(value1 != value2)

        scheme = CommitRevealScheme()
        commitment1, _ = scheme.commit(value1)
        commitment2, _ = scheme.commit(value2)

        # Different values should produce different commitments
        # (This is probabilistic due to hash function properties)
        assert commitment1 != commitment2

    @given(safe_text(), st.binary(min_size=32, max_size=32))
    def test_same_value_same_salt_same_commitment(self, value, salt):
        """Property: same value and salt should always produce the same commitment."""
        scheme = CommitRevealScheme()

        commitment1, _ = scheme.commit(value, salt=salt)
        commitment2, _ = scheme.commit(value, salt=salt)

        assert commitment1 == commitment2

    @given(safe_text(), safe_text())
    def test_wrong_value_fails_reveal(self, correct_value, wrong_value):
        """Property: revealing with wrong value should fail."""
        assume(correct_value != wrong_value)

        scheme = CommitRevealScheme()
        commitment, salt = scheme.commit(correct_value)

        assert scheme.reveal(wrong_value, salt, commitment) is False

    @given(safe_text(), st.binary(min_size=32, max_size=32))
    def test_wrong_salt_fails_reveal(self, value, wrong_salt):
        """Property: revealing with wrong salt should fail."""
        scheme = CommitRevealScheme()
        commitment, correct_salt = scheme.commit(value)

        assume(correct_salt != wrong_salt)
        assert scheme.reveal(value, wrong_salt, commitment) is False

    @given(safe_text())
    def test_commitment_deterministic_properties(self, value):
        """Property: commitments should have consistent properties."""
        scheme = CommitRevealScheme()
        commitment, salt = scheme.commit(value)

        # Commitment should always be 32 bytes (SHA-256)
        assert len(commitment) == 32
        assert len(salt) == 32

        # Should be bytes objects
        assert isinstance(commitment, bytes)
        assert isinstance(salt, bytes)

    @given(safe_text())
    def test_verify_alias_consistency(self, value):
        """Property: verify should be consistent with reveal."""
        scheme = CommitRevealScheme()
        commitment, salt = scheme.commit(value)

        reveal_result = scheme.reveal(value, salt, commitment)
        verify_result = scheme.verify(value, salt, commitment)

        assert reveal_result == verify_result

    @given(st.sampled_from(['sha256', 'sha512', 'sha1']))
    def test_different_hash_algorithms(self, hash_alg):
        """Property: different hash algorithms should work consistently."""
        scheme = CommitRevealScheme(hash_algorithm=hash_alg)
        value = "test value"

        commitment, salt = scheme.commit(value)
        assert scheme.reveal(value, salt, commitment) is True


class TestZKPProperties:
    """Property-based tests for zero-knowledge proof properties."""

    @given(safe_text())
    def test_zkp_proof_verification_roundtrip(self, value):
        """Property: ZKP proof should verify correctly for valid inputs."""
        scheme = CommitRevealScheme(use_zkp=True)
        commitment, salt = scheme.commit(value)

        nonce, challenge, response = scheme.create_zkp_proof(value, salt, commitment)
        assert scheme.verify_zkp_proof(commitment, nonce, challenge, response) is True

    @given(safe_text(), st.integers(min_value=0, max_value=2**256-1))
    def test_zkp_wrong_challenge_fails(self, value, wrong_challenge):
        """Property: ZKP verification should fail with wrong challenge."""
        scheme = CommitRevealScheme(use_zkp=True)
        commitment, salt = scheme.commit(value)

        nonce, correct_challenge, response = scheme.create_zkp_proof(value, salt, commitment)
        assume(wrong_challenge != correct_challenge)

        assert scheme.verify_zkp_proof(commitment, nonce, wrong_challenge, response) is False

    @given(safe_text())
    def test_zkp_proof_properties(self, value):
        """Property: ZKP proofs should have consistent structure."""
        scheme = CommitRevealScheme(use_zkp=True)
        commitment, salt = scheme.commit(value)

        nonce, challenge, response = scheme.create_zkp_proof(value, salt, commitment)

        # Check types and sizes
        assert isinstance(nonce, bytes)
        assert isinstance(challenge, int)
        assert isinstance(response, int)
        assert len(nonce) == 32
        assert 0 <= challenge < 2**256
        assert 0 <= response < 2**256


class TestSecurityProperties:
    """Property-based tests for security properties."""

    @given(st.lists(safe_text(), min_size=2, max_size=100, unique=True))
    def test_collision_resistance(self, values):
        """Property: hash collisions should be extremely rare."""
        scheme = CommitRevealScheme()
        commitments = set()

        for value in values:
            commitment, _ = scheme.commit(value)
            commitments.add(commitment)

        # All commitments should be unique (with very high probability)
        assert len(commitments) == len(values)

    @given(safe_text(), st.integers(min_value=1, max_value=100))
    def test_salt_randomness(self, value, num_commits):
        """Property: salts should be random across multiple commits."""
        scheme = CommitRevealScheme()
        salts = set()

        for _ in range(num_commits):
            _, salt = scheme.commit(value)
            salts.add(salt)

        # All salts should be unique (with very high probability)
        assert len(salts) == num_commits

    @given(safe_text())
    @settings(max_examples=10)  # This test is more for demonstration
    def test_timing_consistency(self, value):
        """Property: operations should have consistent timing characteristics."""
        import time

        scheme = CommitRevealScheme()

        # Measure commit times
        times = []
        for _ in range(10):
            start = time.perf_counter()
            commitment, salt = scheme.commit(value)
            end = time.perf_counter()
            times.append(end - start)

        # Times should be reasonably consistent (no extreme outliers)
        avg_time = sum(times) / len(times)
        for t in times:
            assert abs(t - avg_time) < avg_time * 2  # Within 200% of average


class CommitRevealStateMachine(RuleBasedStateMachine):
    """Stateful testing of commit-reveal operations."""

    def __init__(self):
        super().__init__()
        self.scheme = CommitRevealScheme()
        self.commitments = {}  # Track commitments for testing

    # Bundle for tracking values
    values = Bundle('values')
    commitments_bundle = Bundle('commitments')

    @initialize()
    def init_scheme(self):
        """Initialize the scheme."""
        self.scheme = CommitRevealScheme()

    @rule(target=values, value=safe_text())
    def add_value(self, value):
        """Add a value to track."""
        return value

    @rule(target=commitments_bundle, value=values)
    def commit_value(self, value):
        """Commit to a value."""
        commitment, salt = self.scheme.commit(value)
        self.commitments[commitment] = (value, salt)
        return commitment

    @rule(commitment=commitments_bundle)
    def reveal_commitment(self, commitment):
        """Reveal a commitment."""
        if commitment in self.commitments:
            value, salt = self.commitments[commitment]
            result = self.scheme.reveal(value, salt, commitment)
            assert result is True, "Valid reveal should succeed"

    @rule(commitment=commitments_bundle, wrong_value=safe_text())
    def reveal_with_wrong_value(self, commitment, wrong_value):
        """Try to reveal with wrong value."""
        if commitment in self.commitments:
            value, salt = self.commitments[commitment]
            if wrong_value != value:
                result = self.scheme.reveal(wrong_value, salt, commitment)
                assert result is False, "Wrong value should fail reveal"


# Test class for running the state machine
class TestStateMachine:
    """Test using the state machine."""

    def test_state_machine(self):
        """Run the state machine test."""
        # Import here to avoid issues if hypothesis is not available
        from hypothesis.stateful import run_state_machine_as_test
        run_state_machine_as_test(CommitRevealStateMachine)


# Run these tests with: pytest tests/test_properties.py -v
if __name__ == "__main__":
    pytest.main([__file__, "-v"])