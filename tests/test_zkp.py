"""
Unit tests for commit_reveal.zkp — the Schnorr ZKP + EllipticCurve layer
that the rest of the library relies on for proof-of-knowledge claims.

zkp.py shipped without a dedicated test file; the package-level tests
under tests/test_core.py exercise the commit/reveal surface but never
the inner EC arithmetic or the Schnorr challenge/response math directly.
These tests pin the contracts that the rest of the codebase silently
depends on (curve order, generator on-curve, Schnorr roundtrip, Fiat-Shamir
challenge binding, commitment-secret derivation reproducibility).
"""

from __future__ import annotations

import pytest

from commit_reveal.zkp import (
    CommitmentZKP,
    EllipticCurve,
    SchnorrZKP,
    create_zkp_system,
)


# ---------------------------------------------------------------------------
# EllipticCurve (secp256k1)
# ---------------------------------------------------------------------------


class TestEllipticCurve:
    def setup_method(self) -> None:
        self.curve = EllipticCurve()

    def test_secp256k1_parameters_are_canonical(self) -> None:
        # Per SEC 2 v2.0 / Bitcoin: y^2 = x^3 + 7 (mod p).
        assert self.curve.a == 0
        assert self.curve.b == 7
        assert self.curve.p == (1 << 256) - (1 << 32) - 977  # secp256k1 p
        assert self.curve.n == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    def test_generator_is_on_curve(self) -> None:
        assert self.curve.is_valid_point(self.curve.G)

    def test_off_curve_point_rejected(self) -> None:
        assert not self.curve.is_valid_point((1, 1))

    def test_point_add_identity_is_left_and_right(self) -> None:
        G = self.curve.G
        assert self.curve.point_add(None, G) == G
        assert self.curve.point_add(G, None) == G

    def test_point_add_inverses_yield_identity(self) -> None:
        x, y = self.curve.G
        neg_G = (x, (-y) % self.curve.p)
        assert self.curve.point_add(self.curve.G, neg_G) is None

    def test_point_multiply_k0_is_identity(self) -> None:
        assert self.curve.point_multiply(0, self.curve.G) is None

    def test_point_multiply_k1_is_input(self) -> None:
        assert self.curve.point_multiply(1, self.curve.G) == self.curve.G

    def test_point_multiply_matches_repeated_addition(self) -> None:
        G = self.curve.G
        accum = None
        for k in range(1, 8):
            accum = self.curve.point_add(accum, G)
            assert self.curve.point_multiply(k, G) == accum
            assert self.curve.is_valid_point(accum)

    def test_point_compress_prefix_encodes_y_parity(self) -> None:
        G = self.curve.G
        compressed = self.curve.point_compress(G)
        assert len(compressed) == 33
        assert compressed[0] == 0x02  # G.y is even on secp256k1

        x, y = G
        odd_partner = (x, (-y) % self.curve.p)
        compressed_neg = self.curve.point_compress(odd_partner)
        assert compressed_neg[0] == 0x03
        assert compressed[1:] == compressed_neg[1:]

    def test_point_compress_none_is_all_zero_sentinel(self) -> None:
        assert self.curve.point_compress(None) == b"\x00" * 33


# ---------------------------------------------------------------------------
# SchnorrZKP
# ---------------------------------------------------------------------------


class TestSchnorrZKP:
    def setup_method(self) -> None:
        self.schnorr = SchnorrZKP()
        self.commitment = b"unit-test-commitment-bytes"

    def test_generate_keypair_satisfies_pk_equals_sk_times_G(self) -> None:
        sk, pk = self.schnorr.generate_keypair()
        assert 1 <= sk < self.schnorr.curve.n
        assert pk == self.schnorr.curve.point_multiply(sk, self.schnorr.curve.G)

    def test_create_verify_roundtrip(self) -> None:
        sk, pk = self.schnorr.generate_keypair()
        R, c, s = self.schnorr.create_proof(sk, pk, self.commitment)
        assert self.schnorr.verify_proof(pk, self.commitment, R, c, s)

    def test_verify_rejects_tampered_response(self) -> None:
        sk, pk = self.schnorr.generate_keypair()
        R, c, s = self.schnorr.create_proof(sk, pk, self.commitment)
        tampered = (s + 1) % self.schnorr.curve.n
        assert not self.schnorr.verify_proof(pk, self.commitment, R, c, tampered)

    def test_verify_rejects_tampered_challenge(self) -> None:
        sk, pk = self.schnorr.generate_keypair()
        R, c, s = self.schnorr.create_proof(sk, pk, self.commitment)
        tampered = (c + 1) % self.schnorr.curve.n
        assert not self.schnorr.verify_proof(pk, self.commitment, R, tampered, s)

    def test_verify_rejects_mismatched_commitment(self) -> None:
        sk, pk = self.schnorr.generate_keypair()
        R, c, s = self.schnorr.create_proof(sk, pk, self.commitment)
        assert not self.schnorr.verify_proof(pk, b"different-commitment", R, c, s)

    def test_verify_rejects_wrong_public_key(self) -> None:
        sk_a, pk_a = self.schnorr.generate_keypair()
        _, pk_b = self.schnorr.generate_keypair()
        R, c, s = self.schnorr.create_proof(sk_a, pk_a, self.commitment)
        assert not self.schnorr.verify_proof(pk_b, self.commitment, R, c, s)


# ---------------------------------------------------------------------------
# CommitmentZKP
# ---------------------------------------------------------------------------


class TestCommitmentZKP:
    def setup_method(self) -> None:
        self.zkp = CommitmentZKP()
        self.commitment = b"commitment-binding-bytes"
        self.salt = b"\x01" * 32

    @pytest.mark.parametrize(
        "value",
        ["a string value", 1234567890, b"\xde\xad\xbe\xef"],
    )
    def test_create_verify_roundtrip_for_supported_types(self, value) -> None:
        pk, R, c, s = self.zkp.create_commitment_proof(value, self.salt, self.commitment)
        assert self.zkp.verify_commitment_proof(self.commitment, pk, R, c, s)

    def test_secret_derivation_is_deterministic(self) -> None:
        v, s = "deterministic-input", b"\x02" * 32
        pk1, _, _, _ = self.zkp.create_commitment_proof(v, s, self.commitment)
        pk2, _, _, _ = self.zkp.create_commitment_proof(v, s, self.commitment)
        assert pk1 == pk2

    def test_consistency_check_accepts_correct_value_salt(self) -> None:
        pk, _, _, _ = self.zkp.create_commitment_proof("the value", self.salt, self.commitment)
        assert self.zkp.verify_commitment_consistency("the value", self.salt, self.commitment, pk)

    def test_consistency_check_rejects_wrong_value(self) -> None:
        pk, _, _, _ = self.zkp.create_commitment_proof("the value", self.salt, self.commitment)
        assert not self.zkp.verify_commitment_consistency("WRONG", self.salt, self.commitment, pk)

    def test_consistency_check_rejects_wrong_salt(self) -> None:
        pk, _, _, _ = self.zkp.create_commitment_proof("the value", self.salt, self.commitment)
        assert not self.zkp.verify_commitment_consistency("the value", b"\xff" * 32, self.commitment, pk)

    def test_negative_int_value_rejected(self) -> None:
        with pytest.raises(ValueError):
            self.zkp.create_commitment_proof(-1, self.salt, self.commitment)

    def test_unsupported_value_type_rejected(self) -> None:
        with pytest.raises(TypeError):
            self.zkp.create_commitment_proof(3.14, self.salt, self.commitment)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def test_create_zkp_system_returns_commitment_zkp() -> None:
    system = create_zkp_system()
    assert isinstance(system, CommitmentZKP)
    pk, R, c, s = system.create_commitment_proof("smoke", b"\x03" * 32, b"smoke-commitment")
    assert system.verify_commitment_proof(b"smoke-commitment", pk, R, c, s)
