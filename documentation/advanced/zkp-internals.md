# ZKP Internals

The zero-knowledge proof system uses Schnorr signatures on the secp256k1 elliptic curve, made non-interactive via the Fiat-Shamir heuristic.

## secp256k1 Curve

The same curve used by Bitcoin. Parameters:

| Parameter | Value |
|-----------|-------|
| Equation | y^2^ = x^3^ + 7 |
| Field prime (p) | 2^256^ - 2^32^ - 977 |
| Group order (n) | `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` |
| Generator (G) | Standard SECG generator point |
| Security level | ~128 bits |

## Schnorr Signature Protocol

### Key Generation

1. Choose a random secret key `k` in `[1, n-1]`
2. Compute public key `P = k * G`

### Proof Creation

Given secret `k` and public key `P = k * G`:

1. Choose random nonce `r` in `[1, n-1]`
2. Compute commitment point `R = r * G`
3. Compress `R` to 33 bytes
4. Compute challenge: `e = H(R_compressed || P || message)`
5. Compute response: `s = r - e * k (mod n)`
6. Return `(P, R_compressed, e, s)`

### Proof Verification

Given `(P, R_compressed, e, s)`:

1. Decompress `R_compressed` to point `R`
2. Compute `R' = s * G + e * P`
3. Recompute challenge: `e' = H(R_compressed || P || message)`
4. Verify `e == e'`

If the verification passes, the prover knows the secret key `k` without having revealed it.

## Fiat-Shamir Heuristic

The interactive Schnorr protocol requires a verifier to send a random challenge. The Fiat-Shamir heuristic replaces this with a hash:

```
challenge = H(R_compressed || public_key || commitment)
```

This makes the proof non-interactive -- the prover generates the challenge themselves using a cryptographic hash, which is indistinguishable from a random challenge in the random oracle model.

## Point Compression

Elliptic curve points `(x, y)` are compressed to 33 bytes:

- Byte 0: `0x02` if `y` is even, `0x03` if `y` is odd
- Bytes 1-32: `x` coordinate (32 bytes, big-endian)

Decompression recovers `y` by solving `y^2 = x^3 + 7 (mod p)` and selecting the correct parity.

## Implementation Classes

### EllipticCurve

Low-level curve arithmetic. Not typically used directly.

```python
# Internal use
curve = EllipticCurve()
point = curve.point_multiply(scalar, curve.G)
compressed = curve.point_compress(point)
is_valid = curve.is_valid_point(point)
```

### SchnorrZKP

Schnorr signature implementation.

```python
# Internal use
schnorr = SchnorrZKP(curve)
private_key, public_key = schnorr.generate_keypair()
R_compressed, challenge, response = schnorr.create_proof(
    secret, public_key, commitment
)
is_valid = schnorr.verify_proof(
    public_key, commitment, R_compressed, challenge, response
)
```

### CommitmentZKP

High-level ZKP for commit-reveal, used internally by `CommitRevealScheme`:

```python
# Used via CommitRevealScheme(use_zkp=True)
scheme = CommitRevealScheme(use_zkp=True)
commitment, salt = scheme.commit("secret")
proof = scheme.create_zkp_proof("secret", salt, commitment)
```

## Security Considerations

- **Nonce reuse**: Reusing the random nonce `r` across two proofs with the same key leaks the secret key. The implementation generates fresh nonces using `secrets`.
- **Curve validation**: All points are checked to be on the curve before use.
- **Challenge binding**: The challenge hash includes all public parameters to prevent proof transplanting.
- **Single-use proofs**: Each proof should only be verified once per context.
