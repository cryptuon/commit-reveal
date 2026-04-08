# Hash Algorithms

## Comparison

| Algorithm | Output Size | Speed | Notes |
|-----------|-------------|-------|-------|
| `sha256` | 32 bytes (256 bit) | Fast | **Default.** Widely compatible, recommended for most use cases. |
| `sha384` | 48 bytes (384 bit) | Moderate | Truncated SHA-512. Higher security margin. |
| `sha512` | 64 bytes (512 bit) | Fast (64-bit) | Highest security margin in the SHA-2 family. |
| `sha3_256` | 32 bytes (256 bit) | Moderate | NIST SHA-3 standard. Different internal structure from SHA-2. |
| `sha3_384` | 48 bytes (384 bit) | Moderate | |
| `sha3_512` | 64 bytes (512 bit) | Slower | Maximum security in SHA-3 family. |
| `blake2b` | 64 bytes (512 bit) | Very fast | Optimized for 64-bit platforms. |
| `blake2s` | 32 bytes (256 bit) | Very fast | Optimized for 32-bit and embedded platforms. |

## Rejected Algorithms

These algorithms raise `SecurityError` if used:

| Algorithm | Reason |
|-----------|--------|
| `md5` | Cryptographically broken. Collision attacks are trivial. |
| `sha1` | Known collision attacks (SHAttered, 2017). |
| `sha224` | Truncated SHA-256 with reduced security margin. |

## Choosing an Algorithm

### For Most Applications

Use the default `sha256`. It provides 128-bit collision resistance, is fast on all platforms, and is universally supported.

```python
cr = CommitRevealScheme()  # sha256 by default
```

### For High-Security Applications

Use `sha512` for a wider security margin (256-bit collision resistance):

```python
cr = CommitRevealScheme(hash_algorithm='sha512')
```

### For Algorithm Diversity

If your threat model requires independence from SHA-2 (e.g., hedging against a future SHA-2 break), use SHA-3 or BLAKE2:

```python
# SHA-3: completely different internal construction (Keccak sponge)
cr = CommitRevealScheme(hash_algorithm='sha3_256')

# BLAKE2: fast, modern, based on ChaCha stream cipher
cr = CommitRevealScheme(hash_algorithm='blake2b')
```

### For Performance-Critical Code

BLAKE2 is the fastest option, especially on modern hardware:

```python
cr = CommitRevealScheme(hash_algorithm='blake2b')  # 64-bit platforms
cr = CommitRevealScheme(hash_algorithm='blake2s')  # 32-bit/embedded
```

## How Commitments Work

The commitment is computed as:

```
commitment = H(value || salt)
```

Where `H` is the selected hash function, `value` is the serialized input, and `salt` is a random 32-byte value. The `||` operator denotes concatenation.

The binding property of the hash function ensures that:

- Given `commitment`, it is infeasible to find `value` and `salt`
- Given `commitment`, `value`, and `salt`, verification is a single hash computation
- Different salts produce different commitments for the same value
