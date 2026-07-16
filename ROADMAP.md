# Roadmap

`commit-reveal` is a small, dependency-free fairness primitive: hash-based commitments (8 algorithms) plus optional Schnorr zero-knowledge proofs on secp256k1, in pure Python. This roadmap states where the project is going and — bluntly — the cheapest credible path to calling it "production."

For the market framing (anti-MEV, verifiable AI, sealed-bid auctions, prediction markets) see the [README](README.md#why-this-matters-in-2026).

## Vision

Be the default *fairness primitive* that agent-economy and DeFi infrastructure reaches for when it needs "bind now, reveal later" with an auditable, dependency-free implementation. The library stays deliberately small: it does the cryptography correctly and stays out of the way of the surrounding system design. It is a **library, not a network** — no consensus, no custody, no on-chain settlement of its own.

Concretely, success means:

- A stable, well-typed, well-tested Python package that senior engineers trust on sight because they can read all of it.
- An optional, minimal on-chain reference verifier so teams can settle commit-reveal / Schnorr flows without rebuilding the crypto.
- Clear recipes for the 2026 use cases: fair ordering, sealed-bid auctions, commit-reveal RNG, and verifiable-AI answer submission.

## Milestones

### Now (v1.x) — stabilize the primitive
- Keep the zero-dependency, stdlib-only guarantee.
- Harden the crypto review surface (see *Production-viability changes* below).
- Documented recipes for each 2026 use case in `docs/use-cases.md`.

### Next — reference on-chain verifier
- A minimal, audited reference contract that verifies a commitment opening and a Schnorr proof, published as a companion (not a runtime dependency of this library).
- Test vectors shared between the Python library and the contract so cross-implementation equivalence is checkable in CI.

### Later — ecosystem fit
- Adapters/examples for common intent and auction frameworks.
- Optional deterministic-nonce (RFC 6979-style) ZKP mode for reproducible proofs.
- Domain-separation and versioned commitment encoding for multi-protocol safety.

## Cheapest path to production

For a pure-Python library, "production" is **not** an expensive infrastructure project. It is two cheap, mostly-engineering steps:

### 1. A stable, tested, published package (near-zero cost)

This is the bulk of "production" and it costs essentially nothing but engineering discipline:

- **Publish / refresh on PyPI.** The package is already `commit-reveal` on PyPI at v1.0.0. Keep it current, sign releases, and cut versions from CI on tag. Cost: free (PyPI + GitHub Actions).
- Nail the *Production-viability changes* below (coverage, security review, semver, typing, docs, CI).
- No servers, no hosting, no ongoing spend. A library "in production" means *other people depend on the package* and it does not break them.

### 2. (Optional) A minimal on-chain reference verifier — only if you need on-chain settlement

If a project wants commitments and Schnorr proofs *settled on-chain*, deploy a minimal verifier. Keep it minimal (verify-only, no custody) and put it on the cheapest viable chain. Options, cheapest-first:

| Target | Deploy + verify cost | Tradeoff | When to pick it |
|--------|----------------------|----------|-----------------|
| **Ethereum L2 (Base / Arbitrum / OP)** | Cents to low dollars per verify; deploy under a few dollars | Not L1-grade finality, but inherits Ethereum security via the rollup | **Default choice.** Best cost/security ratio for 2026 fairness apps and intent/auction flows. |
| **secp256k1-native chain** | Very low; native `ecrecover`-style precompiles make Schnorr/ECDSA checks cheap | Chain-specific tooling | If you are already deployed there and want the cheapest possible verify. |
| **Ethereum L1** | Dollars-to-tens per verify | Highest security and composability | Only when L1 finality is a hard requirement (e.g. high-value RWA settlement). |
| **App-specific / local (no chain)** | Free | No public verifiability | Off-chain fairness (internal auctions, agent networks that gossip commitments). Many verifiable-AI setups never touch a chain. |

**Recommendation:** publish/refresh on PyPI as step one (do this now, it is free). Add an on-chain verifier only when a concrete integration needs settlement, and when it does, deploy the minimal verify-only contract on an **Ethereum L2 (Base or Arbitrum)** — the best cost-to-security ratio. secp256k1 is deliberately the curve here precisely because EVM chains verify it cheaply.

## Production-viability changes (the checklist)

These are the concrete changes that move the library from "works" to "trusted in production." Ordered by leverage.

### Crypto security review (highest priority)
- **Constant-time arithmetic.** The secp256k1 implementation in `zkp.py` uses hand-rolled affine arithmetic and Python big-ints; it is **not** constant-time and is susceptible to timing side-channels. Reveal comparison already uses `hmac.compare_digest` (good). Document the ZKP timing caveat, and for high-assurance use offer an optional backend over a vetted constant-time library (kept optional so the zero-dependency default holds).
- **Nonce handling.** The Schnorr nonce is drawn per-proof from `secrets.randbelow` (a CSPRNG — good). Nonce reuse leaks the secret, so the review must confirm a fresh nonce per proof and add a deterministic **RFC 6979-style** mode for reproducibility without weakening randomness.
- **Domain separation** in the Fiat-Shamir challenge (bind the challenge hash to a protocol/version tag) to prevent cross-protocol replay.
- Independent security review / audit before advertising the ZKP path for value-bearing use.

### Test coverage
- Maintain the existing 90%+ coverage floor; extend property-based (Hypothesis) tests to cover ZKP soundness/completeness edge cases and malformed-point rejection.
- Add cross-implementation test vectors (shared with any on-chain verifier).

### Semantic versioning
- Strict semver: no breaking API changes without a major bump. Publish a deprecation policy. The `verify` alias and the exception surface (`ValidationError`, `SecurityError`) are part of the public contract.

### Typed API
- Ship `py.typed` and keep `mypy --strict` green (already configured). Tighten the ZKP return-type tuples into named types (`NamedTuple`/dataclass) so callers don't index by position.

### Documentation
- Keep `docs/` in step with the API. Add the on-chain-verifier recipe and the four 2026 use-case walkthroughs.

### CI
- CI on every push/PR: pytest + coverage gate, `mypy --strict`, `black --check`, `bandit`, and build+publish-on-tag to PyPI. Add supply-chain hygiene (pinned tooling, hash-checked lockfile) — cheap and high-trust.

---

*A note on honesty:* the ZKP path is a real, from-scratch Schnorr implementation and is excellent for learning, prototyping, and off-chain fairness. Before it guards real value, complete the crypto security review above. That candor is deliberate — see [SECURITY.md](SECURITY.md).
