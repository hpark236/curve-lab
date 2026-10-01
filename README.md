# Curve Lab

The cryptography under Bitcoin and Ethereum, written from first principles in plain JavaScript `BigInt` and run live in the browser. No crypto libraries.

**Live:** https://secp-lab.vercel.app

## Experiments

1. **Finite-curve point addition.** Every point of y² = x³ + 7 over F₉₇ / F₂₁₁, click-to-add with the wrapped chord drawn, k·P walks and point orders.
2. **Keypair to Ethereum address.** d·G by double-and-add, SEC1 encoding, Keccak-256 from the spec, EIP-55 checksum.
3. **Sign, verify, recover.** EIP-191 `personal_sign` hashing, RFC 6979 deterministic nonces, low-s normalisation, `ecrecover`. Paste a real MetaMask signature and it returns the signing address.
4. **Nonce-reuse attack.** Two signatures sharing k leak the private key: k = (z₁ − z₂)/(s₁ − s₂), d = (s₁k − z₁)/r. The solver handles low-s sign flips. (Sony PS3, 2010; Android SecureRandom, 2013.)
5. **BIP-340 Schnorr.** Tagged hashes, x-only keys, even-y normalisation.
6. **Shamir 3-of-5.** Split a key over the secp256k1 group order, rebuild with Lagrange interpolation, and watch two shares produce nothing.

## Code

```
lib/ec.js       field inverse (extended Euclid), modpow, curve add/double/mul, point lift and SEC1 encoding
lib/keccak.js   Keccak-f[1600] with the original (Ethereum) padding
lib/sigs.js     RFC 6979, ECDSA sign/verify/recover, nonce-reuse solver, BIP-340
lib/shamir.js   polynomial split and Lagrange combine
test/           10 tests
```

## Verified against

- OpenSSL via Node's `crypto`: our public keys match `createECDH('secp256k1')`; OpenSSL verifies our signatures and we verify OpenSSL's.
- Keccak-256 known digests, the EIP-55 spec example, addresses for d = 1 and d = 2.
- The official BIP-340 test vector 0.

```bash
npm test
```

For learning, not custody: BigInt arithmetic is not constant-time.
