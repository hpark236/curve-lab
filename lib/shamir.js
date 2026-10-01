// Shamir secret sharing over the prime field of the secp256k1 group order.
// A random polynomial f of degree t-1 with f(0) = secret; share i is (i, f(i)).
import { mod, inv, randomScalar, secp256k1 } from './ec.js';

export const P = secp256k1.n;

export function split(secret, t, count, rand = () => randomScalar(P)) {
  if (t < 2 || t > count) throw new Error('need 2 <= threshold <= shares');
  const coeffs = [mod(secret, P), ...Array.from({ length: t - 1 }, rand)];
  const f = x => coeffs.reduceRight((acc, c) => mod(acc * x + c, P), 0n); // Horner
  return Array.from({ length: count }, (_, i) => ({ x: BigInt(i + 1), y: f(BigInt(i + 1)) }));
}

/** Lagrange interpolation at x = 0. */
export function combine(shares) {
  let s = 0n;
  shares.forEach((si, i) => {
    let num = 1n, den = 1n;
    shares.forEach((sj, j) => { if (i !== j) { num = mod(num * -sj.x, P); den = mod(den * (si.x - sj.x), P); } });
    s = mod(s + si.y * num * inv(den, P), P);
  });
  return s;
}
