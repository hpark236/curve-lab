// Elliptic-curve arithmetic over a prime field, written out by hand with BigInt.
// Works for secp256k1 (y^2 = x^3 + 7) and for tiny toy curves used in the visualiser.

export const mod = (a, m) => { const r = a % m; return r >= 0n ? r : r + m; };

/** Modular inverse by the extended Euclidean algorithm. */
export function inv(a, m) {
  a = mod(a, m);
  if (a === 0n) throw new Error('no inverse of 0');
  let [r0, r1, s0, s1] = [m, a, 0n, 1n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error('not invertible');
  return mod(s0, m);
}

/** Square-and-multiply modular exponentiation. */
export function pow(b, e, m) {
  let r = 1n; b = mod(b, m);
  while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; }
  return r;
}

/** Build a short-Weierstrass curve y^2 = x^3 + a x + b over F_p with generator G of order n. */
export function curve({ p, a = 0n, b, G, n, name }) {
  const O = null; // the point at infinity
  const onCurve = P => P === O || mod(P.y * P.y - (P.x ** 3n + a * P.x + b), p) === 0n;
  const neg = P => P === O ? O : { x: P.x, y: mod(-P.y, p) };
  const eq = (P, Q) => P === Q || (P && Q && P.x === Q.x && P.y === Q.y);

  function add(P, Q) {
    if (P === O) return Q;
    if (Q === O) return P;
    if (P.x === Q.x && mod(P.y + Q.y, p) === 0n) return O; // P + (-P)
    const lam = eq(P, Q)
      ? mod((3n * P.x * P.x + a) * inv(2n * P.y, p), p) // tangent slope
      : mod((Q.y - P.y) * inv(Q.x - P.x, p), p); // chord slope
    const x = mod(lam * lam - P.x - Q.x, p);
    return { x, y: mod(lam * (P.x - x) - P.y, p) };
  }

  /** Double-and-add scalar multiplication k * P. */
  function mul(k, P = G) {
    k = n ? mod(k, n) : k;
    let R = O, A = P;
    while (k > 0n) { if (k & 1n) R = add(R, A); A = add(A, A); k >>= 1n; }
    return R;
  }

  /** Recover y from x and a parity bit, using p = 3 mod 4 (true for secp256k1). */
  function lift(x, odd) {
    const rhs = mod(x ** 3n + a * x + b, p);
    const y = pow(rhs, (p + 1n) / 4n, p);
    if (mod(y * y, p) !== rhs) return null;
    return { x, y: (y & 1n) === BigInt(odd ? 1 : 0) ? y : p - y };
  }

  return { p, a, b, G, n, name, O, onCurve, neg, eq, add, mul, lift };
}

export const secp256k1 = curve({
  name: 'secp256k1',
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  b: 7n,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  G: {
    x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
  },
});

// ---------- encoding helpers ----------
export const hex = (n, bytes = 32) => n.toString(16).padStart(bytes * 2, '0');
export const toBig = h => BigInt('0x' + (String(h).replace(/^0x/, '') || '0'));
export const bytesToHex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
export function hexToBytes(h) {
  h = String(h).replace(/^0x/, '');
  if (h.length % 2) h = '0' + h;
  return Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));
}
export const utf8 = s => new TextEncoder().encode(s);
export const concat = (...arrs) => { const out = new Uint8Array(arrs.reduce((a, b) => a + b.length, 0)); let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out; };
export const bigToBytes = (n, len = 32) => hexToBytes(hex(n, len));

/** SEC1 public key encoding. */
export const encodePoint = (P, compressed = true) =>
  compressed ? (P.y & 1n ? '03' : '02') + hex(P.x) : '04' + hex(P.x) + hex(P.y);
export function decodePoint(h, C = secp256k1) {
  h = h.replace(/^0x/, '');
  if (h.startsWith('04') && h.length === 130) return { x: toBig(h.slice(2, 66)), y: toBig(h.slice(66)) };
  if ((h.startsWith('02') || h.startsWith('03')) && h.length === 66) return C.lift(toBig(h.slice(2)), h.startsWith('03'));
  throw new Error('bad point encoding');
}

/** Cryptographically random scalar in [1, n-1]. */
export function randomScalar(n = secp256k1.n) {
  for (;;) {
    const b = crypto.getRandomValues(new Uint8Array(32));
    const k = toBig(bytesToHex(b));
    if (k > 0n && k < n) return k;
  }
}

/** Enumerate every point on a toy curve (only sensible for small p). */
export function allPoints(C) {
  const pts = [];
  for (let x = 0n; x < C.p; x++) for (let y = 0n; y < C.p; y++) if (C.onCurve({ x, y })) pts.push({ x, y });
  return pts;
}
