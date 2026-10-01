// Signatures on secp256k1: ECDSA (RFC 6979 nonces, Ethereum-style recovery) and BIP-340 Schnorr.
// SHA-256 and HMAC come from WebCrypto, available in every browser and in Node.
import { secp256k1 as C, mod, inv, hex, toBig, bytesToHex, hexToBytes, utf8, concat, bigToBytes, encodePoint } from './ec.js';
import { keccak256 } from './keccak.js';

const { n, G } = C;
const subtle = globalThis.crypto.subtle;

export const sha256 = async bytes => new Uint8Array(await subtle.digest('SHA-256', bytes));
export async function hmac(key, data) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}

// ---------- Ethereum helpers ----------
/** EIP-55 mixed-case checksum. */
export function checksum(addrHex) {
  const a = addrHex.toLowerCase().replace(/^0x/, '');
  const h = bytesToHex(keccak256(utf8(a)));
  return '0x' + [...a].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join('');
}
/** Address = last 20 bytes of keccak256(x || y). */
export const ethAddress = Q => checksum(bytesToHex(keccak256(hexToBytes(hex(Q.x) + hex(Q.y)))).slice(-40));
/** EIP-191 personal_sign hash, what MetaMask signs for a text message. */
export function personalHash(message) {
  const m = utf8(message);
  return keccak256(concat(utf8(`\x19Ethereum Signed Message:\n${m.length}`), m));
}

// ---------- ECDSA ----------
/** RFC 6979 deterministic nonce: k is derived from the key and the message, never from an RNG. */
export async function rfc6979(d, h1) {
  const x = bigToBytes(d), hm = bigToBytes(mod(toBig(bytesToHex(h1)), n));
  let V = new Uint8Array(32).fill(1), K = new Uint8Array(32).fill(0);
  K = await hmac(K, concat(V, [0], x, hm)); V = await hmac(K, V);
  K = await hmac(K, concat(V, [1], x, hm)); V = await hmac(K, V);
  for (;;) {
    V = await hmac(K, V);
    const k = toBig(bytesToHex(V));
    if (k > 0n && k < n) return k;
    K = await hmac(K, concat(V, [0])); V = await hmac(K, V);
  }
}

/**
 * Sign a 32-byte hash. Returns { r, s, v, k }.
 * `forceK` exists only for the nonce-reuse demonstration.
 */
export async function signHash(d, h, { forceK = null, lowS = true } = {}) {
  const z = mod(toBig(bytesToHex(h)), n);
  const k = forceK ?? await rfc6979(d, h);
  const R = C.mul(k);
  const r = mod(R.x, n);
  let s = mod(inv(k, n) * (z + r * d), n);
  let recid = Number(R.y & 1n) | (R.x >= n ? 2 : 0);
  if (lowS && s > n / 2n) { s = n - s; recid ^= 1; } // Ethereum and Bitcoin reject high-s
  if (r === 0n || s === 0n) throw new Error('retry with another k');
  return { r, s, v: 27 + recid, recid, k, z };
}

export function verifyHash(Q, h, { r, s }) {
  if (!(r > 0n && r < n && s > 0n && s < n)) return false;
  const z = mod(toBig(bytesToHex(h)), n);
  const w = inv(s, n);
  const P = C.add(C.mul(mod(z * w, n)), C.mul(mod(r * w, n), Q));
  return P !== null && mod(P.x, n) === r;
}

/** ecrecover: the public key that produced (r, s) over hash h, given the recovery id. */
export function recover(h, { r, s, v }) {
  const recid = (v >= 27 ? v - 27 : v) & 3;
  const x = r + (recid & 2 ? n : 0n);
  const R = C.lift(x, recid & 1);
  if (!R) throw new Error('r is not an x-coordinate on the curve');
  const z = mod(toBig(bytesToHex(h)), n);
  const ri = inv(r, n);
  // Q = r^-1 (sR - zG)
  return C.add(C.mul(mod(s * ri, n), R), C.mul(mod(-z * ri, n)));
}

/** 65-byte r||s||v hex, the format wallets return. */
export const sigHex = ({ r, s, v }) => '0x' + hex(r) + hex(s) + v.toString(16).padStart(2, '0');
export function parseSig(h) {
  h = h.trim().replace(/^0x/, '');
  if (h.length !== 130) throw new Error('expected 65 bytes (130 hex chars)');
  return { r: toBig(h.slice(0, 64)), s: toBig(h.slice(64, 128)), v: parseInt(h.slice(128), 16) };
}

/**
 * The nonce-reuse attack. Two signatures that share k share r, and
 *   s1 - s2 = k^-1 (z1 - z2)  =>  k = (z1 - z2) / (s1 - s2)
 *   d = (s1 k - z1) / r
 * Signatures are low-s normalised, so each s may have been negated: try the four sign combinations.
 */
export function recoverFromReusedNonce(a, b, Q = null) {
  if (a.r !== b.r) throw new Error('different r: these signatures did not reuse a nonce');
  for (const s1 of [a.s, n - a.s]) for (const s2 of [b.s, n - b.s]) {
    if (s1 === s2) continue;
    const k = mod((a.z - b.z) * inv(s1 - s2, n), n);
    const d = mod((s1 * k - a.z) * inv(a.r, n), n);
    if (!Q || C.eq(C.mul(d), Q)) return { k, d };
  }
  return null;
}

// ---------- BIP-340 Schnorr ----------
async function taggedHash(tag, ...msgs) {
  const t = await sha256(utf8(tag));
  return sha256(concat(t, t, ...msgs));
}
const hasEvenY = P => (P.y & 1n) === 0n;
export const xOnly = P => bigToBytes(P.x);

export async function schnorrSign(d0, msg, aux = new Uint8Array(32)) {
  const P = C.mul(d0);
  const d = hasEvenY(P) ? d0 : n - d0;
  const t = bigToBytes(d ^ toBig(bytesToHex(await taggedHash('BIP0340/aux', aux))));
  const k0 = mod(toBig(bytesToHex(await taggedHash('BIP0340/nonce', t, xOnly(P), msg))), n);
  if (k0 === 0n) throw new Error('k is zero');
  const R = C.mul(k0);
  const k = hasEvenY(R) ? k0 : n - k0;
  const e = mod(toBig(bytesToHex(await taggedHash('BIP0340/challenge', xOnly(R), xOnly(P), msg))), n);
  return concat(xOnly(R), bigToBytes(mod(k + e * d, n)));
}

export async function schnorrVerify(pubX, msg, sig) {
  const P = C.lift(toBig(bytesToHex(pubX)), false);
  if (!P) return false;
  const r = toBig(bytesToHex(sig.slice(0, 32))), s = toBig(bytesToHex(sig.slice(32)));
  if (r >= C.p || s >= n) return false;
  const e = mod(toBig(bytesToHex(await taggedHash('BIP0340/challenge', sig.slice(0, 32), pubX, msg))), n);
  const R = C.add(C.mul(s), C.mul(n - e, P)); // R = sG - eP
  return R !== null && hasEvenY(R) && R.x === r;
}

export { encodePoint };
