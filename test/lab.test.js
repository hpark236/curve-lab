import test from 'node:test';
import assert from 'node:assert/strict';
import nodeCrypto from 'node:crypto';
import { secp256k1 as C, curve, hex, toBig, bytesToHex, hexToBytes, utf8, encodePoint, decodePoint, randomScalar, allPoints, inv, mod } from '../lib/ec.js';
import { keccak256 } from '../lib/keccak.js';
import { ethAddress, checksum, personalHash, signHash, verifyHash, recover, rfc6979, recoverFromReusedNonce, schnorrSign, schnorrVerify, xOnly, sigHex, parseSig, sha256 } from '../lib/sigs.js';
import { split, combine } from '../lib/shamir.js';

test('field inverse and group order', () => {
  for (const a of [2n, 3n, 12345678901234567890n]) assert.equal(mod(a * inv(a, C.p), C.p), 1n);
  assert.equal(C.mul(C.n), null, 'n * G is the point at infinity');
  assert.ok(C.onCurve(C.mul(0xdeadbeefn)));
});

test('public keys match Node\'s own secp256k1 (OpenSSL)', () => {
  for (let i = 0; i < 5; i++) {
    const d = randomScalar();
    const ecdh = nodeCrypto.createECDH('secp256k1');
    ecdh.setPrivateKey(hexToBytes(hex(d)));
    assert.equal(encodePoint(C.mul(d), false), ecdh.getPublicKey('hex', 'uncompressed'));
    assert.equal(encodePoint(C.mul(d), true), ecdh.getPublicKey('hex', 'compressed'));
    assert.ok(C.eq(decodePoint(encodePoint(C.mul(d), true)), C.mul(d)));
  }
});

test('keccak256 known vectors', () => {
  assert.equal(bytesToHex(keccak256(new Uint8Array())), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(bytesToHex(keccak256(utf8('hello'))), '1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8');
  // multi-block input (> 136-byte rate)
  const long = utf8('a'.repeat(200));
  assert.equal(keccak256(long).length, 32);
  assert.notEqual(bytesToHex(keccak256(long)), bytesToHex(keccak256(utf8('a'.repeat(199)))));
});

test('Ethereum addresses', () => {
  assert.equal(ethAddress(C.mul(1n)), '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf');
  assert.equal(ethAddress(C.mul(2n)), '0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF');
  assert.equal(checksum('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359'), '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359'); // EIP-55 example
});

test('ECDSA signatures verify under OpenSSL, and ours verify OpenSSL\'s', async () => {
  const d = randomScalar(), Q = C.mul(d);
  const jwk = { kty: 'EC', crv: 'secp256k1', x: Buffer.from(hex(Q.x), 'hex').toString('base64url'), y: Buffer.from(hex(Q.y), 'hex').toString('base64url'), d: Buffer.from(hex(d), 'hex').toString('base64url') };
  const priv = nodeCrypto.createPrivateKey({ key: jwk, format: 'jwk' });
  const pub = nodeCrypto.createPublicKey(priv);
  const msg = utf8('gm token2049');
  const h = await sha256(msg);
  const sig = await signHash(d, h);
  const der = nodeCrypto.verify('sha256', msg, { key: pub, dsaEncoding: 'ieee-p1363' }, Buffer.from(hex(sig.r) + hex(sig.s), 'hex'));
  assert.ok(der, 'OpenSSL accepts our signature');
  const theirs = nodeCrypto.sign('sha256', msg, { key: priv, dsaEncoding: 'ieee-p1363' });
  assert.ok(verifyHash(Q, h, { r: toBig(theirs.subarray(0, 32).toString('hex')), s: toBig(theirs.subarray(32).toString('hex')) }), 'we accept OpenSSL\'s');
  assert.ok(!verifyHash(Q, await sha256(utf8('tampered')), sig));
});

test('RFC 6979 is deterministic and recovery returns the signer', async () => {
  const d = 0x1n, h = personalHash('hello');
  assert.equal(await rfc6979(d, h), await rfc6979(d, h));
  for (let i = 0; i < 4; i++) {
    const k = randomScalar(), Q = C.mul(k), hh = personalHash('msg ' + i);
    const sig = await signHash(k, hh);
    assert.ok(sig.s <= C.n / 2n, 'low-s');
    assert.ok(C.eq(recover(hh, parseSig(sigHex(sig))), Q));
  }
});

test('nonce reuse leaks the private key', async () => {
  const d = randomScalar(), Q = C.mul(d), k = randomScalar();
  const a = await signHash(d, personalHash('first'), { forceK: k });
  const b = await signHash(d, personalHash('second'), { forceK: k });
  const out = recoverFromReusedNonce(a, b, Q);
  assert.equal(out.d, d);
  assert.equal(out.k === k || out.k === C.n - k, true);
});

test('BIP-340 Schnorr official vector 0 and round trips', async () => {
  const sig = await schnorrSign(3n, new Uint8Array(32), new Uint8Array(32));
  assert.equal(bytesToHex(sig).toUpperCase(), 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0');
  assert.equal(bytesToHex(xOnly(C.mul(3n))).toUpperCase(), 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9');
  const d = randomScalar(), m = await sha256(utf8('schnorr'));
  const s2 = await schnorrSign(d, m, crypto.getRandomValues(new Uint8Array(32)));
  assert.ok(await schnorrVerify(xOnly(C.mul(d)), m, s2));
  s2[63] ^= 1;
  assert.ok(!(await schnorrVerify(xOnly(C.mul(d)), m, s2)));
});

test('Shamir: any t shares rebuild the secret, t-1 do not', () => {
  const secret = randomScalar();
  const shares = split(secret, 3, 5);
  assert.equal(combine([shares[0], shares[2], shares[4]]), secret);
  assert.equal(combine([shares[4], shares[1], shares[3]]), secret);
  assert.notEqual(combine([shares[0], shares[1]]), secret);
});

test('toy curve over F_97 forms a group', () => {
  const T = curve({ p: 97n, b: 7n, G: { x: 1n, y: 28n } });
  assert.ok(T.onCurve(T.G));
  const pts = allPoints(T);
  const P = pts[3], Q = pts[10];
  assert.ok(T.eq(T.add(P, Q), T.add(Q, P)));
  assert.ok(T.onCurve(T.add(P, Q)));
});
