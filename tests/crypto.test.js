import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import { sha256, hmacSha256, canonicalJson, timingSafeEqual, utf8Bytes } from '../src/engine/crypto/sha256.js';

const CASES = [
  { name: 'empty', input: '' },
  { name: 'abc', input: 'abc' },
  { name: 'exactly 55 bytes', input: 'a'.repeat(55) },
  { name: 'exactly 56 bytes (padding boundary)', input: 'a'.repeat(56) },
  { name: 'exactly 63 bytes', input: 'a'.repeat(63) },
  { name: 'exactly 64 bytes (one full block)', input: 'a'.repeat(64) },
  { name: '65 bytes', input: 'a'.repeat(65) },
  { name: '120 bytes', input: 'a'.repeat(120) },
  { name: '10k bytes', input: 'x'.repeat(10000) },
  { name: '100k bytes', input: 'y'.repeat(100000) },
  { name: 'multibyte utf8', input: 'héllo wörld ✓ 日本語 🎯' },
  { name: 'newlines', input: 'line1\nline2\r\nline3\n' },
];

test('sha256 matches node:crypto for every length boundary', () => {
  for (const c of CASES) {
    const mine = sha256(c.input);
    const ref = createHash('sha256').update(c.input, 'utf8').digest('hex');
    assert.equal(mine, ref, `mismatch for case: ${c.name}`);
  }
});

test('sha256 known vector', () => {
  assert.equal(sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('hmacSha256 matches node:crypto including long keys', () => {
  const vectors = [
    ['key', 'message'],
    ['secret', '{"a":1}'],
    ['k'.repeat(200), 'long key is hashed first'],
    ['', 'empty key'],
    ['k', ''],
  ];
  for (const [key, msg] of vectors) {
    assert.equal(hmacSha256(key, msg), createHmac('sha256', key).update(msg).digest('hex'));
  }
});

test('sha256 is incremental and stateless across calls', () => {
  const a = sha256('hello ');
  const b = sha256('world');
  assert.notEqual(a, b);
  assert.equal(sha256('hello '), a, 'repeat call must be stable');
});

test('utf8Bytes handles surrogate pairs', () => {
  const bytes = utf8Bytes('🎯');
  assert.equal(bytes.length, 4);
});

test('canonicalJson is key-order independent', () => {
  const a = canonicalJson({ b: 1, a: 2, c: { z: 1, y: [3, 2] } });
  const b = canonicalJson({ c: { y: [3, 2], z: 1 }, a: 2, b: 1 });
  assert.equal(a, b);
  assert.equal(sha256(a), sha256(b));
});

test('canonicalJson distinguishes different values', () => {
  assert.notEqual(canonicalJson({ a: 1 }), canonicalJson({ a: '1' }));
});

test('timingSafeEqual compares without short-circuiting on length', () => {
  assert.equal(timingSafeEqual('abc', 'abc'), true);
  assert.equal(timingSafeEqual('abc', 'abd'), false);
  assert.equal(timingSafeEqual('abc', 'abcd'), false);
  assert.equal(timingSafeEqual('', ''), true);
});
