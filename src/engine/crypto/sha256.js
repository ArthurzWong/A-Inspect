/**
 * Dependency-free SHA-256 + HMAC-SHA256.
 *
 * Used for (a) the tamper-evident audit ledger hash chain and (b) GitHub
 * webhook signature validation. Implemented here rather than importing
 * `node:crypto` so the exact same code runs in Node and in the browser
 * bundle, which keeps the verification story honest: the hash you check
 * in the CLI is produced by the same bytes the console produces.
 *
 * This is standard FIPS 180-4 SHA-256. `tests/sha256.test.js` cross-checks
 * every digest against `node:crypto`.
 */

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const BLOCK = 64;

export function utf8Bytes(input) {
  if (input instanceof Uint8Array) return input;
  const s = String(input);
  const out = [];
  for (let i = 0; i < s.length; i += 1) {
    let c = s.codePointAt(i);
    if (c > 0xffff) i += 1; // surrogate pair consumed
    if (c < 0x80) {
      out.push(c);
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c < 0x10000) {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else {
      out.push(
        0xf0 | (c >> 18),
        0x80 | ((c >> 12) & 0x3f),
        0x80 | ((c >> 6) & 0x3f),
        0x80 | (c & 0x3f),
      );
    }
  }
  return new Uint8Array(out);
}

export function toHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 1) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

/** Incremental SHA-256 over raw bytes. */
class Sha256 {
  constructor() {
    this.h = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    this.buffer = new Uint8Array(BLOCK);
    this.bufferLen = 0;
    this.totalBytes = 0;
    this.finished = false;
  }

  update(data) {
    const bytes = utf8Bytes(data);
    this.totalBytes += bytes.length;
    let offset = 0;
    if (this.bufferLen > 0) {
      while (offset < bytes.length && this.bufferLen < BLOCK) {
        this.buffer[this.bufferLen++] = bytes[offset++];
      }
      if (this.bufferLen === BLOCK) {
        this.#compress(this.buffer, 0);
        this.bufferLen = 0;
      }
    }
    while (offset + BLOCK <= bytes.length) {
      this.#compress(bytes, offset);
      offset += BLOCK;
    }
    while (offset < bytes.length) {
      this.buffer[this.bufferLen++] = bytes[offset++];
    }
    return this;
  }

  #compress(chunk, offset) {
    const w = new Uint32Array(64);
    for (let i = 0; i < 16; i += 1) {
      const j = offset + i * 4;
      w[i] = ((chunk[j] << 24) | (chunk[j + 1] << 16) | (chunk[j + 2] << 8) | chunk[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = this.h;
    for (let i = 0; i < 64; i += 1) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    this.h[0] = (this.h[0] + a) >>> 0;
    this.h[1] = (this.h[1] + b) >>> 0;
    this.h[2] = (this.h[2] + c) >>> 0;
    this.h[3] = (this.h[3] + d) >>> 0;
    this.h[4] = (this.h[4] + e) >>> 0;
    this.h[5] = (this.h[5] + f) >>> 0;
    this.h[6] = (this.h[6] + g) >>> 0;
    this.h[7] = (this.h[7] + h) >>> 0;
  }

  digestBytes() {
    const bitLenHi = Math.floor((this.totalBytes * 8) / 0x100000000);
    const bitLenLo = (this.totalBytes * 8) >>> 0;
    // Pad to the next 64-byte block boundary: message + 0x80 + zeros + 8-byte length.
    const paddedLength = Math.ceil((this.bufferLen + 1 + 8) / BLOCK) * BLOCK;
    const padded = new Uint8Array(paddedLength);
    padded.set(this.buffer.subarray(0, this.bufferLen), 0);
    padded[this.bufferLen] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, bitLenHi, false);
    dv.setUint32(padded.length - 4, bitLenLo, false);
    for (let off = 0; off < padded.length; off += BLOCK) this.#compress(padded, off);
    const out = new Uint8Array(32);
    const ov = new DataView(out.buffer);
    for (let i = 0; i < 8; i += 1) ov.setUint32(i * 4, this.h[i], false);
    this.finished = true;
    return out;
  }

  digest() {
    return toHex(this.digestBytes());
  }
}

export function sha256(data) {
  return new Sha256().update(data).digest();
}

export function sha256Bytes(data) {
  return new Sha256().update(data).digestBytes();
}

/** HMAC-SHA256 (RFC 2104). Returns hex. */
export function hmacSha256(key, message) {
  let k = utf8Bytes(key);
  if (k.length > BLOCK) k = sha256Bytes(k);
  const pad = new Uint8Array(BLOCK);
  pad.set(k, 0);
  const oKey = new Uint8Array(BLOCK);
  const iKey = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i += 1) {
    oKey[i] = pad[i] ^ 0x5c;
    iKey[i] = pad[i] ^ 0x36;
  }
  const inner = new Sha256().update(iKey).update(message).digestBytes();
  return new Sha256().update(oKey).update(inner).digest();
}

export function sha256HexOfHex(hex) {
  return sha256(String(hex));
}

/**
 * Constant-time-ish string compare. Used for webhook signature checks so a
 * near-miss does not leak how many leading characters matched.
 */
export function timingSafeEqual(a, b) {
  const x = String(a);
  const y = String(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i += 1) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

/** Stable canonical JSON — key order independent, so hashes are reproducible. */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}
