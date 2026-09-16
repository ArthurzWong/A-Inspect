/**
 * Dependency-free base64 decode.
 *
 * Exists so the content rules can peek at encoded payloads identically in
 * Node and in the browser bundle. Decoding is used *only* to classify; the
 * decoded bytes are never executed (spec §9 R012).
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const LOOKUP = (() => {
  const t = new Int16Array(256).fill(-1);
  for (let i = 0; i < ALPHABET.length; i += 1) t[ALPHABET.charCodeAt(i)] = i;
  return t;
})();

/** Decode base64 to a latin1 string (byte-per-character). Invalid input → ''. */
export function decodeBase64(input) {
  const s = String(input ?? '').replace(/[^A-Za-z0-9+/=]/g, '');
  if (!s) return '';
  const clean = s.replace(/=+$/, '');
  const out = [];
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < clean.length; i += 1) {
    const v = LOOKUP[clean.charCodeAt(i)];
    if (v < 0) continue;
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  let result = '';
  for (let i = 0; i < out.length; i += 1) result += String.fromCharCode(out[i]);
  return result;
}

export function isProbablyBase64(text, minLength = 40) {
  const s = String(text ?? '');
  if (s.length < minLength) return false;
  return /^[A-Za-z0-9+/\s]+={0,2}$/.test(s);
}
