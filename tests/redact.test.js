import test from 'node:test';
import assert from 'node:assert/strict';

import { redactString, redactDeep, looksLikeSecret, REDACTED } from '../src/engine/redact.js';
import { inspectCommandText } from '../src/engine/inspectionEngine.js';

test('redacts provider token shapes', () => {
  const samples = [
    'sk-abcdefghijklmnopqrstuvwx',
    'ghp_abcdefghijklmnopqrstuvwx',
    'xoxb-1234567890-abcdefghij',
    'AKIAIOSFODNN7EXAMPLE',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  ];
  for (const s of samples) {
    const out = redactString(`value=${s}`);
    assert.ok(!out.includes(s), `must redact: ${s}`);
    assert.ok(out.includes(REDACTED));
  }
});

test('redacts credential assignments but keeps the key name', () => {
  const out = redactString('SMTP_PASS=supersecretvalue123');
  assert.ok(out.includes('SMTP_PASS'));
  assert.ok(!out.includes('supersecretvalue123'));
});

test('redacts inline URL credentials', () => {
  const out = redactString('https://user:password@internal.example.com/api');
  assert.ok(!out.includes('password'));
  assert.ok(out.includes('internal.example.com'));
});

test('redacts PEM private keys entirely', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\n-----END RSA PRIVATE KEY-----';
  const out = redactString(`key: ${pem}`);
  assert.ok(!out.includes('MIIEowIBAAKCAQEA1234'));
});

test('redaction is idempotent', () => {
  const once = redactString('API_KEY=abcdefghijklmnop');
  const twice = redactString(once);
  assert.equal(once, twice);
});

test('placeholders are preserved rather than mangled', () => {
  for (const value of ['your-token-here', '${SMTP_PASS}', 'changeme', '<api key>', '']) {
    const out = redactString(`SMTP_PASS=${value}`);
    assert.ok(!out.includes(REDACTED) || value === '', `placeholder ${value} should not be redacted`);
  }
});

test('redactDeep removes secret-named keys at any depth', () => {
  const input = {
    ok: 'value',
    password: 'real-password',
    nested: { token: 'real-token', list: [{ secret: 'real-secret' }] },
  };
  const out = redactDeep(input);
  assert.equal(out.ok, 'value');
  assert.equal(out.password, REDACTED);
  assert.equal(out.nested.token, REDACTED);
  assert.equal(out.nested.list[0].secret, REDACTED);
});

test('looksLikeSecret distinguishes placeholders from values', () => {
  assert.equal(looksLikeSecret('${SMTP_PASS}'), false);
  assert.equal(looksLikeSecret('abc'), false);
  assert.equal(looksLikeSecret('ghp_abcdefghijklmnopqrstuvwx'), true);
});

test('a scanned command never leaks a secret value into the report', () => {
  const report = inspectCommandText('export API_KEY=ghp_abcdefghijklmnopqrstuvwx && echo done', { workspace: '/p' });
  const serialized = JSON.stringify(report);
  assert.ok(!serialized.includes('ghp_abcdefghijklmnopqrstuvwx'), 'the token must not appear anywhere in the report');
});

test('the report states that only names, not values, are read', () => {
  const report = inspectCommandText('cat ~/.ssh/id_rsa', { workspace: '/p' });
  const r003 = report.findings.filter((f) => f.rule === 'R003');
  assert.ok(r003.length >= 1);
  assert.ok(JSON.stringify(r003).includes('REDACTED'));
});
