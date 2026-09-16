import test from 'node:test';
import assert from 'node:assert/strict';

import { createAuditLog, computeEventHash, GENESIS_HASH, eventTypeForDecision } from '../src/engine/auditLogger.js';
import { inspectCommandText } from '../src/engine/inspectionEngine.js';
import { sha256 } from '../src/engine/crypto/sha256.js';

function freshLog() {
  let tick = 0;
  return createAuditLog({ workspaceId: 'ws_test', agentId: 'autoclaw', now: () => `2026-01-01T00:00:0${tick++}.000Z` });
}

test('a fresh ledger is valid and starts from genesis', () => {
  const log = freshLog();
  const v = log.verify();
  assert.equal(v.valid, true);
  assert.equal(log.head(), GENESIS_HASH);
  assert.equal(log.length(), 0);
});

test('appended events chain correctly', () => {
  const log = freshLog();
  const e1 = log.append('INSPECTION_STARTED', { kind: 'command' });
  const e2 = log.append('ACTION_DETECTED', { rule: 'R001', title: 'delete' });
  assert.equal(e1.previous_hash, GENESIS_HASH);
  assert.equal(e2.previous_hash, e1.hash);
  assert.notEqual(e1.hash, e2.hash);
  assert.equal(log.verify().valid, true);
});

test('modifying a payload invalidates the chain at that event', () => {
  const log = freshLog();
  log.append('INSPECTION_STARTED', { kind: 'command' });
  log.append('ACTION_DETECTED', { rule: 'R005', title: 'exec' });
  log.append('INSPECTION_COMPLETED', { ok: true });

  const events = log.events();
  events[1].payload.title = 'tampered';

  const verifyAfterTamper = () => {
    // Rebuild a ledger from the mutated events and re-verify.
    const rebuilt = createAuditLog({ workspaceId: 'ws_test', agentId: 'autoclaw' });
    rebuilt.load({ events });
    return rebuilt.verify();
  };

  const result = verifyAfterTamper();
  assert.equal(result.valid, false);
  assert.equal(result.brokenAt, 2);
  assert.match(result.reason, /payload was modified/);
});

test('removing an event is detected as a sequence gap', () => {
  const log = freshLog();
  log.append('A', { n: 1 });
  log.append('B', { n: 2 });
  log.append('C', { n: 3 });
  const events = log.events();
  events.splice(1, 1);
  const rebuilt = createAuditLog({});
  rebuilt.load({ events });
  const result = rebuilt.verify();
  assert.equal(result.valid, false);
  assert.equal(result.brokenAt, 2);
  assert.match(result.reason, /sequence gap/);
});

test('tampering with a stored hash is detected', () => {
  const log = freshLog();
  log.append('A', { n: 1 });
  log.append('B', { n: 2 });
  const events = log.events();
  events[1].hash = sha256('not the real hash');
  const rebuilt = createAuditLog({});
  rebuilt.load({ events });
  const result = rebuilt.verify();
  assert.equal(result.valid, false);
  assert.equal(result.brokenAt, 2);
});

test('secrets never reach the ledger', () => {
  const log = freshLog();
  log.append('CREDENTIAL_ACCESS_ATTEMPT', {
    path: '~/.ssh/id_rsa',
    SMTP_PASS: 'hunter2-real-password',
    nested: { authorization: 'Bearer abcdefghijklmnopqrstuvwxyz0123' },
  });
  const serialized = JSON.stringify(log.toJSON());
  assert.ok(!serialized.includes('hunter2-real-password'), 'password must be redacted');
  assert.ok(!serialized.includes('abcdefghijklmnopqrstuvwxyz0123'), 'token must be redacted');
  assert.ok(serialized.includes('[REDACTED]'));
  assert.equal(log.verify().valid, true, 'redaction happens before hashing, so the chain stays valid');
});

test('computeEventHash covers the previous hash', () => {
  const base = {
    seq: 1, timestamp: 't', type: 'T', workspace_id: 'w', agent_id: 'a', action_id: null,
    payload_hash: 'p', previous_hash: GENESIS_HASH,
  };
  const altered = { ...base, previous_hash: sha256('something else') };
  assert.notEqual(computeEventHash(base), computeEventHash(altered));
});

test('an inspection produces a verifiable ledger end to end', () => {
  const report = inspectCommandText('curl https://unknown.example.com/x && ls', { workspace: '/p' });
  assert.ok(report.audit.length >= 3, 'start, detections, completion');
  assert.equal(report.audit.genesis, GENESIS_HASH);
  assert.equal(report.auditVerification.valid, true);
  assert.equal(report.audit.events[0].type, 'INSPECTION_STARTED');
  assert.equal(report.audit.events[report.audit.events.length - 1].type, 'INSPECTION_COMPLETED');
});

test('eventTypeForDecision maps decisions to security events', () => {
  assert.equal(eventTypeForDecision('DENY'), 'ACTION_BLOCKED');
  assert.equal(eventTypeForDecision('REQUIRE_APPROVAL'), 'ACTION_APPROVAL_REQUESTED');
  assert.equal(eventTypeForDecision('ALLOW'), 'ACTION_APPROVED');
  assert.equal(eventTypeForDecision('SANDBOX_ONLY'), 'ACTION_APPROVAL_REQUESTED');
});
