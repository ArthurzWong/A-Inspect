/**
 * AuditLogger (spec §20, §21) — tamper-evident hash chain.
 *
 * Each event's hash covers the previous event's hash, so modifying or
 * removing any historical event invalidates every hash after it.
 * `verify()` recomputes the whole chain and reports the first break.
 *
 * Payloads are deep-redacted before hashing, so a secret cannot enter the
 * ledger even transiently (spec §20: never store raw secrets).
 */

import { canonicalJson, sha256 } from './crypto/sha256.js';
import { redactDeep } from './redact.js';

export const GENESIS_HASH = '0'.repeat(64);

export function computeEventHash(event) {
  return sha256(canonicalJson({
    seq: event.seq,
    timestamp: event.timestamp,
    type: event.type,
    workspace_id: event.workspace_id,
    agent_id: event.agent_id,
    action_id: event.action_id,
    payload_hash: event.payload_hash,
    previous_hash: event.previous_hash,
  }));
}

/**
 * Create an append-only ledger.
 * @param {object} opts { workspaceId, agentId, now: () => ISO string }
 */
export function createAuditLog(opts = {}) {
  const workspaceId = opts.workspaceId ?? 'workspace_local';
  const agentId = opts.agentId ?? 'autoclaw';
  const clock = opts.now ?? (() => new Date().toISOString());
  const events = [];

  function append(type, payload = {}, meta = {}) {
    const redacted = redactDeep(payload);
    const previous = events.length ? events[events.length - 1].hash : GENESIS_HASH;
    const event = {
      seq: events.length + 1,
      timestamp: meta.timestamp ?? clock(),
      type,
      workspace_id: workspaceId,
      agent_id: meta.agentId ?? agentId,
      action_id: meta.actionId ?? payload.action_id ?? null,
      payload: redacted,
      payload_hash: sha256(canonicalJson(redacted)),
      previous_hash: previous,
      hash: null,
    };
    event.hash = computeEventHash(event);
    events.push(event);
    return event;
  }

  /**
   * Recompute the chain from genesis. Returns the first divergence.
   * A tampered ledger fails here — see tests/audit.test.js.
   */
  function verify() {
    let previous = GENESIS_HASH;
    for (let i = 0; i < events.length; i += 1) {
      const e = events[i];
      if (e.seq !== i + 1) {
        return { valid: false, brokenAt: i + 1, reason: `sequence gap: expected ${i + 1}, found ${e.seq}` };
      }
      if (e.previous_hash !== previous) {
        return { valid: false, brokenAt: i + 1, reason: 'previous_hash does not match the preceding event hash' };
      }
      const payloadHash = sha256(canonicalJson(e.payload));
      if (payloadHash !== e.payload_hash) {
        return { valid: false, brokenAt: i + 1, reason: 'payload was modified after it was written' };
      }
      const recomputed = computeEventHash(e);
      if (recomputed !== e.hash) {
        return { valid: false, brokenAt: i + 1, reason: 'event hash does not match its contents' };
      }
      previous = e.hash;
    }
    return { valid: true, brokenAt: null, reason: 'chain intact', length: events.length };
  }

  return {
    append,
    verify,
    events: () => events.slice(),
    length: () => events.length,
    head: () => (events.length ? events[events.length - 1].hash : GENESIS_HASH),
    toJSON: () => ({
      workspace_id: workspaceId,
      agent_id: agentId,
      genesis: GENESIS_HASH,
      head: events.length ? events[events.length - 1].hash : GENESIS_HASH,
      length: events.length,
      events: events.slice(),
    }),
    /** Rehydrate a ledger from serialized state (used by the CLI/report). */
    load(serialized) {
      events.length = 0;
      for (const e of serialized.events ?? []) events.push({ ...e });
      return verify();
    },
  };
}

/** Decision → audit event type (spec §21). */
export function eventTypeForDecision(decision) {
  switch (decision) {
    case 'ALLOW':
    case 'ALLOW_WITH_LOG':
      return 'ACTION_APPROVED';
    case 'SANDBOX_ONLY':
      return 'ACTION_APPROVAL_REQUESTED';
    case 'REQUIRE_APPROVAL':
      return 'ACTION_APPROVAL_REQUESTED';
    case 'DENY':
      return 'ACTION_BLOCKED';
    default:
      return 'ACTION_DETECTED';
  }
}
