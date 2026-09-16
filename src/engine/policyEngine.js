/**
 * PolicyEngine (spec §8, §9, §18, §28).
 *
 * This is the authorization boundary. The LLM may explain a finding; it
 * never decides. Every decision produced here is a pure function of
 * (ActionRequest, policy, findings) — no model, no randomness, no network.
 *
 * Fail-closed is implemented as a first-class branch, not as an afterthought:
 * if the action cannot be classified with confidence, the decision is
 * REQUIRE_APPROVAL, and for destructive shapes with unknown scope it is DENY.
 */

import { canonicalJson, sha256 } from './crypto/sha256.js';
import {
  CAPABILITY,
  DECISION,
  DECISION_RANK,
  SEVERITY,
} from './schema.js';
import { READ_ONLY_PROGRAMS } from './normalizer.js';

/* ------------------------------------------------------------------ *
 * Default policy
 * ------------------------------------------------------------------ */

export const DEFAULT_POLICY = {
  id: 'workspace-safe-v1',
  name: 'Workspace safe',
  version: 1,
  description: 'Default posture: workspace-scoped writes, no network unless allowlisted, no persistence, no host credentials.',
  filesystem: { mode: 'workspace-only', allow: [], deny: [] },
  network: { mode: 'deny', allowlist: [] },
  exec: { mode: 'allowlist', commands: [] },
  credentials: { mode: 'deny' },
  packageInstall: { mode: 'require-approval' },
  gitWrite: { mode: 'require-approval' },
  cloud: { mode: 'require-approval' },
  persistence: { mode: 'deny' },
  sandbox: { required: true, provider: 'docker' },
  unknown: { decision: DECISION.REQUIRE_APPROVAL },
  destructive: { projectLocal: DECISION.REQUIRE_APPROVAL, outside: DECISION.DENY },
};

export const PERMISSIVE_POLICY = {
  ...DEFAULT_POLICY,
  id: 'developer-local-v1',
  name: 'Developer local',
  description: 'Local development posture: project writes allowed, approved domains only, still no persistence and no privilege escalation.',
  network: { mode: 'allowlist', allowlist: ['github.com', 'registry.npmjs.org', 'pypi.org', 'docs.openclaw.ai', 'example.com'] },
  exec: { mode: 'allowlist', commands: ['node', 'npm', 'bash', 'sh', 'git', 'curl'] },
  packageInstall: { mode: 'require-approval' },
  sandbox: { required: false, provider: 'none' },
};

/* ------------------------------------------------------------------ *
 * Evaluation
 * ------------------------------------------------------------------ */

/** Merge the strictest decision. DENY beats everything; ALLOW loses to all. */
export function strictest(decisions) {
  let best = DECISION.ALLOW;
  for (const d of decisions) {
    if (!d) continue;
    if (DECISION_RANK[d] > DECISION_RANK[best]) best = d;
  }
  return best;
}

/**
 * @param {object} request   normalized ActionRequest (spec §8)
 * @param {object} policy    policy document
 * @param {object} context   { findings, capabilities, sandboxAvailable, knownFiles }
 */
export function evaluate(request, policy = DEFAULT_POLICY, context = {}) {
  const findings = context.findings ?? [];
  const reasons = [];
  const matchedRules = [];
  const decisions = [];
  let failClosed = false;

  /* 1. Rule defaults come first: they encode what the detectors believe. */
  for (const f of findings) {
    if (!f.defaultDecision) continue;
    decisions.push(f.defaultDecision);
    matchedRules.push({ rule: f.rule, title: f.title, decision: f.defaultDecision, severity: f.severity });
    reasons.push(`${f.rule}: ${f.title} → ${f.defaultDecision}`);
  }

  /* 2. Policy overrides, computed from the capability set. */
  const capabilities = new Set((context.capabilities ?? []).map((c) => c.capabilityType));
  const cmd = String(request.command ?? '');
  const argsText = (request.arguments ?? []).join(' ');
  const scopeHint = request.scope_hint ?? 'unknown';

  // --- credentials
  if (capabilities.has(CAPABILITY.CRED_READ) || capabilities.has(CAPABILITY.CLOUD_SECRET)) {
    if (policy.credentials?.mode === 'deny') {
      decisions.push(DECISION.DENY);
      reasons.push('policy.credentials=deny and the action reads credential-shaped material');
    } else {
      decisions.push(DECISION.REQUIRE_APPROVAL);
      reasons.push('credential access always requires approval');
    }
  }

  // --- filesystem scope
  const touchesOutside = (request.filesystem?.delete ?? []).some((p) => !isLocal(p))
    || (request.filesystem?.write ?? []).some((p) => !isLocal(p));
  if (touchesOutside) {
    if (scopeHint === 'system') {
      decisions.push(policy.destructive?.outside ?? DECISION.DENY);
      reasons.push('the action writes or deletes outside the workspace');
    } else {
      decisions.push(DECISION.REQUIRE_APPROVAL);
      reasons.push(`filesystem mode is ${policy.filesystem?.mode ?? 'workspace-only'} and this action reaches outside it`);
    }
  }
  if ((request.filesystem?.delete ?? []).length) {
    const localOnly = (request.filesystem.delete ?? []).every(isLocal);
    decisions.push(localOnly
      ? (policy.destructive?.projectLocal ?? DECISION.REQUIRE_APPROVAL)
      : (policy.destructive?.outside ?? DECISION.DENY));
    reasons.push(localOnly ? 'project-local deletion' : 'deletion outside the project');
  }

  // --- network
  const hasNetwork = capabilities.has(CAPABILITY.NET_CONNECT)
    || capabilities.has(CAPABILITY.NET_EGRESS)
    || capabilities.has(CAPABILITY.NET_LISTEN);
  if (hasNetwork) {
    const mode = policy.network?.mode ?? 'deny';
    if (mode === 'deny') {
      decisions.push(capabilities.has(CAPABILITY.NET_LISTEN) ? DECISION.SANDBOX_ONLY : DECISION.DENY);
      reasons.push('policy.network=deny');
    } else {
      const targets = request.network?.targets ?? [];
      const allowed = (policy.network?.allowlist ?? []);
      const allAllowed = targets.length > 0 && targets.every((t) => allowed.some((d) => String(t).includes(d)));
      if (!allAllowed) {
        decisions.push(DECISION.REQUIRE_APPROVAL);
        reasons.push('network allowlist is enabled and not every destination is on it');
      }
    }
  }

  // --- exec allowlist
  if (capabilities.has(CAPABILITY.PROC_EXECUTE) || capabilities.has(CAPABILITY.PROC_SPAWN)) {
    const mode = policy.exec?.mode ?? 'allowlist';
    if (mode === 'none') {
      decisions.push(DECISION.DENY);
      reasons.push('policy.exec=none');
    } else if (mode === 'allowlist') {
      const list = policy.exec?.commands ?? [];
      if (!list.length || !list.includes(cmd)) {
        decisions.push(DECISION.REQUIRE_APPROVAL);
        reasons.push(list.length ? `${cmd} is not on the command allowlist` : 'command allowlist is empty, so no command is pre-approved');
      }
    }
  }

  // --- privilege escalation is never policy-configurable to ALLOW
  if (capabilities.has(CAPABILITY.PRIVILEGE)) {
    decisions.push(DECISION.DENY);
    reasons.push('privilege escalation is denied unconditionally');
  }

  // --- persistence
  if (capabilities.has(CAPABILITY.PERSISTENCE)) {
    decisions.push(policy.persistence?.mode === 'deny' ? DECISION.DENY : DECISION.REQUIRE_APPROVAL);
    reasons.push(`policy.persistence=${policy.persistence?.mode ?? 'deny'}`);
  }

  // --- supply chain
  if (capabilities.has(CAPABILITY.PKG_INSTALL)) {
    const mode = policy.packageInstall?.mode ?? 'require-approval';
    decisions.push(mode === 'deny' ? DECISION.DENY : DECISION.REQUIRE_APPROVAL);
    reasons.push(`policy.packageInstall=${mode}`);
  }

  // --- git write
  if (capabilities.has(CAPABILITY.GIT_WRITE)) {
    const mode = policy.gitWrite?.mode ?? 'require-approval';
    decisions.push(mode === 'deny' ? DECISION.DENY : DECISION.REQUIRE_APPROVAL);
    reasons.push(`policy.gitWrite=${mode}`);
  }

  // --- cloud
  const cloudCaps = [CAPABILITY.CLOUD_WRITE, CAPABILITY.CLOUD_DELETE, CAPABILITY.CLOUD_DEPLOY, CAPABILITY.CLOUD_SECRET, CAPABILITY.CONTAINER];
  if (cloudCaps.some((c) => capabilities.has(c))) {
    const mode = policy.cloud?.mode ?? 'require-approval';
    decisions.push(mode === 'deny' ? DECISION.DENY : DECISION.REQUIRE_APPROVAL);
    reasons.push(`policy.cloud=${mode}`);
  }

  /* 3. Fail closed. */
  const classified = findings.length > 0 || capabilities.size > 0;
  if (!classified) {
    failClosed = true;
    const readOnly = READ_ONLY_PROGRAMS.has(cmd);
    if (readOnly) {
      decisions.push(DECISION.ALLOW_WITH_LOG);
      reasons.push('read-only command with no risk signals; allowed with logging');
    } else {
      decisions.push(policy.unknown?.decision ?? DECISION.REQUIRE_APPROVAL);
      reasons.push(`"${cmd || 'this action'}" produced no classification signal — fail closed (unknown is not allow)`);
    }
  }

  /* 4. Sandbox requirement. */
  let sandboxRequired = false;
  const highRisk = decisions.some((d) => d === DECISION.SANDBOX_ONLY || d === DECISION.DENY || d === DECISION.REQUIRE_APPROVAL);
  if (policy.sandbox?.required && (capabilities.size > 0 || highRisk)) {
    sandboxRequired = true;
    if (!context.sandboxAvailable) {
      reasons.push('policy requires a sandbox, and no sandbox provider is currently available');
    }
  }

  const decision = strictest(decisions);

  const approvalId = decision === DECISION.REQUIRE_APPROVAL || decision === DECISION.SANDBOX_ONLY
    ? `apr_${sha256(`${stableRequestKey(request)}|${policy.id}`).slice(0, 12)}`
    : null;

  return {
    decision,
    policyId: policy.id,
    policyVersion: policy.version,
    reasons: dedupe(reasons),
    matchedRules,
    capabilities: Array.from(capabilities),
    sandbox: { required: sandboxRequired, available: Boolean(context.sandboxAvailable), provider: policy.sandbox?.provider ?? 'none' },
    approvalId,
    failClosed,
    scopeHint,
    evaluatedAt: context.now ?? null,
  };
}

/**
 * Stable identity of an action shape. Deliberately excludes the per-run
 * action id: an approval is granted to a *shape* of action, so the same
 * request must always produce the same approval id (and two identical
 * requests must not be approvable twice by accident).
 */
export function stableRequestKey(request) {
  return canonicalJson({
    command: request.command,
    arguments: request.arguments,
    working_directory: request.working_directory,
    filesystem: request.filesystem,
    network: request.network,
    credentials: request.credentials,
    scope_hint: request.scope_hint,
  });
}

function isLocal(path) {
  const p = String(path ?? '');
  if (!p || p === 'unknown') return true; // unknown is handled by the fail-closed branch, not here
  if (p.startsWith('./') || p === '.' ) return true;
  if (p.startsWith('~') || p.startsWith('/')) return false;
  if (p.includes('..')) return false;
  return true;
}

function dedupe(list) {
  return Array.from(new Set(list));
}

/* ------------------------------------------------------------------ *
 * Decision → API response (spec §24)
 * ------------------------------------------------------------------ */

export function decisionResponse(request, evaluation, risk) {
  return {
    decision: evaluation.decision,
    risk: risk
      ? {
        execution: risk.dimensions.execution_risk?.score ?? 0,
        filesystem: risk.dimensions.filesystem_risk?.score ?? 0,
        network: risk.dimensions.network_risk?.score ?? 0,
        credentials: risk.dimensions.credential_risk?.score ?? 0,
        agency: risk.dimensions.agentic_risk?.score ?? 0,
      }
      : null,
    reasons: evaluation.reasons.slice(0, 6),
    approval_id: evaluation.approvalId,
    policy: evaluation.policyId,
    fail_closed: evaluation.failClosed,
    sandbox: evaluation.sandbox,
  };
}

/* ------------------------------------------------------------------ *
 * "MAKE IT SAFE" — policy patch generation (spec §28)
 * ------------------------------------------------------------------ */

export function policyPatchForFinding(finding) {
  const patch = {};
  const c = finding.capability;

  if (c === CAPABILITY.FS_DELETE || c === CAPABILITY.FS_WRITE) {
    patch.filesystem = { mode: 'workspace-only', deny: ['~', '/', '..'] };
  }
  if (c === CAPABILITY.NET_CONNECT || c === CAPABILITY.NET_EGRESS || c === CAPABILITY.NET_LISTEN) {
    patch.network = { mode: 'deny' };
  }
  if (c === CAPABILITY.ENV_READ || c === CAPABILITY.CRED_READ || c === CAPABILITY.CLOUD_SECRET) {
    patch.credentials = { mode: 'deny' };
  }
  if (c === CAPABILITY.PROC_EXECUTE || c === CAPABILITY.PROC_SPAWN || c === CAPABILITY.BROWSER) {
    patch.exec = { mode: 'allowlist', commands: [finding.action ? String(finding.action).split(/\s+/)[0] : 'node'].filter(Boolean) };
  }
  if (c === CAPABILITY.PERSISTENCE) {
    patch.persistence = { mode: 'deny' };
  }
  if (c === CAPABILITY.PKG_INSTALL) {
    patch.packageInstall = { mode: 'require-approval' };
  }
  if (c === CAPABILITY.PRIVILEGE) {
    patch.privilege = { mode: 'deny' };
  }
  if (c === CAPABILITY.MCP_SERVER) {
    patch.mcp = { mode: 'static-inspect-only', autoStart: false };
  }
  if (!Object.keys(patch).length) {
    patch.approval = { mode: 'require' };
  }
  patch.sandbox = { required: true };

  return { yaml: toYaml(patch), object: patch };
}

/** Minimal YAML emitter for the policy-patch shape (scalars + string lists). */
export function toYaml(obj, indent = 0) {
  const pad = ' '.repeat(indent);
  const lines = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v == null) continue;
    if (Array.isArray(v)) {
      if (!v.length) {
        lines.push(`${pad}${k}: []`);
      } else {
        lines.push(`${pad}${k}:`);
        for (const item of v) lines.push(`${pad}  - ${scalar(item)}`);
      }
    } else if (typeof v === 'object') {
      lines.push(`${pad}${k}:`);
      lines.push(toYaml(v, indent + 2));
    } else {
      lines.push(`${pad}${k}: ${scalar(v)}`);
    }
  }
  return lines.filter(Boolean).join('\n');
}

function scalar(v) {
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  const s = String(v);
  return /^[A-Za-z0-9_./-]+$/.test(s) ? s : JSON.stringify(s);
}

export const APPROVAL_ACTIONS = [
  { id: 'allow-once', label: 'ALLOW ONCE', effect: 'Allow this single execution; the next identical action asks again.', decision: DECISION.ALLOW },
  { id: 'allow-project', label: 'ALLOW THIS PROJECT', effect: 'Allow this action shape for this workspace for the rest of the session. Logged.', decision: DECISION.ALLOW_WITH_LOG },
  { id: 'allow-sandbox', label: 'ALLOW IN SANDBOX', effect: 'Run only inside the sandbox provider; host access stays denied.', decision: DECISION.SANDBOX_ONLY },
  { id: 'deny', label: 'DENY', effect: 'Refuse the action and record the refusal permanently.', decision: DECISION.DENY },
  { id: 'inspect-deeper', label: 'INSPECT DEEPER', effect: 'Follow the entrypoint and re-analyse before any decision.', decision: null },
];

/** Deliberately absent: a one-click "allow everything" affordance. */
export const FORBIDDEN_APPROVAL_ACTIONS = ['ALLOW ALL', 'ALLOW EVERYTHING', 'DISABLE POLICY'];

export function explainDecision(evaluation, findings) {
  const lines = [];
  lines.push(`Decision: ${evaluation.decision}`);
  lines.push(`Policy: ${evaluation.policyId} (v${evaluation.policyVersion})`);
  if (evaluation.failClosed) lines.push('Fail-closed branch triggered: the action produced no classification signal.');
  for (const r of evaluation.reasons) lines.push(`• ${r}`);
  const top = findings.slice().sort((a, b) => b.severity - a.severity)[0];
  if (top) lines.push(`Highest-severity finding: ${top.rule} ${top.title} (${top.severityLabel})`);
  return lines;
}
