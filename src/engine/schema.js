/**
 * Agent Inspector — core schema, enums and normalized record factories.
 *
 * Everything the engine emits is built here, so every consumer (CLI, web
 * console, tests, audit ledger) sees the same shape.
 *
 * Security principle: an LLM explanation is never the security boundary.
 * These records are produced by deterministic code only.
 */

/* ------------------------------------------------------------------ *
 * Severity (0-5 per spec §10) and the status colour vocabulary of §5.
 * ------------------------------------------------------------------ */

export const SEVERITY = {
  NONE: 0,
  INFO: 1,
  LOW: 2,
  MODERATE: 3,
  ELEVATED: 4,
  CRITICAL: 5,
};

export const SEVERITY_LABEL = ['NONE', 'INFO', 'LOW', 'MODERATE', 'ELEVATED', 'CRITICAL'];

/** GREEN = allowed/low, YELLOW = controlled, ORANGE = elevated, RED = dangerous, GREY = unknown. */
export const SEVERITY_STATUS = ['grey', 'green', 'green', 'yellow', 'orange', 'red'];

export function severityLabel(score) {
  const i = Math.max(0, Math.min(5, Math.round(Number(score) || 0)));
  return SEVERITY_LABEL[i];
}

export function severityStatus(score) {
  const i = Math.max(0, Math.min(5, Math.round(Number(score) || 0)));
  return SEVERITY_STATUS[i];
}

/* ------------------------------------------------------------------ *
 * Policy decision enum (spec §8). These five values are the only
 * authorization outcomes the system may produce.
 * ------------------------------------------------------------------ */

export const DECISION = {
  ALLOW: 'ALLOW',
  ALLOW_WITH_LOG: 'ALLOW_WITH_LOG',
  REQUIRE_APPROVAL: 'REQUIRE_APPROVAL',
  SANDBOX_ONLY: 'SANDBOX_ONLY',
  DENY: 'DENY',
};

/** Ordered from most permissive to most restrictive; used to combine decisions. */
export const DECISION_RANK = {
  ALLOW: 0,
  ALLOW_WITH_LOG: 1,
  REQUIRE_APPROVAL: 2,
  SANDBOX_ONLY: 3,
  DENY: 4,
};

/* ------------------------------------------------------------------ *
 * Evidence classification. The Inspector must never present an
 * inference as an observed fact (spec §4, §14).
 * ------------------------------------------------------------------ */

export const EVIDENCE = {
  OBSERVED: 'observed',
  INFERRED: 'inferred',
  UNKNOWN: 'unknown',
};

export const CONFIDENCE = {
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
};

/** Scope of a side effect, used by rules that escalate outside the workspace. */
export const SCOPE = {
  PROJECT_LOCAL: 'project-local',
  WORKSPACE: 'workspace',
  USER_HOME: 'user-home',
  SYSTEM: 'system',
  NETWORK_LOCAL: 'localhost',
  NETWORK_PRIVATE: 'private-network',
  NETWORK_APPROVED: 'approved-domain',
  NETWORK_PUBLIC: 'unknown-public-domain',
  UNKNOWN: 'unknown',
};

/* ------------------------------------------------------------------ *
 * Capability vocabulary (spec §11 `capabilities`).
 * ------------------------------------------------------------------ */

export const CAPABILITY = {
  FS_READ: 'filesystem.read',
  FS_WRITE: 'filesystem.write',
  FS_DELETE: 'filesystem.delete',
  PROC_EXECUTE: 'process.execute',
  PROC_SPAWN: 'process.spawn',
  PROC_BACKGROUND: 'process.background',
  PROC_SIGNAL: 'process.signal',
  NET_CONNECT: 'network.connect',
  NET_LISTEN: 'network.listen',
  NET_EGRESS: 'network.egress',
  CRED_READ: 'credential.read',
  ENV_READ: 'environment.read',
  GIT_READ: 'git.read',
  GIT_WRITE: 'git.write',
  CLOUD_READ: 'cloud.read',
  CLOUD_WRITE: 'cloud.write',
  CLOUD_DELETE: 'cloud.delete',
  CLOUD_DEPLOY: 'cloud.deploy',
  CLOUD_SECRET: 'cloud.secret',
  DB_WRITE: 'database.write',
  PKG_INSTALL: 'supply_chain.install',
  PRIVILEGE: 'privilege.escalate',
  PERSISTENCE: 'persistence.create',
  AGENT_CHAIN: 'agent.chain',
  PROMPT_INJECTION: 'agent.prompt_injection',
  MCP_SERVER: 'mcp.server',
  BROWSER: 'browser.navigate',
  CONTAINER: 'container.run',
};

/** Human labels for the capability chips in the UI. */
export const CAPABILITY_LABEL = {
  'filesystem.read': 'Read files',
  'filesystem.write': 'Write files',
  'filesystem.delete': 'Delete files',
  'process.execute': 'Execute program',
  'process.spawn': 'Child processes',
  'process.background': 'Background process',
  'process.signal': 'Signal / stop process',
  'network.connect': 'Network request',
  'network.listen': 'Listen on a port',
  'network.egress': 'Data leaves the machine',
  'credential.read': 'Read credentials',
  'environment.read': 'Read environment',
  'git.read': 'Git read (safe)',
  'git.write': 'Git mutation',
  'cloud.read': 'Cloud read',
  'cloud.write': 'Cloud write',
  'cloud.delete': 'Cloud delete',
  'cloud.deploy': 'Cloud deploy',
  'cloud.secret': 'Cloud secret access',
  'database.write': 'Write database',
  'supply_chain.install': 'Install dependency',
  'privilege.escalate': 'Elevate privileges',
  'persistence.create': 'Create persistent job',
  'agent.chain': 'Agentic chaining',
  'agent.prompt_injection': 'Prompt-injection surface',
  'mcp.server': 'MCP server launch',
  'browser.navigate': 'Browser navigation',
  'container.run': 'Run container',
};

/* ------------------------------------------------------------------ *
 * Record factories
 * ------------------------------------------------------------------ */

let __seq = 0;
export function nextId(prefix) {
  __seq += 1;
  return `${prefix}_${String(__seq).padStart(4, '0')}`;
}

export function resetIdSequence() {
  __seq = 0;
}

/**
 * Normalized action. Produced by the ActionNormalizer for anything the
 * agent could execute. `evidenceType` records whether we saw it directly
 * (script text / code) or inferred it (downstream call).
 */
export function makeAction(input) {
  return {
    id: input.id ?? nextId('act'),
    parentId: input.parentId ?? null,
    origin: input.origin ?? 'script',
    language: input.language ?? 'shell',
    actionType: input.actionType ?? 'process.execute',
    command: input.command ?? '',
    arguments: input.arguments ?? [],
    raw: input.raw ?? '',
    workingDirectory: input.workingDirectory ?? '.',
    sourceFile: input.sourceFile ?? null,
    lineNumber: input.lineNumber ?? null,
    evidenceType: input.evidenceType ?? EVIDENCE.OBSERVED,
    note: input.note ?? null,
  };
}

/**
 * Every risk finding carries the full evidence contract required by
 * spec §33: rule, severity, evidence, scope, confidence,
 * potential_consequence and recommended_control.
 */
export function makeFinding(input) {
  const severity = input.severity == null ? SEVERITY.MODERATE : input.severity;
  return {
    id: input.id ?? nextId('find'),
    rule: input.rule,
    title: input.title,
    severity,
    severityLabel: severityLabel(severity),
    status: severityStatus(severity),
    capability: input.capability ?? null,
    capabilityLabel: input.capability ? (CAPABILITY_LABEL[input.capability] ?? input.capability) : null,
    action: input.action ?? null,
    actionId: input.actionId ?? null,
    scope: input.scope ?? SCOPE.UNKNOWN,
    confidence: input.confidence ?? CONFIDENCE.MEDIUM,
    evidenceType: input.evidenceType ?? EVIDENCE.INFERRED,
    evidence: Array.isArray(input.evidence) ? input.evidence : input.evidence ? [input.evidence] : [],
    potentialConsequence: input.potentialConsequence ?? '',
    recommendedControl: input.recommendedControl ?? '',
    why: Array.isArray(input.why) ? input.why : [],
    mitigations: Array.isArray(input.mitigations) ? input.mitigations : [],
    defaultDecision: input.defaultDecision ?? DECISION.REQUIRE_APPROVAL,
    mappings: input.mappings ?? {},
    location: {
      file: input.location?.file ?? input.sourceFile ?? null,
      line: input.location?.line ?? input.lineNumber ?? null,
    },
    redacted: input.redacted ?? true,
    detector: input.detector ?? 'deterministic',
  };
}

/* ------------------------------------------------------------------ *
 * Risk dimensions (spec §10)
 * ------------------------------------------------------------------ */

export const RISK_DIMENSIONS = [
  'execution_risk',
  'filesystem_risk',
  'network_risk',
  'credential_risk',
  'identity_risk',
  'supply_chain_risk',
  'agentic_risk',
  'persistence_risk',
];

export const RISK_DIMENSION_LABEL = {
  execution_risk: 'Execution',
  filesystem_risk: 'Filesystem',
  network_risk: 'Network',
  credential_risk: 'Credentials',
  identity_risk: 'Identity',
  supply_chain_risk: 'Supply chain',
  agentic_risk: 'Agentic chaining',
  persistence_risk: 'Persistence',
};

/** Map a capability to the risk dimension(s) it feeds. */
export const CAPABILITY_DIMENSION = {
  'filesystem.read': ['filesystem_risk'],
  'filesystem.write': ['filesystem_risk'],
  'filesystem.delete': ['filesystem_risk'],
  'process.execute': ['execution_risk'],
  'process.spawn': ['execution_risk', 'agentic_risk'],
  'process.background': ['persistence_risk'],
  'process.signal': ['execution_risk'],
  'network.connect': ['network_risk'],
  'network.listen': ['network_risk'],
  'network.egress': ['network_risk'],
  'credential.read': ['credential_risk'],
  'environment.read': ['credential_risk', 'identity_risk'],
  'git.read': ['identity_risk'],
  'git.write': ['identity_risk'],
  'cloud.read': ['identity_risk'],
  'cloud.write': ['identity_risk'],
  'cloud.delete': ['identity_risk'],
  'cloud.deploy': ['identity_risk'],
  'cloud.secret': ['credential_risk'],
  'database.write': ['filesystem_risk'],
  'supply_chain.install': ['supply_chain_risk'],
  'privilege.escalate': ['identity_risk', 'execution_risk'],
  'persistence.create': ['persistence_risk'],
  'agent.chain': ['agentic_risk'],
  'agent.prompt_injection': ['agentic_risk'],
  'mcp.server': ['supply_chain_risk', 'execution_risk', 'agentic_risk'],
  'browser.navigate': ['network_risk', 'agentic_risk'],
  'container.run': ['execution_risk', 'identity_risk'],
};

/* ------------------------------------------------------------------ *
 * Audit event types (spec §21)
 * ------------------------------------------------------------------ */

export const EVENT = {
  INSPECTION_STARTED: 'INSPECTION_STARTED',
  INSPECTION_COMPLETED: 'INSPECTION_COMPLETED',
  ACTION_DETECTED: 'ACTION_DETECTED',
  ACTION_BLOCKED: 'ACTION_BLOCKED',
  ACTION_APPROVAL_REQUESTED: 'ACTION_APPROVAL_REQUESTED',
  ACTION_APPROVED: 'ACTION_APPROVED',
  ACTION_DENIED: 'ACTION_DENIED',
  SANDBOX_STARTED: 'SANDBOX_STARTED',
  SANDBOX_STOPPED: 'SANDBOX_STOPPED',
  CREDENTIAL_ACCESS_ATTEMPT: 'CREDENTIAL_ACCESS_ATTEMPT',
  NETWORK_ACCESS_ATTEMPT: 'NETWORK_ACCESS_ATTEMPT',
  PRIVILEGE_ESCALATION_ATTEMPT: 'PRIVILEGE_ESCALATION_ATTEMPT',
  POLICY_CHANGED: 'POLICY_CHANGED',
  AGENT_CONNECTED: 'AGENT_CONNECTED',
  AGENT_DISCONNECTED: 'AGENT_DISCONNECTED',
};

/* ------------------------------------------------------------------ *
 * Agents (spec §11 `agents.type`)
 * ------------------------------------------------------------------ */

export const AGENT_TYPES = ['OpenClaw', 'AutoClaw', 'Claude Code', 'Codex', 'Cursor', 'MCP', 'Custom'];
