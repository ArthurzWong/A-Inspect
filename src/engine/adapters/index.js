/**
 * Agent adapters (spec §15, §16, §33).
 *
 * The system is not hard-coded around OpenClaw. Every agent is described by
 * the same adapter surface:
 *
 *   inspectConfig() inspectSandbox() inspectToolPolicy()
 *   inspectElevatedPolicy() inspectWorkspace()
 *   interceptAction() evaluateAction() recordDecision()
 *
 * Two honesty rules:
 *   1. An adapter never modifies the agent's configuration. It reports.
 *   2. Fixture mode is labelled as fixture mode. A report that came from a
 *      mock is never presented as if it came from the real system.
 */

import { toActionRequest, actionFromCommandLine } from '../normalizer.js';
import { evaluate } from '../policyEngine.js';
import { DEFAULT_POLICY } from '../policyEngine.js';
import { EVIDENCE, makeAction } from '../schema.js';

export const ADAPTER_IDS = ['openclaw', 'autoclaw', 'codex', 'claude-code', 'cursor', 'mcp', 'generic'];

/* ------------------------------------------------------------------ *
 * Base adapter
 * ------------------------------------------------------------------ */

function baseAdapter(id, meta) {
  return {
    id,
    meta,
    mode: 'fixture',
    connected: false,

    inspectConfig() {
      return {
        adapter: id,
        status: this.connected ? 'connected' : 'not-connected',
        mode: this.mode,
        config: meta.defaultConfigSurface,
        note: 'Configuration is read, never written. The Inspector does not modify agent settings.',
      };
    },

    inspectSandbox() {
      return {
        adapter: id,
        sandbox: meta.defaultSandbox,
        note: 'Sandbox state as declared by the adapter. Live values require a connected agent.',
      };
    },

    inspectToolPolicy() {
      return { adapter: id, tools: meta.defaultTools };
    },

    inspectElevatedPolicy() {
      return { adapter: id, elevated: meta.defaultElevated };
    },

    inspectWorkspace() {
      return { adapter: id, workspace: meta.defaultWorkspace };
    },

    /** Normalize whatever the agent sends into an ActionRequest. */
    interceptAction(payload) {
      const command = payload.action?.command ?? payload.command ?? '';
      const args = payload.action?.args ?? payload.action?.arguments ?? payload.arguments ?? [];
      const raw = [command, ...(Array.isArray(args) ? args : [args])].join(' ').trim();
      // Reuse the same parser the rest of the engine uses, so an intercepted
      // action is normalized exactly like a pasted command would be.
      const action = actionFromCommandLine(raw, {
        origin: 'agent',
        workingDirectory: payload.context?.workspace ?? '.',
      }) ?? makeAction({
        origin: 'agent',
        raw,
        command,
        arguments: Array.isArray(args) ? args : [args],
        workingDirectory: payload.context?.workspace ?? '.',
      });
      if (payload.action?.type) action.actionType = payload.action.type;
      action.evidenceType = EVIDENCE.OBSERVED;
      action.note = `Intercepted from agent "${payload.agent ?? id}" via the gateway adapter.`;

      const request = toActionRequest(action, {
        agentId: payload.agent ?? id,
        workingDirectory: payload.context?.workspace ?? '.',
        approvedDomains: payload.context?.approvedDomains ?? [],
        sessionId: payload.session_id ?? null,
      });
      return { action, request };
    },

    /** The policy engine decides; the adapter only transports. */
    evaluateAction(payload, options = {}) {
      const { action, request } = this.interceptAction(payload);
      const evaluation = evaluate(request, options.policy ?? DEFAULT_POLICY, {
        findings: options.findings ?? [],
        capabilities: options.capabilities ?? [],
        sandboxAvailable: Boolean(options.sandboxAvailable),
      });
      return { action, request, evaluation };
    },

    recordDecision(auditLog, evaluation, request) {
      if (!auditLog) return null;
      return auditLog.append('ACTION_APPROVAL_REQUESTED', {
        agent: id,
        action: request.command,
        arguments: request.arguments,
        decision: evaluation.decision,
        policy: evaluation.policyId,
        reasons: evaluation.reasons,
        approval_id: evaluation.approvalId,
      });
    },

    /** Effective policy card (spec §16). */
    effectivePolicy() {
      return meta.effective;
    },
  };
}

/* ------------------------------------------------------------------ *
 * OpenClaw / AutoClaw
 * ------------------------------------------------------------------ */

/**
 * OpenClaw already distinguishes sandbox location, tool policy and elevated
 * execution, and its documentation is explicit that tool policy is the hard
 * stop while sandboxing decides *where* execution happens. Agent Inspector
 * therefore behaves as a policy overlay on top of those mechanisms; it does
 * not try to replace them.
 */
export function createOpenClawAdapter(config = {}) {
  const adapter = baseAdapter('openclaw', {
    label: 'OpenClaw',
    defaultConfigSurface: ['agent configuration', 'workspace skills', 'tool policy'],
    defaultSandbox: { mode: 'sandboxed', location: 'sandbox', network: 'restricted' },
    defaultTools: { exec: 'allowed', elevated: 'requires-approval', network: 'restricted' },
    defaultElevated: { mode: 'requires-approval' },
    defaultWorkspace: { access: 'read/write', scope: 'workspace-only' },
    effective: {
      sandbox: 'ON',
      workspace: 'READ / WRITE',
      exec: 'ALLOWED',
      elevated: 'REQUIRES APPROVAL',
      network: 'RESTRICTED',
      policySource: 'agent + global',
    },
  });

  adapter.mode = config.mode ?? 'fixture';
  adapter.connected = Boolean(config.runner) && adapter.mode === 'live';
  adapter.runner = config.runner ?? null;

  adapter.liveCommands = [
    'openclaw security',
    'openclaw policy',
    'openclaw sandbox explain --json',
  ];

  /**
   * Live inspection requires an injected runner AND user consent. This is
   * the "never automatically" rule from spec §34: the Inspector will not
   * shell out to the user's OpenClaw install on its own.
   */
  adapter.inspectLive = async function inspectLive(consent = false) {
    if (!this.runner) {
      return { ok: false, reason: 'no runner injected; live inspection unavailable', mode: 'fixture' };
    }
    if (!consent) {
      return { ok: false, reason: 'live inspection requires explicit user consent', wouldRun: this.liveCommands };
    }
    const results = {};
    for (const cmd of this.liveCommands) {
      try {
        results[cmd] = await this.runner(cmd);
      } catch (err) {
        results[cmd] = { ok: false, reason: String(err && err.message) };
      }
    }
    return { ok: true, mode: 'live', results };
  };

  return adapter;
}

export const createAutoClawAdapter = (config = {}) => {
  const adapter = createOpenClawAdapter(config);
  adapter.id = 'autoclaw';
  adapter.meta.label = 'AutoClaw';
  return adapter;
};

/* ------------------------------------------------------------------ *
 * Other agents
 * ------------------------------------------------------------------ */

export function createCodexAdapter() {
  return baseAdapter('codex', {
    label: 'Codex',
    defaultConfigSurface: ['config.toml', 'approval policy', 'sandbox mode'],
    defaultSandbox: { mode: 'sandboxed', network: 'restricted' },
    defaultTools: { shell: 'allowed-in-sandbox', apply_patch: 'allowed' },
    defaultElevated: { mode: 'requires-approval' },
    defaultWorkspace: { access: 'read/write', scope: 'workspace-only' },
    effective: {
      sandbox: 'ON',
      workspace: 'READ / WRITE',
      exec: 'SANDBOXED',
      elevated: 'REQUIRES APPROVAL',
      network: 'RESTRICTED',
      policySource: 'config.toml + session flags',
    },
  });
}

export function createClaudeCodeAdapter() {
  return baseAdapter('claude-code', {
    label: 'Claude Code',
    defaultConfigSurface: ['CLAUDE.md', 'settings.json', '.mcp.json', 'skills/'],
    defaultSandbox: { mode: 'none-by-default', note: 'Local execution unless a container is used.' },
    defaultTools: { bash: 'allowed-with-permission-prompts', file_write: 'allowed' },
    defaultElevated: { mode: 'requires-approval' },
    defaultWorkspace: { access: 'read/write', scope: 'project + user home' },
    effective: {
      sandbox: 'NOT DETECTED',
      workspace: 'READ / WRITE',
      exec: 'ALLOWED WITH PROMPTS',
      elevated: 'REQUIRES APPROVAL',
      network: 'NOT RESTRICTED',
      policySource: 'settings.json + per-session allow rules',
    },
  });
}

export function createCursorAdapter() {
  return baseAdapter('cursor', {
    label: 'Cursor',
    defaultConfigSurface: ['.cursorrules', '.cursor/', '.cursor/mcp.json'],
    defaultSandbox: { mode: 'none' },
    defaultTools: { editor: 'allowed', terminal: 'allowed-with-confirmation' },
    defaultElevated: { mode: 'not-applicable' },
    defaultWorkspace: { access: 'read/write', scope: 'project' },
    effective: {
      sandbox: 'NOT DETECTED',
      workspace: 'READ / WRITE',
      exec: 'ALLOWED WITH CONFIRMATION',
      elevated: 'NOT APPLICABLE',
      network: 'NOT RESTRICTED',
      policySource: 'editor settings + per-project rules',
    },
  });
}

export function createMcpAdapter() {
  return baseAdapter('mcp', {
    label: 'MCP',
    defaultConfigSurface: ['mcp.json', '.mcp.json', 'client configuration'],
    defaultSandbox: { mode: 'none', note: 'MCP servers run in the agent\'s own security context by default.' },
    defaultTools: { stdio_servers: 'launched-on-demand', remote_servers: 'network-reachable' },
    defaultElevated: { mode: 'inherits-agent' },
    defaultWorkspace: { access: 'inherits-agent' },
    effective: {
      sandbox: 'NOT DETECTED',
      workspace: 'INHERITS AGENT',
      exec: 'SERVER PROCESS',
      elevated: 'INHERITS AGENT',
      network: 'DEPENDS ON SERVER',
      policySource: 'client configuration files',
    },
  });
}

export function createGenericAdapter() {
  return baseAdapter('generic', {
    label: 'Generic CLI',
    defaultConfigSurface: ['unknown'],
    defaultSandbox: { mode: 'unknown' },
    defaultTools: { unknown: true },
    defaultElevated: { mode: 'unknown' },
    defaultWorkspace: { access: 'unknown' },
    effective: {
      sandbox: 'UNKNOWN',
      workspace: 'UNKNOWN',
      exec: 'UNKNOWN',
      elevated: 'UNKNOWN',
      network: 'UNKNOWN',
      policySource: 'not detected',
    },
  });
}

export function createAdapterRegistry(config = {}) {
  const adapters = {
    openclaw: createOpenClawAdapter(config.openclaw ?? {}),
    autoclaw: createAutoClawAdapter(config.autoclaw ?? {}),
    codex: createCodexAdapter(),
    'claude-code': createClaudeCodeAdapter(),
    cursor: createCursorAdapter(),
    mcp: createMcpAdapter(),
    generic: createGenericAdapter(),
  };
  return {
    get: (id) => adapters[id] ?? adapters.generic,
    list: () => Object.values(adapters),
    ids: () => Object.keys(adapters),
  };
}

/** Gateway routing table (spec §15, §17). */
export const GATEWAY_FLOW = [
  { step: 'agent', detail: 'OpenClaw / AutoClaw / Codex / Claude Code / MCP / generic CLI' },
  { step: 'normalize', detail: 'ActionNormalizer → ActionRequest' },
  { step: 'analyze', detail: 'deterministic analyzers R001–R014' },
  { step: 'policy', detail: 'PolicyEngine evaluates (the only authority)' },
  { step: 'ALLOW', detail: '→ sandbox execution' },
  { step: 'REQUIRE_APPROVAL / SANDBOX_ONLY', detail: '→ human approval gate' },
  { step: 'DENY', detail: '→ returned to the agent with reasons' },
  { step: 'audit', detail: 'every decision appended to the hash-chained ledger' },
];
