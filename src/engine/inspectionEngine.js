/**
 * InspectionEngine (spec §3, §29, §33).
 *
 * Pipeline, in order and with no step able to skip the next:
 *
 *   sources → discovery → action extraction → rule evaluation
 *          → agentic-chain analysis → risk model → repercussions
 *          → graphs → policy draft decisions → report
 *
 * Static only. Nothing in this file reads the host, calls the network,
 * launches a process, or evaluates untrusted content.
 */

import {
  CAPABILITY,
  CONFIDENCE,
  DECISION,
  EVIDENCE,
  EVENT,
  SCOPE,
  SEVERITY,
  makeAction,
  makeFinding,
  resetIdSequence,
  severityLabel,
  severityStatus,
} from './schema.js';
import { actionsFromShell, actionFromCommandLine, toActionRequest, groupPipelines } from './normalizer.js';
import { parseShell } from './shell.js';
import { evaluateCommandRules, RULE_CATALOG } from './rules/commandRules.js';
import { detectPromptInjection, inspectMcpConfig, MCP_INSPECTION_PIPELINE } from './rules/contentRules.js';
import { analyzeDependencies } from './rules/supplyChain.js';
import { buildKnownFileIndex, languageOf, scanCodeFile } from './codeScan.js';
import { discoverTargets, classifySourceKind, DISCOVERY_TARGETS_SPEC } from './discover.js';
import { buildRepercussions } from './repercussionEngine.js';
import { computeRisk } from './riskEngine.js';
import { DEFAULT_POLICY, evaluate, policyPatchForFinding } from './policyEngine.js';
import { buildActionGraph, buildBlastRadius, buildDependencyGraph, buildDownstreamIndex } from './graphBuilder.js';
import { createAuditLog } from './auditLogger.js';
import { redactDeep, redactString } from './redact.js';

/* ------------------------------------------------------------------ *
 * Extraction
 * ------------------------------------------------------------------ */

const SHELL_KINDS = new Set(['script']);
const CODE_LANGS = new Set(['javascript', 'typescript', 'python', 'php']);

function extractFromPackageJson(path, content, out) {
  let pkg;
  try {
    pkg = JSON.parse(content);
  } catch {
    return;
  }
  if (!pkg?.scripts) return;
  for (const [name, cmd] of Object.entries(pkg.scripts)) {
    const parsed = parseShell(String(cmd));
    for (const c of parsed) {
      const action = actionFromCommandLine(c.raw, { origin: 'package-json', file: `${path}#scripts.${name}` });
      if (action) {
        action.lineNumber = c.line;
        out.actions.push(action);
      }
    }
  }
}

function extractFromDockerfile(path, content, out) {
  const lines = String(content).split('\n');
  lines.forEach((line, i) => {
    const m = /^\s*(RUN|CMD|ENTRYPOINT)\s+(.*)$/i.exec(line);
    if (!m) return;
    const cmd = m[2].replace(/^\[|\]$/g, '').replace(/",\s*"/g, ' ').replace(/"/g, '');
    const parsed = parseShell(cmd);
    for (const c of parsed) {
      const action = actionFromCommandLine(c.raw, { origin: 'dockerfile', file: path });
      if (action) {
        action.lineNumber = i + 1;
        out.actions.push(action);
      }
    }
  });
  if (/^\s*HEALTHCHECK/i.test(String(content))) {
    out.notes.push(`${path}: HEALTHCHECK present — the image runs a periodic probe.`);
  }
}

function extractFromMakefile(path, content, out) {
  const lines = String(content).split('\n');
  let target = null;
  lines.forEach((line, i) => {
    const t = /^([A-Za-z0-9_.-]+):/.exec(line);
    if (t) target = t[1];
    if (/^\t/.test(line) && line.trim()) {
      const parsed = parseShell(line.trim());
      for (const c of parsed) {
        const action = actionFromCommandLine(c.raw, { origin: 'makefile', file: `${path}#${target ?? 'target'}` });
        if (action) {
          action.lineNumber = i + 1;
          out.actions.push(action);
        }
      }
    }
  });
}

function extractFromYaml(path, content, out, kind) {
  const lines = String(content).split('\n');
  lines.forEach((line, i) => {
    const run = /^\s*(?:-\s*)?(run|command|entrypoint|shell|script)\s*:\s*(.+)$/i.exec(line);
    if (!run) return;
    let cmd = run[2].trim();
    if (/^[|>]/.test(cmd)) return; // block scalar: handled by the multi-line pass below
    cmd = cmd.replace(/^["']|["']$/g, '');
    const parsed = parseShell(cmd);
    for (const c of parsed) {
      const action = actionFromCommandLine(c.raw, { origin: kind, file: path });
      if (action) {
        action.lineNumber = i + 1;
        out.actions.push(action);
      }
    }
  });
}

/** `.env.example` → the names, never the values. */
function extractEnvNames(path, content) {
  const names = [];
  for (const line of String(content).split('\n')) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=?/.exec(line);
    if (m && m[1]) names.push(m[1]);
  }
  return Array.from(new Set(names));
}

/* ------------------------------------------------------------------ *
 * Agentic chain (R011)
 * ------------------------------------------------------------------ */

export function buildAgenticChain(findings, capabilities, sources) {
  const caps = new Set(capabilities.map((c) => c.capabilityType));
  const injectionFindings = findings.filter((f) => f.capability === CAPABILITY.PROMPT_INJECTION);
  const untrustedSources = sources
    .filter((s) => {
      const k = classifySourceKind(s.path).kind;
      return ['prose', 'skill', 'agent-config', 'mcp', 'config'].includes(k);
    })
    .map((s) => s.path);

  const canExecute = caps.has(CAPABILITY.PROC_EXECUTE) || caps.has(CAPABILITY.PROC_SPAWN);
  const canEgress = caps.has(CAPABILITY.NET_CONNECT) || caps.has(CAPABILITY.NET_EGRESS);
  const canPersist = caps.has(CAPABILITY.PERSISTENCE);
  const canReadCredentials = caps.has(CAPABILITY.CRED_READ) || caps.has(CAPABILITY.ENV_READ);
  const listens = caps.has(CAPABILITY.NET_LISTEN);

  const chain = {
    untrustedInput: {
      present: untrustedSources.length > 0 || injectionFindings.length > 0,
      sources: untrustedSources.slice(0, 12),
      injectionSignals: injectionFindings.length,
    },
    interpret: { present: true, note: 'An agent reads and interprets project content by definition.' },
    execute: { present: canExecute, note: 'The project contains code that can be executed.' },
    egress: { present: canEgress, note: 'The project can transmit data outward.' },
    persist: { present: canPersist },
    credentials: { present: canReadCredentials },
    listen: { present: listens },
    steps: [],
    finding: null,
  };

  chain.steps = [
    { step: 'receive untrusted content', present: chain.untrustedInput.present, detail: chain.untrustedInput.present ? `${chain.untrustedInput.sources.length} content source(s), ${chain.untrustedInput.injectionSignals} injection signal(s)` : 'no untrusted content observed' },
    { step: 'interpret content', present: true, detail: 'an agent reads it as context' },
    { step: 'generate a command', present: canExecute, detail: canExecute ? 'execution capability present' : 'no execution capability observed' },
    { step: 'execute a tool', present: canExecute, detail: canExecute ? 'execution capability present' : 'not observed' },
    { step: 'transmit result', present: canEgress, detail: canEgress ? 'network egress present' : 'no egress observed' },
    { step: 'outlive the session', present: canPersist, detail: canPersist ? 'scheduler/persistence present' : 'not observed' },
  ];

  // The spec's R011 condition: receive → interpret → generate → execute.
  if (!(chain.untrustedInput.present && canExecute)) {
    return chain;
  }

  let severity = SEVERITY.MODERATE;
  if (canEgress) severity = SEVERITY.ELEVATED;
  if (canEgress && canReadCredentials) severity = SEVERITY.CRITICAL;

  chain.finding = makeFinding({
    rule: 'R011',
    title: 'Agentic chain: untrusted content can reach an execution tool',
    severity,
    capability: CAPABILITY.AGENT_CHAIN,
    action: null,
    scope: SCOPE.PROJECT_LOCAL,
    confidence: CONFIDENCE.MEDIUM,
    evidenceType: EVIDENCE.INFERRED,
    evidence: [
      `Untrusted content sources: ${(chain.untrustedInput.sources.slice(0, 6).join(', ') || 'none named')}`,
      `Prompt-injection signals detected: ${chain.untrustedInput.injectionSignals}`,
      `Execution capability present: ${canExecute ? 'yes' : 'no'}`,
      `Network egress present: ${canEgress ? 'yes' : 'no'}`,
      `Credential/environment reads present: ${canReadCredentials ? 'yes' : 'no'}`,
      'This is an inference over the project graph, not an observation of a specific attack.',
    ],
    potentialConsequence:
      'An agent operating on this project can read content written by someone else, be influenced by it, and then execute code. That is the complete shape of an indirect prompt-injection attack: no single step looks wrong, but the path exists end to end.',
    recommendedControl:
      'Keep untrusted content away from the reasoning step that produces commands, or require approval on every execution that follows a read of untrusted content. Sandbox the execution.',
    why: [
      'The four conditions of R011 are all present: receive, interpret, generate, execute.',
      'No detector can tell you whether a specific piece of content will redirect an agent — only that the path exists.',
      'Add egress and credentials and the same path also becomes an exfiltration path.',
    ],
    mitigations: ['Run inside sandbox', 'Require approval', 'Remove credential access', 'Disable network'],
    defaultDecision: severity >= SEVERITY.ELEVATED ? DECISION.REQUIRE_APPROVAL : DECISION.ALLOW_WITH_LOG,
    mappings: { owasp: ['AST01', 'AST05', 'AST06'], snyk: ['prompt_injection_skill_instructions', 'untrusted_content'], agentdojo: ['agentic-chain'] },
    location: { file: null, line: null },
  });

  return chain;
}

/* ------------------------------------------------------------------ *
 * Main entry
 * ------------------------------------------------------------------ */

/**
 * @param {object} input { sources: [{path, content}], options }
 */
export function inspectProject(input) {
  resetIdSequence();
  const sources = (input.sources ?? []).filter((s) => s && typeof s.path === 'string');
  const options = input.options ?? {};
  const workspace = options.workspace ?? '.';
  const policy = options.policy ?? DEFAULT_POLICY;
  const approvedDomains = options.approvedDomains ?? policy.network?.allowlist ?? [];

  const startedAt = options.now ?? null;
  const out = { actions: [], notes: [] };
  const findings = [];
  const capabilities = [];
  const parseErrors = [];
  const uninspected = [];
  const mcpServers = [];

  const discovery = discoverTargets(sources);
  const knownPaths = buildKnownFileIndex(sources);
  const downstreamIndex = buildDownstreamIndex(sources);

  /* ---- 1. Extract actions and per-file findings ---- */
  for (const source of sources) {
    const path = String(source.path);
    const content = String(source.content ?? '');
    const { kind } = classifySourceKind(path);
    const language = languageOf(path);

    try {
      if (kind === 'script' && language !== 'makefile') {
        out.actions.push(...actionsFromShell(content, { file: path, workingDirectory: workspace }));
      } else if (language === 'makefile') {
        extractFromMakefile(path, content, out);
      } else if (/(^|\/)(package\.json)$/.test(path)) {
        extractFromPackageJson(path, content, out);
      } else if (/Dockerfile/i.test(path)) {
        extractFromDockerfile(path, content, out);
      } else if (kind === 'ci' || kind === 'container' || /\.ya?ml$/i.test(path)) {
        extractFromYaml(path, content, out, kind === 'ci' ? 'ci' : 'compose');
      } else if (CODE_LANGS.has(language)) {
        const scan = scanCodeFile(path, content, { approvedDomains, workingDirectory: workspace });
        out.actions.push(...scan.actions);
        findings.push(...scan.findings);
        capabilities.push(...scan.capabilities);
      } else if (kind === 'mcp') {
        const mcp = inspectMcpConfig(content, { file: path });
        findings.push(...mcp.findings);
        mcpServers.push(...mcp.servers);
        for (const server of mcp.servers) {
          if (!server.command) continue;
          const action = actionFromCommandLine(`${server.command} ${server.args.join(' ')}`.trim(), { origin: 'mcp', file: path });
          if (action) {
            action.evidenceType = EVIDENCE.OBSERVED;
            action.note = 'Declared MCP stdio server. Not started by the Inspector.';
            out.actions.push(action);
          }
        }
      } else if (kind === 'env') {
        const names = extractEnvNames(path, content);
        if (names.length) {
          findings.push(makeFinding({
            rule: 'R003',
            title: `Environment template declares ${names.length} variable(s)`,
            severity: SEVERITY.INFO,
            capability: CAPABILITY.ENV_READ,
            action: null,
            scope: SCOPE.PROJECT_LOCAL,
            confidence: CONFIDENCE.HIGH,
            evidenceType: EVIDENCE.OBSERVED,
            evidence: [`File: ${path}`, `Keys: ${names.join(', ')}`, 'Only names are read. Values are never read by the Inspector. Value: REDACTED'],
            potentialConsequence: 'Named variables tell you which credentials the project expects to be present in the environment at run time.',
            recommendedControl: 'Keep real values out of the repository and pass only what each run needs.',
            why: ['The template is a map of the secrets this project consumes.'],
            defaultDecision: DECISION.ALLOW,
            mappings: { owasp: ['AST03'] },
            location: { file: path, line: null },
          }));
        }
      } else if (kind === 'prose' || kind === 'skill' || kind === 'agent-config' || kind === 'config') {
        if (content.length <= 400000) {
          findings.push(...detectPromptInjection(content, { file: path, kind }));
        }
      } else if (kind === 'manifest') {
        // Manifest parsing handled by the supply-chain pass.
      }
    } catch (err) {
      parseErrors.push({ path, error: String(err && err.message) });
    }
  }

  /* ---- 2. Evaluate command rules ---- */
  const pipelines = groupPipelines(sources.map((s) => s.content).join('\n'));
  for (const action of out.actions) {
    if (action.origin === 'code') continue;
    const ctx = {
      workingDirectory: workspace,
      approvedDomains,
      knownFiles: knownPaths,
      knownPaths,
      allCommands: out.actions.filter((a) => a.sourceFile === action.sourceFile),
      pipeline: pipelines.find((p) => p.commands.some((c) => c.raw === action.raw))?.commands ?? null,
      downstreamIndex,
      hasLockfile: false,
    };
    const result = evaluateCommandRules(action, ctx);
    findings.push(...result.findings);
    capabilities.push(...result.capabilities);
  }

  /* ---- 3. Supply chain ---- */
  const sc = analyzeDependencies(sources);
  findings.push(...sc.findings);

  /* ---- 4. Agentic chain ---- */
  const chain = buildAgenticChain(findings, capabilities, sources);
  if (chain.finding) findings.push(chain.finding);

  /* ---- 5. Coverage + unknown surface ---- */
  const entrypointsFound = new Map();
  for (const action of out.actions) {
    if (action.origin === 'code' || !action.arguments?.length) continue;
    for (const arg of action.arguments) {
      const clean = String(arg).replace(/^\.\//, '');
      if (!/[/.]/.test(clean)) continue;
      if (!knownPaths.has(clean)) {
        entrypointsFound.set(clean, action.id);
      }
    }
  }
  for (const [ref, actionId] of entrypointsFound) {
    uninspected.push({
      reason: `Referenced but not present in the inspected set: ${ref}`,
      dimension: 'execution_risk',
      actionId,
    });
  }
  if (chain.untrustedInput.present && !chain.execute.present) {
    uninspected.push({ reason: 'Untrusted content is present but no execution path was observed in this set.', dimension: 'agentic_risk' });
  }

  const safeLen = sources.reduce((n, s) => n + Math.min(String(s.content ?? '').length, 400000), 0);
  const coverage = sources.length ? (sources.length - parseErrors.length) / sources.length : 0;

  const risk = computeRisk(capabilities, findings, {
    coverage,
    hasLockfile: sc.hasLockfile,
    hasAgentConfig: Boolean(discovery.counts['agent-config']),
    uninspected,
    truncated: safeLen > 8_000_000,
  });

  /* ---- 6. Repercussions ---- */
  const repercussions = buildRepercussions(findings, {
    hasLockfile: sc.hasLockfile,
    hasAgentConfig: Boolean(discovery.counts['agent-config']),
    discovery,
    uninspected,
  });

  /* ---- 7. Graphs ---- */
  const actionGraph = buildActionGraph(out.actions, findings, capabilities, {
    downstreamIndex,
    knownPaths,
  });
  const blastRadius = buildBlastRadius(capabilities, out.actions, findings);
  const dependencyGraph = buildDependencyGraph(sources, sc.hasLockfile);

  /* ---- 8. Policy draft decisions per action ---- */
  const decisions = [];
  for (const action of out.actions) {
    const request = toActionRequest(action, { agentId: options.agentId ?? 'autoclaw', workingDirectory: workspace, approvedDomains });
    const actionFindings = findings.filter((f) => f.actionId === action.id);
    const actionCaps = capabilities.filter((c) => c.actionId === action.id);
    const evaluation = evaluate(request, policy, {
      findings: actionFindings,
      capabilities: actionCaps,
      sandboxAvailable: options.sandboxAvailable ?? false,
    });
    decisions.push({
      actionId: action.id,
      request,
      ...evaluation,
      topFinding: actionFindings.slice().sort((a, b) => b.severity - a.severity)[0] ?? null,
    });
  }

  const policyPatches = [];
  const seenCapabilities = new Set();
  for (const finding of findings.slice().sort((a, b) => b.severity - a.severity)) {
    if (finding.severity < SEVERITY.MODERATE || !finding.capability) continue;
    if (seenCapabilities.has(finding.capability)) continue;
    seenCapabilities.add(finding.capability);
    policyPatches.push({
      capability: finding.capability,
      capabilityLabel: finding.capabilityLabel,
      rule: finding.rule,
      title: finding.title,
      ...policyPatchForFinding(finding),
    });
  }

  const byRule = {};
  for (const f of findings) byRule[f.rule] = (byRule[f.rule] ?? 0) + 1;

  const report = {
    meta: {
      kind: input.kind ?? 'project',
      workspaceId: options.workspaceId ?? 'workspace_local',
      agentId: options.agentId ?? 'autoclaw',
      policyId: policy.id,
      startedAt,
      generatedBy: 'agent-inspector/0.1.0',
      mode: 'INSPECT',
      executionDisclaimer: 'Static inspection only. No uploaded or referenced code was executed. No secrets were read.',
      sourceCount: sources.length,
      sourcesInspected: sources.map((s) => ({ path: s.path, bytes: String(s.content ?? '').length, kind: classifySourceKind(s.path).kind })),
    },
    discovery,
    actions: out.actions,
    findings,
    capabilities,
    risk,
    repercussions,
    graphs: { actionGraph, blastRadius, dependencyGraph },
    decisions,
    policy: { id: policy.id, version: policy.version, name: policy.name, document: policy },
    policyPatches,
    mcp: { servers: mcpServers, pipeline: MCP_INSPECTION_PIPELINE },
    agenticChain: chain,
    uninspected,
    notes: out.notes,
    parseErrors,
    stats: {
      actionsDetected: out.actions.length,
      findings: findings.length,
      byRule,
      bySeverity: {
        critical: findings.filter((f) => f.severity === SEVERITY.CRITICAL).length,
        elevated: findings.filter((f) => f.severity === SEVERITY.ELEVATED).length,
        moderate: findings.filter((f) => f.severity === SEVERITY.MODERATE).length,
        low: findings.filter((f) => f.severity === SEVERITY.LOW).length,
        info: findings.filter((f) => f.severity === SEVERITY.INFO).length,
      },
      actionsRequiringApproval: decisions.filter((d) => d.decision === DECISION.REQUIRE_APPROVAL).length,
      actionsDenied: decisions.filter((d) => d.decision === DECISION.DENY).length,
      actionsAllowed: decisions.filter((d) => [DECISION.ALLOW, DECISION.ALLOW_WITH_LOG].includes(d.decision)).length,
      coverage: Math.round(coverage * 100),
      ruleCatalog: RULE_CATALOG,
      discoverySpec: DISCOVERY_TARGETS_SPEC,
    },
  };

  /* ---- 9. Redaction pass ----
   * Nothing that looks like a credential may leave the engine, even if a
   * detection path happened to capture a raw command line containing one.
   * This happens before the audit ledger is built, so the ledger's hashes
   * cover the redacted payloads and the chain stays verifiable. */
  const safeReport = redactDeep(report);

  /* ---- 10. Audit ledger for this inspection ---- */
  const audit = createAuditLog({ workspaceId: safeReport.meta.workspaceId, agentId: safeReport.meta.agentId, now: options.now ? () => options.now : undefined });
  audit.append(EVENT.INSPECTION_STARTED, {
    kind: safeReport.meta.kind,
    source_count: safeReport.meta.sourceCount,
    policy: policy.id,
  });
  for (const f of safeReport.findings.filter((x) => x.severity >= SEVERITY.MODERATE).slice(0, 200)) {
    audit.append(EVENT.ACTION_DETECTED, {
      rule: f.rule,
      title: f.title,
      capability: f.capability,
      scope: f.scope,
      severity: f.severityLabel,
      evidence_type: f.evidenceType,
      potential_consequence: f.potentialConsequence,
      recommended_control: f.recommendedControl,
    });
  }
  audit.append(EVENT.INSPECTION_COMPLETED, {
    actions: safeReport.stats.actionsDetected,
    findings: safeReport.stats.findings,
    overall: safeReport.risk.overall.label,
    confidence: safeReport.risk.confidence,
  });
  safeReport.audit = audit.toJSON();
  safeReport.auditVerification = audit.verify();

  return safeReport;
}

/* ------------------------------------------------------------------ *
 * Single-command inspection (Dashboard "Paste command")
 * ------------------------------------------------------------------ */

export function inspectCommandText(commandText, options = {}) {
  const text = String(commandText ?? '').trim();
  const sources = [{ path: options.file ?? 'pasted-command.sh', content: text }];
  const report = inspectProject({
    sources,
    kind: 'command',
    options: { ...options, now: options.now },
  });
  report.meta.kind = 'command';
  report.commandText = redactString(text);
  return report;
}

/* ------------------------------------------------------------------ *
 * Summary helpers used by the UI and the CLI
 * ------------------------------------------------------------------ */

export function summarizeReport(report) {
  const dims = report.risk.dimensions;
  return {
    kind: report.meta.kind,
    overall: report.risk.overall,
    confidence: report.risk.confidence,
    actions: report.stats.actionsDetected,
    findings: report.stats.findings,
    dimensions: [
      { key: 'filesystem_risk', label: 'Filesystem' },
      { key: 'execution_risk', label: 'Execution' },
      { key: 'network_risk', label: 'Network' },
      { key: 'credential_risk', label: 'Credentials' },
      { key: 'agentic_risk', label: 'Agentic chaining' },
      { key: 'supply_chain_risk', label: 'Supply chain' },
      { key: 'persistence_risk', label: 'Persistence' },
      { key: 'identity_risk', label: 'Identity' },
    ].map(({ key, label }) => {
      const d = dims[key];
      return {
        key,
        label,
        score: d.state === 'not-inspected' ? null : d.score,
        label5: d.state === 'not-inspected' ? 'NOT OBSERVED' : d.scoreLabel,
        status: d.status,
        state: d.state,
      };
    }),
    decisions: {
      allow: report.stats.actionsAllowed,
      approval: report.stats.actionsRequiringApproval,
      deny: report.stats.actionsDenied,
    },
    auditValid: report.auditVerification?.valid ?? null,
    auditLength: report.audit?.length ?? 0,
  };
}

export function overallBanner(report) {
  const { overall } = report.risk;
  return {
    title: overall.exposureWord,
    status: overall.status,
    severityLabel: severityLabel(overall.score),
    confidence: report.risk.confidence,
    actions: report.stats.actionsDetected,
    line: `${report.stats.actionsDetected} actions detected`,
  };
}
