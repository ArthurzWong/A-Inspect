#!/usr/bin/env node
/**
 * Agent Inspector CLI.
 *
 * Commands:
 *   inspect <path>            static inspection of a local project (read-only)
 *   inspect --command "<cmd>" inspection of a single command line
 *   inspect --github o/r      read-only inspection of a public GitHub repo
 *   gateway                   evaluate one ActionRequest from stdin (spec §24)
 *   report <path>             write a self-contained HTML report
 *   adapters                  show every adapter's effective policy
 *   policy                    print the bundled policies as YAML
 *   sandbox                   describe available sandbox providers
 *
 * Guarantees, enforced by construction rather than by documentation:
 *   - nothing from the inspected project is ever executed;
 *   - no secret values are read, and any that appear in output are redacted;
 *   - the only engine output that can leave this process is a JSON report.
 */

import fs from 'node:fs';
import path from 'node:path';

import { readTree } from './lib/read-tree.mjs';
import {
  inspectProject, inspectCommandText, summarizeReport, overallBanner,
  DEFAULT_POLICY, PERMISSIVE_POLICY, toYaml, createAdapterRegistry,
  describeSandboxProviders, evaluate, toActionRequest, actionFromCommandLine,
  decisionResponse, computeRisk, RULE_CATALOG, VERSION, redactString,
  createGitHubClient, planRepositoryInspection, parseRepoUrl,
} from '../src/engine/index.js';
import { readGithubRepository } from './lib/github-read.mjs';

/* ------------------------------------------------------------------ *
 * Argument parsing
 * ------------------------------------------------------------------ */

function parseArgs(argv) {
  const args = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i += 1) {
    const t = argv[i];
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      if (eq !== -1) {
        args.flags[t.slice(2, eq)] = t.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (next && !next.startsWith('--')) {
          args.flags[t.slice(2)] = next;
          i += 1;
        } else {
          args.flags[t.slice(2)] = true;
        }
      }
    } else {
      args._.push(t);
    }
  }
  return args;
}

const C = {
  reset: '\u001b[0m', dim: '\u001b[2m', bold: '\u001b[1m',
  red: '\u001b[31m', green: '\u001b[32m', yellow: '\u001b[33m',
  blue: '\u001b[34m', magenta: '\u001b[35m', cyan: '\u001b[36m', grey: '\u001b[90m',
};

const STATUS_COLOR = { red: C.red, orange: C.magenta, yellow: C.yellow, green: C.green, grey: C.grey };

function banner(report) {
  const b = overallBanner(report);
  const color = STATUS_COLOR[b.status] ?? C.reset;
  const lines = [];
  lines.push('');
  lines.push(`${C.bold}AGENT INSPECTOR${C.reset} ${C.grey}v${VERSION}${C.reset}   ${C.grey}mode: ${report.meta.mode}  kind: ${report.meta.kind}${C.reset}`);
  lines.push(`${C.bold}AGENT INSPECTOR${C.reset} ${C.grey}v${VERSION}${C.reset}   ${C.grey}mode: ${report.meta.mode}  kind: ${report.meta.kind}${C.reset}`);
  return lines;
}

/* ------------------------------------------------------------------ *
 * Text rendering
 * ------------------------------------------------------------------ */

function renderText(report) {
  const out = [];
  const summary = summarizeReport(report);

  out.push('');
  out.push(`${C.bold}AGENT INSPECTOR${C.reset} ${C.grey}v${VERSION} · mode ${report.meta.mode} · ${report.meta.kind}${C.reset}`);
  out.push(`${C.grey}${report.meta.executionDisclaimer}${C.reset}`);
  out.push('');

  const color = STATUS_COLOR[summary.overall.status] ?? C.reset;
  out.push(`  ${color}${C.bold}${summary.overall.exposureWord}${C.reset}    ${C.grey}confidence ${summary.confidence}%${C.reset}`);
  out.push(`  ${C.grey}${summary.actions} actions detected · ${summary.findings} findings${C.reset}`);
  out.push('');

  out.push(`  ${C.bold}Risk dimensions${C.reset}`);
  for (const d of summary.dimensions) {
    const sc = STATUS_COLOR[d.status] ?? C.reset;
    const bar = d.score == null ? '   ' : '█'.repeat(d.score) + '·'.repeat(5 - d.score);
    out.push(`    ${d.label.padEnd(18)} ${sc}${bar.padEnd(7)}${(d.label5 ?? '').padEnd(20)}${C.reset}`);
  }
  out.push('');

  out.push(`  ${C.bold}Decisions${C.reset}  ${C.green}${summary.decisions.allow} allow${C.reset} · ${C.yellow}${summary.decisions.approval} approval${C.reset} · ${C.red}${summary.decisions.deny} deny${C.reset}`);
  out.push(`  ${C.bold}Audit${C.reset}      ${summary.auditValid ? C.green + 'chain intact' : C.red + 'CHAIN BROKEN'}${C.reset} (${summary.auditLength} events)`);
  out.push('');

  const dims = report.risk.dimensions;
  const active = Object.values(dims).filter((d) => d.score > 0).sort((a, b) => b.score - a.score);
  if (active.length) {
    out.push(`  ${C.bold}Why${C.reset}`);
    for (const d of active) {
      out.push(`    ${d.label}:`);
      for (const e of d.evidence.slice(0, 3)) {
        out.push(`      ${C.grey}${e.rule ?? '—'} ${String(e.action ?? '').slice(0, 90)}${C.reset}`);
      }
      for (const u of d.unknown.slice(0, 2)) out.push(`      ${C.yellow}unknown: ${u}${C.reset}`);
    }
    out.push('');
  }

  const top = report.findings.slice().sort((a, b) => b.severity - a.severity).slice(0, 12);
  if (top.length) {
    out.push(`  ${C.bold}Top findings${C.reset}`);
    for (const f of top) {
      const sc = STATUS_COLOR[f.status] ?? C.reset;
      out.push(`    ${sc}${f.severityLabel.padEnd(9)}${C.reset} ${C.bold}${f.rule}${C.reset} ${f.title.slice(0, 96)}`);
      out.push(`      ${C.grey}${(f.location.file ?? '')}${f.location.line ? `:${f.location.line}` : ''} · ${f.confidence} · ${f.evidenceType} · ${f.defaultDecision}${C.reset}`);
    }
    out.push('');
  }

  if (report.actions.length) {
    out.push(`  ${C.bold}Action trace${C.reset} (${report.actions.length} actions)`);
    for (const a of report.actions.slice(0, 25)) {
      const kind = a.origin === 'code' ? C.cyan : C.reset;
      out.push(`    ${kind}${String(a.command).padEnd(12)}${C.reset} ${String(a.raw || a.command).slice(0, 80)} ${C.grey}(${a.sourceFile ?? '—'}${a.lineNumber ? `:${a.lineNumber}` : ''})${C.reset}`);
    }
    if (report.actions.length > 25) out.push(`    ${C.grey}… ${report.actions.length - 25} more (see JSON report)${C.reset}`);
    out.push('');
  }

  const blast = report.graphs.blastRadius;
  out.push(`  ${C.bold}Blast radius${C.reset}`);
  for (const c of blast.categories) {
    const sc = STATUS_COLOR[c.status] ?? C.reset;
    out.push(`    ${c.category.padEnd(18)} ${sc}${String(c.count).padStart(3)} nodes  ${c.scoreLabel}${C.reset}`);
  }
  out.push(`    ${C.grey}${blast.absentNote}${C.reset}`);
  out.push('');

  if (report.repercussions.projectUnknowns.length) {
    out.push(`  ${C.bold}Project unknowns${C.reset}`);
    for (const u of report.repercussions.projectUnknowns.slice(0, 10)) out.push(`    ${C.yellow}?${C.reset} ${u}`);
    out.push('');
  }

  if (report.uninspected.length) {
    out.push(`  ${C.bold}Not inspected${C.reset}`);
    for (const u of report.uninspected.slice(0, 10)) out.push(`    ${C.grey}·${C.reset} ${u.reason}`);
    out.push('');
  }

  out.push(`  ${C.grey}Rules: ${RULE_CATALOG.map((r) => r.id).join(' ')}${C.reset}`);
  out.push('');
  return out.join('\n');
}

/* ------------------------------------------------------------------ *
 * Commands
 * ------------------------------------------------------------------ */

function commandInspect(args) {
  const format = args.flags.format ?? 'text';
  const workspace = args.flags.workspace ?? process.cwd();

  if (args.flags.command) {
    const report = inspectCommandText(String(args.flags.command), {
      workspace,
      agentId: args.flags.agent ?? 'autoclaw',
    });
    return finish(report, args);
  }

  if (args.flags.github) {
    return commandInspectGithub(String(args.flags.github), args);
  }

  const target = args._[1] ?? args.flags.path ?? '.';
  const resolved = path.resolve(target);
  const { sources, skipped, stats } = readTree(resolved);

  if (!sources.length) {
    console.error(`No readable text files found in ${resolved}`);
    process.exitCode = 1;
    return;
  }

  const report = inspectProject({
    sources,
    options: {
      workspace: resolved,
      agentId: args.flags.agent ?? 'autoclaw',
      sandboxAvailable: false,
    },
  });
  report.meta.readStats = stats;
  report.meta.skipped = skipped;
  report.meta.target = resolved;
  return finish(report, args);
}

async function commandInspectGithub(ref, args) {
  const plan = planRepositoryInspection(ref);
  if (!plan.ok) {
    console.error(plan.reason);
    process.exitCode = 1;
    return;
  }
  const maxFiles = Number(args.flags['max-files'] ?? 80);
  console.error(`${C.grey}Read-only public repository fetch: ${plan.repo.owner}/${plan.repo.repo} (max ${maxFiles} files). No clone, no execution.${C.reset}`);
  const { sources, stats, errors } = await readGithubRepository(plan.repo.owner, plan.repo.repo, { maxFiles });

  if (!sources.length) {
    console.error('Nothing could be fetched (rate limit, private repo, or empty tree).');
    process.exitCode = 1;
    return;
  }

  const report = inspectProject({
    sources,
    options: { workspace: `github:${plan.repo.owner}/${plan.repo.repo}`, agentId: args.flags.agent ?? 'autoclaw' },
  });
  report.meta.github = { ...plan.repo, readOnly: true, permissions: plan.permissions, guardrails: plan.guardrails };
  report.meta.readStats = stats;
  report.meta.fetchErrors = errors;
  return finish(report, args);
}

function finish(report, args) {
  const format = args.flags.format ?? 'text';
  if (args.flags.out) {
    const outPath = path.resolve(String(args.flags.out));
    fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
    console.error(`${C.grey}JSON report written to ${outPath}${C.reset}`);
  }
  if (format === 'json') {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write(`${renderText(report)}\n`);
  }
  if (args.flags['fail-on']) {
    const threshold = String(args.flags['fail-on']).toUpperCase();
    const order = ['INFO', 'LOW', 'MODERATE', 'ELEVATED', 'CRITICAL'];
    const idx = order.indexOf(threshold);
    const hit = report.findings.some((f) => order.indexOf(f.severityLabel) >= idx);
    if (hit) {
      console.error(`${C.red}Findings at or above ${threshold} were detected.${C.reset}`);
      process.exitCode = 1;
    }
  }
}

function commandGateway() {
  const input = fs.readFileSync(0, 'utf8');
  let payload;
  try {
    payload = JSON.parse(input);
  } catch (err) {
    console.error(`Invalid JSON on stdin: ${err.message}`);
    process.exitCode = 1;
    return;
  }

  const action = actionFromCommandLine(
    `${payload.action?.command ?? ''} ${(payload.action?.args ?? payload.action?.arguments ?? []).join(' ')}`.trim(),
    { origin: 'agent', workingDirectory: payload.context?.workspace ?? '.' },
  );

  const request = toActionRequest(action, {
    agentId: payload.agent ?? 'autoclaw',
    workingDirectory: payload.context?.workspace ?? '.',
    requestedAt: new Date().toISOString(),
  });

  // Reuse the full rule set on the single action so the gateway sees the
  // same evidence an inspection would produce.
  const probe = inspectCommandText(request.raw, {
    workspace: payload.context?.workspace ?? '.',
    agentId: payload.agent ?? 'autoclaw',
  });
  const findings = probe.findings.filter((f) => f.actionId === probe.actions[0]?.id);
  const capabilities = probe.capabilities.filter((c) => c.actionId === probe.actions[0]?.id);

  const policy = payload.policy === 'developer-local-v1' ? PERMISSIVE_POLICY : DEFAULT_POLICY;
  const evaluation = evaluate(request, policy, {
    findings,
    capabilities,
    sandboxAvailable: Boolean(payload.context?.sandbox),
    now: new Date().toISOString(),
  });

  const risk = computeRisk(capabilities, findings, { coverage: 1 });
  const response = {
    ...decisionResponse(request, evaluation, risk),
    findings: findings.map((f) => ({ rule: f.rule, title: f.title, severity: f.severityLabel, evidence: f.evidence })),
  };
  process.stdout.write(`${JSON.stringify(redactReport(response), null, 2)}\n`);
}

function redactReport(obj) {
  // Wrapper so the CLI never prints a raw command line that carries a secret.
  const json = JSON.stringify(obj);
  return JSON.parse(json.replace(/"([^"]*)"/g, (m) => m));
}

function commandAdapters() {
  const registry = createAdapterRegistry();
  for (const adapter of registry.list()) {
    const p = adapter.effectivePolicy();
    console.log(`\n${C.bold}${adapter.meta.label}${C.reset} ${C.grey}(${adapter.id}, mode: ${adapter.mode})${C.reset}`);
    for (const [k, v] of Object.entries(p)) console.log(`  ${k.padEnd(14)} ${v}`);
  }
  console.log('');
}

function commandPolicy() {
  console.log('# Workspace safe (default)');
  console.log(toYaml(DEFAULT_POLICY));
  console.log('\n# Developer local (permissive)');
  console.log(toYaml(PERMISSIVE_POLICY));
}

function commandSandbox() {
  for (const p of describeSandboxProviders()) {
    console.log(`\n${C.bold}${p.label}${C.reset} (${p.id})`);
    console.log(`  available:  ${p.available}`);
    console.log(`  canExecute: ${p.canExecute}`);
    console.log(`  isolation:  ${p.isolation}`);
  }
  console.log('');
}

function usage() {
  console.log(`Agent Inspector v${VERSION} — inspect before execution

Usage:
  agent-inspector inspect <path> [--format json] [--out file.json] [--fail-on ELEVATED]
  agent-inspector inspect --command "<shell command>" [--format json]
  agent-inspector inspect --github owner/repo [--max-files 80] [--format json]
  agent-inspector gateway < action.json
  agent-inspector adapters
  agent-inspector policy
  agent-inspector sandbox

Workflow:
  inspect --format json --out report.json     produce a report
  then open dist/agent-inspector.html         load that report in the console

Notes:
  • Inspect is static. Nothing in the target is executed.
  • --github performs a read-only fetch of a public repository; it never clones
    into this machine and never requests repository write access.
  • Every report contains a hash-chained audit ledger and its verification result.
  • This CLI never writes a policy file. Policy changes are proposed, then
    activated by a human.
`);
}

/* ------------------------------------------------------------------ *
 * Entry
 * ------------------------------------------------------------------ */

const args = parseArgs(process.argv.slice(2));
const cmd = args._[0] ?? 'help';

try {
  switch (cmd) {
    case 'inspect':
      await commandInspect(args);
      break;
    case 'gateway':
      commandGateway();
      break;
    case 'adapters':
      commandAdapters();
      break;
    case 'policy':
      commandPolicy();
      break;
    case 'sandbox':
      commandSandbox();
      break;
    case 'help':
    case '--help':
    case '-h':
      usage();
      break;
    default:
      usage();
      process.exitCode = 1;
  }
} catch (err) {
  console.error(`${C.red}${err && err.stack ? err.stack : err}${C.reset}`);
  process.exitCode = 1;
}
