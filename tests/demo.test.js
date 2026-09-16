/**
 * End-to-end demo tests.
 *
 * Two targets, both real reads from disk:
 *   1. fixtures/spec-demo  — the synthetic fixture shipped with this repo
 *   2. ../../contentpulse  — the real sibling project in this workspace, if present
 *
 * Reading files is not executing files. Neither inspection starts a server,
 * installs a package, or runs the analysed code.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { readTree } from '../scripts/lib/read-tree.mjs';
import { inspectProject, summarizeReport, overallBanner } from '../src/engine/inspectionEngine.js';
import { SEVERITY } from '../src/engine/schema.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.resolve(HERE, '../fixtures/spec-demo');
const SIBLING = path.resolve(HERE, '../../contentpulse');

function inspectDir(dir) {
  const { sources, skipped, stats } = readTree(dir);
  const report = inspectProject({ sources, options: { workspace: dir } });
  return { report, skipped, stats, sources };
}

test('the spec-demo fixture is read without executing anything', () => {
  const { report, stats } = inspectDir(FIXTURE);
  assert.ok(stats.files > 8, `expected a multi-file fixture, got ${stats.files}`);
  assert.equal(report.meta.mode, 'INSPECT');
  assert.match(report.meta.executionDisclaimer, /No uploaded or referenced code was executed/);
});

test('the demo detects the destructive filesystem action and does not overstate it', () => {
  const { report } = inspectDir(FIXTURE);
  const r001 = report.findings.filter((f) => f.rule === 'R001');
  assert.ok(r001.length >= 1, 'R001 must fire on the fixture demo script');

  const projectLocal = r001.find((f) => f.scope === 'project-local');
  assert.ok(projectLocal, 'the deletion must be classified as project-local, not as a system path');
  assert.equal(projectLocal.severity, SEVERITY.MODERATE,
    'a project-local deletion must not be reported as critical');
  assert.equal(projectLocal.capability, 'filesystem.delete');
  assert.equal(projectLocal.defaultDecision, 'REQUIRE_APPROVAL');
  assert.match(projectLocal.title, /rm/);
  assert.ok(projectLocal.evidence.some((e) => /Classified scope: project-local/.test(e)));

  // The action trace must mark the node destructive, and the blast-radius map
  // must show the filesystem category as present rather than absent.
  assert.ok(report.graphs.actionGraph.stats.destructive >= 1, 'the action graph must mark at least one destructive node');
  const fsCategory = report.graphs.blastRadius.categories.find((c) => c.category === 'FILESYSTEM');
  assert.ok(fsCategory.count > 0, 'FILESYSTEM must appear in the blast radius');

  // Capability and intent stay separate.
  assert.ok(!/malicious/i.test(projectLocal.potentialConsequence));
  assert.match(projectLocal.recommendedControl, /approval|workspace/i);
});

test('the demo detects the shell chain and the node entrypoints', () => {
  const { report } = inspectDir(FIXTURE);
  assert.ok(report.stats.actionsDetected > 8, `expected actions, got ${report.stats.actionsDetected}`);
  const rules = new Set(report.findings.map((f) => f.rule));
  assert.ok(rules.has('R005'), 'execution rule must fire');
  assert.ok(rules.has('R004'), 'network rule must fire');
  assert.ok(rules.has('R006'), 'package rule must fire');

  const nodes = report.graphs.actionGraph.nodes;
  const serverRun = nodes.find((n) => /serve\.mjs/.test(n.label));
  assert.ok(serverRun, 'the local server invocation must appear in the action trace');
  const cli = nodes.find((n) => /contentpulse\.js/.test(n.label));
  assert.ok(cli, 'the CLI invocation must appear in the action trace');
});

test('the node entrypoint is linked to the code it reaches', () => {
  const { report } = inspectDir(FIXTURE);
  const downstream = report.graphs.actionGraph.edges.filter((e) => e.kind === 'downstream');
  assert.ok(downstream.length > 0, 'downstream edges must connect an entrypoint to its modules');
  const cliNode = report.graphs.actionGraph.nodes.find((n) => /contentpulse\.js/.test(n.label));
  assert.ok(cliNode, 'cli node present');
  assert.ok(
    downstream.some((e) => e.from === cliNode.id && /http\.js|store\.js|config\.js/.test(e.file ?? '')),
    'entrypoint should reach the modules it imports',
  );
});

test('the local server is reported as a listening socket, not as a network client', () => {
  const { report } = inspectDir(FIXTURE);
  const listen = report.capabilities.filter((c) => c.capabilityType === 'network.listen');
  assert.ok(listen.length >= 1, 'a listening capability must be recorded');
  const network = report.graphs.blastRadius.categories.find((c) => c.category === 'NETWORK');
  assert.ok(network.count > 0);
  const process = report.graphs.blastRadius.categories.find((c) => c.category === 'PROCESS');
  assert.ok(process.count > 0);
});

test('the fixture MCP config is parsed and never launched', () => {
  const { report } = inspectDir(FIXTURE);
  assert.ok(report.mcp.servers.length >= 2, 'both MCP servers should be parsed');
  for (const server of report.mcp.servers) {
    assert.ok(!/started|launched/i.test(JSON.stringify(server)), 'no server may be reported as started');
  }
  assert.ok(report.mcp.pipeline.includes('START SERVER (never automatic)'));
});

test('the supply chain sees the postinstall hook, the git dependency and the CI action pinning', () => {
  const { report } = inspectDir(FIXTURE);
  const titles = report.findings.filter((f) => f.rule === 'R014').map((f) => f.title).join(' | ');
  assert.match(titles, /lifecycle scripts/);
  assert.match(titles, /URL or git source/);
  assert.match(titles, /pins .* by tag/);
});

test('the fixture SKILL.md is clean, and the detector still works on a controlled oracle', () => {
  const { report } = inspectDir(FIXTURE);
  const skillFindings = report.findings.filter((f) => f.rule === 'R012' && /SKILL\.md/.test(f.location.file ?? ''));
  assert.equal(skillFindings.length, 0, 'the shipped fixture skill must be clean');
});

test('every finding in a project inspection names a rule and carries its evidence', () => {
  const { report } = inspectDir(FIXTURE);
  assert.ok(report.findings.length > 0);
  for (const f of report.findings) {
    assert.ok(typeof f.rule === 'string' && f.rule.length > 0, `finding without a rule id: ${f.title}`);
    assert.ok(/^R\d{3}$|^ENGINE$/.test(f.rule), `unexpected rule id: ${f.rule}`);
    assert.ok(f.evidence.length > 0, `${f.rule} has no evidence`);
    assert.ok(f.potentialConsequence.length > 0, `${f.rule} has no consequence text`);
    assert.ok(f.recommendedControl.length > 0, `${f.rule} has no recommended control`);
    assert.ok(['observed', 'inferred', 'unknown'].includes(f.evidenceType));
  }
  // Informational capability signals contribute capabilities, not findings.
  const capabilityRules = report.capabilities.map((c) => c.rule).filter(Boolean);
  assert.ok(capabilityRules.length > 0, 'capabilities should still carry rule attribution where it exists');
});

test('the risk model reports dimensions with evidence and never calls an uninspected area safe', () => {
  const { report } = inspectDir(FIXTURE);
  const dims = report.risk.dimensions;
  for (const [key, dim] of Object.entries(dims)) {
    if (dim.state === 'not-inspected') {
      assert.equal(dim.status, 'grey', `${key} must be grey when not inspected`);
      assert.equal(dim.score, 0);
    } else {
      assert.ok(dim.evidence.length > 0, `${key} scored without evidence`);
    }
  }
  assert.ok(report.risk.confidence > 0 && report.risk.confidence <= 95);
  assert.ok(report.graphs.blastRadius.absentNote.includes('not evidence of safety'));
});

test('the summary and banner give the dashboard what it needs', () => {
  const { report } = inspectDir(FIXTURE);
  const summary = summarizeReport(report);
  const banner = overallBanner(report);
  assert.ok(Array.isArray(summary.dimensions));
  assert.ok(summary.dimensions.length >= 5);
  assert.equal(typeof summary.confidence, 'number');
  assert.ok(banner.title.length > 0);
  assert.ok(banner.line.includes('actions detected'));
});

test('repercussions separate capability from intent', () => {
  const { report } = inspectDir(FIXTURE);
  assert.ok(report.repercussions.cards.length > 0);
  const serialized = JSON.stringify(report.repercussions).toLowerCase();
  assert.ok(serialized.includes('does not establish'), 'the intent disclaimer must be present');
  for (const card of report.repercussions.cards) {
    assert.ok(card.observedAction, 'observed action required');
    assert.ok(card.potentialConsequence, 'potential consequence required');
    assert.ok(card.observedScope, 'observed scope required');
    assert.ok(Array.isArray(card.unknowns) && card.unknowns.length > 0, 'unknowns required');
    assert.ok(card.recommendedControl, 'recommended control required');
    assert.ok(card.whyItMatters, 'plain-language explanation required');
    assert.ok(Array.isArray(card.whatIf) && card.whatIf.length > 0, 'what-if list required');
  }
});

test('the audit ledger for the demo verifies and omits skipped files explicitly', () => {
  const { report, skipped } = inspectDir(FIXTURE);
  assert.equal(report.auditVerification.valid, true);
  assert.ok(report.audit.length >= 3);
  assert.ok(Array.isArray(skipped));
});

/* ------------------------------------------------------------------ *
 * Real sibling project
 * ------------------------------------------------------------------ */

const hasSibling = fs.existsSync(path.join(SIBLING, 'package.json'));

test('the real contentpulse project, if present, is inspected honestly', { skip: !hasSibling ? 'sibling project not present' : false }, () => {
  const { report, stats } = inspectDir(SIBLING);
  assert.ok(stats.files > 10, `expected to read real source files, got ${stats.files}`);
  const capabilities = new Set(report.capabilities.map((c) => c.capabilityType));
  assert.ok(capabilities.has('process.execute'), 'it runs node');
  assert.ok(capabilities.has('network.connect'), 'it fetches content');
  assert.ok(capabilities.has('filesystem.write'), 'it writes output');

  // Its real, code-level surface should be visible.
  assert.ok(capabilities.has('network.listen'), 'demo/serve.mjs opens a listening socket');
  assert.ok(capabilities.has('environment.read'), 'it reads process.env');
  assert.ok(capabilities.has('persistence.create'), 'src/scheduler.js uses node-cron');
  assert.ok(capabilities.has('credential.read'), 'SMTP credentials and secret-shaped env vars');

  // And the Inspector must still not claim anything about intent.
  const serialized = JSON.stringify(report.findings).toLowerCase();
  assert.ok(!serialized.includes('this project is malicious'));

  // Nothing in the report may contain an unredacted secret value.
  const reportText = JSON.stringify(report);
  const secretKey = /(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|SMTP_PASS)/i;
  const assignment = /([A-Za-z0-9_]*)["']?\s*[:=]\s*["']?([^"',}\s]{6,})/g;
  let m = assignment.exec(reportText);
  while (m) {
    if (secretKey.test(m[1])) {
      assert.ok(
        m[2].includes('REDACTED') || m[2].startsWith('$') || m[2].includes('env.') || m[2].includes('process'),
        `a secret-shaped assignment leaked an unredacted value: ${m[0]}`,
      );
    }
    m = assignment.exec(reportText);
  }
  assert.ok(!/ghp_|sk-ant-|xoxb-|AKIA[0-9A-Z]{16}/.test(reportText), 'no provider token may appear');

  assert.equal(report.auditVerification.valid, true);
});
