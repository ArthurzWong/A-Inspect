/**
 * Graph construction (spec §4, §5, §14).
 *
 * Three graphs, all derived from the same analysis:
 *   actionGraph     — the execution chain, parent → child
 *   blastRadius     — capability → resource, grouped into categories
 *   dependencyGraph — manifests → direct dependencies
 *
 * The interesting piece is `buildDownstreamIndex`: a small static module
 * graph. It is what lets the Inspector answer "what does
 * `node bin/contentpulse.js` actually reach?" without running anything —
 * by following relative imports from the entrypoint to the files it loads.
 */

import { CAPABILITY, SEVERITY, severityLabel, severityStatus } from './schema.js';
import { classifySourceKind } from './discover.js';

/* ------------------------------------------------------------------ *
 * Category mapping (spec §5)
 * ------------------------------------------------------------------ */

export const BLAST_CATEGORIES = [
  'FILESYSTEM', 'PROCESS', 'NETWORK', 'CREDENTIALS', 'IDENTITY',
  'GIT', 'CLOUD', 'DATABASE', 'EXTERNAL SERVICES', 'AGENT TOOLS',
];

export const CAPABILITY_CATEGORY = {
  'filesystem.read': 'FILESYSTEM',
  'filesystem.write': 'FILESYSTEM',
  'filesystem.delete': 'FILESYSTEM',
  'process.execute': 'PROCESS',
  'process.spawn': 'PROCESS',
  'process.background': 'PROCESS',
  'process.signal': 'PROCESS',
  'persistence.create': 'PROCESS',
  'network.connect': 'NETWORK',
  'network.listen': 'NETWORK',
  'network.egress': 'NETWORK',
  'browser.navigate': 'NETWORK',
  'credential.read': 'CREDENTIALS',
  'environment.read': 'CREDENTIALS',
  'cloud.read': 'CLOUD',
  'cloud.write': 'CLOUD',
  'cloud.delete': 'CLOUD',
  'cloud.deploy': 'CLOUD',
  'cloud.secret': 'CREDENTIALS',
  'container.run': 'CLOUD',
  'privilege.escalate': 'IDENTITY',
  'git.read': 'GIT',
  'git.write': 'GIT',
  'database.write': 'DATABASE',
  'supply_chain.install': 'EXTERNAL SERVICES',
  'mcp.server': 'AGENT TOOLS',
  'agent.chain': 'AGENT TOOLS',
  'agent.prompt_injection': 'AGENT TOOLS',
};

/* ------------------------------------------------------------------ *
 * Static module graph
 * ------------------------------------------------------------------ */

const IMPORT_RE = /(?:^|\n)\s*(?:import\s+[^'"\n]*?from\s*['"]([^'"]+)['"]|import\s*['"]([^'"]+)['"]|(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"]\s+import)/g;

export function parseImportSpecifiers(content) {
  const out = [];
  const text = String(content ?? '');
  let m = IMPORT_RE.exec(text);
  while (m) {
    const spec = m[1] ?? m[2] ?? m[3] ?? m[4];
    if (spec) out.push(spec);
    m = IMPORT_RE.exec(text);
  }
  return Array.from(new Set(out));
}

function normalizePath(p) {
  const parts = String(p).replace(/^\.\//, '').split('/');
  const stack = [];
  for (const part of parts) {
    if (part === '.' || part === '') continue;
    if (part === '..') stack.pop();
    else stack.push(part);
  }
  return stack.join('/');
}

export function resolveSpecifier(fromPath, spec, allPaths) {
  if (!spec.startsWith('.')) return null; // external package: not a project file
  const baseDir = String(fromPath).split('/').slice(0, -1).join('/');
  const target = normalizePath(`${baseDir}/${spec}`);
  const candidates = [
    target,
    `${target}.js`, `${target}.mjs`, `${target}.cjs`, `${target}.ts`,
    `${target}/index.js`, `${target}/index.mjs`, `${target}/index.ts`,
    target.replace(/\.js$/, '.ts'),
  ];
  for (const c of candidates) {
    if (allPaths.has(c)) return c;
  }
  return null;
}

/**
 * Build a map: entry file → every project file reachable through relative
 * imports. Depth-limited and cycle-safe.
 */
export function buildDownstreamIndex(sources, maxDepth = 6) {
  const byPath = new Map();
  for (const s of sources) byPath.set(normalizePath(s.path), String(s.content ?? ''));
  const allPaths = new Set(byPath.keys());

  const index = new Map();
  for (const entry of allPaths) {
    const reachable = new Set();
    const queue = [{ path: entry, depth: 0 }];
    while (queue.length) {
      const { path, depth } = queue.shift();
      if (depth > maxDepth) continue;
      const content = byPath.get(path);
      if (content == null) continue;
      for (const spec of parseImportSpecifiers(content)) {
        const resolved = resolveSpecifier(path, spec, allPaths);
        if (!resolved || reachable.has(resolved)) continue;
        reachable.add(resolved);
        queue.push({ path: resolved, depth: depth + 1 });
      }
    }
    index.set(entry, Array.from(reachable));
  }
  return index;
}

/** Entrypoint referenced by an action, if any (`node bin/x.js` → bin/x.js). */
export function entrypointOf(action, knownPaths) {
  const args = action.arguments ?? [];
  for (const a of args) {
    const clean = String(a).replace(/^\.\//, '');
    if (knownPaths.has(clean)) return clean;
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * Action graph
 * ------------------------------------------------------------------ */

export function buildActionGraph(actions, findings, capabilities, ctx = {}) {
  const findingsByAction = new Map();
  for (const f of findings) {
    if (!f.actionId) continue;
    if (!findingsByAction.has(f.actionId)) findingsByAction.set(f.actionId, []);
    findingsByAction.get(f.actionId).push(f);
  }
  const capsByAction = new Map();
  for (const c of capabilities) {
    if (!c.actionId) continue;
    if (!capsByAction.has(c.actionId)) capsByAction.set(c.actionId, []);
    capsByAction.get(c.actionId).push(c);
  }

  const nodes = actions.map((a) => {
    const f = findingsByAction.get(a.id) ?? [];
    const severity = f.reduce((m, x) => Math.max(m, x.severity), 0);
    const kind = classifySourceKind(a.sourceFile ?? '');
    return {
      id: a.id,
      label: a.raw || `${a.command} ${(a.arguments ?? []).join(' ')}`.trim(),
      command: a.command,
      actionType: a.actionType,
      origin: a.origin,
      language: a.language,
      file: a.sourceFile,
      line: a.lineNumber,
      evidenceType: a.evidenceType,
      severity,
      severityLabel: severityLabel(severity),
      status: severity ? severityStatus(severity) : 'grey',
      findingIds: f.map((x) => x.id),
      rules: Array.from(new Set(f.map((x) => x.rule).filter(Boolean))),
      capabilities: (capsByAction.get(a.id) ?? []).map((c) => c.capabilityType),
      note: a.note,
      fileKind: kind.kind,
    };
  });

  const edges = [];
  const byId = new Map(nodes.map((n) => [n.id, n]));

  // 1. Explicit parent → child.
  for (const a of actions) {
    if (a.parentId && byId.has(a.parentId)) {
      edges.push({ from: a.parentId, to: a.id, kind: 'child' });
    }
  }

  // 2. Sequential flow inside a script (line order, same file, no parent).
  const byFile = new Map();
  for (const a of actions) {
    if (!a.sourceFile || a.parentId) continue;
    if (!byFile.has(a.sourceFile)) byFile.set(a.sourceFile, []);
    byFile.get(a.sourceFile).push(a);
  }
  for (const [file, list] of byFile) {
    const ordered = list.slice().sort((x, y) => (x.lineNumber ?? 0) - (y.lineNumber ?? 0));
    for (let i = 1; i < ordered.length; i += 1) {
      edges.push({ from: ordered[i - 1].id, to: ordered[i].id, kind: 'sequence', file });
    }
  }

  // 3. Downstream: an interpreter action linked to the code it reaches.
  const downstreamIndex = ctx.downstreamIndex ?? new Map();
  const knownPaths = ctx.knownPaths ?? new Set();
  const codeActionsByFile = new Map();
  for (const a of actions) {
    if (a.origin !== 'code' || !a.sourceFile) continue;
    if (!codeActionsByFile.has(a.sourceFile)) codeActionsByFile.set(a.sourceFile, []);
    codeActionsByFile.get(a.sourceFile).push(a);
  }
  for (const a of actions) {
    if (a.origin === 'code') continue;
    const entry = entrypointOf(a, knownPaths);
    if (!entry) continue;
    const reached = new Set([entry, ...(downstreamIndex.get(entry) ?? [])]);
    for (const file of reached) {
      for (const child of codeActionsByFile.get(file) ?? []) {
        edges.push({ from: a.id, to: child.id, kind: 'downstream', file });
      }
    }
    if (reached.size > 1) {
      const node = byId.get(a.id);
      if (node) node.downstreamFiles = Array.from(reached);
    }
  }

  const roots = nodes.filter((n) => !edges.some((e) => e.to === n.id)).map((n) => n.id);

  return {
    nodes,
    edges,
    roots,
    stats: {
      nodes: nodes.length,
      edges: edges.length,
      destructive: nodes.filter((n) => n.rules.includes('R001')).length,
      executors: nodes.filter((n) => n.capabilities.includes(CAPABILITY.PROC_EXECUTE)).length,
      servers: nodes.filter((n) => n.capabilities.includes(CAPABILITY.NET_LISTEN)).length,
    },
  };
}

/* ------------------------------------------------------------------ *
 * Blast radius
 * ------------------------------------------------------------------ */

export function buildBlastRadius(capabilities, actions, findings) {
  const actionById = new Map(actions.map((a) => [a.id, a]));
  const findingByAction = new Map();
  for (const f of findings) {
    if (!f.actionId) continue;
    if (!findingByAction.has(f.actionId)) findingByAction.set(f.actionId, []);
    findingByAction.get(f.actionId).push(f);
  }

  const categories = {};
  for (const cat of BLAST_CATEGORIES) {
    categories[cat] = {
      category: cat,
      status: 'grey',
      score: 0,
      scoreLabel: severityLabel(0),
      count: 0,
      items: [],
      untested: true,
    };
  }

  for (const c of capabilities) {
    const cat = CAPABILITY_CATEGORY[c.capabilityType];
    if (!cat || !categories[cat]) continue;
    const bucket = categories[cat];
    bucket.count += 1;
    bucket.untested = false;
    bucket.score = Math.max(bucket.score, c.riskLevel ?? 0);
    const action = actionById.get(c.actionId);
    if (bucket.items.length < 30) {
      bucket.items.push({
        capability: c.capabilityType,
        target: c.target ?? 'unknown',
        scope: c.scope,
        rule: c.rule,
        severity: c.riskLevel,
        severityLabel: severityLabel(c.riskLevel ?? 0),
        status: severityStatus(c.riskLevel ?? 0),
        evidence: c.evidence,
        actionId: c.actionId,
        action: action?.raw ?? c.evidence,
        file: action?.sourceFile ?? null,
        line: action?.lineNumber ?? null,
      });
    }
  }

  for (const cat of BLAST_CATEGORIES) {
    const b = categories[cat];
    if (b.count === 0) {
      b.status = 'grey';
      b.scoreLabel = 'NOT OBSERVED';
    } else {
      b.status = severityStatus(b.score);
      b.scoreLabel = severityLabel(b.score);
    }
  }

  const present = BLAST_CATEGORIES.map((c) => categories[c]).filter((c) => c.count > 0);
  const absent = BLAST_CATEGORIES.map((c) => categories[c]).filter((c) => c.count === 0);

  return {
    agent: { label: 'AGENT', sublabel: 'detected capability surface' },
    categories: BLAST_CATEGORIES.map((c) => categories[c]),
    present,
    absent,
    stats: {
      categoriesObserved: present.length,
      categoriesNotObserved: absent.length,
      totalNodes: capabilities.length,
      highest: present.reduce((m, c) => Math.max(m, c.score), 0),
    },
    /** Absence must be stated as "not observed", never as "safe". */
    absentNote: 'Categories marked NOT OBSERVED had no evidence in the inspected set. That is an absence of evidence, not evidence of safety.',
  };
}

/* ------------------------------------------------------------------ *
 * Dependency graph
 * ------------------------------------------------------------------ */

export function buildDependencyGraph(sources, hasLockfile) {
  const nodes = [];
  const edges = [];
  const byPath = new Map(sources.map((s) => [String(s.path).replace(/^\.\//, ''), s]));

  for (const [path, source] of byPath) {
    if (!/(^|\/)package\.json$/.test(path)) continue;
    let pkg;
    try { pkg = JSON.parse(source.content); } catch { continue; }
    const projectId = `proj:${path}`;
    nodes.push({ id: projectId, label: pkg.name ?? path, kind: 'project', group: path });
    for (const [group, deps] of Object.entries({
      dependencies: pkg.dependencies ?? {},
      devDependencies: pkg.devDependencies ?? {},
      optionalDependencies: pkg.optionalDependencies ?? {},
    })) {
      for (const [name, spec] of Object.entries(deps)) {
        const id = `dep:${path}:${name}`;
        nodes.push({
          id,
          label: `${name}@${spec}`,
          kind: 'dependency',
          group,
          name,
          spec,
          pinned: !/^[\^~*]/.test(String(spec)) && !/^(latest|next|x|\*)$/i.test(String(spec)),
          remote: /^(git|github:|gitlab:|https?:|file:|link:)/i.test(String(spec)),
        });
        edges.push({ from: projectId, to: id, kind: group });
      }
    }
    nodes.push({
      id: `lock:${path}`,
      label: hasLockfile ? 'lockfile present' : 'NO LOCKFILE',
      kind: 'lockfile',
      present: hasLockfile,
    });
    edges.push({ from: projectId, to: `lock:${path}`, kind: 'integrity' });
  }

  const deps = nodes.filter((n) => n.kind === 'dependency');
  return {
    nodes,
    edges,
    stats: {
      projects: nodes.filter((n) => n.kind === 'project').length,
      dependencies: deps.length,
      unpinned: deps.filter((d) => !d.pinned).length,
      remote: deps.filter((d) => d.remote).length,
      hasLockfile,
    },
    states: {
      knownLockfile: hasLockfile,
      note: 'Dependencies are listed for visibility. The Inspector makes no trust claim about a package unless a specific rule matched it.',
    },
  };
}
