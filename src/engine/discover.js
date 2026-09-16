/**
 * Target discovery (spec §13).
 *
 * Given a set of sources, decide which of them matter for security review
 * and what kind of artifact each one is. Nothing here touches the network
 * or the host: it is a classifier over an in-memory file list.
 */

import { languageOf } from './codeScan.js';

export const TARGET_PATTERNS = [
  { kind: 'agent-config', label: 'Agent configuration', re: /(^|\/)(AGENTS|CLAUDE|GEMINI|COPILOT|CURSOR)\.md$/i },
  { kind: 'agent-config', label: 'Cursor rules', re: /(^|\/)\.cursorrules$|(^|\/)\.cursor\// },
  { kind: 'agent-config', label: 'Agent dotfile', re: /(^|\/)\.(opencode|aider|continue|windsurf)\// },
  { kind: 'mcp', label: 'MCP configuration', re: /(^|\/)(\.mcp|mcp)\.json$|(^|\/)mcp\.json$|(^|\/)\.vscode\/mcp\.json$/ },
  { kind: 'skill', label: 'Agent skill', re: /(^|\/)SKILL\.md$|(^|\/)skills\// },
  { kind: 'manifest', label: 'Package manifest', re: /(^|\/)package\.json$/ },
  { kind: 'lockfile', label: 'Lockfile', re: /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb|npm-shrinkwrap\.json|poetry\.lock|uv\.lock|composer\.lock|go\.sum)$/ },
  { kind: 'manifest', label: 'Python manifest', re: /(^|\/)(requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py|setup\.cfg)$/ },
  { kind: 'manifest', label: 'Other manifest', re: /(^|\/)(composer\.json|go\.mod|Cargo\.toml|Gemfile|build\.gradle|pom\.xml)$/ },
  { kind: 'container', label: 'Container definition', re: /(^|\/)(Dockerfile[^/]*|docker-compose\.ya?ml|compose\.ya?ml|\.dockerignore)$/ },
  { kind: 'env', label: 'Environment template', re: /(^|\/)\.env(\.example|\.sample|\.template)?$/ },
  { kind: 'ci', label: 'CI/CD workflow', re: /(^|\/)\.github\/workflows\/.*\.ya?ml$|(^|\/)\.gitlab-ci\.yml$|(^|\/)\.circleci\// },
  { kind: 'infra', label: 'Infrastructure as code', re: /\.tf$|\.tfvars$|(^|\/)k8s\/|(^|\/)kubernetes\/|(^|\/)helm\// },
  { kind: 'script', label: 'Shell script', re: /\.(sh|bash|zsh)$|(^|\/)(Makefile|makefile|justfile)$/ },
  { kind: 'code', label: 'Source code', re: /\.(mjs|cjs|js|jsx|ts|tsx|py|rb|php|go|rs|java|kt|c|cpp|cs)$/ },
  { kind: 'prose', label: 'Documentation', re: /\.(md|markdown|txt|rst|adoc)$/ },
  { kind: 'config', label: 'Configuration', re: /\.(json|ya?ml|toml|ini|cfg|conf|properties)$/ },
];

export function classifySourceKind(path) {
  const p = String(path ?? '');
  for (const t of TARGET_PATTERNS) {
    if (t.re.test(p)) return { kind: t.kind, label: t.label };
  }
  return { kind: 'other', label: 'Other file' };
}

/**
 * Discovery summary. `counts` answers "did this project even have an agent
 * config / MCP config / lockfile", which the report states explicitly so a
 * missing artifact is never silently read as "clean".
 */
export function discoverTargets(sources) {
  const byKind = {};
  const targets = [];

  for (const s of sources) {
    const path = String(s.path ?? '');
    const { kind, label } = classifySourceKind(path);
    const language = languageOf(path);
    byKind[kind] = byKind[kind] ?? { kind, label, count: 0, files: [] };
    byKind[kind].count += 1;
    if (byKind[kind].files.length < 40) byKind[kind].files.push(path);
    targets.push({ path, kind, label, language, size: (s.content ?? '').length });
  }

  const counts = Object.fromEntries(Object.entries(byKind).map(([k, v]) => [k, v.count]));

  const expectations = [
    { key: 'agent-config', prompt: 'No agent instruction file (AGENTS.md / CLAUDE.md) was found.' },
    { key: 'mcp', prompt: 'No MCP configuration was found.' },
    { key: 'skill', prompt: 'No agent skill definition was found.' },
    { key: 'lockfile', prompt: 'No lockfile was found, so dependency versions are not pinned.' },
    { key: 'container', prompt: 'No container definition was found.' },
  ];
  const notFound = expectations.filter((e) => !counts[e.key]).map((e) => ({ kind: e.key, note: e.prompt }));

  return { targets, byKind, counts, notFound, total: targets.length };
}

export const DISCOVERY_TARGETS_SPEC = [
  'AGENTS.md', 'CLAUDE.md', 'GEMINI.md', '.cursor/', '.cursorrules', '.github/',
  '.mcp.json', 'mcp.json', 'skills/', 'SKILL.md', 'package.json', 'package-lock.json',
  'pnpm-lock.yaml', 'requirements.txt', 'pyproject.toml', 'Dockerfile', 'docker-compose.yml',
  '.env.example', 'scripts/', 'bin/', 'Makefile',
];
