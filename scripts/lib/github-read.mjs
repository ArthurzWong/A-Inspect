/**
 * Read-only public GitHub fetch (Node only).
 *
 * Used by `agent-inspector inspect --github owner/repo`. This is the only
 * component in the project that touches the network, and it is:
 *   - read-only (no token required, no write calls, no repository clone);
 *   - bounded (file count, per-file size, and a modest concurrency limit);
 *   - text-only (files are fetched as strings for static analysis).
 *
 * Nothing fetched here is ever executed. If the API rate-limits us, that is
 * reported as an error rather than retried in a loop.
 */

const TEXT_EXT = /\.(mjs|cjs|js|jsx|ts|tsx|py|rb|php|go|rs|java|kt|sh|bash|zsh|ya?ml|toml|json|md|markdown|txt|rst|ini|cfg|conf|env|example|tf|dockerfile|lock|sum|mod|gradle|xml|properties|sql|html|css)$/i;
const NAME_OK = /(^|\/)(Dockerfile[^/]*|Makefile|justfile|AGENTS\.md|CLAUDE\.md|GEMINI\.md|SKILL\.md|\.cursorrules|\.mcp\.json|mcp\.json|\.env\.example|\.npmrc|\.gitignore)$/i;
const SIZE_CAP = 256 * 1024;

export async function readGithubRepository(owner, repo, opts = {}) {
  const maxFiles = opts.maxFiles ?? 80;
  const ref = opts.ref ?? null;
  const errors = [];
  const sources = [];

  const api = async (url) => {
    const res = await fetch(url, {
      headers: { accept: 'application/vnd.github+json', 'user-agent': 'agent-inspector/0.1.0' },
    });
    if (!res.ok) {
      errors.push(`${url} → HTTP ${res.status}`);
      return null;
    }
    return res.json();
  };

  const repoInfo = await api(`https://api.github.com/repos/${owner}/${repo}`);
  if (!repoInfo) return { sources, stats: { files: 0, bytes: 0 }, errors };

  const tree = await api(`https://api.github.com/repos/${owner}/${repo}/git/trees/${ref ?? repoInfo.default_branch}?recursive=1`);
  if (!tree || !Array.isArray(tree.tree)) return { sources, stats: { files: 0, bytes: 0 }, errors };

  const candidates = tree.tree
    .filter((n) => n.type === 'blob')
    .filter((n) => !n.path.includes('node_modules/'))
    .filter((n) => (n.size ?? 0) > 0 && (n.size ?? 0) <= SIZE_CAP)
    .filter((n) => TEXT_EXT.test(n.path) || NAME_OK.test(n.path))
    // Prefer the security-relevant files when the tree is large.
    .sort((a, b) => score(b.path) - score(a.path))
    .slice(0, maxFiles);

  const sha = tree.sha;
  let totalBytes = 0;

  // Modest concurrency: sequential chunks of 4, no tight loop.
  for (let i = 0; i < candidates.length; i += 4) {
    const chunk = candidates.slice(i, i + 4);
    const results = await Promise.all(chunk.map(async (node) => {
      const raw = `https://raw.githubusercontent.com/${owner}/${repo}/${sha}/${node.path}`;
      try {
        const res = await fetch(raw, { headers: { 'user-agent': 'agent-inspector/0.1.0' } });
        if (!res.ok) {
          errors.push(`${node.path} → HTTP ${res.status}`);
          return null;
        }
        const text = await res.text();
        if (text.includes('\u0000')) return null;
        return { path: node.path, content: text };
      } catch (err) {
        errors.push(`${node.path} → ${err.message}`);
        return null;
      }
    }));
    for (const r of results) {
      if (r) {
        sources.push(r);
        totalBytes += r.content.length;
      }
    }
  }

  return {
    sources: sources.sort((a, b) => a.path.localeCompare(b.path)),
    stats: { files: sources.length, bytes: totalBytes, totalInTree: tree.tree.length, ref: sha },
    errors,
  };
}

function score(path) {
  let s = 0;
  if (/(^|\/)(AGENTS|CLAUDE|GEMINI)\.md$/i.test(path)) s += 100;
  if (/(^|\/)(SKILL\.md|skills\/)/i.test(path)) s += 90;
  if (/(^|\/)(\.mcp|mcp)\.json$/i.test(path)) s += 95;
  if (/(^|\/)package\.json$/.test(path)) s += 80;
  if (/(Dockerfile|docker-compose)/i.test(path)) s += 60;
  if (/\.github\/workflows\//.test(path)) s += 55;
  if (/(^|\/)\.env\.example$/.test(path)) s += 40;
  if (/\.(sh|bash|mjs|cjs|js|ts|py|php)$/.test(path)) s += 30;
  if (/\.(md|txt)$/.test(path)) s += 10;
  if (/\.(json|ya?ml|toml)$/.test(path)) s += 15;
  return s;
}
