/**
 * GitHub App adapter (spec §12, §13, §34).
 *
 * Least privilege by construction: the permission set below is a constant,
 * read-only, and the client refuses write calls unless a caller passes an
 * explicit capability token. Webhook deliveries are signature-checked with
 * HMAC-SHA256 over the raw body, which is the check GitHub documents.
 *
 * Nothing here clones a repository into the application's runtime
 * filesystem. Files are fetched as text for static analysis, or the local
 * CLI reads a checkout the user already has.
 */

import { hmacSha256, timingSafeEqual, sha256 } from '../crypto/sha256.js';

/** Read-only by design. Do not add write permissions without a policy change. */
export const GITHUB_APP_PERMISSIONS = {
  contents: 'read',
  metadata: 'read',
  pull_requests: 'read',
  issues: 'read',
  actions: 'read',
  // Explicitly not requested in the MVP:
  // contents: write, pull_requests: write, checks: write, workflows: write
};

export const GITHUB_FORBIDDEN_PERMISSIONS = [
  'contents:write',
  'pull_requests:write',
  'checks:write',
  'workflows:write',
  'administration:write',
  'secrets:write',
];

export const GITHUB_INSPECTION_WORKFLOW = [
  'CONNECT GITHUB',
  'SELECT REPOSITORY',
  'CREATE INSPECTION',
  'CLONE INTO EPHEMERAL SANDBOX',
  'STATIC ANALYSIS',
  'DEPENDENCY ANALYSIS',
  'AGENT CONFIGURATION DISCOVERY',
  'RISK GRAPH',
  'REPORT',
];

export const GITHUB_LATER = ['PR security comment', 'PR status check', 'automatic re-scan'];

/** Accepts https URLs and `owner/repo` shorthand. */
export function parseRepoUrl(input) {
  const s = String(input ?? '').trim().replace(/\.git$/, '').replace(/\/$/, '');
  const m1 = /^https?:\/\/github\.com\/([^/\s]+)\/([^/\s#?]+)/i.exec(s);
  if (m1) return { owner: m1[1], repo: m1[2] };
  const m2 = /^([\w.-]+)\/([\w.-]+)$/.exec(s);
  if (m2) return { owner: m2[1], repo: m2[2] };
  return null;
}

/**
 * Validate a GitHub webhook signature.
 * @param {string} rawBody   the exact bytes received (do not re-serialize)
 * @param {string} signature value of the X-Hub-Signature-256 header
 * @param {string} secret    the configured webhook secret
 */
export function verifyWebhookSignature(rawBody, signature, secret) {
  if (!secret) return { ok: false, reason: 'no webhook secret configured' };
  if (!signature) return { ok: false, reason: 'missing signature header' };
  const expected = `sha256=${hmacSha256(secret, rawBody)}`;
  const ok = timingSafeEqual(expected, String(signature).trim());
  return { ok, reason: ok ? 'signature valid' : 'signature mismatch', expectedPrefix: `sha256=${expected.slice(7, 15)}…` };
}

/**
 * Build a GitHub inspection plan for a repository reference.
 * The plan is inert: it lists the steps and the guardrails, and performs
 * no network call. Actual fetching is done by the caller's client.
 */
export function planRepositoryInspection(repoUrl) {
  const parsed = parseRepoUrl(repoUrl);
  if (!parsed) {
    return { ok: false, reason: 'Could not parse repository reference. Expected https://github.com/owner/repo or owner/repo.' };
  }
  return {
    ok: true,
    repo: parsed,
    permissions: GITHUB_APP_PERMISSIONS,
    steps: GITHUB_INSPECTION_WORKFLOW,
    guardrails: [
      'Read-only GitHub App permissions; no write scope is requested in the MVP.',
      'Files are fetched as text for static analysis, never executed.',
      'No repository is cloned into the application runtime filesystem; cloning happens in an ephemeral sandbox if at all.',
      'Webhook deliveries must pass signature validation before their content is trusted.',
    ],
    targetsSpec: 'See discovery spec: AGENTS.md, CLAUDE.md, .mcp.json, skills/, package.json, lockfiles, Dockerfiles, CI workflows.',
  };
}

/**
 * Minimal API client. Read-only by construction: write helpers require the
 * explicit `allowWrite` capability, which the MVP never grants.
 */
export function createGitHubClient(config = {}) {
  const fetchImpl = config.fetchImpl ?? (typeof fetch === 'function' ? fetch : null);
  const base = config.apiBase ?? 'https://api.github.com';
  const headers = {
    accept: 'application/vnd.github+json',
    'user-agent': 'agent-inspector/0.1.0',
    ...(config.token ? { authorization: `Bearer ${config.token}` } : {}),
  };

  async function api(path, options = {}) {
    if (!fetchImpl) return { ok: false, reason: 'no fetch implementation available' };
    if (options.method && options.method !== 'GET' && !config.allowWrite) {
      return { ok: false, reason: 'write operations are disabled: the MVP is read-only by policy' };
    }
    try {
      const res = await fetchImpl(`${base}${path}`, { ...options, headers: { ...headers, ...(options.headers ?? {}) } });
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch { /* non-JSON error body */ }
      return { ok: res.ok, status: res.status, json, text };
    } catch (err) {
      return { ok: false, reason: String(err && err.message) };
    }
  }

  return {
    permissions: GITHUB_APP_PERMISSIONS,
    readOnly: !config.allowWrite,
    listTree: (owner, repo, ref = 'HEAD') => api(`/repos/${owner}/${repo}/git/trees/${ref}?recursive=1`),
    getFile: (owner, repo, path, ref) => api(`/repos/${owner}/${repo}/contents/${encodeURI(path)}${ref ? `?ref=${ref}` : ''}`),
    getRepo: (owner, repo) => api(`/repos/${owner}/${repo}`),
    listPullRequests: (owner, repo) => api(`/repos/${owner}/${repo}/pulls?state=open&per_page=20`),
    listCommits: (owner, repo, ref) => api(`/repos/${owner}/${repo}/commits?sha=${ref ?? ''}&per_page=20`),
    /** Explicitly gated. Present so the interface is complete, not so it is used. */
    postPrComment: (owner, repo, number, body) => api(`/repos/${owner}/${repo}/issues/${number}/comments`, {
      method: 'POST',
      body: JSON.stringify({ body }),
    }),
    _api: api,
  };
}

/** Stable fingerprint of a repository state, used to make re-scans comparable. */
export function repositoryFingerprint(files) {
  const sorted = files
    .map((f) => `${f.path}:${sha256(String(f.content ?? '')).slice(0, 16)}`)
    .sort();
  return sha256(sorted.join('\n'));
}
