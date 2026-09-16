/**
 * ActionNormalizer (spec §8, §33).
 *
 * Turns raw observable things — a command line, a shell script, a
 * package.json script, a Dockerfile instruction, a code construct — into
 * the normalized `ActionRequest` shape the PolicyEngine evaluates.
 *
 * Pure functions, no I/O, no execution. Same input always yields the same
 * ActionRequest.
 */

import { CAPABILITY, EVIDENCE, SCOPE, makeAction } from './schema.js';
import { parseShell, parseCommand } from './shell.js';

/* ------------------------------------------------------------------ *
 * Path + URL classification
 * ------------------------------------------------------------------ */

const SYSTEM_PREFIXES = [
  '/etc', '/usr', '/bin', '/sbin', '/var', '/opt', '/root', '/boot',
  '/System', '/Library', '/Applications', '/private', '/dev', '/proc', '/sys',
  'C:\\Windows', 'C:\\Program Files',
];

const CREDENTIAL_HINTS = [
  '.ssh', '.aws', '.gnupg', '.npmrc', '.netrc', '.docker/config.json',
  '.kube/config', 'credentials', 'id_rsa', 'id_ed25519', '.pem', '.p12', '.pfx',
  'keychain', '.env', '.git-credentials', '.config/gcloud', '.config/gh', '.claude.json',
];

const PRIVATE_IP_RE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|127\.|0\.0\.0\.0|::1|fc00:|fe80:)/i;

/** Where does a path live, relative to the workspace we were given? */
export function classifyPathScope(target, workspace = '.') {
  if (!target) return SCOPE.UNKNOWN;
  let t = String(target).trim().replace(/^["']|["']$/g, '');
  if (!t || t === 'unknown') return SCOPE.UNKNOWN;

  const ws = String(workspace).replace(/\/+$/, '');
  let normalized = t.replace(/\/+$/, '');
  // A root path normalises to an empty string; restore it so `/` is not
  // mistaken for a relative path.
  if (!normalized) normalized = '/';

  if (normalized === '/' || /^[A-Za-z]:\\?$/.test(normalized)) return SCOPE.SYSTEM;

  if (normalized === '.' || normalized === './' || normalized.startsWith('./')) return SCOPE.PROJECT_LOCAL;
  if (normalized.startsWith('$') || normalized.startsWith('${')) return SCOPE.UNKNOWN;
  if (normalized === '~' || normalized.startsWith('~/') || normalized.startsWith('$HOME')) {
    const lower = normalized.toLowerCase();
    if (CREDENTIAL_HINTS.some((h) => lower.includes(h.toLowerCase()))) return SCOPE.USER_HOME;
    return SCOPE.USER_HOME;
  }
  if (SYSTEM_PREFIXES.some((p) => normalized === p || normalized.startsWith(`${p}/`))) return SCOPE.SYSTEM;
  if (normalized.startsWith('/')) {
    if (ws && normalized.startsWith(ws)) return SCOPE.PROJECT_LOCAL;
    return SCOPE.SYSTEM;
  }
  if (/^[A-Za-z]:\\/.test(normalized)) return SCOPE.SYSTEM;
  if (normalized.includes('..')) {
    // Escaping the working directory.
    return SCOPE.WORKSPACE;
  }
  return SCOPE.PROJECT_LOCAL;
}

export function looksLikeCredentialPath(target) {
  if (!target) return false;
  const lower = String(target).toLowerCase();
  return CREDENTIAL_HINTS.some((h) => lower.includes(h.toLowerCase()));
}

/** Classify a URL into the network scopes of spec §9 R004 / R010. */
export function classifyUrl(url, approvedDomains = []) {
  let raw = String(url ?? '').trim().replace(/^["']|["']$/g, '');
  if (!raw) return { scope: SCOPE.UNKNOWN, host: null, protocol: null, metadata: false };
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    if (raw.startsWith('/') || raw.startsWith('#')) return { scope: SCOPE.PROJECT_LOCAL, host: null, protocol: 'relative', metadata: false };
    raw = `https://${raw}`;
  }
  let parsed;
  try {
    parsed = new URL(raw.replace(/\$\{[^}]*\}/g, 'unknown'));
  } catch {
    return { scope: SCOPE.UNKNOWN, host: null, protocol: null, metadata: false };
  }
  const host = parsed.hostname.toLowerCase();
  const metadata = host === '169.254.169.254' || host === 'metadata.google.internal' || host === '100.100.100.200';
  const loopback = host === 'localhost' || host === '::1' || host === '[::1]' || host === '0.0.0.0'
    || host.endsWith('.localhost') || /^127\./.test(host) || /^0\.0\.0\.0$/.test(host);
  let scope;
  if (loopback) scope = SCOPE.NETWORK_LOCAL;
  else if (PRIVATE_IP_RE.test(host)) scope = SCOPE.NETWORK_PRIVATE;
  else if (approvedDomains.some((d) => host === d || host.endsWith(`.${d}`))) scope = SCOPE.NETWORK_APPROVED;
  else scope = SCOPE.NETWORK_PUBLIC;
  return { scope, host, protocol: parsed.protocol.replace(':', ''), metadata, url: parsed.toString() };
}

export function extractUrls(text) {
  // Note: the backtick is written as \x60 so the source contains no bare
  // backtick inside a regex literal (which would confuse naive tooling).
  const re = /\bhttps?:\/\/[^\s"'\x60<>)\]}]+/g;
  const found = String(text ?? '').match(re) ?? [];
  return Array.from(new Set(found.map((u) => u.replace(/[.,;:]+$/, ''))));
}

/* ------------------------------------------------------------------ *
 * Command knowledge base
 * ------------------------------------------------------------------ */

/** Commands that are read-only and therefore low risk by themselves. */
export const READ_ONLY_PROGRAMS = new Set([
  'ls', 'cat', 'head', 'tail', 'wc', 'file', 'stat', 'find', 'grep', 'rg', 'awk', 'sed',
  'echo', 'printf', 'pwd', 'whoami', 'id', 'env', 'printenv', 'date', 'which', 'type',
  'sort', 'uniq', 'cut', 'tr', 'diff', 'du', 'df', 'tree', 'jq', 'yq', 'test', '[', '[[',
  'sleep', 'true', 'false', 'basename', 'dirname', 'realpath', 'readlink', 'sha256sum', 'shasum',
]);

export const SHELL_PROGRAMS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'fish', 'cmd', 'powershell', 'pwsh']);

export const INTERPRETERS = new Set(['node', 'python', 'python3', 'py', 'ruby', 'perl', 'php', 'deno', 'bun', 'ts-node', 'tsx', 'npx', 'uv', 'uvx']);

export const DOWNLOADERS = new Set(['curl', 'wget', 'fetch', 'aria2c', 'httpie', 'http', 'nc', 'ncat', 'netcat', 'telnet', 'ssh', 'scp', 'sftp', 'rsync']);

export const PACKAGE_MANAGERS = new Set(['npm', 'pnpm', 'yarn', 'bun', 'pip', 'pip3', 'uv', 'poetry', 'cargo', 'gem', 'composer', 'go', 'brew', 'apt', 'apt-get', 'yum', 'dnf', 'pacman', 'apk', 'nix', 'choco', 'winget']);

export const CLOUD_PROGRAMS = new Set(['aws', 'gcloud', 'az', 'terraform', 'tofu', 'pulumi', 'kubectl', 'helm', 'docker', 'docker-compose', 'podman', 'vercel', 'netlify', 'supabase', 'firebase', 'heroku', 'flyctl', 'railway', 'wrangler', 'sam', 'serverless', 'cdk']);

export const PERSISTENCE_PROGRAMS = new Set(['launchctl', 'systemctl', 'crontab', 'cron', 'at', 'batch', 'nohup', 'setsid', 'daemon', 'pm2', 'supervisord', 'forever', 'disown']);

export const DESTRUCTIVE_PROGRAMS = new Set(['rm', 'shred', 'dd', 'truncate', 'unlink', 'rmdir', 'wipefs', 'mkfs', 'srm', 'del', 'erase']);

export const GIT_WRITE_SUBCOMMANDS = new Set(['push', 'reset', 'clean', 'checkout', 'switch', 'branch', 'rebase', 'merge', 'cherry-pick', 'revert', 'stash', 'tag', 'filter-branch', 'gc', 'prune', 'update-ref', 'commit', 'am', 'apply', 'remote']);

export const GIT_READ_SUBCOMMANDS = new Set(['status', 'diff', 'log', 'show', 'fetch', 'ls-files', 'cat-file', 'rev-parse', 'describe', 'blame', 'shortlog', 'remote']);

/* ------------------------------------------------------------------ *
 * ActionRequest
 * ------------------------------------------------------------------ */

/**
 * Build the normalized ActionRequest for a single parsed command.
 * `ctx` supplies agent identity, working directory and the workspace root.
 */
export function toActionRequest(action, ctx = {}) {
  const workspace = ctx.workingDirectory ?? action.workingDirectory ?? '.';
  const approvedDomains = ctx.approvedDomains ?? [];

  const read = [];
  const write = [];
  const del = [];
  const credentials = [];
  const networkTargets = [];

  for (const r of action.redirections ?? []) {
    if (!r.target) continue;
    const scope = classifyPathScope(r.target, workspace);
    if (r.op.startsWith('>')) {
      if (scope === SCOPE.SYSTEM || scope === SCOPE.USER_HOME) del.push(r.target);
      else write.push(r.target);
    } else {
      read.push(r.target);
    }
  }

  for (const arg of [action.command, ...(action.arguments ?? [])]) {
    if (!arg || typeof arg !== 'string') continue;
    if (/^[./~]|^[A-Za-z]:\\/.test(arg) || arg.includes('/')) {
      const scope = classifyPathScope(arg, workspace);
      if (looksLikeCredentialPath(arg)) credentials.push(arg);
      else if (scope === SCOPE.PROJECT_LOCAL) read.push(arg);
      else if (scope === SCOPE.USER_HOME || scope === SCOPE.SYSTEM) read.push(arg);
    }
    for (const url of extractUrls(arg)) {
      const info = classifyUrl(url, approvedDomains);
      if (info.host) networkTargets.push(url);
    }
  }

  const isDelete = DESTRUCTIVE_PROGRAMS.has(action.programBase);
  if (isDelete) {
    const targets = (action.arguments ?? []).filter((a) => !a.startsWith('-'));
    if (targets.length === 0) del.push('unknown');
    for (const t of targets) del.push(t);
  }

  const scopeHint = scopeOfAction(action, workspace);

  return {
    action_id: action.id,
    agent_id: ctx.agentId ?? 'autoclaw',
    session_id: ctx.sessionId ?? null,
    action_type: action.actionType,
    command: action.programBase ?? '',
    arguments: action.arguments ?? [],
    raw: action.raw ?? '',
    working_directory: workspace,
    filesystem: { read: uniq(read), write: uniq(write), delete: uniq(del) },
    network: { targets: uniq(networkTargets).length ? uniq(networkTargets) : ['unknown'] },
    credentials: uniq(credentials),
    environment: action.env ?? [],
    scope_hint: scopeHint,
    evidence_type: action.evidenceType ?? EVIDENCE.OBSERVED,
    source: { file: action.sourceFile ?? null, line: action.lineNumber ?? null },
    requested_at: ctx.requestedAt ?? null,
  };
}

function uniq(list) {
  return Array.from(new Set(list.filter(Boolean)));
}

/** Coarse scope of the action as a whole, used by the risk rules. */
export function scopeOfAction(action, workspace) {
  const scopes = [];
  for (const arg of [action.command, ...(action.arguments ?? [])]) {
    if (typeof arg === 'string' && (/[/~]/.test(arg) || arg.includes('\\'))) {
      scopes.push(classifyPathScope(arg, workspace));
    }
  }
  for (const r of action.redirections ?? []) {
    if (r.target) scopes.push(classifyPathScope(r.target, workspace));
  }
  if (scopes.includes(SCOPE.SYSTEM)) return SCOPE.SYSTEM;
  if (scopes.includes(SCOPE.USER_HOME)) return SCOPE.USER_HOME;
  if (scopes.includes(SCOPE.WORKSPACE)) return SCOPE.WORKSPACE;
  if (scopes.length) return SCOPE.PROJECT_LOCAL;
  return action.programBase && READ_ONLY_PROGRAMS.has(action.programBase) ? SCOPE.PROJECT_LOCAL : SCOPE.UNKNOWN;
}

/* ------------------------------------------------------------------ *
 * Extraction helpers
 * ------------------------------------------------------------------ */

/** Parse a shell script into normalized actions (one per command). */
export function actionsFromShell(script, opts = {}) {
  const file = opts.file ?? null;
  const workingDirectory = opts.workingDirectory ?? '.';
  const parentId = opts.parentId ?? null;
  const commands = parseShell(script);
  const actions = [];
  for (const cmd of commands) {
    if (!cmd.program) continue;
    const kind = classifyCommandKind(cmd);
    actions.push(makeAction({
      parentId,
      origin: opts.origin ?? 'script',
      language: 'shell',
      actionType: kind.actionType,
      command: cmd.programBase,
      arguments: cmd.args,
      raw: cmd.raw,
      workingDirectory,
      sourceFile: file,
      lineNumber: cmd.line,
      evidenceType: EVIDENCE.OBSERVED,
      // Parsed-command extras are attached for the rules; not part of ActionRequest.
      note: null,
      ...{},
    }));
    const created = actions[actions.length - 1];
    created.program = cmd.program;
    created.programBase = cmd.programBase;
    created.redirections = cmd.redirections;
    created.env = cmd.env;
    created.substitutions = cmd.substitutions;
    // `cmd &` leaves the `&` as the segment separator, so carry it across.
    created.background = Boolean(cmd.background || cmd.separator === '&');
    created.hasDynamicConstruction = cmd.hasDynamicConstruction;
    created.hasVariableExpansion = cmd.hasVariableExpansion;
  }
  return actions;
}

export function classifyCommandKind(cmd) {
  const base = cmd.programBase;
  if (base === 'cd' || base === 'pushd' || base === 'popd' || base === 'export' || base === 'source' || base === '.') {
    return { actionType: 'shell.builtin' };
  }
  if (base === 'git') return { actionType: 'git.operation' };
  if (base === 'npm' || base === 'pnpm' || base === 'yarn' || base === 'bun') {
    return { actionType: 'package.manager' };
  }
  if (CLOUD_PROGRAMS.has(base)) return { actionType: 'cloud.operation' };
  if (PERSISTENCE_PROGRAMS.has(base)) return { actionType: 'process.persist' };
  if (base === 'kill' || base === 'pkill' || base === 'killall') return { actionType: 'process.signal' };
  if (DOWNLOADERS.has(base)) return { actionType: 'network.fetch' };
  if (SHELL_PROGRAMS.has(base)) return { actionType: 'process.execute' };
  if (INTERPRETERS.has(base)) return { actionType: 'process.execute' };
  if (READ_ONLY_PROGRAMS.has(base)) return { actionType: 'filesystem.read' };
  return { actionType: 'process.execute' };
}

/** Build one action from a plain command line (Dashboard "Paste command"). */
export function actionFromCommandLine(commandLine, opts = {}) {
  const cmd = parseCommand(commandLine, 1);
  if (!cmd.program) return null;
  const kind = classifyCommandKind(cmd);
  const action = makeAction({
    origin: opts.origin ?? 'pasted',
    language: 'shell',
    actionType: kind.actionType,
    command: cmd.programBase,
    arguments: cmd.args,
    raw: cmd.raw,
    workingDirectory: opts.workingDirectory ?? '.',
    sourceFile: opts.file ?? null,
    lineNumber: 1,
    evidenceType: EVIDENCE.OBSERVED,
    parentId: opts.parentId ?? null,
  });
  action.program = cmd.program;
  action.programBase = cmd.programBase;
  action.redirections = cmd.redirections;
  action.env = cmd.env;
  action.substitutions = cmd.substitutions;
  action.background = cmd.background;
  action.hasDynamicConstruction = cmd.hasDynamicConstruction;
  action.hasVariableExpansion = cmd.hasVariableExpansion;
  return action;
}

/** Child actions for an interpreter invocation (INFERRED, never assumed trusted). */
export function inferredChildActions(action, ctx = {}) {
  const children = [];
  const base = action.programBase;

  if (INTERPRETERS.has(base) || SHELL_PROGRAMS.has(base)) {
    for (const sub of action.substitutions ?? []) {
      const child = actionFromCommandLine(sub, {
        origin: 'inferred',
        workingDirectory: ctx.workingDirectory ?? action.workingDirectory,
        parentId: action.id,
      });
      if (child) {
        child.evidenceType = EVIDENCE.INFERRED;
        child.note = 'Command substitution inside the parent command.';
        children.push(child);
      }
    }
  }

  // `curl ... | bash` style: a downloader feeding an interpreter.
  return children;
}

/** Group parsed commands by pipeline so `curl x | bash` can be detected. */
export function groupPipelines(source, opts = {}) {
  const segments = parseShell(source);
  const pipelines = [];
  let current = [];
  for (const cmd of segments) {
    current.push(cmd);
    if (cmd.separator !== '|') {
      pipelines.push(current);
      current = [];
    }
  }
  if (current.length) pipelines.push(current);
  return pipelines.map((cmds) => ({ commands: cmds, file: opts.file ?? null }));
}
