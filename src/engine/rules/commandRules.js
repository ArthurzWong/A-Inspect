/**
 * Deterministic command rules R001–R011 (spec §9).
 *
 * Every function here is pure: same ActionRequest in, same findings out.
 * No model call, no heuristic scoring service, no randomness. This is the
 * layer that a human can audit and that a test can pin.
 *
 * Each rule contributes:
 *   - findings     → explainable risk items (spec §33 evidence contract)
 *   - capabilities → what the action can actually affect (spec §11)
 */

import {
  CAPABILITY,
  CONFIDENCE,
  DECISION,
  EVIDENCE,
  SCOPE,
  SEVERITY,
  makeFinding,
} from '../schema.js';
import {
  CLOUD_PROGRAMS,
  DESTRUCTIVE_PROGRAMS,
  DOWNLOADERS,
  GIT_READ_SUBCOMMANDS,
  GIT_WRITE_SUBCOMMANDS,
  INTERPRETERS,
  PACKAGE_MANAGERS,
  PERSISTENCE_PROGRAMS,
  READ_ONLY_PROGRAMS,
  SHELL_PROGRAMS,
  classifyPathScope,
  classifyUrl,
  extractUrls,
  looksLikeCredentialPath,
  scopeOfAction,
} from '../normalizer.js';

function cap(action, capabilityType, extra = {}) {
  return {
    actionId: action.id,
    capabilityType,
    target: extra.target ?? null,
    scope: extra.scope ?? SCOPE.UNKNOWN,
    riskLevel: extra.riskLevel ?? SEVERITY.MODERATE,
    rule: extra.rule ?? null,
    evidence: extra.evidence ?? '',
  };
}

const RECURSIVE_FLAGS = new Set(['-r', '-R', '-rf', '-fr', '-Rf', '-fR', '--recursive', '-rfv', '-rvf']);

/* ================================================================== *
 * R001 — Destructive filesystem
 * ================================================================== */
export function ruleR001(action, ctx, out) {
  const base = action.programBase;
  const workspace = ctx.workingDirectory ?? action.workingDirectory ?? '.';

  if (!DESTRUCTIVE_PROGRAMS.has(base)) return;

  const targets = (action.arguments ?? []).filter((a) => !String(a).startsWith('-'));
  const recursive = (action.arguments ?? []).some((a) => RECURSIVE_FLAGS.has(String(a)) || (String(a).startsWith('-') && !String(a).startsWith('--') && /[rR]/.test(String(a))));
  const scope = scopeOfAction(action, workspace);
  const credentialTarget = targets.some(looksLikeCredentialPath);

  let severity = SEVERITY.MODERATE;
  if (scope === SCOPE.SYSTEM) severity = SEVERITY.CRITICAL;
  else if (scope === SCOPE.USER_HOME) severity = credentialTarget ? SEVERITY.CRITICAL : SEVERITY.ELEVATED;
  else if (scope === SCOPE.WORKSPACE) severity = SEVERITY.ELEVATED;
  else if (scope === SCOPE.UNKNOWN) severity = SEVERITY.ELEVATED;
  if (recursive && severity >= SEVERITY.MODERATE) severity = Math.min(5, severity + (scope === SCOPE.PROJECT_LOCAL ? 0 : 1));

  const targetLabel = targets.length ? targets.join(' ') : 'unknown target';
  const isRoot = targets.some((t) => t === '/' || t === '/*' || t === '~' || t === '$HOME');
  if (isRoot) {
    out.findings.push(makeFinding({
      rule: 'R001',
      title: `Recursive deletion of a root-level path (${targetLabel})`,
      severity: SEVERITY.CRITICAL,
      capability: CAPABILITY.FS_DELETE,
      action: action.raw,
      actionId: action.id,
      scope,
      confidence: CONFIDENCE.HIGH,
      evidenceType: EVIDENCE.OBSERVED,
      evidence: [
        `Command: ${base} ${(action.arguments ?? []).join(' ')}`,
        `Target resolves to a root or home path: ${targetLabel}`,
        recursive ? 'Recursive flag present.' : 'No recursive flag observed, but the target is catastrophic.',
      ],
      potentialConsequence:
        'Deletion at this scope is effectively irreversible and can destroy the operating system install, other projects, or the user home directory.',
      recommendedControl: 'Deny. If the intent is legitimate, require a sandbox and a narrowed, explicit path that stays inside the workspace.',
      why: [
        'The target path is a filesystem root or the user home directory rather than a project directory.',
        'Recursive deletion there is not recoverable by any normal means.',
      ],
      mitigations: ['Convert to a workspace-scoped path', 'Run inside sandbox', 'Require approval'],
      defaultDecision: DECISION.DENY,
      location: { file: action.sourceFile, line: action.lineNumber },
    }));
  } else {
    out.findings.push(makeFinding({
      rule: 'R001',
      title: `Filesystem deletion: ${base}${recursive ? ' (recursive)' : ''} ${targetLabel}`,
      severity,
      capability: CAPABILITY.FS_DELETE,
      action: action.raw,
      actionId: action.id,
      scope,
      confidence: CONFIDENCE.HIGH,
      evidenceType: EVIDENCE.OBSERVED,
      evidence: [
        `Command: ${base} ${(action.arguments ?? []).join(' ')}`,
        `Observed target: ${targetLabel}`,
        `Classified scope: ${scope}`,
      ],
      potentialConsequence:
        scope === SCOPE.PROJECT_LOCAL
          ? 'Files inside that project directory may be permanently removed. Content there is not recoverable unless it is committed or backed up.'
          : 'Files outside the project may be permanently removed, which can affect other projects or the user account.',
      recommendedControl:
        scope === SCOPE.PROJECT_LOCAL
          ? 'Allow project-local deletion, but require approval on first execution and keep the path inside the workspace.'
          : 'Require approval and restrict the path to the workspace before execution.',
      why: [
        `${base} removes files rather than reading them.`,
        recursive ? 'The recursive flag makes the effect apply to a whole tree, not a single file.' : 'The effect applies to each named target.',
        `The Inspector classified the target as ${scope}, so the blast radius is ${scope === SCOPE.PROJECT_LOCAL ? 'limited to this project' : 'larger than this project'}.`,
      ],
      mitigations: ['Restrict filesystem to project', 'Require approval', 'Convert to read-only'],
      defaultDecision: scope === SCOPE.PROJECT_LOCAL ? DECISION.REQUIRE_APPROVAL : DECISION.DENY,
      location: { file: action.sourceFile, line: action.lineNumber },
    }));
  }

  out.capabilities.push(cap(action, CAPABILITY.FS_DELETE, {
    target: targetLabel,
    scope,
    riskLevel: severity,
    rule: 'R001',
    evidence: `${base} ${(action.arguments ?? []).join(' ')}`.trim(),
  }));

  // Truncating redirection is a gentler sibling of deletion.
  for (const r of action.redirections ?? []) {
    if (r.op === '>' && r.target) {
      const rScope = classifyPathScope(r.target, workspace);
      out.capabilities.push(cap(action, CAPABILITY.FS_WRITE, {
        target: r.target,
        scope: rScope,
        riskLevel: rScope === SCOPE.PROJECT_LOCAL ? SEVERITY.LOW : SEVERITY.ELEVATED,
        rule: 'R001',
        evidence: `> ${r.target} truncates the file before writing`,
      }));
      out.findings.push(makeFinding({
        rule: 'R001',
        title: `Overwrite redirection truncates ${r.target}`,
        severity: rScope === SCOPE.PROJECT_LOCAL ? SEVERITY.LOW : SEVERITY.ELEVATED,
        capability: CAPABILITY.FS_WRITE,
        action: action.raw,
        actionId: action.id,
        scope: rScope,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [`Redirection: > ${r.target}`, `Classified scope: ${rScope}`],
        potentialConsequence: 'Any previous content of that file is replaced. There is no undo unless the file is under version control.',
        recommendedControl: 'Confirm the target is an intended output file, not a source file.',
        why: ['A single `>` truncates the destination file before the command writes to it.'],
        defaultDecision: DECISION.ALLOW_WITH_LOG,
        location: { file: action.sourceFile, line: action.lineNumber },
      }));
    }
  }
}

/* ================================================================== *
 * R002 — Privilege escalation
 * ================================================================== */
const PRIV_ESC_PROGRAMS = new Set(['sudo', 'su', 'doas', 'runas', 'pkexec', 'gsudo', 'sudoedit']);

export function ruleR002(action, ctx, out) {
  const base = action.programBase;
  const args = (action.arguments ?? []).map(String);
  const rawLower = String(action.raw ?? '').toLowerCase();

  const escalators = [];
  if (PRIV_ESC_PROGRAMS.has(base)) escalators.push(base);
  if (base === 'chmod' && args.some((a) => a === '777' || a === 'a+rwx' || a === '666')) escalators.push('chmod with world-writable mode');
  if (base === 'chown' && args.some((a) => a === 'root' || a === 'root:')) escalators.push('chown to root');
  if (rawLower.includes('--privileged')) escalators.push('--privileged container flag');
  if (/\bsetuid\b/.test(rawLower)) escalators.push('setuid');

  if (!escalators.length) return;

  const severity = SEVERITY.CRITICAL;
  out.findings.push(makeFinding({
    rule: 'R002',
    title: `Privilege escalation: ${escalators.join(', ')}`,
    severity,
    capability: CAPABILITY.PRIVILEGE,
    action: action.raw,
    actionId: action.id,
    scope: SCOPE.SYSTEM,
    confidence: CONFIDENCE.HIGH,
    evidenceType: EVIDENCE.OBSERVED,
    evidence: [`Command: ${action.raw}`, `Detected: ${escalators.join(', ')}`],
    potentialConsequence:
      'The action would run with administrative rights. From that point the agent can modify the operating system, install persistent services, and read any file on the machine.',
    recommendedControl: 'Deny by default. If genuinely required, require out-of-band approval and run inside a disposable sandbox that has no host root.',
    why: [
      'Elevated rights remove the containment that makes the rest of the policy meaningful.',
      'Once a process is root, filesystem and credential policy can be bypassed by that process.',
    ],
    mitigations: ['Remove credential access', 'Run inside sandbox', 'Require approval', 'Add command allowlist'],
    defaultDecision: DECISION.DENY,
    location: { file: action.sourceFile, line: action.lineNumber },
  }));
  out.capabilities.push(cap(action, CAPABILITY.PRIVILEGE, {
    target: escalators.join(','),
    scope: SCOPE.SYSTEM,
    riskLevel: severity,
    rule: 'R002',
    evidence: action.raw,
  }));
}

/* ================================================================== *
 * R003 — Credential access
 * ================================================================== */
const CREDENTIAL_PATTERNS = [
  { re: /(^|\/)\.ssh(\/|$)/, what: 'SSH private keys' },
  { re: /(^|\/)\.aws(\/|$)/, what: 'AWS credentials' },
  { re: /(^|\/)\.config(\/|$)/, what: 'application config with tokens' },
  { re: /(^|\/)\.gnupg(\/|$)/, what: 'GPG keyring' },
  { re: /\.env(\.|$)/, what: '.env secret file' },
  { re: /id_(rsa|dsa|ecdsa|ed25519)/, what: 'SSH private key' },
  { re: /\.(pem|p12|pfx|key)$/i, what: 'private key material' },
  { re: /\.npmrc|\.netrc|\.git-credentials/, what: 'package/registry credentials' },
  { re: /\.kube\/config/, what: 'Kubernetes credentials' },
  { re: /keychain/i, what: 'system keychain' },
  { re: /credentials(\.json)?$/i, what: 'credential file' },
];

const ENV_SECRET_HINTS = /(TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|SMTP_PASS|CLIENT_SECRET|AUTH|CREDENTIAL)/i;

export function ruleR003(action, ctx, out) {
  const argsRaw = (action.arguments ?? []).map(String);
  const hits = [];
  const scanTargets = [action.raw, ...argsRaw];

  for (const target of scanTargets) {
    for (const { re, what } of CREDENTIAL_PATTERNS) {
      if (re.test(target)) hits.push({ what, target });
    }
  }

  const envSecretReads = [];
  for (const name of action.env ?? []) {
    if (ENV_SECRET_HINTS.test(name)) envSecretReads.push(name);
  }
  for (const arg of argsRaw) {
    if (ENV_SECRET_HINTS.test(arg) && /\$\{?[A-Z_]+\}?/.test(arg)) envSecretReads.push(arg);
  }
  // `printenv SMTP_PASS`, `env API_TOKEN`, `echo $GITHUB_TOKEN` …
  if (['printenv', 'env', 'set'].includes(action.programBase)) {
    for (const arg of argsRaw) {
      if (!arg.startsWith('-') && ENV_SECRET_HINTS.test(arg)) envSecretReads.push(arg);
    }
  }
  for (const arg of argsRaw) {
    const m = /^\$\{?([A-Z][A-Z0-9_]*)\}?$/.exec(arg);
    if (m && ENV_SECRET_HINTS.test(m[1])) envSecretReads.push(`$${m[1]}`);
  }
  const envReaders = ['printenv', 'env', 'set', 'export'];
  const readsAllEnv = envReaders.includes(action.programBase) && argsRaw.length === 0;

  if (!hits.length && !envSecretReads.length && !readsAllEnv) return;

  const uniqueTargets = Array.from(new Set(hits.map((h) => h.target)));
  // An explicitly named secret variable is a real credential read; dumping the
  // whole environment is lower-signal because it may contain nothing sensitive.
  const severity = hits.length || envSecretReads.length ? SEVERITY.ELEVATED : SEVERITY.LOW;

  const evidence = [];
  if (hits.length) {
    evidence.push(`Credential-shaped path(s) referenced: ${uniqueTargets.join(', ')}`);
    evidence.push(`Category: ${Array.from(new Set(hits.map((h) => h.what))).join(', ')}`);
  }
  if (envSecretReads.length) evidence.push(`Secret-named environment variable(s) referenced: ${Array.from(new Set(envSecretReads)).join(', ')}`);
  if (readsAllEnv) evidence.push(`Command prints the full environment: ${action.raw}`);
  evidence.push('Secret values are never read, stored or displayed by the Inspector. Value: REDACTED');

  out.findings.push(makeFinding({
    rule: 'R003',
    title: hits.length ? `Potential credential access: ${uniqueTargets[0]}` : 'Environment/secret variable access',
    severity,
    capability: CAPABILITY.CRED_READ,
    action: action.raw,
    actionId: action.id,
    scope: hits.length ? SCOPE.USER_HOME : SCOPE.PROJECT_LOCAL,
    confidence: hits.length ? CONFIDENCE.HIGH : CONFIDENCE.MEDIUM,
    evidenceType: EVIDENCE.OBSERVED,
    evidence,
    potentialConsequence:
      'Credential material could be read into the process. If that process also has network access, the credentials could leave the machine. Credentials are often long-lived and grant access far beyond this project.',
    recommendedControl: 'Require approval. Deny host credential paths inside a sandbox and inject only the narrowest scoped token the task needs.',
    why: [
      'The command references a path or variable that conventionally holds a secret.',
      'A secret that enters a process is only as safe as everything that process can reach next.',
    ],
    mitigations: ['Remove credential access', 'Run inside sandbox', 'Require approval'],
    defaultDecision: hits.length || envSecretReads.length ? DECISION.REQUIRE_APPROVAL : DECISION.ALLOW_WITH_LOG,
    location: { file: action.sourceFile, line: action.lineNumber },
    redacted: true,
  }));

  out.capabilities.push(cap(action, CAPABILITY.CRED_READ, {
    target: uniqueTargets.join(', ') || envSecretReads.join(', ') || 'environment',
    scope: hits.length ? SCOPE.USER_HOME : SCOPE.PROJECT_LOCAL,
    riskLevel: severity,
    rule: 'R003',
    evidence: 'Secret value: REDACTED',
  }));

  if (envSecretReads.length || readsAllEnv) {
    out.capabilities.push(cap(action, CAPABILITY.ENV_READ, {
      target: (envSecretReads.length ? envSecretReads : ['all environment variables']).join(', '),
      scope: SCOPE.PROJECT_LOCAL,
      riskLevel: SEVERITY.LOW,
      rule: 'R003',
      evidence: 'Environment read (values redacted)',
    }));
  }
}

/* ================================================================== *
 * R004 — Network transmission
 * ================================================================== */
export function ruleR004(action, ctx, out) {
  const base = action.programBase;
  const approvedDomains = ctx.approvedDomains ?? [];
  const args = (action.arguments ?? []).map(String);
  const urls = [];

  for (const arg of args) for (const u of extractUrls(arg)) urls.push(u);
  for (const u of extractUrls(action.raw)) if (!urls.includes(u)) urls.push(u);

  const isFetcher = DOWNLOADERS.has(base);
  if (!isFetcher && !urls.length) return;

  const classified = urls.map((u) => ({ url: u, ...classifyUrl(u, approvedDomains) }));
  const worst = classified.reduce((acc, c) => (c.metadata ? 'metadata' : c.scope === SCOPE.NETWORK_PUBLIC ? 'public' : acc ?? c.scope), null);

  let severity = SEVERITY.LOW;
  let confidence = CONFIDENCE.HIGH;
  let scope = SCOPE.NETWORK_LOCAL;

  const notes = [];
  notes.push(`Command: ${action.raw}`);

  if (classified.some((c) => c.metadata)) {
    severity = SEVERITY.CRITICAL;
    scope = SCOPE.NETWORK_PRIVATE;
    notes.push('Target is a cloud instance metadata endpoint (169.254.169.254 / equivalent).');
  } else if (classified.some((c) => c.scope === SCOPE.NETWORK_PUBLIC)) {
    severity = SEVERITY.MODERATE;
    scope = SCOPE.NETWORK_PUBLIC;
    notes.push('Target is a public domain that is not on the approved list.');
  } else if (classified.some((c) => c.scope === SCOPE.NETWORK_PRIVATE)) {
    severity = SEVERITY.ELEVATED;
    scope = SCOPE.NETWORK_PRIVATE;
    notes.push('Target is on a private network segment.');
  } else if (classified.some((c) => c.scope === SCOPE.NETWORK_LOCAL)) {
    severity = SEVERITY.LOW;
    scope = SCOPE.NETWORK_LOCAL;
    notes.push('Target is localhost.');
  } else if (!urls.length) {
    severity = SEVERITY.MODERATE;
    confidence = CONFIDENCE.MEDIUM;
    scope = SCOPE.UNKNOWN;
    notes.push('Destination is not a literal URL — it is computed or supplied at runtime.');
  }

  if (classified.some((c) => c.scope === SCOPE.NETWORK_APPROVED)) notes.push('At least one target is on the approved domain list.');

  out.findings.push(makeFinding({
    rule: 'R004',
    title: urls.length ? `Network request to ${classified[0].host}` : `Network request with a runtime-computed destination`,
    severity,
    capability: CAPABILITY.NET_CONNECT,
    action: action.raw,
    actionId: action.id,
    scope,
    confidence,
    evidenceType: EVIDENCE.OBSERVED,
    evidence: notes,
    potentialConsequence:
      'Data can leave this machine and data can be pulled in from outside. A response body is also an input channel: content fetched here may later be interpreted as instructions.',
    recommendedControl:
      severity >= SEVERITY.ELEVATED
        ? 'Require approval. Deny network by default and add explicit domain allowlisting for anything the task truly needs.'
        : 'Allow with logging, or deny network and add a domain allowlist if the destination set is not stable.',
    why: [
      'The command performs an outbound request rather than a purely local operation.',
      urls.length ? `The destination was classified as ${worst ?? scope}.` : 'The destination cannot be determined from the command text alone.',
    ],
    mitigations: ['Disable network', 'Add domain allowlist', 'Require approval'],
    defaultDecision: severity >= SEVERITY.ELEVATED ? DECISION.REQUIRE_APPROVAL : DECISION.ALLOW_WITH_LOG,
    location: { file: action.sourceFile, line: action.lineNumber },
  }));

  out.capabilities.push(cap(action, CAPABILITY.NET_CONNECT, {
    target: classified.map((c) => c.host).filter(Boolean).join(', ') || 'runtime-computed',
    scope,
    riskLevel: severity,
    rule: 'R004',
    evidence: action.raw,
  }));

  if (severity >= SEVERITY.MODERATE) {
    out.capabilities.push(cap(action, CAPABILITY.NET_EGRESS, {
      target: classified.map((c) => c.host).filter(Boolean).join(', ') || 'unknown destination',
      scope,
      riskLevel: severity,
      rule: 'R004',
      evidence: 'Outbound transmission',
    }));
  }
}

/* ================================================================== *
 * R005 — Arbitrary code execution
 * ================================================================== */
const INLINE_FLAGS = new Set(['-e', '--eval', '-c', '--command', '--exec', '-p', '--print']);

export function ruleR005(action, ctx, out) {
  const base = action.programBase;
  const workspace = ctx.workingDirectory ?? '.';
  const knownFiles = ctx.knownFiles ?? new Set();
  const args = (action.arguments ?? []).map(String);

  const isShell = SHELL_PROGRAMS.has(base);
  const isInterpreter = INTERPRETERS.has(base);
  const inline = args.some((a) => INLINE_FLAGS.has(a)) || (isShell && args.length > 1 && args[0] === '-c');
  const dynamic = Boolean(action.hasDynamicConstruction) || (action.substitutions ?? []).length > 0;

  if (!isShell && !isInterpreter) {
    if (dynamic) {
      out.findings.push(makeFinding({
        rule: 'R005',
        title: 'Command constructed at runtime',
        severity: SEVERITY.ELEVATED,
        capability: CAPABILITY.PROC_EXECUTE,
        action: action.raw,
        actionId: action.id,
        scope: SCOPE.UNKNOWN,
        confidence: CONFIDENCE.MEDIUM,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [
          `Command: ${action.raw}`,
          `Command substitution or eval present: ${(action.substitutions ?? []).join(' | ') || 'yes'}`,
        ],
        potentialConsequence: 'The program that actually runs is not visible in the command text, so the real capability set cannot be determined statically.',
        recommendedControl: 'Require approval, or resolve the substitution to a literal before execution.',
        why: ['One part of this command is produced by another command at runtime.', 'Static inspection cannot see through that boundary.'],
        defaultDecision: DECISION.REQUIRE_APPROVAL,
        location: { file: action.sourceFile, line: action.lineNumber },
      }));
      out.capabilities.push(cap(action, CAPABILITY.PROC_EXECUTE, { target: 'runtime-constructed', scope: SCOPE.UNKNOWN, riskLevel: SEVERITY.ELEVATED, rule: 'R005', evidence: action.raw }));
    }
    return;
  }

  // Known script inside the project?
  const scriptArg = args.find((a) => !a.startsWith('-') && (a.includes('/') || /\.[a-z]{2,4}$/i.test(a)));
  const scriptKnown = scriptArg ? knownFiles.has(scriptArg.replace(/^\.\//, '')) : false;

  let severity = SEVERITY.MODERATE;
  const evidence = [`Command: ${action.raw}`, `Interpreter: ${base}`];

  if (inline) {
    severity = SEVERITY.ELEVATED;
    evidence.push('Inline program text supplied with -e / -c. The program is arbitrary code, not a reviewed file.');
  } else if (scriptArg && scriptKnown) {
    severity = SEVERITY.MODERATE;
    evidence.push(`Entrypoint ${scriptArg} exists in the project and was inspected.`);
  } else if (scriptArg) {
    severity = SEVERITY.ELEVATED;
    evidence.push(`Entrypoint ${scriptArg} was not found among inspected project files.`);
  } else {
    severity = SEVERITY.MODERATE;
    evidence.push('No script path was given, so the interpreter reads from stdin or does nothing.');
  }
  if (dynamic) {
    severity = Math.min(5, severity + 1);
    evidence.push('Command substitution present inside the invocation.');
  }

  out.findings.push(makeFinding({
    rule: 'R005',
    title: `${base} executes ${inline ? 'inline code' : scriptArg ?? 'a program'}`,
    severity,
    capability: CAPABILITY.PROC_EXECUTE,
    action: action.raw,
    actionId: action.id,
    scope: classifyPathScope(scriptArg ?? '.', workspace),
    confidence: scriptKnown || inline ? CONFIDENCE.HIGH : CONFIDENCE.MEDIUM,
    evidenceType: EVIDENCE.OBSERVED,
    evidence,
    potentialConsequence:
      `A ${base} process can perform filesystem, network and child-process operations that are not visible from the shell command itself. The blast radius of this one line is whatever that program does next, plus everything it can reach.`,
    recommendedControl: scriptKnown
      ? 'Review the entrypoint, then allow. Keep the surrounding policy (filesystem, network, credentials) in force — the program inherits it.'
      : 'Inspect the entrypoint before granting unrestricted execution. Prefer SANDBOX_ONLY while the program is unreviewed.',
    why: [
      `${base} is a general-purpose runtime, not a single-purpose tool.`,
      'Its capability set is decided by the program it loads, which is a different artifact from this command.',
      scriptKnown ? 'The Inspector found and read that artifact, so the risk is bounded by what was found there.' : 'The Inspector has not read that artifact, so downstream behaviour is unknown.',
    ],
    mitigations: ['Run inside sandbox', 'Restrict filesystem to project', 'Disable network', 'Require approval', 'Add command allowlist'],
    defaultDecision: scriptKnown ? DECISION.ALLOW_WITH_LOG : DECISION.REQUIRE_APPROVAL,
    location: { file: action.sourceFile, line: action.lineNumber },
  }));

  out.capabilities.push(cap(action, CAPABILITY.PROC_EXECUTE, {
    target: scriptArg ?? base,
    scope: SCOPE.PROJECT_LOCAL,
    riskLevel: severity,
    rule: 'R005',
    evidence: action.raw,
  }));

  // Execution implies it can spawn children unless proven otherwise.
  out.capabilities.push(cap(action, CAPABILITY.PROC_SPAWN, {
    target: 'possible child processes',
    scope: SCOPE.UNKNOWN,
    riskLevel: SEVERITY.MODERATE,
    rule: 'R005',
    evidence: `${base} is capable of spawning child processes`,
  }));

  // `cmd | bash` — downloaded code piped straight into an interpreter.
  if (ctx.pipeline) {
    const prev = ctx.pipeline.filter((c) => c.separator === '|');
    const feeders = (ctx.allCommands ?? []).filter((c) => DOWNLOADERS.has(c.programBase));
    if (feeders.length && prev.length) {
      out.findings.push(makeFinding({
        rule: 'R004',
        title: 'Remote content piped directly into an interpreter',
        severity: SEVERITY.CRITICAL,
        capability: CAPABILITY.PROC_EXECUTE,
        action: `${feeders[0].raw} | ${action.raw}`,
        actionId: action.id,
        scope: SCOPE.NETWORK_PUBLIC,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [
          `Pipeline: ${feeders[0].raw} | ${action.raw}`,
          'The interpreter receives its entire program from the network, unread by anyone.',
        ],
        potentialConsequence: 'Whatever the remote server returns at that moment is executed with the agent\'s full permissions. The program can change after review, and is not pinned by a hash.',
        recommendedControl: 'Deny by default. Download to a file, inspect and hash it, then execute the reviewed artifact.',
        why: ['One command fetches bytes and the next executes them.', 'Nothing between the two verifies what was fetched.'],
        mitigations: ['Convert to read-only', 'Require approval', 'Disable network'],
        defaultDecision: DECISION.DENY,
        location: { file: action.sourceFile, line: action.lineNumber },
      }));
      out.capabilities.push(cap(action, CAPABILITY.AGENT_CHAIN, {
        target: 'download → execute',
        scope: SCOPE.NETWORK_PUBLIC,
        riskLevel: SEVERITY.CRITICAL,
        rule: 'R005',
        evidence: 'Remote content piped into interpreter',
      }));
    }
  }
}

/* ================================================================== *
 * R006 — Package installation
 * ================================================================== */
const INSTALL_SUBCOMMANDS = new Set(['install', 'i', 'add', 'ci', 'update', 'upgrade', 'get', 'require', 'sync', 'init']);

export function ruleR006(action, ctx, out) {
  const base = action.programBase;
  const args = (action.arguments ?? []).map(String);
  const sub = args[0] ?? '';
  const lower = `${base} ${args.join(' ')}`.toLowerCase();

  const isRemoteRunner = base === 'npx' || base === 'uvx' || base === 'bunx' || base === 'pnpx' || base === 'dlx';
  const isInstaller = PACKAGE_MANAGERS.has(base) && (INSTALL_SUBCOMMANDS.has(sub) || /(^|\s)(install|add)\b/.test(lower));
  const isUvRun = base === 'uv' && sub === 'run';
  const isGoInstall = base === 'go' && sub === 'install';

  if (!isInstaller && !isRemoteRunner && !isUvRun && !isGoInstall) return;

  const packages = args.filter((a) => !a.startsWith('-') && !INSTALL_SUBCOMMANDS.has(a) && a !== 'run' && !/\.(txt|toml|lock|json|yaml|yml)$/.test(a) && a !== '.');
  const hasLockfile = Boolean(ctx.hasLockfile);
  const unpinned = packages.filter((p) => !/@\d/.test(p) && !/^[\w.-]+@[\d^~]/.test(p));

  let severity = SEVERITY.MODERATE;
  const evidence = [`Command: ${action.raw}`, `Package manager: ${base}`];
  if (isRemoteRunner) {
    severity = SEVERITY.ELEVATED;
    evidence.push('Package is fetched and executed immediately, without landing in a manifest or lockfile.');
  }
  if (packages.length) evidence.push(`Packages named: ${packages.slice(0, 8).join(', ')}${packages.length > 8 ? ` (+${packages.length - 8} more)` : ''}`);
  else evidence.push('No specific packages named — the manifest determines what is installed.');
  if (!hasLockfile) {
    severity = Math.max(severity, SEVERITY.ELEVATED);
    evidence.push('No lockfile was found, so resolved versions are not pinned.');
  }
  if (unpinned.length && packages.length) evidence.push(`Unpinned requirement(s): ${unpinned.slice(0, 5).join(', ')}`);

  out.findings.push(makeFinding({
    rule: 'R006',
    title: isRemoteRunner ? `Remote package executed directly: ${action.raw}` : `Dependency installation: ${base} ${sub}`.trim(),
    severity,
    capability: CAPABILITY.PKG_INSTALL,
    action: action.raw,
    actionId: action.id,
    scope: SCOPE.PROJECT_LOCAL,
    confidence: CONFIDENCE.HIGH,
    evidenceType: EVIDENCE.OBSERVED,
    evidence,
    potentialConsequence:
      'Installing a package creates a new supply-chain dependency. Packages can run install scripts (preinstall/postinstall) as this process, so installation is itself code execution, not just a download.',
    recommendedControl: 'Require approval. Prefer a committed lockfile, install with lifecycle scripts disabled where possible, and pin versions.',
    why: [
      'A dependency is code that will run later, usually with this same permission set.',
      'Install-time lifecycle scripts run immediately, before anything is reviewed.',
      hasLockfile ? 'A lockfile is present, which constrains versions — this reduces but does not remove the risk.' : 'Without a lockfile the resolved version can change between runs.',
    ],
    mitigations: ['Require approval', 'Run inside sandbox', 'Disable network'],
    defaultDecision: DECISION.REQUIRE_APPROVAL,
    location: { file: action.sourceFile, line: action.lineNumber },
  }));

  out.capabilities.push(cap(action, CAPABILITY.PKG_INSTALL, {
    target: packages.join(', ') || `${base} manifest`,
    scope: SCOPE.PROJECT_LOCAL,
    riskLevel: severity,
    rule: 'R006',
    evidence: action.raw,
  }));
}

/* ================================================================== *
 * R007 — Git mutation
 * ================================================================== */
export function ruleR007(action, ctx, out) {
  if (action.programBase !== 'git') return;
  const args = (action.arguments ?? []).map(String);
  const sub = args.find((a) => !a.startsWith('-')) ?? '';
  if (!sub) return;

  if (GIT_READ_SUBCOMMANDS.has(sub) && !GIT_WRITE_SUBCOMMANDS.has(sub)) {
    out.findings.push(makeFinding({
      rule: 'R007',
      title: `Git read: git ${sub}`,
      severity: SEVERITY.INFO,
      capability: CAPABILITY.GIT_READ,
      action: action.raw,
      actionId: action.id,
      scope: SCOPE.PROJECT_LOCAL,
      confidence: CONFIDENCE.HIGH,
      evidenceType: EVIDENCE.OBSERVED,
      evidence: [`Command: ${action.raw}`, `git ${sub} does not modify the repository or the remote.`],
      potentialConsequence: 'None beyond reading repository metadata.',
      recommendedControl: 'Allow. Read-only git commands do not need approval.',
      why: ['The subcommand only reads state.'],
      defaultDecision: DECISION.ALLOW,
      location: { file: action.sourceFile, line: action.lineNumber },
    }));
    out.capabilities.push(cap(action, CAPABILITY.GIT_READ, { target: `git ${sub}`, scope: SCOPE.PROJECT_LOCAL, riskLevel: SEVERITY.INFO, rule: 'R007', evidence: action.raw }));
    return;
  }

  if (!GIT_WRITE_SUBCOMMANDS.has(sub)) return;

  const destructive = ['reset', 'clean', 'filter-branch', 'rebase', 'branch'].includes(sub)
    && (args.includes('--hard') || args.some((a) => a.startsWith('-f')) || args.includes('-D') || args.includes('-fd') || args.includes('-fdx'));
  const forcePush = sub === 'push' && args.some((a) => a === '--force' || a === '-f' || a === '--force-with-lease');
  const remoteWrite = sub === 'push' || sub === 'remote';

  let severity = SEVERITY.MODERATE;
  let title = `Git mutation: git ${sub}`;
  if (forcePush) {
    severity = SEVERITY.CRITICAL;
    title = 'Git force push';
  } else if (destructive) {
    severity = SEVERITY.CRITICAL;
    title = `Destructive git operation: git ${sub}`;
  } else if (remoteWrite) {
    severity = SEVERITY.ELEVATED;
  }

  const evidence = [`Command: ${action.raw}`];
  if (forcePush) evidence.push('Force push rewrites remote history; commits can be lost for every collaborator.');
  if (destructive) evidence.push('This operation discards or rewrites local work that is not recoverable from the working tree.');
  if (remoteWrite) evidence.push('This operation writes to a remote other people depend on.');

  out.findings.push(makeFinding({
    rule: 'R007',
    title,
    severity,
    capability: CAPABILITY.GIT_WRITE,
    action: action.raw,
    actionId: action.id,
    scope: remoteWrite ? SCOPE.NETWORK_APPROVED : SCOPE.PROJECT_LOCAL,
    confidence: CONFIDENCE.HIGH,
    evidenceType: EVIDENCE.OBSERVED,
    evidence,
    potentialConsequence:
      forcePush || destructive
        ? 'Unreviewed or unbacked-up work can be permanently destroyed, locally or for everyone on the remote.'
        : 'Repository state changes. Recovery is possible through git history for most operations, but not for all.',
    recommendedControl: 'Require approval. Never allow force operations without an explicit, narrow approval.',
    why: ['This subcommand writes repository state rather than reading it.', forcePush || destructive ? 'The flags present make the change irreversible.' : 'A write to a shared remote affects other people.'],
    mitigations: ['Require approval', 'Add command allowlist', 'Convert to read-only'],
    defaultDecision: severity >= SEVERITY.ELEVATED ? DECISION.REQUIRE_APPROVAL : DECISION.ALLOW_WITH_LOG,
    location: { file: action.sourceFile, line: action.lineNumber },
  }));

  out.capabilities.push(cap(action, CAPABILITY.GIT_WRITE, { target: `git ${sub}`, scope: SCOPE.PROJECT_LOCAL, riskLevel: severity, rule: 'R007', evidence: action.raw }));
}

/* ================================================================== *
 * R008 — Cloud infrastructure
 * ================================================================== */
const CLOUD_OP_CLASSES = [
  { cls: 'delete', re: /\b(delete|destroy|remove|rm|purge|terminate|drop)\b/ },
  { cls: 'deploy', re: /\b(deploy|apply|rollout|publish|release|upgrade|sync|push)\b/ },
  { cls: 'secret', re: /\b(secret|secretsmanager|ssm|get-parameter|get-secret|keyring|kms|vault)\b/ },
  { cls: 'write', re: /\b(create|set|update|put|edit|enable|disable|attach|grant|add)\b/ },
  { cls: 'read', re: /\b(describe|list|get|show|logs|status|inspect|history|plan|validate)\b/ },
];

export function ruleR008(action, ctx, out) {
  const base = action.programBase;
  if (!CLOUD_PROGRAMS.has(base)) return;
  const args = (action.arguments ?? []).map(String);
  const joined = args.join(' ').toLowerCase();
  const cls = CLOUD_OP_CLASSES.find((c) => c.re.test(joined))?.cls ?? 'read';

  const capabilityByClass = {
    read: CAPABILITY.CLOUD_READ,
    write: CAPABILITY.CLOUD_WRITE,
    delete: CAPABILITY.CLOUD_DELETE,
    deploy: CAPABILITY.CLOUD_DEPLOY,
    secret: CAPABILITY.CLOUD_SECRET,
  };
  const capability = capabilityByClass[cls];

  const severityByClass = {
    read: SEVERITY.LOW,
    write: SEVERITY.MODERATE,
    deploy: SEVERITY.ELEVATED,
    secret: SEVERITY.ELEVATED,
    delete: SEVERITY.CRITICAL,
  };
  let severity = severityByClass[cls];

  const isContainer = base === 'docker' || base === 'podman' || base === 'docker-compose';
  const privilegedFlags = [];
  if (isContainer) {
    if (args.includes('--privileged')) privilegedFlags.push('--privileged');
    if (args.some((a) => /^-v$/.test(a)) && args.some((a) => /^\/:|^\/root/.test(a))) privilegedFlags.push('host root bind mount');
    if (args.includes('--net=host') || args.includes('--network=host')) privilegedFlags.push('host network');
    if (privilegedFlags.length) severity = SEVERITY.CRITICAL;
  }

  const evidence = [`Command: ${action.raw}`, `Provider/CLI: ${base}`, `Operation class: ${cls.toUpperCase()}`];
  if (privilegedFlags.length) evidence.push(`Container escape surface: ${privilegedFlags.join(', ')}`);
  if (cls === 'secret') evidence.push('This class of operation retrieves secret material from the cloud provider.');

  out.findings.push(makeFinding({
    rule: 'R008',
    title: `Cloud operation (${cls.toUpperCase()}): ${base} ${args.slice(0, 3).join(' ')}`.trim(),
    severity,
    capability,
    action: action.raw,
    actionId: action.id,
    scope: cls === 'read' ? SCOPE.PROJECT_LOCAL : SCOPE.NETWORK_PUBLIC,
    confidence: CONFIDENCE.MEDIUM,
    evidenceType: EVIDENCE.OBSERVED,
    evidence,
    potentialConsequence:
      cls === 'read'
        ? 'Cloud metadata is read. Low direct impact, but it can reveal infrastructure that later steps act on.'
        : `Infrastructure outside this machine can be ${cls === 'delete' ? 'destroyed' : cls === 'deploy' ? 'changed in production' : 'modified'} using whatever credentials this process holds. Those changes are not limited to this project.`,
    recommendedControl: 'Require approval, and scope the credential to the narrowest role that supports the task.',
    why: [
      `${base} acts on infrastructure beyond this project.`,
      `The operation was classified as ${cls} from its subcommand and arguments.`,
      isContainer && privilegedFlags.length ? 'Container flags present remove the container boundary entirely.' : 'The Inspector recommends reviewing the target resource before allowing.',
    ],
    mitigations: ['Require approval', 'Remove credential access', 'Run inside sandbox'],
    defaultDecision: cls === 'read' ? DECISION.ALLOW_WITH_LOG : DECISION.REQUIRE_APPROVAL,
    location: { file: action.sourceFile, line: action.lineNumber },
  }));

  out.capabilities.push(cap(action, capability, { target: args.slice(0, 4).join(' '), scope: SCOPE.NETWORK_PUBLIC, riskLevel: severity, rule: 'R008', evidence: action.raw }));
  if (isContainer) {
    out.capabilities.push(cap(action, CAPABILITY.CONTAINER, { target: args.slice(0, 4).join(' '), scope: SCOPE.PROJECT_LOCAL, riskLevel: severity, rule: 'R008', evidence: action.raw }));
  }
}

/* ================================================================== *
 * R009 — Persistent process
 * ================================================================== */
export function ruleR009(action, ctx, out) {
  const base = action.programBase;
  const rawLower = String(action.raw ?? '').toLowerCase();
  const args = (action.arguments ?? []).map(String);

  const persistenceHits = [];
  if (PERSISTENCE_PROGRAMS.has(base)) persistenceHits.push(base);
  if (base === 'systemctl' && args.some((a) => ['enable', 'start', 'daemon-reload'].includes(a))) persistenceHits.push('systemctl enable/start');
  if (base === 'launchctl' && args.some((a) => ['load', 'bootstrap', 'enable'].includes(a))) persistenceHits.push('launchctl load');
  if (/crontab\s+-/.test(rawLower)) persistenceHits.push('crontab modification');
  if (/\bat\s+now\b|\bbatch\b/.test(rawLower)) persistenceHits.push('scheduled job');
  if (action.background) persistenceHits.push('background job (&)');

  if (!persistenceHits.length) return;

  const isBackgroundOnly = persistenceHits.length === 1 && persistenceHits[0] === 'background job (&)';
  const severity = isBackgroundOnly ? SEVERITY.MODERATE : SEVERITY.CRITICAL;

  out.findings.push(makeFinding({
    rule: 'R009',
    title: `Persistent process: ${persistenceHits.join(', ')}`,
    severity,
    capability: CAPABILITY.PERSISTENCE,
    action: action.raw,
    actionId: action.id,
    scope: SCOPE.SYSTEM,
    confidence: CONFIDENCE.HIGH,
    evidenceType: EVIDENCE.OBSERVED,
    evidence: [
      `Command: ${action.raw}`,
      `Detected: ${persistenceHits.join(', ')}`,
      isBackgroundOnly ? 'The job is a background process from this shell; it ends when the shell exits unless disowned.' : 'This mechanism survives process exit, reboot, or both.',
    ],
    potentialConsequence: isBackgroundOnly
      ? 'A process keeps running after the current step finishes. If the parent exits, the work is silently abandoned mid-flight.'
      : 'Code continues to run after the agent session ends. It can act again later, with no human watching and no Inspector in the loop.',
    recommendedControl: isBackgroundOnly
      ? 'Allow, but pair every background job with an explicit stop/cleanup step.'
      : 'Deny unless explicitly approved. Persistence defeats the assumption that ending the session ends the risk.',
    why: [
      'This action creates something that outlives the current command.',
      'Anything that outlives the session also outlives the approval you just gave it.',
    ],
    mitigations: ['Require approval', 'Run inside sandbox', 'Convert to read-only'],
    defaultDecision: isBackgroundOnly ? DECISION.ALLOW_WITH_LOG : DECISION.DENY,
    location: { file: action.sourceFile, line: action.lineNumber },
  }));

  out.capabilities.push(cap(action, CAPABILITY.PERSISTENCE, { target: persistenceHits.join(','), scope: SCOPE.SYSTEM, riskLevel: severity, rule: 'R009', evidence: action.raw }));
  if (isBackgroundOnly) {
    out.capabilities.push(cap(action, CAPABILITY.PROC_BACKGROUND, { target: 'background job', scope: SCOPE.PROJECT_LOCAL, riskLevel: SEVERITY.LOW, rule: 'R009', evidence: action.raw }));
  }
}

export function ruleR009Signal(action, ctx, out) {
  const base = action.programBase;
  if (!['kill', 'pkill', 'killall'].includes(base)) return;
  out.findings.push(makeFinding({
    rule: 'R009',
    title: `Process termination: ${action.raw}`,
    severity: SEVERITY.LOW,
    capability: CAPABILITY.PROC_SIGNAL,
    action: action.raw,
    actionId: action.id,
    scope: SCOPE.PROJECT_LOCAL,
    confidence: CONFIDENCE.HIGH,
    evidenceType: EVIDENCE.OBSERVED,
    evidence: [`Command: ${action.raw}`, 'Signals a running process.'],
    potentialConsequence: 'A running process is stopped. If it held unsaved state, that state is lost — which is usually the intent.',
    recommendedControl: 'Allow with logging. Prefer targeting a recorded PID over a broad name match.',
    why: ['The command stops a process rather than starting one.', 'Broad name matches can stop unrelated processes.'],
    defaultDecision: DECISION.ALLOW_WITH_LOG,
    location: { file: action.sourceFile, line: action.lineNumber },
  }));
  out.capabilities.push(cap(action, CAPABILITY.PROC_SIGNAL, { target: (action.arguments ?? []).join(' '), scope: SCOPE.PROJECT_LOCAL, riskLevel: SEVERITY.LOW, rule: 'R009', evidence: action.raw }));
}

/* ================================================================== *
 * R010 — Browser / SSRF
 * ================================================================== */
const METADATA_HOSTS = ['169.254.169.254', 'metadata.google.internal', '100.100.100.200', 'fd00:ec2::254'];

export function ruleR010(action, ctx, out) {
  const args = (action.arguments ?? []).map(String);
  const urls = extractUrls(action.raw);
  if (!urls.length) return;

  for (const u of urls) {
    const info = classifyUrl(u, ctx.approvedDomains ?? []);
    const isMetadata = info.metadata || METADATA_HOSTS.includes(info.host);
    const isPrivate = info.scope === SCOPE.NETWORK_PRIVATE;

    if (!isMetadata && !isPrivate) continue;

    out.findings.push(makeFinding({
      rule: 'R010',
      title: isMetadata ? `Cloud metadata endpoint referenced: ${info.host}` : `Private-network address referenced: ${info.host}`,
      severity: isMetadata ? SEVERITY.CRITICAL : SEVERITY.ELEVATED,
      capability: CAPABILITY.NET_CONNECT,
      action: action.raw,
      actionId: action.id,
      scope: isMetadata ? SCOPE.NETWORK_PRIVATE : info.scope,
      confidence: CONFIDENCE.HIGH,
      evidenceType: EVIDENCE.OBSERVED,
      evidence: [
        `URL: ${u}`,
        `Host classification: ${isMetadata ? 'cloud instance metadata service' : 'RFC1918 / link-local / loopback-adjacent'}`,
        isMetadata ? 'The metadata service issues temporary cloud credentials to anything that can reach it.' : 'Private addresses are usually not intended to be reachable from agent-generated code.',
      ],
      potentialConsequence: isMetadata
        ? 'A successful request can return short-lived cloud credentials, which turn a local capability into a cloud-account capability.'
        : 'The request can reach services that were never meant to be exposed to this agent, including internal admin interfaces.',
      recommendedControl: 'Deny. Metadata endpoints should be unreachable from agent execution; private ranges should require an explicit allowlist entry.',
      why: [
        'This address belongs to infrastructure, not to the public internet.',
        'Reaching it is a privilege boundary crossing, not an ordinary web request.',
      ],
      mitigations: ['Disable network', 'Add domain allowlist', 'Run inside sandbox'],
      defaultDecision: DECISION.DENY,
      location: { file: action.sourceFile, line: action.lineNumber },
    }));

    out.capabilities.push(cap(action, CAPABILITY.NET_CONNECT, { target: info.host, scope: info.scope, riskLevel: isMetadata ? SEVERITY.CRITICAL : SEVERITY.ELEVATED, rule: 'R010', evidence: u }));
  }
}

/* ================================================================== *
 * Agentic chaining (R011) — needs whole-project context,
 * implemented in inspectionEngine as `buildAgenticChain`.
 * ================================================================== */

/** Read-only commands still produce capability records for the blast-radius map. */
export function ruleReadOnly(action, ctx, out) {
  if (!READ_ONLY_PROGRAMS.has(action.programBase)) return;
  const targets = (action.arguments ?? []).filter((a) => !String(a).startsWith('-'));
  const workspace = ctx.workingDirectory ?? '.';
  for (const t of targets) {
    if (!/[/~.]/.test(t)) continue;
    out.capabilities.push(cap(action, CAPABILITY.FS_READ, {
      target: t,
      scope: classifyPathScope(t, workspace),
      riskLevel: SEVERITY.INFO,
      rule: null,
      evidence: action.raw,
    }));
  }
}

/* ================================================================== *
 * Aggregate
 * ================================================================== */

const RULES = [ruleR001, ruleR002, ruleR003, ruleR004, ruleR005, ruleR006, ruleR007, ruleR008, ruleR009, ruleR009Signal, ruleR010, ruleReadOnly];

export function evaluateCommandRules(action, ctx = {}) {
  const out = { findings: [], capabilities: [] };
  for (const rule of RULES) {
    try {
      rule(action, ctx, out);
    } catch (err) {
      // A rule that throws must not silently disappear: surface it as an
      // unknown-state finding so the engine fails closed rather than open.
      out.findings.push(makeFinding({
        rule: 'ENGINE',
        title: `Rule ${rule.name} could not classify this action`,
        severity: SEVERITY.ELEVATED,
        capability: null,
        action: action.raw,
        actionId: action.id,
        scope: SCOPE.UNKNOWN,
        confidence: CONFIDENCE.LOW,
        evidenceType: EVIDENCE.UNKNOWN,
        evidence: [`Internal error while classifying: ${String(err && err.message)}`],
        potentialConsequence: 'Because classification failed, the real capability set of this action is unknown.',
        recommendedControl: 'Require approval. Unknown is not allow.',
        why: ['An analyzer error means the Inspector cannot vouch for this action.'],
        defaultDecision: DECISION.REQUIRE_APPROVAL,
        location: { file: action.sourceFile, line: action.lineNumber },
      }));
    }
  }
  return out;
}

export const RULE_CATALOG = [
  { id: 'R001', name: 'Destructive filesystem' },
  { id: 'R002', name: 'Privilege escalation' },
  { id: 'R003', name: 'Credential access' },
  { id: 'R004', name: 'Network transmission' },
  { id: 'R005', name: 'Arbitrary code execution' },
  { id: 'R006', name: 'Package installation' },
  { id: 'R007', name: 'Git mutation' },
  { id: 'R008', name: 'Cloud infrastructure' },
  { id: 'R009', name: 'Persistent process' },
  { id: 'R010', name: 'Browser / SSRF' },
  { id: 'R011', name: 'Agent chaining' },
  { id: 'R012', name: 'Prompt injection' },
  { id: 'R013', name: 'MCP inspection safety' },
  { id: 'R014', name: 'Dependency supply chain' },
];
