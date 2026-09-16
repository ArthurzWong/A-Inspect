/**
 * Code-level capability scanning.
 *
 * Command rules read shell text. This module reads *program* text — JS, TS,
 * Python, PHP, YAML, Dockerfile, Makefile — and answers the question the
 * shell cannot: "what is this program able to do?"
 *
 * This is what makes `node bin/contentpulse.js` inspectable. The shell line
 * says only "run node". The code says: outbound fetch, a listening socket,
 * environment reads, SMTP credentials, a cron scheduler, database writes.
 *
 * Static only. Nothing is executed, imported or evaluated.
 */

import {
  CAPABILITY,
  CONFIDENCE,
  DECISION,
  EVIDENCE,
  SCOPE,
  SEVERITY,
  makeAction,
  makeFinding,
} from './schema.js';
import { redactString } from './redact.js';
import { extractUrls, classifyUrl } from './normalizer.js';

/**
 * Each entry: a textual capability signal with the rule it maps onto.
 * `languages` limits which file types it applies to.
 */
export const CODE_SIGNALS = [
  // ---- process execution / child processes -------------------------
  {
    id: 'child-process',
    languages: ['javascript', 'typescript'],
    re: /\b(?:require\(\s*['"]node:child_process['"]\s*\)|from\s+['"]node:child_process['"]|child_process)\b/,
    rule: 'R005',
    capability: CAPABILITY.PROC_SPAWN,
    severity: SEVERITY.ELEVATED,
    title: 'Code can spawn child processes',
    consequence: 'This program can start other programs. Those programs are not visible in the shell command that started this one, so the reachable capability set is larger than it appears.',
    control: 'Keep the parent process inside the sandbox and add a command allowlist rather than relying on the entry command.',
    why: ['`child_process` gives the program the same execution authority the agent has.'],
  },
  {
    id: 'exec-call',
    languages: ['javascript', 'typescript'],
    // `re.exec(...)` and `db.exec(...)` are method calls, not process
    // execution, so a plain `.exec(` must not match. `child_process.exec(`
    // is still caught by the child-process signal below.
    re: /(?<![\w$.])(?:execSync|execFileSync|execFile|spawnSync|spawn|fork)\s*\(|(?<!\.)\bexec\s*\(|child_process[^\n]{0,24}\.\s*(?:exec|execSync|execFile|spawn|spawnSync|fork)\s*\(/,
    rule: 'R005',
    capability: CAPABILITY.PROC_EXECUTE,
    severity: SEVERITY.ELEVATED,
    title: 'Shell/process execution call in code',
    consequence: 'If any part of the invoked command is built from untrusted input, this is a command-injection sink.',
    control: 'Require approval. Prefer string-free argument arrays over shell strings.',
    why: ['Programs that build command strings dynamically are injection sinks by construction.'],
  },
  {
    id: 'dynamic-eval',
    languages: ['javascript', 'typescript', 'python', 'php'],
    re: /\b(eval|new Function|vm\.runInContext|vm\.runInNewContext|vm\.compileFunction)\s*\(/,
    rule: 'R005',
    capability: CAPABILITY.PROC_EXECUTE,
    severity: SEVERITY.CRITICAL,
    title: 'Dynamic code evaluation in code',
    consequence: 'Evaluated text becomes executable code with the full authority of this process. Static inspection cannot see what it will do.',
    control: 'Deny. Remove the eval path or confine it to a sandbox with no credentials and no network.',
    why: ['Dynamic evaluation is the canonical way to hide intent from static analysis.'],
  },
  {
    id: 'python-subprocess',
    languages: ['python'],
    re: /\b(subprocess\.(run|Popen|call|check_output|check_call)|os\.system|os\.popen|os\.exec[lv]p?e?)\s*\(/,
    rule: 'R005',
    capability: CAPABILITY.PROC_EXECUTE,
    severity: SEVERITY.ELEVATED,
    title: 'Python process execution',
    consequence: 'The script can start other programs and inherit their authority.',
    control: 'Require approval and run inside a sandbox.',
    why: ['Process execution from a script is the same capability as from a shell.'],
  },
  {
    id: 'php-shell',
    languages: ['php'],
    re: /\b(shell_exec|exec|system|passthru|popen|proc_open)\s*\(/,
    rule: 'R005',
    capability: CAPABILITY.PROC_EXECUTE,
    severity: SEVERITY.ELEVATED,
    title: 'PHP shell execution',
    consequence: 'The PHP service can run arbitrary host commands as the service user.',
    control: 'Require approval. This is especially important for a service that accepts requests over the network.',
    why: ['A network-reachable service that also shells out turns a request into host execution.'],
  },

  // ---- filesystem -------------------------------------------------
  {
    id: 'fs-delete',
    languages: ['javascript', 'typescript'],
    re: /\b(fs\.(rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync|truncate)|rimraf|fsExtra\.remove|fse\.remove)\s*\(/,
    rule: 'R001',
    capability: CAPABILITY.FS_DELETE,
    severity: SEVERITY.MODERATE,
    title: 'Code deletes files',
    consequence: 'Files are removed from within the program, so the deletion is invisible in the shell command that started it.',
    control: 'Confirm the deletion target is inside the workspace and that the program cannot be pointed at an arbitrary path by configuration.',
    why: ['Deletion implemented in code is driven by configuration and inputs, not by the visible command line.'],
  },
  {
    id: 'py-delete',
    languages: ['python'],
    re: /\b(shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir)\s*\(/,
    rule: 'R001',
    capability: CAPABILITY.FS_DELETE,
    severity: SEVERITY.MODERATE,
    title: 'Python code deletes files',
    consequence: 'Files or directory trees are removed from inside the program.',
    control: 'Verify the path is derived from a constrained configuration value.',
    why: ['Recursive deletion driven by configuration can reach further than the command suggests.'],
  },
  {
    id: 'fs-write',
    languages: ['javascript', 'typescript', 'python', 'php'],
    re: /\b(fs\.(writeFile|writeFileSync|appendFile|mkdir|mkdtemp)|open\s*\([^)]*['"][wa])/,
    rule: null,
    capability: CAPABILITY.FS_WRITE,
    severity: SEVERITY.LOW,
    title: 'Code writes files',
    consequence: 'Output files are created or modified inside the project.',
    control: 'Allow. Keep the write root inside the workspace.',
    why: ['Writing output is expected for most tools; the concern is only where it writes.'],
  },
  {
    id: 'db-write',
    languages: ['javascript', 'typescript', 'python', 'php'],
    re: /\b(sqlite|better-sqlite3|CREATE TABLE|INSERT INTO|UPDATE\s+\w+\s+SET|DELETE FROM|pg\.|mysql\.)\b/i,
    rule: null,
    capability: CAPABILITY.DB_WRITE,
    severity: SEVERITY.LOW,
    title: 'Program writes to a local database',
    consequence: 'Persistent local state accumulates. Running the tool twice is not idempotent.',
    control: 'Allow with logging, and keep the database file inside the workspace.',
    why: ['Local state means later runs depend on earlier runs.'],
  },

  // ---- network ----------------------------------------------------
  {
    id: 'fetch',
    languages: ['javascript', 'typescript'],
    re: /\b(fetch|axios\.(get|post|put|delete)|http\.request|https\.request|got\(|undici)\s*\(/,
    rule: 'R004',
    capability: CAPABILITY.NET_CONNECT,
    severity: SEVERITY.MODERATE,
    title: 'Code makes outbound network requests',
    consequence: 'Data can leave the machine and remote content can enter the process. A fetched response is also an input channel that can carry instructions.',
    control: 'Require approval, or deny network and add a domain allowlist.',
    why: ['A network call inside code is driven by configuration; the shell command does not reveal the destination.'],
  },
  {
    id: 'py-network',
    languages: ['python'],
    re: /\b(requests\.(get|post|put|delete|Session)|urllib\.request|urlopen|httpx\.)\s*\(/,
    rule: 'R004',
    capability: CAPABILITY.NET_CONNECT,
    severity: SEVERITY.MODERATE,
    title: 'Python code makes outbound network requests',
    consequence: 'Remote content is fetched and processed by this program.',
    control: 'Require approval or restrict egress.',
    why: ['Same reasoning as any outbound call: it is a data path in both directions.'],
  },
  {
    id: 'server-listen',
    languages: ['javascript', 'typescript', 'python', 'php'],
    re: /\b(createServer|\.listen\s*\(|app\.listen|Flask\(|FastAPI\(|http\.server|HTTPServer)\b/,
    rule: 'R004',
    capability: CAPABILITY.NET_LISTEN,
    severity: SEVERITY.MODERATE,
    title: 'Program opens a listening socket',
    consequence: 'The program accepts inbound connections. Whatever it exposes becomes reachable by anything that can route to it.',
    control: 'Allow only if bound to loopback. Verify the bind host is not 0.0.0.0.',
    why: ['An inbound socket is an attack surface, not just a feature.'],
  },
  {
    id: 'smtp',
    languages: ['javascript', 'typescript', 'python'],
    re: /\b(nodemailer|createTransport|smtplib|SMTP_)\b/,
    rule: 'R003',
    capability: CAPABILITY.CRED_READ,
    severity: SEVERITY.ELEVATED,
    title: 'Program sends email using stored credentials',
    consequence: 'Mail credentials are read from the environment and used to send mail as this identity. Both the credential and the identity can be misused.',
    control: 'Require approval, scope the mailbox credential narrowly, and never expose the value to a model.',
    why: ['Sending mail needs a long-lived secret, and the secret is readable by the whole process.'],
  },
  {
    id: 'webhook-out',
    languages: ['javascript', 'typescript', 'python'],
    re: /\b(webhook|slack\.com\/services|hooks\.|dingtalk|feishu|open\.feishu\.cn|qyapi\.weixin)\b/i,
    rule: 'R004',
    capability: CAPABILITY.NET_EGRESS,
    severity: SEVERITY.MODERATE,
    title: 'Program posts digests to external webhook endpoints',
    consequence: 'Project content is transmitted to third-party endpoints. A webhook URL is a credential in itself: anyone holding it can post as this integration.',
    control: 'Require an allowlisted domain and keep webhook URLs in secret storage, not in the repository.',
    why: ['Webhook delivery is outbound data flow to a destination the operator may not control.'],
  },

  // ---- credentials / identity -------------------------------------
  {
    id: 'env-read',
    languages: ['javascript', 'typescript', 'python', 'php'],
    re: /\b(process\.env\.?[A-Za-z_]*|os\.environ(\.get)?|getenv\s*\(|\$_ENV|\$_SERVER)/,
    rule: 'R003',
    capability: CAPABILITY.ENV_READ,
    severity: SEVERITY.LOW,
    title: 'Code reads environment variables',
    consequence: 'Whatever the operator exported is readable by this process, including unrelated secrets that were not intended for it.',
    control: 'Pass only the variables the task needs; do not inherit the full environment.',
    why: ['Environment inheritance is the quietest way a tool gets more authority than it needs.'],
  },
  {
    id: 'cloud-sdk',
    languages: ['javascript', 'typescript', 'python', 'php'],
    re: /\b(aws-sdk|@aws-sdk|boto3|google-cloud|@google-cloud|azure-identity|@azure\/|stripe|openai|anthropic|@supabase)\b/,
    rule: 'R008',
    capability: CAPABILITY.CLOUD_READ,
    severity: SEVERITY.MODERATE,
    title: 'Code links a cloud or third-party SDK',
    consequence: 'The program is built to act on external infrastructure or third-party APIs using whatever credentials it can find.',
    control: 'Confirm which credential source the SDK resolves to, and scope that credential to this task only.',
    why: ['An SDK present in the dependency graph means the credential path exists whether or not it is used today.'],
  },
  {
    id: 'crypto-keys',
    languages: ['javascript', 'typescript', 'python', 'php'],
    re: /\b(readFileSync\s*\([^)]*\.(pem|key|p12)|generateKeyPair|createPrivateKey|paramiko|ssh2)\b/,
    rule: 'R003',
    capability: CAPABILITY.CRED_READ,
    severity: SEVERITY.ELEVATED,
    title: 'Code loads private key material or implements SSH',
    consequence: 'Private keys are read into the process, and code that speaks SSH can reach other machines with that identity.',
    control: 'Require approval; deny host key directories inside the sandbox.',
    why: ['Key material plus a transport that uses it equals lateral movement capability.'],
  },

  // ---- persistence ------------------------------------------------
  {
    id: 'scheduler',
    languages: ['javascript', 'typescript', 'python'],
    re: /\b(node-cron|cron\.schedule|schedule\.every|APScheduler|celery|setInterval\s*\()/,
    rule: 'R009',
    capability: CAPABILITY.PERSISTENCE,
    severity: SEVERITY.MODERATE,
    title: 'Program contains a scheduler',
    consequence: 'Work is designed to repeat without a human starting it. If the process is kept alive, the agent keeps acting unattended.',
    control: 'Allow with logging, but pair with an explicit stop condition and never run it detached from an approved session.',
    why: ['Repeating work means repeated authority, long after the review that granted it.'],
  },

  // ---- browser / SSRF --------------------------------------------
  {
    id: 'browser-automation',
    languages: ['javascript', 'typescript', 'python'],
    re: /\b(playwright|puppeteer|selenium|webdriver|page\.goto|chromedp)\b/i,
    rule: 'R010',
    capability: CAPABILITY.BROWSER,
    severity: SEVERITY.MODERATE,
    title: 'Program drives a real browser',
    consequence: 'A browser carries the operator\'s session cookies and can reach internal addresses the network was supposed to block.',
    control: 'Require approval. Use a throwaway profile with no logged-in sessions and block private ranges.',
    why: ['A browser is a network client that also holds identity.'],
  },
];

/** Map file extension → the language buckets above. */
export function languageOf(path) {
  const p = String(path ?? '').toLowerCase();
  if (/\.(mjs|cjs|jsx?)$/.test(p)) return 'javascript';
  if (/\.(ts|tsx|mts|cts)$/.test(p)) return 'typescript';
  if (/\.py$/.test(p)) return 'python';
  if (/\.php$/.test(p)) return 'php';
  if (/\.(ya?ml)$/.test(p)) return 'yaml';
  if (/dockerfile/.test(p)) return 'dockerfile';
  if (/makefile/.test(p)) return 'makefile';
  if (/\.(sh|bash|zsh)$/.test(p)) return 'shell';
  if (/\.(json)$/.test(p)) return 'json';
  if (/\.(md|markdown|txt|rst)$/.test(p)) return 'prose';
  if (/\.(toml|ini|cfg|conf|env|example)$/.test(p)) return 'config';
  return 'text';
}

/** Line number of an index within a string. */
function lineOf(text, index) {
  return text.slice(0, Math.max(0, index)).split('\n').length;
}

/**
 * Scan one program file. Returns capability findings plus pseudo-actions so
 * the Action Trace can render code-level capabilities next to shell actions.
 */
export function scanCodeFile(path, content, opts = {}) {
  const language = languageOf(path);
  const text = String(content ?? '');
  const findings = [];
  const capabilities = [];
  const actions = [];
  if (!text.trim()) return { findings, capabilities, actions, language };

  for (const signal of CODE_SIGNALS) {
    if (signal.languages && !signal.languages.includes(language)) continue;
    signal.re.lastIndex = 0;
    const m = signal.re.exec(text);
    if (!m) continue;

    const line = lineOf(text, m.index);
    const snippet = redactString(text.split('\n')[line - 1]?.trim().slice(0, 160) ?? '');

    let severity = signal.severity;
    let extraEvidence = [];

    // Contextual escalation: environment reads on secret-shaped names.
    if (signal.id === 'env-read') {
      const names = Array.from(new Set((text.match(/\b(?:process\.env\.|getenv\(\s*['"]|os\.environ(?:\.get)?\(\s*['"])([A-Z][A-Z0-9_]{2,})/g) ?? [])
        .map((s) => (s.match(/([A-Z][A-Z0-9_]{2,})$/) ?? [])[1])
        .filter(Boolean)));
      const secretNames = names.filter((n) => /(TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|SMTP_PASS|CLIENT_SECRET|AUTH|CREDENTIAL)/i.test(n));
      if (names.length) {
        extraEvidence.push(`Environment variables read: ${names.slice(0, 12).join(', ')}${names.length > 12 ? ` (+${names.length - 12} more)` : ''}`);
        extraEvidence.push('Values are never read by the Inspector. Value: REDACTED');
      }
      if (secretNames.length) {
        severity = SEVERITY.ELEVATED;
        extraEvidence.push(`Secret-shaped variable names: ${secretNames.join(', ')}`);
      }
    }

    if (signal.id === 'fetch' || signal.id === 'py-network' || signal.id === 'webhook-out') {
      const urls = extractUrls(text);
      if (urls.length) {
        const classified = urls.map((u) => ({ u, ...classifyUrl(u, opts.approvedDomains ?? []) }));
        extraEvidence.push(`Literal URL(s) in file: ${urls.slice(0, 5).join(', ')}`);
        if (classified.some((c) => c.metadata)) severity = SEVERITY.CRITICAL;
        else if (classified.some((c) => c.scope === SCOPE.NETWORK_PRIVATE)) severity = SEVERITY.ELEVATED;
      } else {
        extraEvidence.push('Destination is not a literal: it is built from configuration or input at run time.');
      }
    }

    const action = makeAction({
      origin: 'code',
      language,
      actionType: 'code.capability',
      command: signal.id,
      arguments: [],
      raw: snippet,
      workingDirectory: opts.workingDirectory ?? '.',
      sourceFile: path,
      lineNumber: line,
      evidenceType: EVIDENCE.OBSERVED,
      note: `Static capability detected in ${language} source.`,
    });
    actions.push(action);

    capabilities.push({
      actionId: action.id,
      capabilityType: signal.capability,
      target: path,
      scope: SCOPE.PROJECT_LOCAL,
      riskLevel: severity,
      rule: signal.rule,
      evidence: `${signal.id} at ${path}:${line}`,
    });

    // A finding always names a rule (spec §33 evidence contract). Informational
    // signals that belong to no rule contribute a capability record only — they
    // still appear in the blast-radius map and as dimension evidence.
    if (!signal.rule) continue;

    const finding = makeFinding({
      rule: signal.rule,
      title: `${signal.title} — ${path}:${line}`,
      severity,
      capability: signal.capability,
      action: snippet,
      actionId: action.id,
      scope: language === 'prose' ? SCOPE.UNKNOWN : SCOPE.PROJECT_LOCAL,
      confidence: CONFIDENCE.HIGH,
      evidenceType: EVIDENCE.OBSERVED,
      evidence: [
        `File: ${path}:${line}`,
        `Detected: ${signal.id}`,
        `Source: ${snippet}`,
        ...extraEvidence,
        'Static read only — this file was not executed.',
      ],
      potentialConsequence: signal.consequence,
      recommendedControl: signal.control,
      why: signal.why,
      defaultDecision: severity >= SEVERITY.ELEVATED ? DECISION.REQUIRE_APPROVAL : DECISION.ALLOW_WITH_LOG,
      mappings: { owasp: [], snyk: [] },
      location: { file: path, line },
    });
    findings.push(finding);
  }

  return { findings, capabilities, actions, language };
}

/**
 * Known-file index: lets R005 distinguish "runs a project file we read"
 * from "runs something we have never seen".
 */
export function buildKnownFileIndex(sources) {
  const set = new Set();
  for (const s of sources) {
    const p = String(s.path ?? '').replace(/^\.\//, '');
    set.add(p);
    set.add(p.replace(/^.*\//, ''));
  }
  return set;
}
