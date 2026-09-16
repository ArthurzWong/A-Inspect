/**
 * Content rules — R012 (prompt injection) and R013 (MCP inspection safety).
 *
 * Reference grounding:
 *   - OWASP Agentic Skills Top 10: AST01 Malicious Skills, AST04 Insecure
 *     Metadata, AST05 Untrusted External Instructions, AST08 Poor Scanning.
 *   - Snyk Agent Scan risk vocabulary: prompt_injection_tool_desc,
 *     dangerous_words, untrusted_content, private_data, suspicious_download_url.
 *   - AgentDojo threat model: untrusted content reaching an agent that also
 *     holds tools is the attack surface, not the content alone.
 *
 * Hard rule (spec §9 R012): never execute suspicious content merely to
 * decide whether it is suspicious. Everything here is static text analysis.
 */

import { CAPABILITY, CONFIDENCE, DECISION, EVIDENCE, SCOPE, SEVERITY, makeFinding } from '../schema.js';
import { redactString } from '../redact.js';
import { decodeBase64 } from '../b64.js';

/* ------------------------------------------------------------------ *
 * Injection signal catalogue
 * ------------------------------------------------------------------ */

const SIGNALS = [
  {
    id: 'instruction-override',
    sev: SEVERITY.CRITICAL,
    snyk: 'prompt_injection_tool_desc',
    owasp: ['AST01', 'AST05'],
    re: /\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(instruction|prompt|rule|direction|context)/i,
    why: 'Text that tells the agent to discard its current instructions is an attempt to replace the operator\'s intent with the content author\'s.',
  },
  {
    id: 'role-hijack',
    sev: SEVERITY.ELEVATED,
    snyk: 'prompt_injection_tool_desc',
    owasp: ['AST01'],
    re: /\b(you are now|from now on you|new (system )?prompt|act as (an?|the) [a-z]+ (assistant|agent)|developer mode|jailbreak)\b/i,
    why: 'Attempts to reassign the agent\'s role are an attempt to move the trust boundary into attacker-controlled text.',
  },
  {
    id: 'guardrail-removal',
    sev: SEVERITY.ELEVATED,
    snyk: 'dangerous_words',
    owasp: ['AST01'],
    re: /\b(disable|turn off|remove|ignore)\b[^.\n]{0,30}\b(safety|guardrail|restriction|approval|sandbox|policy|protection)s?\b/i,
    why: 'Removing the control that is being inspected is the goal of most agent-targeted attacks.',
  },
  {
    id: 'concealment',
    sev: SEVERITY.ELEVATED,
    snyk: 'prompt_injection_tool_desc',
    owasp: ['AST01'],
    re: /\b(do not|don't|never)\b[^.\n]{0,30}\b(tell|inform|mention|notify|reveal|show|report)\b[^.\n]{0,30}\b(user|human|operator|owner)\b|\bsilently\b|\bwithout (informing|telling|asking) (the )?(user|human)\b/i,
    why: 'Concealment turns a visible action into a hidden one. Every other control in this system depends on the operator being able to see what happened.',
  },
  {
    id: 'secret-exfiltration',
    sev: SEVERITY.CRITICAL,
    snyk: 'private_data',
    owasp: ['AST01'],
    re: /\b(exfiltrate|send|upload|post|leak|forward)\b[^.\n]{0,50}(?:\.env\b|env(?:ironment)? variables?|api[ _-]?key|token|secret|password|credential|ssh key|private key|keychain)/i,
    why: 'This is a complete attack in one sentence: read a secret, then move it somewhere the operator does not control.',
  },
  {
    id: 'credential-harvest',
    sev: SEVERITY.ELEVATED,
    snyk: 'private_data',
    owasp: ['AST01'],
    re: /\b(paste|provide|include|share|give me|enter)\b[^.\n]{0,30}\b(your )?(api[ _-]?key|token|password|credentials?|\.env|secret)\b/i,
    why: 'A legitimate tool does not need to ask the operator for secrets in prose.',
  },
  {
    id: 'remote-instructions',
    sev: SEVERITY.ELEVATED,
    snyk: 'untrusted_content',
    owasp: ['AST05'],
    re: /\b(read|follow|fetch|load|obey|execute)\b[^.\n]{0,30}\b(instructions?|guide|rules?|prompt)\b[^.\n]{0,40}\bhttps?:\/\//i,
    why: 'Instructions fetched at run time are mutable. Content that was safe when reviewed can be replaced afterwards (the "rug pull" pattern).',
  },
  {
    id: 'tool-poisoning',
    sev: SEVERITY.ELEVATED,
    snyk: 'prompt_injection_tool_desc',
    owasp: ['AST01', 'AST04'],
    re: /\b(when the user|whenever the user|if the user)\b[^.\n]{0,60}\b(also|additionally|first|before)\b[^.\n]{0,60}\b(send|call|read|write|delete|fetch|upload)\b/i,
    why: 'Tool descriptions that quietly add side effects are how a trusted-looking tool acquires capabilities nobody reviewed.',
  },
  {
    id: 'destructive-instruction',
    sev: SEVERITY.ELEVATED,
    snyk: 'destructive_capabilities',
    owasp: ['AST01'],
    re: /\b(delete|remove|wipe|destroy|overwrite)\b[^.\n]{0,40}\b(all|everything|entire|whole)\b[^.\n]{0,30}\b(files?|directory|directories|repo|project|home|disk)\b/i,
    why: 'Prose that instructs broad destruction is capability escalatable by any later confusion or injection.',
  },
];

/** Hidden / smuggling channels. */
const HIDDEN_UNICODE = [
  { name: 'zero-width character', re: /[\u200B-\u200D\u2060\uFEFF]/g },
  { name: 'bidi control character', re: /[\u202A-\u202E\u2066-\u2069]/g },
  { name: 'unicode tag character', re: /[\u{E0000}-\u{E007F}]/gu },
  { name: 'variation selector payload', re: /[\uFE00-\uFE0F]{4,}/g },
];

const INVISIBLE_NORMALIZE = /[\u200B-\u200D\u2060\uFEFF\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}]/gu;

/**
 * Normalize away invisible characters so a payload that hides behind them
 * is still matched by the textual rules (a common way to defeat scanners).
 */
export function deobfuscate(text) {
  return String(text ?? '').replace(INVISIBLE_NORMALIZE, '');
}

/* ------------------------------------------------------------------ *
 * R012 — Prompt injection
 * ------------------------------------------------------------------ */

export function detectPromptInjection(content, meta = {}) {
  const findings = [];
  const raw = String(content ?? '');
  if (!raw.trim()) return findings;

  const file = meta.file ?? null;
  const kind = meta.kind ?? 'text';

  // 1. Direct instruction signals, matched on the de-obfuscated text.
  const visible = deobfuscate(raw);
  const lowered = visible.toLowerCase();

  for (const signal of SIGNALS) {
    const m = signal.re.exec(visible);
    if (!m) continue;
    const line = lineOf(raw, m.index);
    const excerpt = excerptAround(visible, m.index, 120);
    findings.push(makeFinding({
      rule: 'R012',
      title: `Prompt-injection signal (${signal.id}) in ${file ?? kind}`,
      severity: signal.sev,
      capability: CAPABILITY.PROMPT_INJECTION,
      action: null,
      scope: SCOPE.UNKNOWN,
      confidence: CONFIDENCE.MEDIUM,
      evidenceType: EVIDENCE.OBSERVED,
      evidence: [
        `Location: ${file ?? kind}${line ? `:${line}` : ''}`,
        `Matched text: "${redactString(excerpt)}"`,
        'Detection is textual and static. The content was not executed to test it.',
      ],
      potentialConsequence:
        'If an agent reads this file as part of its context, the text can compete with the operator\'s actual instructions. The risk is not the text itself — it is that the agent holding tools may act on it.',
      recommendedControl: 'Treat this file as untrusted input. Do not let it reach an agent that also holds filesystem, network or execution tools without review.',
      why: [
        'This is an instruction addressed to the agent, not documentation for a human.',
        signal.why,
      ],
      mitigations: ['Require approval', 'Convert to read-only', 'Remove credential access'],
      defaultDecision: DECISION.REQUIRE_APPROVAL,
      mappings: { owasp: signal.owasp, snyk: [signal.snyk], agentdojo: ['untrusted-content-to-action'] },
      location: { file, line },
    }));
  }

  // 2. Hidden characters.
  for (const hidden of HIDDEN_UNICODE) {
    hidden.re.lastIndex = 0;
    const matches = raw.match(hidden.re);
    if (!matches || matches.length === 0) continue;
    findings.push(makeFinding({
      rule: 'R012',
      title: `Hidden ${hidden.name} sequence detected (${matches.length} occurrence(s))`,
      severity: SEVERITY.ELEVATED,
      capability: CAPABILITY.PROMPT_INJECTION,
      action: null,
      scope: SCOPE.UNKNOWN,
      confidence: CONFIDENCE.HIGH,
      evidenceType: EVIDENCE.OBSERVED,
      evidence: [
        `Location: ${file ?? kind}`,
        `Character class: ${hidden.name}`,
        `Count: ${matches.length}`,
        'These characters are generally invisible in editors and diffs, which lets text hide from human review while remaining in the model\'s context.',
      ],
      potentialConsequence:
        'Payload text can be hidden where a human reviewer will not see it but an agent will read it. Hidden text has no legitimate purpose in a skill, config or README.',
      recommendedControl: 'Deny until the hidden characters are removed and the diff is re-reviewed.',
      why: ['Invisible characters are a deliberate concealment technique.', 'Reviewers cannot approve what they cannot see.'],
      mitigations: ['Convert to read-only', 'Require approval'],
      defaultDecision: DECISION.REQUIRE_APPROVAL,
      mappings: { owasp: ['AST01', 'AST08'], snyk: ['prompt_injection_skill_instructions'], agentdojo: ['untrusted-content'] },
      location: { file, line: lineOf(raw, raw.search(hidden.re)) },
    }));
  }

  // 3. Encoded payload.
  const b64 = findBase64Payload(raw);
  if (b64) {
    findings.push(makeFinding({
      rule: 'R012',
      title: 'Long base64-encoded blob embedded in content',
      severity: SEVERITY.MODERATE,
      capability: CAPABILITY.PROMPT_INJECTION,
      action: null,
      scope: SCOPE.UNKNOWN,
      confidence: CONFIDENCE.MEDIUM,
      evidenceType: EVIDENCE.INFERRED,
      evidence: [
        `Location: ${file ?? kind}`,
        `Encoded length: ${b64.length} characters`,
        b64.decodedHint ? `Decoded bytes contain: ${b64.decodedHint}` : 'Decoded bytes are opaque.',
      ],
      potentialConsequence:
        'Encoding is used to carry text or code past reviewers and simple scanners. The decoded content, not the encoded blob, is what would eventually be acted on.',
      recommendedControl: 'Inspect the decoded payload manually. The Inspector will not execute or decode-and-run it.',
      why: ['A long opaque blob in documentation is not documentation.', 'The Inspector deliberately does not auto-execute decoded content to decide whether it is safe.'],
      mitigations: ['Convert to read-only', 'Require approval'],
      defaultDecision: DECISION.REQUIRE_APPROVAL,
      mappings: { owasp: ['AST08'], snyk: ['malicious_code'], agentdojo: ['obfuscation'] },
      location: { file, line: lineOf(raw, b64.index) },
    }));
  }

  // 4. HTML comments containing instructions (invisible in rendered view).
  const commentRe = /<!--([\s\S]*?)-->/g;
  let cm = commentRe.exec(raw);
  while (cm) {
    const body = deobfuscate(cm[1]);
    if (SIGNALS.some((s) => s.re.test(body)) || /\b(ignore|system|instruction|you must|agent)\b/i.test(body)) {
      findings.push(makeFinding({
        rule: 'R012',
        title: 'Instructions hidden in an HTML comment',
        severity: SEVERITY.ELEVATED,
        capability: CAPABILITY.PROMPT_INJECTION,
        action: null,
        scope: SCOPE.UNKNOWN,
        confidence: CONFIDENCE.MEDIUM,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [
          `Location: ${file ?? kind}:${lineOf(raw, cm.index)}`,
          `Comment content: "${redactString(excerptAround(body.trim(), 0, 140))}"`,
          'HTML comments are invisible in a rendered page but fully present in raw text.',
        ],
        potentialConsequence: 'Instruction-shaped text can be delivered through a channel a human reviewer of the rendered page never sees.',
        recommendedControl: 'Strip instruction-like comments from content before it reaches an agent.',
        why: ['The reviewer and the model read different renderings of the same file.'],
        defaultDecision: DECISION.REQUIRE_APPROVAL,
        mappings: { owasp: ['AST01'], snyk: ['prompt_injection_skill_instructions'], agentdojo: ['untrusted-content'] },
        location: { file, line: lineOf(raw, cm.index) },
      }));
    }
    cm = commentRe.exec(raw);
  }

  // 5. Inbound URL that could carry content to a model.
  if (/\b(fetch|read|load|curl|wget|GET)\b/i.test(lowered) && /https?:\/\//.test(lowered)) {
    const urls = raw.match(/https?:\/\/[^\s"'\x60<>)\]}]+/g) ?? [];
    const risky = urls.filter((u) => !/github\.com|raw\.githubusercontent\.com|docs\.|\.gov|\.edu/i.test(u)).slice(0, 3);
    if (risky.length) {
      findings.push(makeFinding({
        rule: 'R012',
        title: 'Content that instructs the agent to retrieve remote text',
        severity: SEVERITY.MODERATE,
        capability: CAPABILITY.PROMPT_INJECTION,
        action: null,
        scope: SCOPE.NETWORK_PUBLIC,
        confidence: CONFIDENCE.LOW,
        evidenceType: EVIDENCE.INFERRED,
        evidence: [
          `Location: ${file ?? kind}`,
          `Candidate remote source(s): ${risky.join(', ')}`,
          'Remote content is not pinned and can change after review.',
        ],
        potentialConsequence: 'Instructions sourced at run time can be swapped after the review that approved them.',
        recommendedControl: 'Pin remote content by hash, or vendor it into the repository and review it as code.',
        why: ['A link to instructions is an unfixed dependency on someone else\'s text.'],
        defaultDecision: DECISION.ALLOW_WITH_LOG,
        mappings: { owasp: ['AST05'], snyk: ['untrusted_content'], agentdojo: ['indirect-injection'] },
        location: { file, line: null },
      }));
    }
  }

  return findings;
}

function lineOf(text, index) {
  if (index == null || index < 0) return null;
  return text.slice(0, index).split('\n').length;
}

function excerptAround(text, index, len) {
  const start = Math.max(0, index - Math.floor(len / 3));
  return text.slice(start, start + len).replace(/\s+/g, ' ').trim();
}

function findBase64Payload(text) {
  const re = /[A-Za-z0-9+/]{200,}={0,2}/g;
  let m = re.exec(text);
  while (m) {
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(m[0])) {
      let hint = null;
      try {
        const decoded = decodeBase64(m[0].slice(0, 4000));
        if (/https?:\/\/|bash|sh\s|curl|wget|node|import |require\(/i.test(decoded)) {
          hint = redactString(decoded.slice(0, 120).replace(/[^\x20-\x7e]/g, '.'));
        }
      } catch {
        hint = null;
      }
      return { value: m[0].slice(0, 40) + '…', length: m[0].length, index: m.index, decodedHint: hint };
    }
    m = re.exec(text);
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * R013 — MCP inspection safety
 * ------------------------------------------------------------------ */

/**
 * Parse an MCP configuration statically. Never launch anything.
 * Snyk's Agent Scan documentation warns explicitly that scanning an MCP
 * config executes the configured stdio commands; this inspector refuses to
 * do that at inspection time and states the requirement instead.
 */
export function inspectMcpConfig(content, meta = {}) {
  const findings = [];
  const servers = [];
  let parsed;
  try {
    parsed = typeof content === 'string' ? JSON.parse(content) : content;
  } catch (err) {
    findings.push(makeFinding({
      rule: 'R013',
      title: 'MCP configuration could not be parsed',
      severity: SEVERITY.ELEVATED,
      capability: CAPABILITY.MCP_SERVER,
      action: null,
      scope: SCOPE.PROJECT_LOCAL,
      confidence: CONFIDENCE.MEDIUM,
      evidenceType: EVIDENCE.OBSERVED,
      evidence: [`Location: ${meta.file ?? 'mcp config'}`, `Parse error: ${String(err.message)}`],
      potentialConsequence: 'The server definitions cannot be inspected, so their capabilities are unknown.',
      recommendedControl: 'Fix the configuration, or treat every server in it as unreviewed.',
      why: ['Unparsable configuration is unknown configuration, and unknown is not allow.'],
      defaultDecision: DECISION.REQUIRE_APPROVAL,
      mappings: { owasp: ['AST04'], snyk: ['untrusted_content'] },
      location: { file: meta.file ?? null, line: null },
    }));
    return { servers, findings };
  }

  const map = parsed?.mcpServers ?? parsed?.servers ?? parsed?.mcp?.servers ?? ({});
  for (const [name, def] of Object.entries(map)) {
    const command = def?.command ?? def?.cmd ?? '';
    const args = Array.isArray(def?.args) ? def.args : [];
    const env = def?.env ?? {};
    const url = def?.url ?? def?.serverUrl ?? null;
    const transport = def?.type ?? (url ? 'http' : 'stdio');
    const envKeys = Object.keys(env);

    servers.push({ name, command, args, transport, url, envKeys, raw: redactString(`${command} ${args.join(' ')}`.trim()) });

    const evidence = [
      `Server: ${name}`,
      `Transport: ${transport}`,
      command ? `Command: ${command} ${args.join(' ')}`.trim() : `URL: ${url ?? 'unknown'}`,
      envKeys.length ? `Environment keys declared: ${envKeys.join(', ')} (values redacted)` : 'No environment variables declared.',
    ];

    findings.push(makeFinding({
      rule: 'R013',
      title: `MCP server declared: ${name}`,
      severity: SEVERITY.MODERATE,
      capability: CAPABILITY.MCP_SERVER,
      action: command ? `${command} ${args.join(' ')}`.trim() : url,
      scope: transport === 'stdio' ? SCOPE.PROJECT_LOCAL : SCOPE.NETWORK_PUBLIC,
      confidence: CONFIDENCE.HIGH,
      evidenceType: EVIDENCE.OBSERVED,
      evidence: [
        ...evidence,
        'Inspector action: configuration parsed statically. The server was NOT started.',
      ],
      potentialConsequence:
        transport === 'stdio'
          ? 'Starting this server means executing the command above with this project\'s environment. Per Snyk\'s Agent Scan documentation, MCP scanning itself executes configured stdio commands — so "just scanning" is already execution.'
          : 'A remote MCP server receives every tool call payload from this agent, including whatever content the agent has read.',
      recommendedControl:
        transport === 'stdio'
          ? 'Inspect statically. If the server must be started, do it inside a sandbox with no host credentials and no host filesystem, and treat the consent prompt as the last line of defence.'
          : 'Require an explicit domain allowlist entry and review what the remote server does with inputs.',
      why: [
        'An MCP server is a program the agent will run and trust for tool descriptions.',
        'Tool descriptions are instructions the model obeys, which makes the server a prompt-injection delivery path as well as a code path.',
      ],
      mitigations: ['Run inside sandbox', 'Remove credential access', 'Disable network', 'Require approval'],
      defaultDecision: DECISION.SANDBOX_ONLY,
      mappings: { owasp: ['AST01', 'AST04', 'AST06'], snyk: ['prompt_injection_tool_desc', 'untrusted_content'] },
      location: { file: meta.file ?? null, line: null },
    }));

    if (envKeys.length) {
      findings.push(makeFinding({
        rule: 'R003',
        title: `MCP server ${name} receives ${envKeys.length} environment value(s)`,
        severity: SEVERITY.MODERATE,
        capability: CAPABILITY.CRED_READ,
        action: null,
        scope: SCOPE.PROJECT_LOCAL,
        confidence: CONFIDENCE.MEDIUM,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [`Server: ${name}`, `Keys passed through: ${envKeys.join(', ')}`, 'Values are never read by the Inspector. Value: REDACTED'],
        potentialConsequence: 'Anything passed here is readable by the server process, including anything it spawns.',
        recommendedControl: 'Pass the narrowest possible values and prefer short-lived tokens.',
        why: ['Environment inheritance is the most common way a tool silently receives more authority than it needs.'],
        defaultDecision: DECISION.REQUIRE_APPROVAL,
        mappings: { owasp: ['AST03'], snyk: ['insecure_credential_handling'] },
        location: { file: meta.file ?? null, line: null },
      }));
    }
  }

  return { servers, findings };
}

export const MCP_INSPECTION_PIPELINE = [
  'UPLOAD MCP CONFIG',
  'STATIC PARSE',
  'SHOW COMMAND',
  'SANDBOX REQUIRED',
  'OPTIONAL USER APPROVAL',
  'START SERVER (never automatic)',
];
