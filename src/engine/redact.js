/**
 * Secret redaction (spec §20, §31).
 *
 * Rule: anything that looks like a credential is replaced before it can
 * reach a UI, a log line, an audit payload, or an external analysis model.
 * Redaction happens at the edge of the engine, not in the renderer, so a
 * consumer that forgets to redact still receives redacted data.
 */

const PATTERNS = [
  // PEM private keys (multi-line, handled separately as well)
  { name: 'private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  // Authorization headers / bearer tokens
  { name: 'authorization', re: /\b(authorization|auth)\s*[:=]\s*(bearer|basic|token)?\s*[A-Za-z0-9._~+/=-]{8,}/gi },
  { name: 'bearer', re: /\bbearer\s+[A-Za-z0-9._~+/=-]{12,}/gi },
  // Well-known provider token shapes
  { name: 'openai', re: /\bsk-[A-Za-z0-9_-]{16,}\b/g },
  { name: 'anthropic', re: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g },
  { name: 'github-pat', re: /\bgh[pousr]_[A-Za-z0-9]{16,}\b/g },
  { name: 'slack', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: 'aws-key-id', re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { name: 'google-api', re: /\bAIza[0-9A-Za-z_-]{30,}\b/g },
  { name: 'stripe', re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  // credential-ish assignments: PASSWORD=..., api_key: "..."
  {
    name: 'assignment',
    re: /\b([A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|SMTP_PASS|AUTH)[A-Za-z0-9_]*)\s*[:=]\s*("[^"\n]*"|'[^'\n]*'|<[^>\n]*>|[^\s'"#]{4,})/gi,
  },
  // URLs with inline credentials
  { name: 'url-credentials', re: /\b([a-z][a-z0-9+.-]*:\/\/)[^\s:/@]+:[^\s:/@]+@/gi },
  // .env style long random values on sensitive-looking keys
  { name: 'hex-secret', re: /\b[a-fA-F0-9]{40,}\b/g },
];

/** Values that are obviously placeholders, not live secrets. */
const PLACEHOLDER = /^(REDACTED|xxx+|\.\.\.|<.*>|your[-_].*|changeme|placeholder|\$\{.*\}|""|''|null|undefined|true|false)$/i;

export const REDACTED = '[REDACTED]';

/**
 * Redact secrets in a string. Idempotent: re-running on already-redacted
 * text does not double-mangle it.
 */
export function redactString(input) {
  if (input == null) return input;
  let out = String(input);
  for (const { re } of PATTERNS) {
    out = out.replace(re, (match, ...groups) => {
      // For assignment-style matches keep the key, drop the value.
      if (groups.length >= 2 && typeof groups[0] === 'string' && groups[1] != null && typeof groups[1] === 'string' && /^[A-Za-z0-9_]/.test(groups[0])) {
        const key = groups[0];
        const value = groups[1];
        const bare = value.replace(/^["']|["']$/g, '');
        if (PLACEHOLDER.test(bare) || bare.startsWith('${')) return match;
        return `${key}=${REDACTED}`;
      }
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(match)) {
        return match.replace(/\/\/[^@]*@/, `//${REDACTED}@`);
      }
      return REDACTED;
    });
  }
  return out;
}

/** Deep redaction for records that go into the audit ledger or a report. */
export function redactDeep(value, depth = 0) {
  if (depth > 12) return REDACTED;
  if (value == null) return value;
  if (typeof value === 'string') return redactString(value);
  if (typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (/^(password|passwd|secret|token|apiKey|api_key|privateKey|private_key|authorization|auth|cookie|client_secret|smtp_pass)$/i.test(k)) {
      out[k] = typeof v === 'string' && PLACEHOLDER.test(v) ? v : REDACTED;
    } else {
      out[k] = redactDeep(v, depth + 1);
    }
  }
  return out;
}

/** Does this text contain something that looks like a live secret? */
export function looksLikeSecret(value) {
  if (!value) return false;
  const s = String(value).trim();
  if (PLACEHOLDER.test(s)) return false;
  if (s.length < 12) return false;
  return PATTERNS.some(({ re }) => {
    re.lastIndex = 0;
    return re.test(s);
  });
}
