/**
 * Minimal, dependency-free POSIX-shell reader.
 *
 * Scope discipline: this is a *static reader*. It never evaluates, expands
 * or executes anything. It produces token lists plus the structural facts
 * the rules need (pipelines, redirections, background jobs, command
 * substitution, environment prefixes).
 *
 * Anything it cannot resolve is reported as UNKNOWN rather than guessed —
 * the engine fails closed on unknown (spec §18).
 */

/** Remove a trailing `#` comment while respecting quotes. */
function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i += 1) {
    const c = line[i];
    if (quote) {
      if (c === '\\' && quote === '"') i += 1;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
    } else if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

/**
 * Split a shell source into statement segments, preserving line numbers.
 * Handles: newlines, `;`, `&&`, `||`, `|`, backslash continuations, and
 * nested `$( ... )` / backtick regions (treated as opaque).
 */
export function splitSegments(source) {
  const segments = [];
  let buffer = '';
  let line = 1;
  let segmentLine = 1;
  let quote = null;
  let depth = 0;
  let backtick = false;

  const push = (separator) => {
    const raw = buffer.trim();
    if (raw) {
      segments.push({ raw, line: segmentLine, separator });
    }
    buffer = '';
    segmentLine = line;
  };

  const text = String(source).replace(/\r\n?/g, '\n');

  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    const next = text[i + 1];

    if (quote) {
      buffer += c;
      if (c === '\\' && quote === '"') {
        buffer += next ?? '';
        i += 1;
      } else if (c === quote) {
        quote = null;
      }
      continue;
    }

    if (backtick) {
      buffer += c;
      if (c === '`') backtick = false;
      continue;
    }

    if (c === '\\' && next === '\n') {
      i += 1;
      line += 1;
      continue;
    }

    if (c === '"' || c === "'") {
      quote = c;
      buffer += c;
      continue;
    }

    if (c === '`') {
      backtick = true;
      buffer += c;
      continue;
    }

    if (c === '$' && next === '(') {
      depth += 1;
      buffer += '$(';
      i += 1;
      continue;
    }

    if (c === ')' && depth > 0) {
      depth -= 1;
      buffer += c;
      continue;
    }

    if (depth > 0) {
      buffer += c;
      continue;
    }

    if (c === '\n' || c === ';') {
      const separator = c === '\n' ? '\n' : ';';
      push(separator);
      if (c === '\n') line += 1;
      segmentLine = line;
      continue;
    }

    if (c === '&' && next === '&') {
      push('&&');
      i += 1;
      segmentLine = line;
      continue;
    }

    if (c === '|' && next === '|') {
      push('||');
      i += 1;
      segmentLine = line;
      continue;
    }

    // `&>`, `>&` and `2>&1` are redirections, not job control.
    if ((c === '|' || c === '&') && !(c === '&' && (next === '>' || buffer.endsWith('>')))) {
      push(c);
      segmentLine = line;
      continue;
    }

    buffer += c;
  }
  push('\n');
  return segments;
}

/** Tokenize one segment. Quotes are removed, escapes preserved as literal. */
export function tokenize(segment) {
  const tokens = [];
  let current = '';
  let started = false;
  let quote = null;

  for (let i = 0; i < segment.length; i += 1) {
    const c = segment[i];
    if (quote) {
      if (c === '\\' && quote === '"') {
        current += segment[i + 1] ?? '';
        i += 1;
      } else if (c === quote) {
        quote = null;
      } else {
        current += c;
      }
      started = true;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      started = true;
      continue;
    }
    if (c === '\\') {
      current += segment[i + 1] ?? '';
      i += 1;
      started = true;
      continue;
    }
    if (/\s/.test(c)) {
      if (started || current) {
        tokens.push(current);
        current = '';
        started = false;
      }
      continue;
    }
    if (c === '>' || c === '<') {
      const rest = segment.slice(i);
      const m = /^(\d*)(&>|>>|>&(?=\d)|<<|>|<)(\d*)/.exec(rest);
      if (m) {
        // An fd number may already be buffered (`2` in `2>&1`).
        let fd = m[1];
        if (!fd && /^\d+$/.test(current)) {
          fd = current;
          current = '';
          started = false;
        } else if (current) {
          tokens.push(current);
          current = '';
          started = false;
        }
        tokens.push(`${fd}${m[2]}${m[3]}`);
        i += m[0].length - 1;
        continue;
      }
      if (current) {
        tokens.push(current);
        current = '';
        started = false;
      }
      tokens.push(c);
      continue;
    }
    current += c;
    started = true;
  }
  if (started || current) tokens.push(current);
  return tokens;
}

const REDIRECTION_RE = /^(?:&>|\d*(?:>>|>&|<<|>|<)\d*)$/;

/**
 * Convert a token list into a command descriptor.
 *
 * Detects: env prefixes (`FOO=bar cmd`), the program, arguments,
 * redirection targets, background marker and any command substitution
 * present in the raw text.
 */
export function parseCommand(rawSegment, line) {
  const raw = rawSegment.trim();
  const tokens = tokenize(raw);

  const env = [];
  let idx = 0;
  while (idx < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[idx])) {
    env.push(tokens[idx].slice(0, tokens[idx].indexOf('=')));
    idx += 1;
  }

  const program = tokens[idx] ?? '';
  const rest = tokens.slice(idx + 1);

  const redirections = [];
  const args = [];
  let background = /&\s*$/.test(rawSegment);
  for (let i = 0; i < rest.length; i += 1) {
    const t = rest[i];
    if (t === '&') {
      // A bare `&` is job control, not an argument.
      background = true;
      continue;
    }
    if (REDIRECTION_RE.test(t)) {
      // `2>&1` carries its target fd inside the operator.
      const fdTarget = /^(?:\d*)>&(\d+)$/.exec(t);
      if (fdTarget) {
        redirections.push({ op: t, target: fdTarget[1] });
        continue;
      }
      const target = rest[i + 1] && !REDIRECTION_RE.test(rest[i + 1]) ? rest[i + 1] : null;
      redirections.push({ op: t, target });
      i += 1;
      continue;
    }
    args.push(t);
  }

  const substitutions = [];
  const subRe = /\$\(([^()]*)\)|`([^`]*)`/g;
  let m = subRe.exec(raw);
  while (m) {
    substitutions.push((m[1] ?? m[2] ?? '').trim());
    m = subRe.exec(raw);
  }

  return {
    raw,
    line,
    env,
    program,
    programBase: program.split('/').pop(),
    args,
    redirections,
    substitutions,
    background,
    hasVariableExpansion: /\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/.test(raw),
    hasDynamicConstruction: /\$\(|`|\beval\b/.test(raw),
  };
}

/** Read a shell file into structural segments + parsed commands. */
export function parseShell(source) {
  return splitSegments(stripCommentsPerLine(source))
    .map((seg) => ({ ...parseCommand(seg.raw, seg.line), separator: seg.separator }))
    .filter((cmd) => cmd.program || cmd.raw);
}

function stripCommentsPerLine(source) {
  return String(source)
    .split('\n')
    .map((l) => stripComment(l))
    .join('\n');
}

/** Heuristic for "this looks like a shell script" when the path is ambiguous. */
export function looksLikeShell(source) {
  const s = String(source).slice(0, 4000);
  if (/^#!.*\b(bash|sh|zsh|dash|ksh)\b/.test(s)) return true;
  return /(^|\n)\s*(set -e|cd |rm |cp |mkdir |node |npm |curl |wget |export )/.test(s);
}
