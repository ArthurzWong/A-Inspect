/**
 * Read-only directory loader (Node only — not part of the browser bundle).
 *
 * Used by the CLI and the test suite to turn a local project into the
 * `sources` array the engine consumes. It never writes, never follows
 * symlinks out of the tree, never reads files above the size cap, and
 * skips binary/secret-bearing files that cannot be analysed as text.
 *
 * Reading a file is not executing a file.
 */

import fs from 'node:fs';
import path from 'node:path';

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'dist', 'build', '.next', '.nuxt',
  'coverage', '.cache', '.venv', 'venv', '__pycache__', '.mypy_cache',
  '.terraform', 'vendor', 'target', '.gradle', '.idea', '.DS_Store',
]);

/** Files we deliberately do not read at all. */
const SKIP_FILES = [
  /^\.env$/, /^\.env\.[a-z]+$/i,          // real .env files may hold live secrets
  /\.pem$/, /\.key$/, /\.p12$/, /\.pfx$/, /\.keystore$/, /\.jks$/,
  /^id_(rsa|dsa|ecdsa|ed25519)$/,
  /\.(png|jpe?g|gif|webp|ico|svgz|pdf|zip|gz|tgz|bz2|xz|7z|rar|mp4|mov|mp3|wav|woff2?|ttf|eot|wasm|so|dylib|dll|exe|bin|class|jar|lockb)$/i,
];

const MAX_FILE_BYTES = 512 * 1024;      // 512 KB per file
const MAX_FILES = 4000;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;

export function shouldSkipFile(name) {
  return SKIP_FILES.some((re) => re.test(name));
}

/**
 * @param {string} root absolute or relative directory
 * @param {object} opts { maxFiles, maxFileBytes, maxTotalBytes, onNote }
 * @returns {{sources: Array<{path,content}>, skipped: Array<{path,reason}>, stats}}
 */
export function readTree(root, opts = {}) {
  const maxFiles = opts.maxFiles ?? MAX_FILES;
  const maxFileBytes = opts.maxFileBytes ?? MAX_FILE_BYTES;
  const maxTotalBytes = opts.maxTotalBytes ?? MAX_TOTAL_BYTES;
  const onNote = opts.onNote ?? (() => {});

  const base = path.resolve(root);
  const sources = [];
  const skipped = [];
  let totalBytes = 0;

  if (!fs.existsSync(base)) {
    throw new Error(`Path does not exist: ${base}`);
  }
  const stat = fs.statSync(base);
  if (!stat.isDirectory()) {
    // Single file: inspect exactly that file.
    const name = path.basename(base);
    if (shouldSkipFile(name)) {
      skipped.push({ path: name, reason: 'skipped by policy (binary or secret-bearing file)' });
      return { sources, skipped, stats: { files: 0, bytes: 0, truncated: false } };
    }
    const content = fs.readFileSync(base, 'utf8');
    return { sources: [{ path: name, content }], skipped, stats: { files: 1, bytes: content.length, truncated: false } };
  }

  const queue = [base];
  let truncated = false;

  while (queue.length) {
    const dir = queue.shift();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      skipped.push({ path: dir, reason: `unreadable directory: ${err.message}` });
      continue;
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      const rel = path.relative(base, full).split(path.sep).join('/');

      if (entry.isSymbolicLink()) {
        skipped.push({ path: rel, reason: 'symlink not followed' });
        continue;
      }
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) {
          skipped.push({ path: rel, reason: 'excluded directory' });
          continue;
        }
        queue.push(full);
        continue;
      }
      if (!entry.isFile()) continue;

      if (shouldSkipFile(entry.name)) {
        skipped.push({ path: rel, reason: 'skipped by policy (binary or secret-bearing file)' });
        continue;
      }
      if (sources.length >= maxFiles) {
        truncated = true;
        skipped.push({ path: rel, reason: `file limit reached (${maxFiles})` });
        continue;
      }

      let fileStat;
      try {
        fileStat = fs.statSync(full);
      } catch (err) {
        skipped.push({ path: rel, reason: `stat failed: ${err.message}` });
        continue;
      }
      if (fileStat.size > maxFileBytes) {
        skipped.push({ path: rel, reason: `file larger than ${Math.round(maxFileBytes / 1024)} KB` });
        continue;
      }
      if (totalBytes + fileStat.size > maxTotalBytes) {
        truncated = true;
        skipped.push({ path: rel, reason: 'total size limit reached' });
        continue;
      }

      let content;
      try {
        content = fs.readFileSync(full, 'utf8');
      } catch (err) {
        skipped.push({ path: rel, reason: `read failed: ${err.message}` });
        continue;
      }
      if (content.includes('\u0000')) {
        skipped.push({ path: rel, reason: 'binary content detected' });
        continue;
      }

      totalBytes += fileStat.size;
      sources.push({ path: rel, content });
    }
  }

  onNote(`Read ${sources.length} file(s) from ${base}`);
  if (truncated) onNote('File limits were reached: the inspection is incomplete and the report says so.');

  return {
    sources: sources.sort((a, b) => a.path.localeCompare(b.path)),
    skipped,
    stats: { files: sources.length, bytes: totalBytes, truncated, root: base },
  };
}
