#!/usr/bin/env node
/**
 * Build a single self-contained HTML file for the console.
 *
 * Why a bundler at all: the console and the engine share one module graph, so
 * the graphs, scores and decisions you see in the browser come from exactly
 * the same code the CLI and the test suite run. Bundling keeps that true while
 * still producing a file that opens directly from disk with no server, no
 * CDN, and no network access.
 *
 * The transform is intentionally tiny and strict: named ESM imports with
 * relative specifiers only. Anything else fails the build rather than
 * silently producing a broken bundle.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { inspectProject } from '../src/engine/inspectionEngine.js';
import { readTree } from './lib/read-tree.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = 'app/app.js';
const OUT_HTML = path.join(ROOT, 'dist', 'agent-inspector.html');

/* ------------------------------------------------------------------ *
 * Module graph
 * ------------------------------------------------------------------ */

const IMPORT_NAMED = /^[ \t]*import\s*\{([\s\S]*?)\}\s*from\s*['"]([^'"]+)['"];?[ \t]*$/gm;
const IMPORT_DEFAULT = /^[ \t]*import\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{([\s\S]*?)\})?\s*from\s*['"]([^'"]+)['"];?[ \t]*$/gm;
const IMPORT_SIDE = /^[ \t]*import\s*['"]([^'"]+)['"];?[ \t]*$/gm;
const EXPORT_DECL = /^[ \t]*export\s+(const|let|var|function|async\s+function|class)\s+([A-Za-z_$][\w$]*)/gm;
const EXPORT_DEFAULT = /^[ \t]*export\s+default\s+/gm;
const EXPORT_BLOCK = /^[ \t]*export\s*\{([^}]*)\};?[ \t]*$/gm;
const REEXPORT_STAR = /^[ \t]*export\s+\*\s+from\s*['"]([^'"]+)['"];?[ \t]*$/gm;
const REEXPORT_NAMED = /^[ \t]*export\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"];?[ \t]*$/gm;

function resolveId(fromId, spec) {
  if (!spec.startsWith('.')) {
    throw new Error(`Only relative specifiers are supported in the bundle. "${spec}" imported from ${fromId}`);
  }
  const dir = path.posix.dirname(fromId);
  const base = path.posix.normalize(path.posix.join(dir, spec));
  const candidates = [base, `${base}.js`, `${base}/index.js`, base.replace(/\.js$/, '.js')];
  for (const c of candidates) {
    if (fs.existsSync(path.join(ROOT, c)) && fs.statSync(path.join(ROOT, c)).isFile()) return c;
  }
  throw new Error(`Cannot resolve "${spec}" from ${fromId}`);
}

function transform(id, source) {
  const deps = [];

  const bind = (list, depId) => {
    const pairs = list
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .map((part) => {
        const [orig, alias] = part.split(/\s+as\s+/).map((x) => x.trim());
        return alias && alias !== orig ? `${orig}: ${alias}` : orig;
      });
    return `const { ${pairs.join(', ')} } = require(${JSON.stringify(depId)});`;
  };

  /**
   * Replace matches of `re` in `input`, skipping any match that falls inside a
   * template literal (detected by blanking template interiors and comparing
   * offsets). The mask is recomputed on every call because earlier rewrites
   * shift offsets.
   */
  const replaceCode = (re, input, handler) => {
    const mask = maskTemplateLiterals(input);
    const re2 = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    let out = '';
    let last = 0;
    let m = re2.exec(input);
    while (m !== null) {
      const masked = mask.slice(m.index, m.index + m[0].length);
      const insideTemplate = masked.length > 0 && /^\s*$/.test(masked);
      if (!insideTemplate) {
        out += input.slice(last, m.index);
        out += handler(m);
        last = m.index + m[0].length;
      }
      m = re2.exec(input);
    }
    return out + input.slice(last);
  };

  let code = replaceCode(IMPORT_NAMED, source, (m) => {
    const depId = resolveId(id, m[2]);
    deps.push({ id: depId, spec: m[2] });
    return bind(m[1].replace(/\s+/g, ' '), depId);
  });

  code = replaceCode(IMPORT_DEFAULT, code, (m) => {
    const depId = resolveId(id, m[3]);
    deps.push({ id: depId, spec: m[3] });
    const lines = [`const ${m[1]} = require(${JSON.stringify(depId)}).default ?? require(${JSON.stringify(depId)});`];
    if (m[2]) lines.push(bind(m[2].replace(/\s+/g, ' '), depId));
    return lines.join('\n');
  });

  code = replaceCode(IMPORT_SIDE, code, (m) => {
    const depId = resolveId(id, m[1]);
    deps.push({ id: depId, spec: m[1] });
    return `require(${JSON.stringify(depId)});`;
  });

  // Any remaining import statement that is real code (not template text) means
  // an import form this bundler does not understand: fail loudly.
  const leftoverLines = code.split('\n');
  const leftoverMask = maskTemplateLiterals(code).split('\n');
  const leftover = leftoverLines
    .map((line, i) => ({ line, masked: leftoverMask[i] ?? '' }))
    .find(({ line, masked }) => /^\s*import\s/.test(line) && /^\s*import\s/.test(masked));
  if (leftover) {
    throw new Error(`Unhandled import form in ${id}: ${leftover.line}`);
  }

  let reexportCounter = 0;

  // Named re-exports must be handled before the plain `export {…}` stripper.
  code = replaceCode(REEXPORT_NAMED, code, (m) => {
    const depId = resolveId(id, m[2]);
    deps.push({ id: depId, spec: m[2] });
    const n = (reexportCounter += 1);
    const parts = m[1]
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .map((part) => {
        const [orig, alias] = part.split(/\s+as\s+/).map((x) => x.trim());
        return { orig, out: alias || orig };
      });
    const lines = [`const __re${n} = require(${JSON.stringify(depId)});`];
    for (const p of parts) lines.push(`exports.${p.out} = __re${n}.${p.orig};`);
    return lines.join('\n');
  });

  code = replaceCode(REEXPORT_STAR, code, (m) => {
    const depId = resolveId(id, m[1]);
    deps.push({ id: depId, spec: m[1] });
    const n = (reexportCounter += 1);
    return `const __star${n} = require(${JSON.stringify(depId)});\n`
      + `for (const __k${n} of Object.keys(__star${n})) { if (__k${n} !== "default" && !(__k${n} in exports)) exports[__k${n}] = __star${n}[__k${n}]; }`;
  });

  // Named declarations: drop the `export` keyword and record the binding so
  // it can be published at the end of the module body.
  const exportedNames = [];
  code = replaceCode(EXPORT_DECL, code, (m) => {
    exportedNames.push(m[2]);
    // Keep the declaration; only the `export` keyword goes away.
    return `${m[1]} ${m[2]}`;
  });

  code = replaceCode(EXPORT_DEFAULT, code, () => 'exports.default = ');

  code = replaceCode(EXPORT_BLOCK, code, (m) => {
    const parts = m[1]
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .map((part) => {
        const [orig, alias] = part.split(/\s+as\s+/).map((x) => x.trim());
        return { orig, out: alias || orig };
      });
    if (!parts.length) return '';
    return parts.map((p) => `exports.${p.out} = ${p.orig};`).join('\n');
  });

  if (exportedNames.length) {
    const unique = Array.from(new Set(exportedNames));
    code += `\nObject.assign(exports, { ${unique.join(', ')} });\n`;
  }

  // Fail loudly rather than shipping a bundle with a stray `export`. This is
  // the guard that catches any construct the masker did not understand.
  const strayLines = code.split('\n');
  const strayMask = maskTemplateLiterals(code).split('\n');
  const stray = strayLines
    .map((line, i) => ({ line, masked: strayMask[i] ?? '' }))
    .find(({ line, masked }) => /^\s*export\s/.test(line) && /^\s*export\s/.test(masked));
  if (stray) {
    throw new Error(`Unhandled export form in ${id}: ${stray.line.trim().slice(0, 80)}`);
  }

  return { code, deps };
}

/**
 * Blank out the interior of template literals, preserving line structure, so
 * embedded code samples are never rewritten by the bundler.
 */
function maskTemplateLiterals(source) {
  const lines = source.split('\n');
  let inside = false;
  return lines.map((line) => {
    if (!inside && !line.includes('`')) return line;
    let out = '';
    for (let i = 0; i < line.length; i += 1) {
      const c = line[i];
      if (c === '\\') {
        out += inside ? ' ' : c;
        i += 1;
        out += inside ? ' ' : (line[i] ?? '');
        continue;
      }
      if (c === '`') {
        inside = !inside;
        out += ' ';
        continue;
      }
      out += inside ? ' ' : c;
    }
    return out;
  }).join('\n');
}

function collect(entryId) {
  const modules = new Map();
  const queue = [entryId];
  while (queue.length) {
    const id = queue.shift();
    if (modules.has(id)) continue;
    const source = fs.readFileSync(path.join(ROOT, id), 'utf8');
    const { code, deps } = transform(id, source);
    modules.set(id, code);
    for (const d of deps) if (!modules.has(d.id)) queue.push(d.id);
  }
  return modules;
}

/* ------------------------------------------------------------------ *
 * Emit
 * ------------------------------------------------------------------ */

function bundle(entryId) {
  const modules = collect(entryId);
  const parts = [];
  parts.push('(function () {');
  parts.push('"use strict";');
  parts.push('const __registry = Object.create(null);');
  parts.push('const __cache = Object.create(null);');
  parts.push('function require(id) {');
  parts.push('  if (__cache[id]) return __cache[id].exports;');
  parts.push('  const factory = __registry[id];');
  parts.push('  if (!factory) throw new Error("module not bundled: " + id);');
  parts.push('  const module = { exports: {} };');
  parts.push('  __cache[id] = module;');
  parts.push('  factory(module, module.exports, require);');
  parts.push('  return module.exports;');
  parts.push('}');
  parts.push('const window = globalThis;');
  parts.push('const global = globalThis;');

  for (const [id, code] of modules) {
    parts.push(`__registry[${JSON.stringify(id)}] = function (module, exports, require) {`);
    parts.push(code);
    parts.push('};');
  }

  parts.push('globalThis.__AGENT_INSPECTOR_BUNDLE__ = { require, modules: Object.keys(__registry) };');
  // Only boot the UI when a DOM is present, so the same bundle can be
  // verified headlessly in Node.
  parts.push(`if (typeof document !== "undefined") { require(${JSON.stringify(entryId)}); }`);
  parts.push('})();');
  return { code: parts.join('\n'), modules: Array.from(modules.keys()) };
}

/* ------------------------------------------------------------------ *
 * Compose the HTML
 * ------------------------------------------------------------------ */

function compose({ js, css, moduleList, fixtureReport, fixtureSources }) {
  const html = fs.readFileSync(path.join(ROOT, 'app/index.html'), 'utf8');
  // Every replacement uses a function. A string replacement would interpret
  // `$$`, `$&`, `$'` in the injected code as escape sequences and silently
  // corrupt the bundle (this is exactly how `const $$ = …` once became
  // `const $ = …`).
  let out = html
    .replace(/<link rel="stylesheet" href="\.\/styles\.css"\s*\/?>/, () => `<style>\n${css}\n</style>`)
    .replace(/<script type="module" src="\.\/app\.js"><\/script>/, () => `<script>\n${js}\n</script>`);

  out = out.replace('<head>', () => `<head>\n<!--
  Agent Inspector — single-file build.
  Generated by scripts/build-web.mjs. Modules bundled (${moduleList.length}):
${moduleList.map((m) => `    ${m}`).join('\n')}
  Open this file directly in a browser: no server, no CDN, no network.
-->`);

  const safeJson = (value) => JSON.stringify(value).replace(/</g, '\\u003c');
  const injected = [
    '<script id="fixture-sources" type="application/json">',
    safeJson(fixtureSources),
    '</script>',
    '<script id="fixture-report" type="application/json">',
    safeJson(fixtureReport),
    '</script>',
    '<script>window.__FIXTURE_SOURCES__ = JSON.parse(document.getElementById(\'fixture-sources\').textContent);</script>',
    '<script>\n',
  ].join('\n');
  out = out.replace('<script>\n', () => injected);
  return out;
}

/* ------------------------------------------------------------------ *
 * Run
 * ------------------------------------------------------------------ */

const { code: js, modules: moduleList } = bundle(ENTRY);
const css = fs.readFileSync(path.join(ROOT, 'app/styles.css'), 'utf8');

// Generate a real inspection of the shipped fixture, so the console can load
// a genuine engine output rather than a hand-written sample.
const { sources } = readTree(path.join(ROOT, 'fixtures/spec-demo'));
const fixtureReport = inspectProject({
  sources,
  options: { workspace: 'fixture://spec-demo', agentId: 'autoclaw' },
});
fixtureReport.meta.fixture = 'fixtures/spec-demo (synthetic, non-destructive)';

const html = compose({ js, css, moduleList, fixtureReport, fixtureSources: sources });

fs.mkdirSync(path.join(ROOT, 'dist'), { recursive: true });
fs.writeFileSync(OUT_HTML, html);
fs.writeFileSync(path.join(ROOT, 'dist', 'engine.bundle.js'), js);
fs.writeFileSync(path.join(ROOT, 'dist', 'fixture-report.json'), JSON.stringify(fixtureReport, null, 2));

// The console reads the fixture from JSON rather than embedding code samples
// in its own source, so the fixture has exactly one definition.
const fixtureSourcesPath = { sources };
fs.writeFileSync(path.join(ROOT, 'app', 'fixture-sources.json'), JSON.stringify(fixtureSourcesPath, null, 2));
fs.writeFileSync(path.join(ROOT, 'dist', 'fixture-sources.json'), JSON.stringify(fixtureSourcesPath, null, 2));

const sizeKb = (Buffer.byteLength(html) / 1024).toFixed(1);
console.log(`Bundled ${moduleList.length} modules → ${path.relative(ROOT, OUT_HTML)} (${sizeKb} KB)`);
console.log('Also wrote: dist/engine.bundle.js, dist/fixture-report.json, dist/fixture-sources.json, app/fixture-sources.json');
