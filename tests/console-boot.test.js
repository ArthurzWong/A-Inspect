/**
 * Console boot test.
 *
 * The browser console is the one part of the system that cannot be exercised
 * by the engine tests, so it gets its own: the real single-file bundle is
 * evaluated against a minimal DOM stub, the INSPECT button is clicked, and the
 * five screens are checked for rendered output.
 *
 * This is not a substitute for looking at it in a browser — it is a guard
 * against the console throwing on boot or rendering nothing, which is how a
 * view layer usually breaks.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { extractInlineBundle } from '../scripts/lib/extract-inline-bundle.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/* ------------------------------------------------------------------ *
 * Minimal DOM
 * ------------------------------------------------------------------ */

function createElement(selector = '') {
  const el = {
    selector,
    tagName: 'DIV',
    _text: '',
    _html: '',
    className: '',
    hidden: false,
    disabled: false,
    value: '',
    files: null,
    style: {},
    dataset: {},
    attrs: {},
    handlers: {},
    children: [],
    get textContent() { return this._text; },
    set textContent(v) { this._text = String(v); },
    get innerHTML() { return this._html; },
    set innerHTML(v) { this._html = String(v); },
    classList: {
      _set: new Set(),
      add(c) { this._set.add(c); },
      remove(c) { this._set.delete(c); },
      contains(c) { return this._set.has(c); },
      toggle(c, force) {
        const on = force === undefined ? !this._set.has(c) : Boolean(force);
        if (on) this._set.add(c); else this._set.delete(c);
        return on;
      },
    },
    addEventListener(type, fn) {
      (this.handlers[type] = this.handlers[type] ?? []).push(fn);
    },
    removeEventListener() {},
    dispatch(type, event = {}) {
      return (this.handlers[type] ?? []).map((fn) => fn({ preventDefault() {}, target: this, ...event }));
    },
    setAttribute(k, v) { this.attrs[k] = v; },
    getAttribute(k) { return this.attrs[k]; },
    appendChild(child) { this.children.push(child); return child; },
    click() { this.dispatch('click'); },
    focus() {},
    querySelector(sel) { return createElement(sel); },
    querySelectorAll() { return []; },
  };
  return el;
}

function createDom() {
  const registry = new Map();
  const byClass = new Map();

  const querySelector = (sel) => {
    if (registry.has(sel)) return registry.get(sel);
    const el = createElement(sel);
    registry.set(sel, el);
    return el;
  };

  const querySelectorAll = (sel) => {
    if (byClass.has(sel)) return byClass.get(sel);
    // Return one stub per known selector so forEach/classList work.
    const list = [createElement(sel)];
    byClass.set(sel, list);
    return list;
  };

  // Pre-seed the two selectors the boot path reads state from.
  const activeTab = createElement('.itab.is-active');
  activeTab.dataset.input = 'paste';
  registry.set('.itab.is-active', activeTab);

  const document = {
    readyState: 'complete',
    body: createElement('body'),
    documentElement: createElement('html'),
    querySelector,
    querySelectorAll,
    getElementById: (id) => querySelector(`#${id}`),
    createElement: () => createElement('created'),
    addEventListener() {},
  };

  return { document, registry };
}

/* ------------------------------------------------------------------ *
 * Sandbox
 * ------------------------------------------------------------------ */

const BUNDLE = path.join(ROOT, 'dist', 'engine.bundle.js');

function bootConsole() {
  // Boot the script that actually ships: the one inlined in the single-file
  // HTML. Reading the standalone bundle file would miss exactly the class of
  // build bug that broke the console once (a `$$` eaten by String.replace).
  const { code } = extractInlineBundle();
  const { document, registry } = createDom();

  let alerted = null;
  const sandbox = {
    console,
    document,
    TextEncoder,
    TextDecoder,
    URL,
    URLSearchParams,
    Math, Date, JSON, Object, Array, String, Number, Boolean, Error, TypeError, RangeError, RegExp,
    Map, Set, Promise, Symbol, Uint8Array, Uint32Array, Int16Array, DataView, ArrayBuffer, WeakMap,
    setTimeout, clearTimeout, queueMicrotask,
    alert: (msg) => { alerted = String(msg); },
    confirm: () => true,
    fetch: async () => ({
      ok: true,
      json: async () => JSON.parse(fs.readFileSync(path.join(ROOT, 'app', 'fixture-sources.json'), 'utf8')),
      text: async () => '',
    }),
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  sandbox.scrollTo = () => {};

  vm.createContext(sandbox);
  new vm.Script(code).runInContext(sandbox);

  return {
    sandbox,
    registry,
    // Selectors are stubbed lazily, exactly like the real DOM: asking for an
    // element creates it once, and both the test and the app then share it.
    get: (sel) => registry.get(sel) ?? document.querySelector(sel),
    alerted: () => alerted,
  };
}

/* ------------------------------------------------------------------ *
 * Tests
 * ------------------------------------------------------------------ */

test('the console boots without a real browser and renders the dashboard', () => {
  const app = bootConsole();
  const result = app.get('#dashboard-result');
  assert.ok(result, 'dashboard container must exist');
  assert.match(result.innerHTML, /How this works/, 'the empty state should render on boot');
  assert.match(result.innerHTML, /R001/, 'the rule catalogue should be visible');
});

test('clicking INSPECT with a pasted command renders real findings', async () => {
  const app = bootConsole();
  app.get('#cmd-input').value = 'node bin/contentpulse.js run --config demo/sources.yaml';
  await Promise.all(app.get('#inspect-btn').dispatch('click'));

  const dashboard = app.get('#dashboard-result').innerHTML;
  assert.match(dashboard, /EXPOSURE/, 'an exposure banner must render');
  assert.match(dashboard, /actions detected/);
  assert.match(dashboard, /Exposure by dimension/);

  // Screen 2 and 5 must have rendered too.
  assert.match(app.get('#trace-tree').innerHTML, /data-action=/, 'the action tree should have nodes');
  assert.match(app.get('#audit-table').innerHTML, /INSPECTION_STARTED/, 'the ledger should show the start event');
});

test('the fixture loads and produces a multi-screen report', async () => {
  const app = bootConsole();
  app.get('#load-fixture').dispatch('click');
  // The handler is async; let its promise chain settle.
  await new Promise((resolve) => setTimeout(resolve, 30));

  const dashboard = app.get('#dashboard-result').innerHTML;
  assert.match(dashboard, /fixture|synthetic/i, 'the fixture must be labelled as synthetic');
  assert.match(app.get('#blast-graph').innerHTML, /<svg/, 'the blast-radius graph should render');
  assert.match(app.get('#rep-list').innerHTML, /Observed action/, 'repercussion cards should render');
});

test('the sandbox button explains the fail-closed behaviour instead of executing', async () => {
  const app = bootConsole();
  await Promise.all(app.get('#sandbox-btn').dispatch('click'));
  const message = app.alerted() ?? '';
  assert.match(message, /Sandbox plan \(nothing executed\)/);
  assert.match(message, /docker run/);
  assert.match(message, /--network none/);
  assert.match(message, /not a complete security boundary/);
});

test('verifying the audit ledger from the console succeeds, and tampering is detected', async () => {
  const app = bootConsole();
  app.get('#cmd-input').value = 'git status && node bin/app.js';
  await Promise.all(app.get('#inspect-btn').dispatch('click'));

  app.get('#audit-verify').dispatch('click');
  assert.match(app.get('#audit-verdict').textContent, /chain intact/);

  app.get('#audit-tamper').dispatch('click');
  assert.match(app.get('#audit-verdict').textContent, /simulated tamper detected/);
  assert.match(app.get('#audit-verdict').textContent, /payload was modified/);
});

test('the approval gate records a decision and offers no allow-everything button', async () => {
  const app = bootConsole();
  app.get('#cmd-input').value = 'node bin/app.js';
  await Promise.all(app.get('#inspect-btn').dispatch('click'));

  const gate = app.get('#gate-list').innerHTML;
  assert.match(gate, /ALLOW ONCE/);
  assert.match(gate, /ALLOW IN SANDBOX/);
  assert.match(gate, /DENY/);
  assert.match(gate, /INSPECT DEEPER/);

  // Only the offered buttons matter here: the explanatory note deliberately
  // names the forbidden actions in order to say they are not offered.
  const offered = Array.from(gate.matchAll(/data-approve="([^"]+)"/g)).map((m) => m[1]);
  assert.ok(offered.length >= 4, `expected the four approval actions, got ${offered.join(',')}`);
  for (const forbidden of ['allow-all', 'allow-everything', 'disable-policy']) {
    assert.ok(!offered.includes(forbidden), `${forbidden} must not be offered`);
  }
  assert.match(gate, /There is deliberately no "allow everything" option/);

  const before = app.get('#audit-table').innerHTML;
  app.get('#audit-verify').dispatch('click');
  assert.match(app.get('#audit-verdict').textContent, /chain intact/);
  assert.ok(before.includes('INSPECTION_STARTED'));
});
