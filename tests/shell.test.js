import test from 'node:test';
import assert from 'node:assert/strict';

import { splitSegments, tokenize, parseCommand, parseShell } from '../src/engine/shell.js';
import {
  classifyPathScope, classifyUrl, actionFromCommandLine, toActionRequest, scopeOfAction,
} from '../src/engine/normalizer.js';

test('splitSegments separates && || ; | and newlines', () => {
  const segs = splitSegments('a && b || c ; d | e\nf');
  const seps = segs.map((s) => s.separator);
  assert.ok(seps.includes('&&'));
  assert.ok(seps.includes('||'));
  assert.ok(seps.includes('|'));
  assert.ok(seps.includes(';') || seps.includes('\n'));
  assert.equal(segs.length, 6);
});

test('splitSegments does not split inside quotes', () => {
  const segs = splitSegments(`echo "a && b" 'c ; d'`);
  assert.equal(segs.length, 1);
  assert.equal(segs[0].raw, `echo "a && b" 'c ; d'`);
});

test('splitSegments keeps command substitution intact', () => {
  const segs = splitSegments('echo $(date; uname) && ls');
  assert.equal(segs[0].raw, 'echo $(date; uname)');
  assert.equal(segs[1].raw, 'ls');
});

test('tokenize handles quoting and escapes', () => {
  assert.deepEqual(tokenize(`cmd --flag "two words" 'a b'`), ['cmd', '--flag', 'two words', 'a b']);
  assert.deepEqual(tokenize('cmd a\\ b'), ['cmd', 'a b']);
});

test('parseCommand extracts program, args, redirections, background, env', () => {
  const cmd = parseCommand('FOO=bar node script.js --x > out.log &', 3);
  assert.equal(cmd.program, 'node');
  assert.deepEqual(cmd.env, ['FOO']);
  assert.deepEqual(cmd.args, ['script.js', '--x']);
  assert.equal(cmd.redirections[0].op, '>');
  assert.equal(cmd.redirections[0].target, 'out.log');
  assert.equal(cmd.background, true);
});

test('redirection operators are not mistaken for job control', () => {
  const segs = splitSegments('cmd 2>&1 | tee log');
  assert.equal(segs.length, 2);
  assert.equal(segs[0].raw, 'cmd 2>&1');
  const cmd = parseCommand(segs[0].raw, 1);
  assert.equal(cmd.background, false);
  assert.equal(cmd.program, 'cmd');
  assert.equal(cmd.redirections.length, 1);
  assert.equal(cmd.redirections[0].op, '2>&1');
  assert.deepEqual(cmd.args, []);
});

test('parseCommand flags dynamic construction', () => {
  assert.equal(parseCommand('eval "$USER_INPUT"', 1).hasDynamicConstruction, true);
  assert.equal(parseCommand('echo $(whoami)', 1).hasDynamicConstruction, true);
  assert.equal(parseCommand('cat file.txt', 1).hasDynamicConstruction, false);
});

test('parseShell returns one entry per command; shebangs and comments are not commands', () => {
  const cmds = parseShell('#!/bin/bash\nset -e\ncd demo\nnode app.js\n');
  assert.equal(cmds.length, 3);
  assert.equal(cmds[0].programBase, 'set');
  assert.equal(cmds[1].programBase, 'cd');
  assert.equal(cmds[1].line, 3);
  assert.equal(cmds[2].programBase, 'node');
  assert.equal(cmds[2].line, 4);
});

test('classifyPathScope treats the filesystem root as system, not as a relative path', () => {
  assert.equal(classifyPathScope('/', '/p'), 'system');
  assert.equal(classifyPathScope('/etc/passwd', '/p'), 'system');
  assert.equal(classifyPathScope('./x', '/p'), 'project-local');
});

test('classifyUrl covers localhost, private, metadata and public', () => {
  assert.equal(classifyUrl('http://127.0.0.1:8787/').scope, 'localhost');
  assert.equal(classifyUrl('http://localhost:3000/').scope, 'localhost');
  assert.equal(classifyUrl('http://10.0.0.5/admin').scope, 'private-network');
  assert.equal(classifyUrl('http://192.168.1.10/router').scope, 'private-network');
  assert.equal(classifyUrl('http://169.254.169.254/latest/meta-data/').metadata, true);
  assert.equal(classifyUrl('https://example.com/x').scope, 'unknown-public-domain');
  assert.equal(classifyUrl('https://github.com/x', ['github.com']).scope, 'approved-domain');
});

test('toActionRequest produces the documented ActionRequest shape', () => {
  const action = actionFromCommandLine('node bin/app.js run --config demo/sources.yaml', { workingDirectory: '/project/app' });
  const request = toActionRequest(action, { agentId: 'autoclaw', workingDirectory: '/project/app' });
  assert.equal(request.agent_id, 'autoclaw');
  assert.equal(request.command, 'node');
  assert.deepEqual(request.arguments, ['bin/app.js', 'run', '--config', 'demo/sources.yaml']);
  assert.equal(request.working_directory, '/project/app');
  assert.ok(Array.isArray(request.filesystem.read));
  assert.ok(Array.isArray(request.network.targets));
  assert.equal(request.network.targets[0], 'unknown');
  assert.ok(request.requested_at === null || typeof request.requested_at === 'string');
});

test('toActionRequest records deletion targets', () => {
  const action = actionFromCommandLine('rm -rf demo/.state');
  const request = toActionRequest(action, { workingDirectory: '.' });
  assert.ok(request.filesystem.delete.length > 0);
  assert.equal(scopeOfAction(action, '.'), 'project-local');
});
