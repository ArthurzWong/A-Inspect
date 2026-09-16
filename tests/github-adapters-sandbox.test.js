import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import {
  verifyWebhookSignature, GITHUB_APP_PERMISSIONS, GITHUB_FORBIDDEN_PERMISSIONS,
  parseRepoUrl, planRepositoryInspection, createGitHubClient, repositoryFingerprint,
  GITHUB_INSPECTION_WORKFLOW,
} from '../src/engine/github/githubAdapter.js';

import { createAdapterRegistry, GATEWAY_FLOW } from '../src/engine/adapters/index.js';
import {
  createSandboxProvider, NullSandboxProvider, PlanOnlySandboxProvider,
  DockerSandboxProvider, dockerArgs, SANDBOX_LIMITATIONS, SANDBOX_MINIMUM_REQUIREMENTS,
} from '../src/engine/sandbox/index.js';

/* ---------------- GitHub ---------------- */

test('webhook signature validation accepts a correct signature', () => {
  const body = '{"action":"opened"}';
  const signature = `sha256=${createHmac('sha256', 'topsecret').update(body).digest('hex')}`;
  assert.equal(verifyWebhookSignature(body, signature, 'topsecret').ok, true);
});

test('webhook signature validation rejects a wrong signature or secret', () => {
  const body = '{"action":"opened"}';
  const signature = `sha256=${createHmac('sha256', 'topsecret').update(body).digest('hex')}`;
  assert.equal(verifyWebhookSignature(body, signature, 'different').ok, false);
  assert.equal(verifyWebhookSignature(body, 'sha256=deadbeef', 'topsecret').ok, false);
  assert.equal(verifyWebhookSignature(body, signature, '').ok, false);
  assert.equal(verifyWebhookSignature(body, null, 'topsecret').ok, false);
});

test('signature check is not fooled by a re-serialized body', () => {
  const original = '{"a":1,"b":2}';
  const reserialized = '{ "a": 1, "b": 2 }';
  const signature = `sha256=${createHmac('sha256', 's').update(original).digest('hex')}`;
  assert.equal(verifyWebhookSignature(original, signature, 's').ok, true);
  assert.equal(verifyWebhookSignature(reserialized, signature, 's').ok, false);
});

test('GitHub permissions are read-only in the MVP', () => {
  for (const value of Object.values(GITHUB_APP_PERMISSIONS)) {
    assert.equal(value, 'read');
  }
  for (const forbidden of GITHUB_FORBIDDEN_PERMISSIONS) {
    const [scope] = forbidden.split(':');
    assert.ok(!(scope in GITHUB_APP_PERMISSIONS) || GITHUB_APP_PERMISSIONS[scope] === 'read');
  }
});

test('parses repository references', () => {
  assert.deepEqual(parseRepoUrl('https://github.com/snyk/agent-scan'), { owner: 'snyk', repo: 'agent-scan' });
  assert.deepEqual(parseRepoUrl('https://github.com/OWASP/www-project-agentic-skills-top-10.git'), { owner: 'OWASP', repo: 'www-project-agentic-skills-top-10' });
  assert.deepEqual(parseRepoUrl('ethz-spylab/agentdojo'), { owner: 'ethz-spylab', repo: 'agentdojo' });
  assert.equal(parseRepoUrl('not a repo'), null);
});

test('repository inspection plan states the guardrails', () => {
  const plan = planRepositoryInspection('snyk/agent-scan');
  assert.equal(plan.ok, true);
  assert.equal(plan.repo.owner, 'snyk');
  assert.equal(plan.steps.length, GITHUB_INSPECTION_WORKFLOW.length);
  assert.ok(plan.guardrails.some((g) => /never executed/.test(g)));
  assert.ok(plan.guardrails.some((g) => /signature validation/.test(g)));
});

test('the GitHub client refuses writes unless explicitly allowed', async () => {
  const client = createGitHubClient({ fetchImpl: async () => ({ ok: true, status: 200, text: async () => '{}' }) });
  const res = await client.postPrComment('o', 'r', 1, 'hello');
  assert.equal(res.ok, false);
  assert.match(res.reason, /read-only by policy/);
  assert.equal(client.readOnly, true);
});

test('repository fingerprint is stable and content-sensitive', () => {
  const a = repositoryFingerprint([{ path: 'a.js', content: 'x' }, { path: 'b.js', content: 'y' }]);
  const b = repositoryFingerprint([{ path: 'b.js', content: 'y' }, { path: 'a.js', content: 'x' }]);
  const c = repositoryFingerprint([{ path: 'a.js', content: 'z' }, { path: 'b.js', content: 'y' }]);
  assert.equal(a, b);
  assert.notEqual(a, c);
});

/* ---------------- Adapters ---------------- */

test('every adapter exposes the documented surface', () => {
  const registry = createAdapterRegistry();
  for (const id of registry.ids()) {
    const adapter = registry.get(id);
    for (const fn of ['inspectConfig', 'inspectSandbox', 'inspectToolPolicy', 'inspectElevatedPolicy', 'inspectWorkspace', 'interceptAction', 'evaluateAction', 'recordDecision']) {
      assert.equal(typeof adapter[fn], 'function', `${id}.${fn} missing`);
    }
  }
});

test('adapters normalise an agent action into an ActionRequest and let policy decide', () => {
  const adapter = createAdapterRegistry().get('autoclaw');
  const { request, evaluation } = adapter.evaluateAction({
    agent: 'autoclaw',
    session_id: 'session_123',
    action: { type: 'process.execute', command: 'node', args: ['bin/app.js', 'run'] },
    context: { workspace: '/project/app', sandbox: true },
  });
  assert.equal(request.command, 'node');
  assert.deepEqual(request.arguments, ['bin/app.js', 'run']);
  assert.ok(['REQUIRE_APPROVAL', 'ALLOW', 'ALLOW_WITH_LOG', 'SANDBOX_ONLY', 'DENY'].includes(evaluation.decision));
});

test('the OpenClaw adapter is honest about fixture vs live mode', async () => {
  const registry = createAdapterRegistry();
  const adapter = registry.get('openclaw');
  assert.equal(adapter.mode, 'fixture');
  assert.equal(adapter.connected, false);
  const live = await adapter.inspectLive(false);
  assert.equal(live.ok, false);
  assert.ok(adapter.liveCommands.includes('openclaw sandbox explain --json'));
  const policy = adapter.effectivePolicy();
  assert.equal(policy.elevated, 'REQUIRES APPROVAL');
});

test('adapters never claim to modify agent configuration', () => {
  const adapter = createAdapterRegistry().get('claude-code');
  assert.match(adapter.inspectConfig().note, /never written/);
  assert.equal(typeof adapter.inspectConfig, 'function');
  assert.equal(typeof adapter.writeConfig, 'undefined');
});

test('the gateway flow names the policy engine as the only authority', () => {
  const policyStep = GATEWAY_FLOW.find((s) => s.step === 'policy');
  assert.match(policyStep.detail, /only authority/i);
});

/* ---------------- Sandbox ---------------- */

test('the default sandbox provider refuses to execute anything', async () => {
  const provider = createSandboxProvider({});
  assert.ok(provider instanceof NullSandboxProvider);
  const result = await provider.execute({}, 'node app.js');
  assert.equal(result.executed, false);
  assert.equal(result.failClosed, true);
  assert.match(result.reason, /no sandbox provider is configured/);
});

test('the plan-only provider describes the command without running it', async () => {
  const provider = createSandboxProvider({ provider: 'plan' });
  const { handle } = await provider.create({ workspace: '/p' });
  const result = await provider.execute(handle, 'node app.js');
  assert.equal(result.executed, false);
  assert.ok(Array.isArray(result.container));
  assert.ok(result.container.includes('--network'));
});

test('docker args are hardened by default', () => {
  const args = dockerArgs({ workspace: '/p', image: 'node:22-alpine' });
  const joined = args.join(' ');
  assert.match(joined, /--network none/);
  assert.match(joined, /--read-only/);
  assert.match(joined, /--cap-drop ALL/);
  assert.match(joined, /no-new-privileges/);
  assert.match(joined, /--pids-limit/);
  assert.match(joined, /--memory/);
  assert.match(joined, /:ro/, 'workspace must be mounted read-only');
  assert.ok(!joined.includes('--privileged'));
});

test('the docker provider plans but does not execute without authorization', async () => {
  const provider = new DockerSandboxProvider({ runner: async () => ({ code: 0, stdout: '', stderr: '' }) });
  const { handle } = await provider.create({ workspace: '/p' });
  const result = await provider.execute(handle, 'node app.js');
  assert.equal(result.executed, false);
  assert.match(result.reason, /not authorized/);
});

test('docker provider executes only when a runner and authorization are both present', async () => {
  let called = [];
  const provider = new DockerSandboxProvider({
    runner: async (argv) => { called.push(argv); return { code: 0, stdout: 'ok', stderr: '' }; },
    authorized: true,
    workspace: '/p',
  });
  const { handle } = await provider.create({ workspace: '/p' });
  const result = await provider.execute(handle, 'node app.js');
  assert.equal(result.executed, true);
  assert.equal(result.ok, true);
  assert.equal(called.length, 1);
});

test('sandbox limitations are stated rather than hidden', () => {
  const provider = new PlanOnlySandboxProvider();
  assert.ok(provider.capabilities().limitations.some((l) => /not a complete security boundary/.test(l)));
  assert.ok(SANDBOX_LIMITATIONS.length >= 3);
  assert.ok(SANDBOX_MINIMUM_REQUIREMENTS.some((r) => r.id === 'no-host-credentials'));
});
