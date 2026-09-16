import test from 'node:test';
import assert from 'node:assert/strict';

import { inspectCommandText, inspectProject } from '../src/engine/inspectionEngine.js';
import { evaluate, DEFAULT_POLICY, PERMISSIVE_POLICY, strictest, policyPatchForFinding, APPROVAL_ACTIONS, FORBIDDEN_APPROVAL_ACTIONS } from '../src/engine/policyEngine.js';
import { toActionRequest, actionFromCommandLine } from '../src/engine/normalizer.js';
import { DECISION } from '../src/engine/schema.js';

function requestFor(command, workspace = '/project/app') {
  const action = actionFromCommandLine(command, { workingDirectory: workspace });
  return toActionRequest(action, { workingDirectory: workspace });
}

test('strictest() returns the most restrictive decision', () => {
  assert.equal(strictest([DECISION.ALLOW, DECISION.ALLOW_WITH_LOG]), DECISION.ALLOW_WITH_LOG);
  assert.equal(strictest([DECISION.ALLOW, DECISION.DENY, DECISION.REQUIRE_APPROVAL]), DECISION.DENY);
  assert.equal(strictest([]), DECISION.ALLOW);
});

test('fail-closed: an unclassifiable action requires approval', () => {
  const result = evaluate(requestFor('weirdbinary --do-things'), DEFAULT_POLICY, {});
  assert.equal(result.decision, DECISION.REQUIRE_APPROVAL);
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.some((r) => /fail closed/.test(r)));
  assert.ok(result.approvalId && result.approvalId.startsWith('apr_'));
});

test('fail-closed: a read-only command is allowed with logging', () => {
  const result = evaluate(requestFor('ls -la'), DEFAULT_POLICY, {});
  assert.equal(result.decision, DECISION.ALLOW_WITH_LOG);
  assert.equal(result.failClosed, true);
});

test('privilege escalation cannot be allowed by any bundled policy', () => {
  for (const policy of [DEFAULT_POLICY, PERMISSIVE_POLICY]) {
    const result = evaluate(requestFor('sudo reboot'), policy, {
      findings: [{ rule: 'R002', title: 'sudo', defaultDecision: 'DENY', severity: 5 }],
      capabilities: [{ capabilityType: 'privilege.escalate', riskLevel: 5 }],
    });
    assert.equal(result.decision, DECISION.DENY, `policy ${policy.id} must deny privilege escalation`);
  }
});

test('credential access under the default deny policy is denied', () => {
  const result = evaluate(requestFor('cat ~/.ssh/id_rsa'), DEFAULT_POLICY, {
    findings: [{ rule: 'R003', title: 'credential', defaultDecision: 'REQUIRE_APPROVAL', severity: 4 }],
    capabilities: [{ capabilityType: 'credential.read', riskLevel: 4 }],
  });
  assert.equal(result.decision, DECISION.DENY);
});

test('network is denied by default and allowlisted under the permissive policy', () => {
  const caps = [{ capabilityType: 'network.connect', riskLevel: 3 }];
  const deny = evaluate(requestFor('curl https://api.github.com/x'), DEFAULT_POLICY, { capabilities: caps });
  assert.equal(deny.decision, DECISION.DENY);

  const request = requestFor('curl https://api.github.com/x');
  const permissive = evaluate(request, PERMISSIVE_POLICY, { capabilities: caps });
  assert.notEqual(permissive.decision, DECISION.DENY);
});

test('exec allowlist blocks commands that are not listed', () => {
  const policy = { ...DEFAULT_POLICY, exec: { mode: 'allowlist', commands: ['node'] } };
  const allowed = evaluate(requestFor('node build.js'), policy, { capabilities: [{ capabilityType: 'process.execute', riskLevel: 3 }] });
  const blocked = evaluate(requestFor('curl https://x.example'), policy, { capabilities: [{ capabilityType: 'process.execute', riskLevel: 3 }] });
  assert.notEqual(allowed.decision, DECISION.REQUIRE_APPROVAL);
  assert.equal(blocked.decision, DECISION.REQUIRE_APPROVAL);
});

test('persistence is denied by the default policy', () => {
  const result = evaluate(requestFor('crontab -l'), DEFAULT_POLICY, {
    findings: [{ rule: 'R009', title: 'persistence', defaultDecision: 'DENY', severity: 5 }],
    capabilities: [{ capabilityType: 'persistence.create', riskLevel: 5 }],
  });
  assert.equal(result.decision, DECISION.DENY);
});

test('sandbox requirement is reported when no provider is available', () => {
  const result = evaluate(requestFor('node bin/app.js'), DEFAULT_POLICY, {
    capabilities: [{ capabilityType: 'process.execute', riskLevel: 3 }],
  });
  assert.equal(result.sandbox.required, true);
  assert.equal(result.sandbox.available, false);
  assert.ok(result.reasons.some((r) => /no sandbox provider is currently available/.test(r)));
});

test('policy evaluation is deterministic, including the approval id', () => {
  const a = evaluate(requestFor('node bin/app.js'), DEFAULT_POLICY, { capabilities: [{ capabilityType: 'process.execute', riskLevel: 3 }] });
  const b = evaluate(requestFor('node bin/app.js'), DEFAULT_POLICY, { capabilities: [{ capabilityType: 'process.execute', riskLevel: 3 }] });
  assert.equal(a.decision, b.decision);
  assert.equal(a.approvalId, b.approvalId);
  assert.deepEqual(a.reasons, b.reasons);
});

test('the gateway API response matches the documented shape', () => {
  const report = inspectCommandText('node bin/app.js', { workspace: '/project/app' });
  const d = report.decisions.find((x) => x.request.command === 'node');
  assert.ok(d);
  assert.ok(['ALLOW', 'ALLOW_WITH_LOG', 'REQUIRE_APPROVAL', 'SANDBOX_ONLY', 'DENY'].includes(d.decision));
  assert.ok(Array.isArray(d.reasons));
  assert.ok(d.request.action_type);
  assert.ok(d.request.working_directory);
});

test('policy patch generation produces YAML for elevated findings', () => {
  const report = inspectCommandText('curl http://169.254.169.254/latest/meta-data/', { workspace: '/p' });
  const patch = report.policyPatches[0];
  assert.ok(patch, 'a patch should be generated');
  assert.match(patch.yaml, /network:/);
  assert.match(patch.yaml, /mode: deny/);
  assert.match(patch.yaml, /sandbox:/);
});

test('policyPatchForFinding maps capabilities to controls', () => {
  const del = policyPatchForFinding({ capability: 'filesystem.delete', action: 'rm -rf x' });
  assert.ok(del.object.filesystem);
  assert.equal(del.object.filesystem.mode, 'workspace-only');
  const net = policyPatchForFinding({ capability: 'network.connect', action: 'curl x' });
  assert.equal(net.object.network.mode, 'deny');
  const mcp = policyPatchForFinding({ capability: 'mcp.server', action: 'uv run s.py' });
  assert.equal(mcp.object.mcp.autoStart, false);
});

test('the approval gate offers no allow-everything action', () => {
  const labels = APPROVAL_ACTIONS.map((a) => a.label);
  assert.ok(labels.includes('ALLOW ONCE'));
  assert.ok(labels.includes('ALLOW IN SANDBOX'));
  assert.ok(labels.includes('DENY'));
  assert.ok(labels.includes('INSPECT DEEPER'));
  for (const forbidden of FORBIDDEN_APPROVAL_ACTIONS) {
    assert.ok(!labels.includes(forbidden), `${forbidden} must not be offered`);
  }
});

test('the default policy denies network and persistence in its document', () => {
  assert.equal(DEFAULT_POLICY.network.mode, 'deny');
  assert.equal(DEFAULT_POLICY.persistence.mode, 'deny');
  assert.equal(DEFAULT_POLICY.credentials.mode, 'deny');
  assert.equal(DEFAULT_POLICY.sandbox.required, true);
});
