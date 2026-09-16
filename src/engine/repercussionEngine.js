/**
 * RepercussionEngine (spec §6) — the signature feature.
 *
 * For every significant finding, answer in plain language:
 *   observed action → potential consequence → observed scope → unknowns
 *   → recommended control
 *
 * Two deliberate wording rules:
 *   1. Capability and intent are separate. "This can delete files" is not
 *      "this is malicious".
 *   2. Unknown stays unknown. Nothing here fills a gap with a guess.
 */

import { CAPABILITY, SEVERITY, severityLabel, severityStatus } from './schema.js';

const WHY_IT_MATTERS = {
  R001: 'Deleting files is one of the very few agent actions with no undo. A read can be repeated; a delete cannot.',
  R002: 'Administrative rights remove every other boundary in this system at once. There is nothing left to contain the process.',
  R003: 'A credential is a key to something outside this project. Losing control of it affects systems that were never part of this task.',
  R004: 'Network access works in two directions: your data leaves, and someone else\'s content arrives. Both are real risks, and the arriving direction is the one people forget.',
  R005: 'Running a program is a promise about what that program will do — and the shell line you approved rarely shows it. The program decides, after your approval.',
  R006: 'Installing a dependency is installing code that will run later with the same permissions, often including install-time scripts that run immediately.',
  R007: 'Repository history is shared with other people. Rewriting it can destroy work that exists nowhere else.',
  R008: 'Cloud operations act on infrastructure that is not on this machine and usually not in this project. Mistakes there are expensive and public.',
  R009: 'Anything that outlives the session also outlives your approval. It can act again when nobody is watching.',
  R010: 'Addresses inside your own network are not "the internet". Reaching them is a boundary crossing, and metadata endpoints hand out cloud credentials.',
  R011: 'When an agent can read untrusted content and also execute tools, the content can drive the tools. That combination is the actual attack surface.',
  R012: 'Instructions that arrive inside content are indistinguishable from instructions that come from you, unless something separates them. This is the most common way agent systems get redirected.',
  R013: 'An MCP configuration is an instruction to run a program, not a description of one. Inspecting it is safe; launching it is execution.',
  R014: 'Dependencies are code you did not write that runs with your permissions. Pinning and provenance are what let you review a dependency once instead of forever.',
};

const WHAT_IF = {
  'filesystem.delete': [
    'Project files could be permanently removed.',
    'Files outside the project could be removed if the path is ever redirected.',
    'A backup or version history would be the only recovery path.',
  ],
  'filesystem.write': [
    'Existing files could be replaced with different content.',
    'Build outputs or configuration could be altered in ways that are not obvious in review.',
  ],
  'process.execute': [
    'Arbitrary filesystem, network and child-process operations could occur.',
    'The behaviour is decided by the program, not by the command you approved.',
  ],
  'process.spawn': [
    'Additional programs could be started that are invisible in the original command.',
    'The chain of what actually ran could be longer than what was reviewed.',
  ],
  'network.connect': [
    'Data could be sent to an external destination.',
    'Untrusted content could be pulled in and later treated as instructions.',
  ],
  'network.egress': [
    'Project content, environment values or tokens could leave the machine.',
    'The destination may log or retain whatever is sent.',
  ],
  'credential.read': [
    'Credentials could be read into the process.',
    'If the process also has network access, those credentials could leave the machine.',
    'Credentials are usually long-lived and grant access beyond this project.',
  ],
  'environment.read': [
    'Every exported variable becomes readable, including ones unrelated to this task.',
    'Environment variables frequently carry tokens by accident.',
  ],
  'supply_chain.install': [
    'New code would be added that runs with these permissions.',
    'Install-time lifecycle scripts would run immediately, before review.',
    'A compromised transitive dependency would be invisible in the direct list.',
  ],
  'persistence.create': [
    'A process or job could keep running after this session ends.',
    'It could act again later without a human present.',
  ],
  'git.write': [
    'Repository state could change in ways other people depend on.',
    'Force or destructive operations could permanently remove commits.',
  ],
  'cloud.deploy': [
    'Production infrastructure could change.',
    'A failed deployment could affect users directly.',
  ],
  'cloud.delete': [
    'Cloud resources could be destroyed.',
    'Some destroy operations are irreversible and can cascade to dependent resources.',
  ],
  'cloud.secret': [
    'Cloud secret material could be retrieved into this process.',
    'Those secrets often unlock wider access than the current task needs.',
  ],
  'agent.prompt_injection': [
    'The agent could follow instructions from the content instead of from you.',
    'Concealment instructions could hide subsequent actions.',
  ],
  'mcp.server': [
    'A program would be started and trusted for tool descriptions.',
    'Tool descriptions are instructions the model obeys, making the server an injection path.',
  ],
  'agent.chain': [
    'Untrusted content could drive tool execution.',
    'A single fetched page could become the operator.',
  ],
  'browser.navigate': [
    'A browser carries session cookies and can reach internal addresses.',
    'Rendered content can include hidden instructions.',
  ],
  'privilege.escalate': [
    'The process would run with administrative rights.',
    'Every other filesystem and credential restriction could be bypassed.',
  ],
  'container.run': [
    'A container would run code, potentially with host mounts or elevated flags.',
    'Container boundaries are weaker than they look when privileged flags are present.',
  ],
};

/** Findings below this severity are listed but do not get a card. */
const CARD_THRESHOLD = SEVERITY.LOW;

export function buildRepercussions(findings, ctx = {}) {
  const cards = [];

  const significant = findings
    .filter((f) => f.severity >= CARD_THRESHOLD)
    .sort((a, b) => b.severity - a.severity);

  for (const f of significant) {
    const unknowns = [];
    if (f.evidenceType !== 'observed') unknowns.push(`The evidence for this item is ${f.evidenceType}, not directly observed.`);
    if (f.confidence !== 'HIGH') unknowns.push(`Detector confidence is ${f.confidence}, not HIGH.`);
    if (f.scope === 'unknown') unknowns.push('The scope of the target could not be determined.');
    if (f.capability === CAPABILITY.PROC_EXECUTE) unknowns.push('Downstream behaviour of the executed program is not fully visible from the command line.');
    if (f.capability === CAPABILITY.NET_CONNECT) unknowns.push('The server-side behaviour and response content at the destination are unknown to this inspector.');
    if (f.capability === CAPABILITY.MCP_SERVER) unknowns.push('Tool descriptions are only available if the server is started, which this inspector refuses to do.');
    if (f.rule === 'R012') unknowns.push('Whether an agent reading this file would follow it depends on the agent, not on this file.');
    if (!unknowns.length) unknowns.push('No additional unknowns were identified for this action.');

    cards.push({
      id: `rep_${f.id}`,
      findingId: f.id,
      rule: f.rule,
      title: f.title,
      severity: f.severity,
      severityLabel: severityLabel(f.severity),
      status: severityStatus(f.severity),
      capability: f.capability,
      capabilityLabel: f.capabilityLabel,
      observedAction: f.action ?? f.title,
      potentialConsequence: f.potentialConsequence,
      observedScope: scopeSentence(f),
      unknowns,
      recommendedControl: f.recommendedControl,
      whyItMatters: WHY_IT_MATTERS[f.rule] ?? 'This item was flagged by a deterministic rule and carries the capability named above.',
      whatIf: WHAT_IF[f.capability] ?? [
        'The capability named above could be exercised beyond its intended use.',
        'Current evidence does not establish intent; it establishes what is possible.',
      ],
      location: f.location,
      mappings: f.mappings ?? {},
      decision: f.defaultDecision,
    });
  }

  /* Project-level unknowns (not tied to one action). */
  const projectUnknowns = [];
  if (!ctx.hasLockfile) projectUnknowns.push('No lockfile was found, so installed versions are not pinned to what was reviewed.');
  if (!ctx.hasAgentConfig) projectUnknowns.push('No agent instruction file was found, so the agent\'s declared operating rules are unknown.');
  for (const nf of ctx.discovery?.notFound ?? []) projectUnknowns.push(nf.note);
  for (const item of ctx.uninspected ?? []) projectUnknowns.push(item.reason);

  return {
    cards,
    projectUnknowns,
    summary: {
      total: cards.length,
      critical: cards.filter((c) => c.severity === SEVERITY.CRITICAL).length,
      elevated: cards.filter((c) => c.severity === SEVERITY.ELEVATED).length,
      moderate: cards.filter((c) => c.severity === SEVERITY.MODERATE).length,
      low: cards.filter((c) => c.severity === SEVERITY.LOW).length,
    },
  };
}

function scopeSentence(finding) {
  const scope = finding.scope ?? 'unknown';
  const map = {
    'project-local': 'The effect is confined to the inspected project directory.',
    workspace: 'The effect reaches the workspace, including paths outside this project directory.',
    'user-home': 'The effect reaches the user home directory, which holds credentials and unrelated work.',
    system: 'The effect reaches system locations outside any project.',
    localhost: 'The target is on this machine (loopback).',
    'private-network': 'The target is on a private network segment, not the public internet.',
    'approved-domain': 'The target is on the approved domain list.',
    'unknown-public-domain': 'The target is a public domain that is not on the approved list.',
    unknown: 'The scope could not be determined from the available evidence.',
  };
  return map[scope] ?? `Scope classified as ${scope}.`;
}

/** Plain-language "WHY?" block (spec §26). */
export function whyIsThisElevated(finding) {
  const lines = [...(finding.why ?? [])];
  if (!lines.length) lines.push('This item matched a deterministic rule; the evidence list above shows exactly what matched.');
  lines.push('The Inspector recommends reviewing the entrypoint before granting unrestricted execution.');
  return lines;
}
