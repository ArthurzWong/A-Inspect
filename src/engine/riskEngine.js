/**
 * RiskEngine (spec §10).
 *
 * Deliberately *not* a single opaque score. Eight dimensions, each a number
 * 0-5 with the evidence that produced it, so a human can disagree with the
 * arithmetic instead of arguing with a black box.
 *
 * Two rules this file exists to enforce:
 *   1. Every score carries evidence.
 *   2. "Not inspected" is not "safe" — it is its own state.
 */

import {
  CAPABILITY_DIMENSION,
  RISK_DIMENSIONS,
  RISK_DIMENSION_LABEL,
  SEVERITY,
  severityLabel,
  severityStatus,
} from './schema.js';

export const DIMENSION_STATE = {
  NONE: 'none',         // nothing of this kind observed
  NOT_INSPECTED: 'not-inspected', // no evidence, and no basis to claim safety
  ASSESSED: 'assessed', // evidence-backed score
};

/**
 * @param {Array} capabilities  capability records from the analyzers
 * @param {Array} findings      findings from the analyzers
 * @param {object} ctx          { coverage, uninspected: string[] }
 */
export function computeRisk(capabilities, findings, ctx = {}) {
  const dimensions = {};
  const seenEvidence = new Set();
  const pushEvidence = (dim, entry) => {
    // Keyed per dimension: the same evidence legitimately belongs to several
    // dimensions (an env read is both credential and identity surface).
    const key = `${dim.dimension}|${entry.rule}|${entry.action}|${entry.target}`;
    if (seenEvidence.has(key)) return;
    seenEvidence.add(key);
    dim.evidence.push(entry);
  };

  for (const dim of RISK_DIMENSIONS) {
    dimensions[dim] = {
      dimension: dim,
      label: RISK_DIMENSION_LABEL[dim],
      score: 0,
      scoreLabel: severityLabel(0),
      status: 'grey',
      state: DIMENSION_STATE.NOT_INSPECTED,
      evidence: [],
      unknown: [],
    };
  }

  // Capabilities feed their dimensions.
  for (const capability of capabilities) {
    const dims = CAPABILITY_DIMENSION[capability.capabilityType] ?? [];
    for (const dim of dims) {
      const d = dimensions[dim];
      if (!d) continue;
      d.score = Math.max(d.score, capability.riskLevel ?? 0);
      if (d.evidence.length < 24) {
        pushEvidence(d, {
          rule: capability.rule,
          capability: capability.capabilityType,
          action: capability.evidence,
          target: capability.target,
          scope: capability.scope,
        });
      }
    }
  }

  // Findings feed their dimensions too, so a rule with no capability record
  // (for example a prompt-injection signal) still lands somewhere.
  for (const finding of findings) {
    const dims = CAPABILITY_DIMENSION[finding.capability] ?? [];
    for (const dim of dims) {
      const d = dimensions[dim];
      if (!d) continue;
      d.score = Math.max(d.score, finding.severity ?? 0);
      if (d.evidence.length < 24) {
        pushEvidence(d, {
          rule: finding.rule,
          capability: finding.capability,
          action: finding.action ?? finding.title,
          target: finding.scope,
          scope: finding.scope,
        });
      }
      if (finding.evidenceType === 'unknown') {
        d.unknown.push(`${finding.rule}: ${finding.title}`);
      }
    }
  }

  // Uninspectable surface: named entrypoints we could not read.
  for (const item of ctx.uninspected ?? []) {
    const dim = item.dimension ?? 'execution_risk';
    const d = dimensions[dim];
    if (!d) continue;
    d.unknown.push(item.reason ?? String(item));
    if (d.score < SEVERITY.MODERATE) d.score = SEVERITY.MODERATE; // unknown floor, never zero-because-blind
  }

  for (const dim of RISK_DIMENSIONS) {
    const d = dimensions[dim];
    if (d.evidence.length === 0 && d.unknown.length === 0) {
      d.state = DIMENSION_STATE.NOT_INSPECTED;
      d.score = 0;
    } else {
      d.state = DIMENSION_STATE.ASSESSED;
    }
    if (d.unknown.length && d.score === 0) d.score = SEVERITY.LOW;
    d.scoreLabel = severityLabel(d.score);
    d.status = d.state === DIMENSION_STATE.NOT_INSPECTED ? 'grey' : severityStatus(d.score);
  }

  const assessed = RISK_DIMENSIONS.map((d) => dimensions[d]);
  const maxScore = assessed.reduce((m, d) => Math.max(m, d.score), 0);
  const overall = {
    score: maxScore,
    label: severityLabel(maxScore),
    status: severityStatus(maxScore),
    // Wording discipline: the headline names exposure, not intent.
    exposureWord: exposureWord(maxScore),
  };

  return {
    dimensions,
    overall,
    confidence: computeConfidence(findings, ctx),
    uninspected: ctx.uninspected ?? [],
  };
}

function exposureWord(score) {
  switch (score) {
    case 0: return 'NOT INSPECTED';
    case 1: return 'INFORMATIONAL';
    case 2: return 'LOW EXPOSURE';
    case 3: return 'MODERATE EXPOSURE';
    case 4: return 'ELEVATED EXPOSURE';
    case 5: return 'CRITICAL EXPOSURE';
    default: return 'UNKNOWN';
  }
}

/**
 * Confidence is about *coverage*, not about how scary the result is.
 * It answers: "how much of this did we actually manage to read?"
 */
function computeConfidence(findings, ctx) {
  let score = 35;
  const coverage = ctx.coverage ?? 0;           // 0..1 fraction of sources successfully parsed
  score += Math.round(coverage * 35);

  const total = findings.length || 1;
  const high = findings.filter((f) => f.confidence === 'HIGH').length;
  score += Math.round((high / total) * 15);

  if (ctx.hasLockfile) score += 5;
  if (ctx.hasAgentConfig) score += 5;
  if (ctx.truncated) score -= 10;

  return Math.max(20, Math.min(95, score));
}

/** Human explanation lines for a dimension card (spec §10 example). */
export function explainDimension(dimension) {
  const lines = [];
  const byRule = {};
  for (const e of dimension.evidence) {
    if (!e.rule) continue;
    byRule[e.rule] = (byRule[e.rule] ?? 0) + 1;
  }
  for (const [rule, count] of Object.entries(byRule)) {
    lines.push(`${count} evidence item(s) from ${rule}`);
  }
  if (dimension.unknown.length) lines.push(`${dimension.unknown.length} unknown factor(s) — see unknown list`);
  if (!lines.length) lines.push('No evidence of this kind of activity in the inspected set.');
  return lines;
}

export function summarizeRisk(risk) {
  const parts = [];
  for (const dim of RISK_DIMENSIONS) {
    const d = risk.dimensions[dim];
    if (d.score > 0) parts.push({ label: d.label, score: d.score, label5: d.scoreLabel, status: d.status, state: d.state });
  }
  return parts.sort((a, b) => b.score - a.score);
}
