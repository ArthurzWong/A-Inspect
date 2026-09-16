/**
 * R014 — Dependency supply-chain analysis (spec §14).
 *
 * Vocabulary discipline, enforced here rather than left to prose:
 *   UNKNOWN              → we found a dependency and know nothing about it
 *   UNVERIFIED           → unpinned / not integrity-checked
 *   SUSPICIOUS           → a pattern that is a known attack shape
 *   KNOWN_VULNERABILITY  → reported by an external source (never asserted by us)
 *
 * A dependency is never described as malicious merely because it is
 * unfamiliar. Unfamiliar is a state, not a verdict.
 */

import { CAPABILITY, CONFIDENCE, DECISION, EVIDENCE, SCOPE, SEVERITY, makeFinding } from '../schema.js';

export const DEP_STATE = {
  UNKNOWN: 'UNKNOWN',
  UNVERIFIED: 'UNVERIFIED',
  SUSPICIOUS: 'SUSPICIOUS',
  KNOWN_VULNERABILITY: 'KNOWN_VULNERABILITY',
};

const LOCKFILE_NAMES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'npm-shrinkwrap.json', 'poetry.lock', 'uv.lock', 'Pipfile.lock', 'composer.lock', 'go.sum', 'Cargo.lock'];
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly'];

function isUnpinned(spec) {
  const s = String(spec ?? '').trim();
  if (!s) return true;
  if (/^[\^~*]/.test(s)) return true;
  if (/^(latest|next|beta|canary|x|\*)$/i.test(s)) return true;
  if (/^>=|^>|^\|\|/.test(s)) return true;
  if (/^(file|link|workspace):/.test(s)) return true;
  return false;
}

function isRemoteSource(spec) {
  const s = String(spec ?? '').trim();
  return /^(git\+|git:|github:|gitlab:|bitbucket:|https?:)/i.test(s) || /\.tarball|\.tgz$/i.test(s);
}

export function analyzeDependencies(sources) {
  const findings = [];
  const byPath = new Map(sources.map((s) => [String(s.path).replace(/^\.\//, ''), s]));
  const hasLockfile = LOCKFILE_NAMES.some((n) => byPath.has(n) || [...byPath.keys()].some((k) => k.endsWith(`/${n}`)));

  const add = (o) => findings.push(makeFinding(o));

  /* ---------------- package.json ---------------- */
  for (const [path, source] of byPath) {
    if (!/(^|\/)package\.json$/.test(path)) continue;
    let pkg;
    try {
      pkg = JSON.parse(source.content);
    } catch {
      add({
        rule: 'R014',
        title: `${path} is not valid JSON`,
        severity: SEVERITY.LOW,
        capability: CAPABILITY.PKG_INSTALL,
        scope: SCOPE.PROJECT_LOCAL,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [`File: ${path}`, 'The dependency set cannot be read, so it cannot be assessed.'],
        potentialConsequence: 'Dependencies are unknown, and unknown is not the same as safe.',
        recommendedControl: 'Fix the manifest so the dependency set is inspectable.',
        defaultDecision: DECISION.ALLOW_WITH_LOG,
        location: { file: path, line: null },
      });
      continue;
    }

    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}), ...(pkg.optionalDependencies ?? {}) };
    const names = Object.keys(deps);
    const remote = names.filter((n) => isRemoteSource(deps[n]));
    const unpinned = names.filter((n) => isUnpinned(deps[n]) && !isRemoteSource(deps[n]));
    const gitDeps = names.filter((n) => /^(git\+|git:|github:)/i.test(String(deps[n])));
    const hooks = INSTALL_HOOKS.filter((h) => pkg.scripts && pkg.scripts[h]);

    if (remote.length) {
      add({
        rule: 'R014',
        title: `${path} installs ${remote.length} dependency from a URL or git source`,
        severity: SEVERITY.ELEVATED,
        capability: CAPABILITY.PKG_INSTALL,
        scope: SCOPE.NETWORK_PUBLIC,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [
          `File: ${path}`,
          `State: ${DEP_STATE.SUSPICIOUS}`,
          `Dependencies: ${remote.slice(0, 6).map((n) => `${n}@${deps[n]}`).join(', ')}`,
          gitDeps.length ? 'Git-sourced dependencies are not content-addressed and can change without a version change.' : 'URL dependencies bypass the registry trust chain entirely.',
        ],
        potentialConsequence: 'A git or URL dependency can be repointed to different code without any version change. The code that installs today is not guaranteed to be the code that installs tomorrow.',
        recommendedControl: 'Pin to an immutable commit SHA and vendor the artifact, or move the package into the registry with provenance.',
        why: ['Version numbers in a registry are an integrity mechanism. A branch name is not.'],
        defaultDecision: DECISION.REQUIRE_APPROVAL,
        mappings: { owasp: ['AST02', 'AST07'], snyk: ['suspicious_download_url'] },
        location: { file: path, line: null },
      });
    }

    if (unpinned.length) {
      add({
        rule: 'R014',
        title: `${path} has ${unpinned.length} unpinned dependency range(s)`,
        severity: hasLockfile ? SEVERITY.LOW : SEVERITY.MODERATE,
        capability: CAPABILITY.PKG_INSTALL,
        scope: SCOPE.PROJECT_LOCAL,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [
          `File: ${path}`,
          `State: ${hasLockfile ? DEP_STATE.UNKNOWN : DEP_STATE.UNVERIFIED}`,
          `Examples: ${unpinned.slice(0, 8).map((n) => `${n}@${deps[n]}`).join(', ')}`,
          hasLockfile ? 'A lockfile exists, which pins the resolved versions for installs that respect it.' : 'No lockfile was found in the inspected file set.',
        ],
        potentialConsequence: 'Without a lockfile, a reinstall can resolve to a newer — possibly compromised — version than the one that was reviewed.',
        recommendedControl: hasLockfile ? 'Keep the lockfile committed and install with it.' : 'Commit a lockfile and install from it.',
        why: ['A caret or tilde range is a promise about future code, not a statement about present code.'],
        defaultDecision: hasLockfile ? DECISION.ALLOW_WITH_LOG : DECISION.REQUIRE_APPROVAL,
        mappings: { owasp: ['AST02', 'AST07'] },
        location: { file: path, line: null },
      });
    }

    if (hooks.length) {
      add({
        rule: 'R014',
        title: `${path} runs lifecycle scripts on install: ${hooks.join(', ')}`,
        severity: SEVERITY.ELEVATED,
        capability: CAPABILITY.PKG_INSTALL,
        scope: SCOPE.PROJECT_LOCAL,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [
          `File: ${path}`,
          `Hooks: ${hooks.map((h) => `${h}: ${pkg.scripts[h]}`).join(' | ')}`,
          'Lifecycle scripts execute automatically during installation, before any human reviews the package.',
        ],
        potentialConsequence: 'Installation becomes code execution. A malicious or compromised dependency, or a tampered lockfile, runs here with the installer\'s permissions.',
        recommendedControl: 'Require approval. Install with lifecycle scripts disabled when the dependency set allows it, and review the hook body.',
        why: ['The install step is the most attractive execution point in the Node ecosystem.'],
        defaultDecision: DECISION.REQUIRE_APPROVAL,
        mappings: { owasp: ['AST02'], snyk: ['malicious_code'] },
        location: { file: path, line: null },
      });
    }

    add({
      rule: 'R014',
      title: `${path} declares ${names.length} dependencies`,
      severity: SEVERITY.INFO,
      capability: CAPABILITY.PKG_INSTALL,
      scope: SCOPE.PROJECT_LOCAL,
      confidence: CONFIDENCE.HIGH,
      evidenceType: EVIDENCE.OBSERVED,
      evidence: [
        `File: ${path}`,
        `Direct dependencies: ${names.join(', ') || 'none'}`,
        `Lockfile present in inspected set: ${hasLockfile ? 'yes' : 'no'}`,
        `State: ${DEP_STATE.UNKNOWN} — the Inspector lists these; it does not make a trust claim about them.`,
      ],
      potentialConsequence: 'Each direct dependency expands the transitive graph. The Inspector does not assert that any of them are malicious or vulnerable.',
      recommendedControl: 'Review the direct list, then rely on provenance and lockfile integrity for the transitive part.',
      why: ['An inventory is not a verdict. This line exists so the graph is visible, not to raise alarm.'],
      defaultDecision: DECISION.ALLOW,
      mappings: { owasp: ['AST02'] },
      location: { file: path, line: null },
    });
  }

  /* ---------------- Python ---------------- */
  for (const [path, source] of byPath) {
    if (!/(^|\/)requirements[^/]*\.txt$/.test(path)) continue;
    const lines = String(source.content).split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
    const unpinned = lines.filter((l) => !l.includes('==') && !l.startsWith('-r') && !l.startsWith('--'));
    const remote = lines.filter((l) => /^(git\+|https?:|-e\s)/i.test(l) || /\.git(@|$)/.test(l));
    if (remote.length) {
      add({
        rule: 'R014',
        title: `${path} installs Python packages from URL or VCS sources`,
        severity: SEVERITY.ELEVATED,
        capability: CAPABILITY.PKG_INSTALL,
        scope: SCOPE.NETWORK_PUBLIC,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [`File: ${path}`, `State: ${DEP_STATE.SUSPICIOUS}`, `Entries: ${remote.slice(0, 5).join(' | ')}`],
        potentialConsequence: 'VCS/URL installs are not content-addressed and execute the project\'s build backend on install.',
        recommendedControl: 'Pin to a commit SHA, or publish the package to a registry with hashes.',
        why: ['Same reasoning as a git-sourced npm dependency: the resolution target is mutable.'],
        defaultDecision: DECISION.REQUIRE_APPROVAL,
        mappings: { owasp: ['AST02'] },
        location: { file: path, line: null },
      });
    }
    if (unpinned.length) {
      add({
        rule: 'R014',
        title: `${path} has ${unpinned.length} unpinned Python requirement(s)`,
        severity: SEVERITY.MODERATE,
        capability: CAPABILITY.PKG_INSTALL,
        scope: SCOPE.PROJECT_LOCAL,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [`File: ${path}`, `State: ${DEP_STATE.UNVERIFIED}`, `Examples: ${unpinned.slice(0, 8).join(', ')}`, 'No hash pinning observed.'],
        potentialConsequence: 'An unpinned Python requirement can resolve to a different version on the next install.',
        recommendedControl: 'Pin exact versions and use a lockfile or hashes.',
        why: ['Reproducibility is the precondition for reviewing a dependency once and trusting it later.'],
        defaultDecision: DECISION.REQUIRE_APPROVAL,
        mappings: { owasp: ['AST02', 'AST07'] },
        location: { file: path, line: null },
      });
    }
  }

  /* ---------------- Containers ---------------- */
  for (const [path, source] of byPath) {
    if (!/(^|\/)Dockerfile/.test(path)) continue;
    const text = String(source.content);
    const fromLines = text.split('\n').map((l) => l.trim()).filter((l) => /^FROM\s+/i.test(l));
    const latestTags = fromLines.filter((l) => /:latest\s*$/i.test(l) || !/:[^\s/]+/.test(l));
    const curlPipe = /(curl|wget)[^\n]*\|\s*(ba)?sh/i.test(text);
    const runAsRoot = /^\s*USER\s+root\s*$/im.test(text);
    const addFromUrl = /^ADD\s+https?:/im.test(text);

    if (latestTags.length) {
      add({
        rule: 'R014',
        title: `${path} uses an unpinned base image`,
        severity: SEVERITY.LOW,
        capability: CAPABILITY.CONTAINER,
        scope: SCOPE.PROJECT_LOCAL,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [`File: ${path}`, `State: ${DEP_STATE.UNVERIFIED}`, `Lines: ${latestTags.join(' | ')}`, 'A floating tag can point at different content over time.'],
        potentialConsequence: 'A build is not reproducible, and the base image can change without a repository change.',
        recommendedControl: 'Pin by digest (image@sha256:...).',
        why: ['A tag is a moving pointer.'],
        defaultDecision: DECISION.ALLOW_WITH_LOG,
        mappings: { owasp: ['AST07'] },
        location: { file: path, line: null },
      });
    }
    if (curlPipe || addFromUrl) {
      add({
        rule: 'R014',
        title: `${path} downloads and executes content during build`,
        severity: SEVERITY.ELEVATED,
        capability: CAPABILITY.CONTAINER,
        scope: SCOPE.NETWORK_PUBLIC,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [`File: ${path}`, curlPipe ? 'Pattern: download piped into a shell.' : 'Pattern: remote ADD source.', 'Content fetched at build time is not verified by hash.'],
        potentialConsequence: 'Build-time code execution from an unverified remote source.',
        recommendedControl: 'Download, verify a checksum, then execute.',
        why: ['The build is inside the trust boundary even though the bytes are not.'],
        defaultDecision: DECISION.REQUIRE_APPROVAL,
        mappings: { owasp: ['AST02'], snyk: ['suspicious_download_url'] },
        location: { file: path, line: null },
      });
    }
    if (runAsRoot) {
      add({
        rule: 'R014',
        title: `${path} runs as root inside the container`,
        severity: SEVERITY.MODERATE,
        capability: CAPABILITY.CONTAINER,
        scope: SCOPE.PROJECT_LOCAL,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [`File: ${path}`, 'USER root', 'Container root is still root relative to the container, but it broadens the effect of any escape.'],
        potentialConsequence: 'If the container boundary is weakened (privileged flags, host mounts), root inside becomes root outside.',
        recommendedControl: 'Add a non-root USER and drop capabilities.',
        why: ['Least privilege applies inside the container too.'],
        defaultDecision: DECISION.ALLOW_WITH_LOG,
        mappings: { owasp: ['AST06'] },
        location: { file: path, line: null },
      });
    }
  }

  /* ---------------- CI/CD ---------------- */
  for (const [path, source] of byPath) {
    if (!/\.github\/workflows\/.*\.ya?ml$/.test(path)) continue;
    const text = String(source.content);
    const unpinnedActions = (text.match(/uses:\s*([^\s#]+@(?!([0-9a-f]{40}))[^\s#]+)/g) ?? []).slice(0, 8);
    const pipeToShell = /(curl|wget)[^\n]*\|\s*(ba)?sh/i.test(text);
    if (unpinnedActions.length) {
      add({
        rule: 'R014',
        title: `${path} pins ${unpinnedActions.length} action(s) by tag, not by SHA`,
        severity: SEVERITY.MODERATE,
        capability: CAPABILITY.PKG_INSTALL,
        scope: SCOPE.NETWORK_APPROVED,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [`File: ${path}`, `Detected: ${unpinnedActions.join(' | ')}`, 'Tags on third-party actions are mutable and can be repointed to malicious code.'],
        potentialConsequence: 'A repointed action tag executes attacker code inside CI, where repository and cloud credentials are typically available.',
        recommendedControl: 'Pin each action to a full commit SHA and enable Dependabot for updates.',
        why: ['CI is a high-value target because it usually holds long-lived credentials.'],
        defaultDecision: DECISION.REQUIRE_APPROVAL,
        mappings: { owasp: ['AST02', 'AST07'] },
        location: { file: path, line: null },
      });
    }
    if (pipeToShell) {
      add({
        rule: 'R014',
        title: `${path} pipes a download into a shell`,
        severity: SEVERITY.ELEVATED,
        capability: CAPABILITY.PROC_EXECUTE,
        scope: SCOPE.NETWORK_PUBLIC,
        confidence: CONFIDENCE.HIGH,
        evidenceType: EVIDENCE.OBSERVED,
        evidence: [`File: ${path}`, 'Pattern: curl/wget | sh'],
        potentialConsequence: 'Unverified remote code executes in CI with the workflow token.',
        recommendedControl: 'Vendor the installer or verify a checksum before executing.',
        why: ['Same deny-by-default reasoning as the equivalent shell pipeline.'],
        defaultDecision: DECISION.DENY,
        mappings: { owasp: ['AST02'], snyk: ['suspicious_download_url'] },
        location: { file: path, line: null },
      });
    }
  }

  return { findings, hasLockfile };
}
