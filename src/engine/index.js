/**
 * Agent Inspector — engine entrypoint.
 *
 * Everything exported here is deterministic and dependency-free. The same
 * module graph is used by:
 *   - the Node CLI  (scripts/cli.mjs)
 *   - the test suite (tests/)
 *   - the browser console (bundled into dist/agent-inspector.html)
 */

export * from './schema.js';
export * from './crypto/sha256.js';
export * from './redact.js';
export * from './b64.js';
export * from './shell.js';
export * from './normalizer.js';
export * from './codeScan.js';
export * from './discover.js';
export * from './riskEngine.js';
export * from './repercussionEngine.js';
export * from './policyEngine.js';
export * from './graphBuilder.js';
export * from './auditLogger.js';
export * from './inspectionEngine.js';
export * from './rules/commandRules.js';
export * from './rules/contentRules.js';
export * from './rules/supplyChain.js';
export * from './sandbox/index.js';
export * from './github/githubAdapter.js';
export * from './adapters/index.js';

export const VERSION = '0.1.0';
