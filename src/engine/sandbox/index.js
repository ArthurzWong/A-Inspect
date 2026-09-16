/**
 * Sandbox abstraction (spec §19, §34).
 *
 *   SandboxProvider: create() → execute() → inspect() → destroy()
 *
 * Design rule from the spec: the UI must never be coupled to Docker, and
 * the system must fail closed. So the *default* provider is one that
 * refuses to execute anything. Execution requires an explicit provider plus
 * an explicit authorization flag, and local execution is never the default.
 *
 * OpenClaw's own documentation makes the same point this file makes: a
 * sandbox reduces blast radius, it is not a perfect boundary. That limit is
 * reported in `limitations` rather than hidden.
 */

export const SANDBOX_LIMITATIONS = [
  'A sandbox reduces blast radius; it is not a complete security boundary.',
  'Container escapes exist, especially with privileged flags or host mounts.',
  'Network policy inside a sandbox is only as good as the runtime enforcing it.',
  'A sandbox does not make malicious intent safe; it limits what intent can reach.',
];

/* ------------------------------------------------------------------ *
 * Provider interface
 * ------------------------------------------------------------------ */

class BaseSandboxProvider {
  constructor(config = {}) {
    this.config = config;
    this.id = 'base';
    this.label = 'Base';
  }

  /* eslint-disable no-unused-vars */
  async create(spec) { throw new Error('create() not implemented'); }
  async execute(handle, command) { throw new Error('execute() not implemented'); }
  async inspect(handle) { throw new Error('inspect() not implemented'); }
  async destroy(handle) { throw new Error('destroy() not implemented'); }
  /* eslint-enable no-unused-vars */

  capabilities() {
    return {
      id: this.id,
      label: this.label,
      available: false,
      canExecute: false,
      isolation: 'unknown',
      limitations: SANDBOX_LIMITATIONS,
    };
  }
}

/* ------------------------------------------------------------------ *
 * Null provider — the default. Fail closed.
 * ------------------------------------------------------------------ */

export class NullSandboxProvider extends BaseSandboxProvider {
  constructor(config = {}) {
    super(config);
    this.id = 'none';
    this.label = 'No sandbox (fail closed)';
  }

  capabilities() {
    return {
      id: this.id,
      label: this.label,
      available: false,
      canExecute: false,
      isolation: 'none',
      reason: 'No sandbox provider is configured, so the Inspector will not execute anything.',
      limitations: SANDBOX_LIMITATIONS,
    };
  }

  async create() {
    return { ok: false, reason: 'no sandbox provider configured', failClosed: true };
  }

  async execute(_handle, command) {
    return {
      ok: false,
      executed: false,
      failClosed: true,
      reason: 'Execution refused: no sandbox provider is configured. Unknown is not allow.',
      wouldRun: command,
    };
  }
}

/* ------------------------------------------------------------------ *
 * Plan-only provider — describes what would run, runs nothing.
 * ------------------------------------------------------------------ */

export class PlanOnlySandboxProvider extends BaseSandboxProvider {
  constructor(config = {}) {
    super(config);
    this.id = 'plan-only';
    this.label = 'Plan only (no execution)';
  }

  capabilities() {
    return {
      id: this.id,
      label: this.label,
      available: true,
      canExecute: false,
      isolation: 'none',
      reason: 'Produces the container plan and the command line that would run, without running it.',
      limitations: SANDBOX_LIMITATIONS,
    };
  }

  async create(spec = {}) {
    const plan = this.#plan(spec);
    return {
      ok: true,
      handle: { id: `plan_${Date.now()}`, spec, plan },
      plan,
      executed: false,
    };
  }

  async execute(handle, command) {
    return {
      ok: true,
      executed: false,
      wouldRun: command,
      container: handle?.plan?.dockerArgs ?? null,
      note: 'Plan-only provider: nothing was executed. Use DockerSandboxProvider with explicit authorization to run this.',
    };
  }

  async inspect(handle) {
    return { ok: true, isolation: 'none', handle };
  }

  async destroy() {
    return { ok: true, note: 'nothing to destroy (plan-only)' };
  }

  #plan(spec = {}) {
    return {
      image: spec.image ?? 'node:22-alpine',
      workdir: '/workspace',
      mounts: [{ from: spec.workspace ?? '.', to: '/workspace', mode: 'ro' }],
      network: spec.network ?? 'none',
      dockerArgs: dockerArgs(spec),
    };
  }
}

/* ------------------------------------------------------------------ *
 * Docker provider (spec §19 MVP)
 * ------------------------------------------------------------------ */

export function dockerArgs(spec = {}) {
  const workspace = spec.workspace ?? '.';
  const network = spec.network ?? 'none';
  const memory = spec.memory ?? '512m';
  const cpus = spec.cpus ?? '1.0';
  const pids = spec.pidsLimit ?? 128;
  return [
    'run', '--rm', '-i',
    '--network', network,
    '--memory', memory,
    '--cpus', cpus,
    '--pids-limit', String(pids),
    '--read-only',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '-v', `${workspace}:/workspace:ro`,
    '-w', '/workspace',
    '--user', '1000:1000',
    spec.image ?? 'node:22-alpine',
    ...(spec.argv ?? []),
  ];
}

export class DockerSandboxProvider extends BaseSandboxProvider {
  /**
   * @param {object} config { runner: async (argv) => {stdout,stderr,code},
   *                          authorized: boolean, workspace, image,
   *                          allowNetwork: boolean }
   */
  constructor(config = {}) {
    super(config);
    this.id = 'docker';
    this.label = 'Docker (hardened)';
  }

  capabilities() {
    return {
      id: this.id,
      label: this.label,
      available: Boolean(this.config.runner),
      canExecute: Boolean(this.config.runner && this.config.authorized),
      isolation: 'container',
      reason: this.config.authorized
        ? 'Authorized: commands may be executed inside the container.'
        : 'Constructed but not authorized: commands are planned, not executed.',
      limitations: SANDBOX_LIMITATIONS,
    };
  }

  async create(spec = {}) {
    const argv = dockerArgs({
      workspace: spec.workspace ?? this.config.workspace ?? '.',
      image: spec.image ?? this.config.image,
      network: this.config.allowNetwork ? 'bridge' : 'none',
      argv: spec.argv ?? [],
    });
    return { ok: true, handle: { id: `docker_${Date.now()}`, argv }, plan: { dockerArgs: argv } };
  }

  async execute(handle, command) {
    const argv = [...(handle?.argv ?? []), ...toArgv(command)];
    if (!this.config.runner) {
      return { ok: false, executed: false, failClosed: true, reason: 'no runner injected; nothing executed', wouldRun: argv };
    }
    if (!this.config.authorized) {
      return {
        ok: true,
        executed: false,
        wouldRun: argv,
        reason: 'DockerSandboxProvider is not authorized. Set authorized: true after explicit human approval.',
      };
    }
    const result = await this.config.runner(argv);
    return { ok: result.code === 0, executed: true, argv, ...result };
  }

  async inspect() {
    return { ok: true, isolation: 'container', readOnlyRoot: true, network: this.config.allowNetwork ? 'bridge' : 'none' };
  }

  async destroy() {
    return { ok: true, note: 'containers are started with --rm and remove themselves on exit' };
  }
}

function toArgv(command) {
  if (Array.isArray(command)) return command;
  if (!command) return [];
  return ['sh', '-lc', String(command)];
}

/* ------------------------------------------------------------------ *
 * Registry
 * ------------------------------------------------------------------ */

export function createSandboxProvider(config = {}) {
  if (!config.provider || config.provider === 'none') return new NullSandboxProvider(config);
  if (config.provider === 'plan') return new PlanOnlySandboxProvider(config);
  if (config.provider === 'docker') return new DockerSandboxProvider(config);
  return new NullSandboxProvider(config);
}

export function describeSandboxProviders() {
  return [
    new NullSandboxProvider().capabilities(),
    new PlanOnlySandboxProvider().capabilities(),
    new DockerSandboxProvider().capabilities(),
  ];
}

/** Minimum sandbox requirements from spec §19, as checkable items. */
export const SANDBOX_MINIMUM_REQUIREMENTS = [
  { id: 'no-host-ssh', label: 'No host SSH agent or keys mounted' },
  { id: 'no-host-credentials', label: 'No host credential directories mounted' },
  { id: 'restricted-fs', label: 'Filesystem restricted to a read-only workspace copy' },
  { id: 'restricted-network', label: 'Network restricted or disabled' },
  { id: 'cpu-limit', label: 'CPU limit enforced' },
  { id: 'memory-limit', label: 'Memory limit enforced' },
  { id: 'execution-timeout', label: 'Execution timeout enforced' },
  { id: 'process-limit', label: 'Process/PID limit enforced' },
];
