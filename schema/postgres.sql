-- Agent Inspector — PostgreSQL schema (spec §11).
--
-- The MVP engine runs with no database: the audit ledger is an in-process,
-- hash-chained structure that serialises to JSON. This schema is the durable
-- form of the same records, for when inspections are stored server-side
-- (Supabase in the target stack) instead of passed around as JSON reports.
--
-- Design notes worth keeping:
--   * `actions.arguments` is jsonb, and nothing secret is ever stored: the
--     engine redacts before a record reaches this layer (spec §20).
--   * `audit_events` carries `previous_hash`/`current_hash` so tamper-evidence
--     survives a round trip through the database.
--   * `capabilities.evidence` is jsonb because evidence is a list of strings
--     produced by the analyzers, and it must stay readable years later.

create extension if not exists "pgcrypto";

-- ── identity ────────────────────────────────────────────────────────
create table if not exists users (
  id           uuid primary key default gen_random_uuid(),
  email        text not null unique,
  created_at   timestamptz not null default now()
);

create table if not exists workspaces (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid not null references users (id) on delete cascade,
  name           text not null,
  repository_url text,
  created_at     timestamptz not null default now()
);

create table if not exists agents (
  id                 uuid primary key default gen_random_uuid(),
  workspace_id       uuid not null references workspaces (id) on delete cascade,
  name               text not null,
  type               text not null check (type in ('OpenClaw', 'AutoClaw', 'Claude Code', 'Codex', 'Cursor', 'MCP', 'Custom')),
  version            text,
  configuration_hash text,
  created_at         timestamptz not null default now()
);

-- ── inspections ─────────────────────────────────────────────────────
create table if not exists inspections (
  id               uuid primary key default gen_random_uuid(),
  workspace_id     uuid not null references workspaces (id) on delete cascade,
  agent_id         uuid references agents (id) on delete set null,
  source_type      text not null check (source_type in ('command', 'script', 'project', 'repository', 'mcp', 'skill', 'agent_config', 'workspace')),
  source_reference text,
  status           text not null default 'running' check (status in ('running', 'completed', 'failed')),
  overall_state    text,
  confidence       integer check (confidence between 0 and 100),
  created_at       timestamptz not null default now(),
  completed_at     timestamptz
);

create table if not exists actions (
  id                uuid primary key default gen_random_uuid(),
  inspection_id     uuid not null references inspections (id) on delete cascade,
  parent_action_id  uuid references actions (id) on delete set null,
  action_type       text not null,
  command           text,
  arguments         jsonb not null default '[]'::jsonb,
  working_directory text,
  source_file       text,
  line_number       integer,
  status            text not null default 'detected'
);

create table if not exists capabilities (
  id              uuid primary key default gen_random_uuid(),
  action_id       uuid not null references actions (id) on delete cascade,
  capability_type text not null,
  target          text,
  scope           text,
  risk_level      integer not null check (risk_level between 0 and 5),
  evidence        jsonb not null default '[]'::jsonb
);

-- ── policy + decisions ──────────────────────────────────────────────
create table if not exists policies (
  id           uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references workspaces (id) on delete cascade,
  name         text not null,
  version      integer not null default 1,
  rules        jsonb not null default '{}'::jsonb,
  created_at   timestamptz not null default now(),
  unique (workspace_id, name, version)
);

create table if not exists decisions (
  id         uuid primary key default gen_random_uuid(),
  action_id  uuid not null references actions (id) on delete cascade,
  policy_id  uuid references policies (id) on delete set null,
  decision   text not null check (decision in ('ALLOW', 'ALLOW_WITH_LOG', 'REQUIRE_APPROVAL', 'SANDBOX_ONLY', 'DENY')),
  reason     jsonb not null default '[]'::jsonb,
  approved_by uuid references users (id) on delete set null,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

-- ── audit ───────────────────────────────────────────────────────────
-- Append-only. Enforce that with a trigger rather than by convention.
create table if not exists audit_events (
  id            uuid primary key default gen_random_uuid(),
  workspace_id  uuid references workspaces (id) on delete cascade,
  agent_id      uuid references agents (id) on delete set null,
  action_id     uuid references actions (id) on delete set null,
  seq           integer not null,
  event_type    text not null,
  payload       jsonb not null default '{}'::jsonb,
  payload_hash  text not null,
  previous_hash text not null,
  current_hash  text not null,
  created_at    timestamptz not null default now(),
  unique (workspace_id, seq)
);

create or replace function audit_events_append_only()
returns trigger as $$
begin
  raise exception 'audit_events is append-only';
end;
$$ language plpgsql;

drop trigger if exists audit_events_no_update on audit_events;
create trigger audit_events_no_update
  before update or delete on audit_events
  for each row execute function audit_events_append_only();

-- ── indexes ─────────────────────────────────────────────────────────
create index if not exists idx_actions_inspection on actions (inspection_id);
create index if not exists idx_capabilities_action on capabilities (action_id);
create index if not exists idx_decisions_action on decisions (action_id);
create index if not exists idx_audit_workspace_seq on audit_events (workspace_id, seq);
create index if not exists idx_inspections_workspace on inspections (workspace_id, created_at desc);

-- ── reporting view: the console's "why" panel in SQL form ───────────
create or replace view v_findings as
select
  a.inspection_id,
  c.capability_type,
  c.risk_level,
  c.scope,
  a.command,
  a.arguments,
  a.source_file,
  a.line_number,
  c.evidence
from capabilities c
join actions a on a.id = c.action_id
order by c.risk_level desc;
