// ── SQLite local (node:sqlite, sem build nativo) + migrations versionadas ──

import { DatabaseSync } from 'node:sqlite'
import { ensureHome } from './paths.js'

const MIGRATIONS = [
  // 1 — schema inicial
  `
  CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE audits (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    status TEXT NOT NULL,               -- pending|running|completed|failed|stopped
    origin TEXT NOT NULL,               -- cli|ui|session
    skills TEXT,                        -- lista separada por virgula
    models_json TEXT,
    plan_json TEXT,
    summary TEXT,
    score INTEGER,
    pid INTEGER,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cache_read_tokens INTEGER,
    cost_usd REAL,
    usage_json TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT
  );
  CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    agent TEXT NOT NULL,
    model TEXT,
    title TEXT NOT NULL,
    checklist TEXT,
    status TEXT NOT NULL,               -- planned|running|done|failed|skipped
    attempts INTEGER NOT NULL DEFAULT 0,
    summary TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,                 -- endpoint|file|host|service|dependency|component
    name TEXT NOT NULL,
    details TEXT,
    agent TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(audit_id, kind, name)
  );
  CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    asset TEXT,
    file_path TEXT,
    line INTEGER,
    severity TEXT NOT NULL,             -- critical|high|medium|low|info
    severity_reason TEXT,
    category TEXT,
    cwe TEXT,
    rule TEXT,
    impact TEXT,
    recommendation TEXT,
    validation_method TEXT,
    limitations TEXT,
    code_snippet TEXT,
    status TEXT NOT NULL,               -- suspected|confirmed|false_positive
    remediation TEXT NOT NULL DEFAULT 'open', -- open|applied|rejected|wont_fix
    confidence TEXT NOT NULL,           -- low|medium|high
    agent TEXT NOT NULL,
    source TEXT NOT NULL,               -- analyzer|agent
    duplicate_of TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE INDEX findings_audit ON findings(audit_id, severity);
  CREATE INDEX findings_fp ON findings(audit_id, fingerprint);
  CREATE TABLE evidence (
    id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    finding_id TEXT REFERENCES findings(id) ON DELETE SET NULL,
    kind TEXT NOT NULL,                 -- http|log|tool_output|code|file|note
    title TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    source TEXT,
    context TEXT,
    agent TEXT,
    collected_at TEXT NOT NULL
  );
  CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id TEXT,
    type TEXT NOT NULL,
    data_json TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX events_audit ON events(audit_id, id);
  CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    format TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    executive_summary TEXT,
    created_at TEXT NOT NULL
  );
  `,
]

let cached = null

export function openDb(file) {
  if (cached && !file) return cached
  const target = file || ensureHome().db
  const db = new DatabaseSync(target)
  db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;')
  migrate(db)
  if (!file) cached = db
  return db
}

export function migrate(db) {
  const { user_version: current } = db.prepare('PRAGMA user_version').get()
  for (let v = current; v < MIGRATIONS.length; v++) {
    db.exec('BEGIN')
    try {
      db.exec(MIGRATIONS[v])
      db.exec(`PRAGMA user_version = ${v + 1}`)
      db.exec('COMMIT')
    } catch (err) {
      db.exec('ROLLBACK')
      throw err
    }
  }
}

export function schemaVersion(db) {
  return db.prepare('PRAGMA user_version').get().user_version
}

export const LATEST_SCHEMA = MIGRATIONS.length
