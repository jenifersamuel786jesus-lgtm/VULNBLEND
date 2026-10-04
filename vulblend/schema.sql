PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  target_url TEXT NOT NULL,
  source_path TEXT,
  environment TEXT NOT NULL DEFAULT 'laboratory',
  technology TEXT,
  category TEXT,
  authorization_confirmed INTEGER NOT NULL DEFAULT 0,
  allowed_paths TEXT DEFAULT '[]',
  excluded_paths TEXT DEFAULT '[]',
  crawler_depth INTEGER NOT NULL DEFAULT 2,
  max_requests INTEGER NOT NULL DEFAULT 50,
  timeout_seconds INTEGER NOT NULL DEFAULT 15,
  vulnerability_classes TEXT DEFAULT '["SQLi","XSS"]',
  archived INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_applications_active ON applications(archived, environment);

CREATE TABLE IF NOT EXISTS scan_configs (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id),
  mode TEXT NOT NULL,
  selected_classes TEXT NOT NULL,
  crawler_depth INTEGER NOT NULL,
  max_requests INTEGER NOT NULL,
  timeout_seconds INTEGER NOT NULL,
  included_routes TEXT DEFAULT '[]',
  excluded_routes TEXT DEFAULT '[]',
  payload_dictionary TEXT DEFAULT 'safe-lab-v1',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_executions (
  id TEXT PRIMARY KEY,
  config_id TEXT NOT NULL REFERENCES scan_configs(id),
  application_id TEXT NOT NULL REFERENCES applications(id),
  status TEXT NOT NULL,
  current_stage TEXT,
  progress REAL NOT NULL DEFAULT 0,
  started_at TEXT,
  ended_at TEXT,
  duration_seconds REAL,
  requests_processed INTEGER NOT NULL DEFAULT 0,
  routes_discovered INTEGER NOT NULL DEFAULT 0,
  findings_count INTEGER NOT NULL DEFAULT 0,
  errors_count INTEGER NOT NULL DEFAULT 0,
  data_origin TEXT NOT NULL DEFAULT 'real',
  limitation TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_status_time ON scan_executions(status, created_at);

CREATE TABLE IF NOT EXISTS execution_events (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scan_executions(id),
  stage TEXT NOT NULL,
  level TEXT NOT NULL DEFAULT 'info',
  message TEXT NOT NULL,
  metadata TEXT DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scan_executions(id),
  application_id TEXT NOT NULL REFERENCES applications(id),
  url TEXT NOT NULL,
  route TEXT NOT NULL,
  method TEXT NOT NULL,
  parameters TEXT DEFAULT '[]',
  form_fields TEXT DEFAULT '[]',
  status_code INTEGER,
  content_type TEXT,
  depth INTEGER NOT NULL DEFAULT 0,
  in_scope INTEGER NOT NULL DEFAULT 1,
  discovered_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scan_executions(id),
  application_id TEXT NOT NULL REFERENCES applications(id),
  finding_type TEXT NOT NULL,
  title TEXT NOT NULL,
  endpoint TEXT,
  method TEXT,
  parameter TEXT,
  file_path TEXT,
  line_number INTEGER,
  source TEXT,
  sink TEXT,
  description TEXT NOT NULL,
  evidence TEXT,
  remediation TEXT,
  severity TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 0,
  verification_status TEXT NOT NULL DEFAULT 'unverified',
  detection_method TEXT NOT NULL,
  correlation_status TEXT NOT NULL DEFAULT 'unverified',
  status TEXT NOT NULL DEFAULT 'open',
  data_origin TEXT NOT NULL DEFAULT 'real',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_risk_filter ON findings(application_id, severity, verification_status, status);

CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id),
  evidence_type TEXT NOT NULL,
  content TEXT NOT NULL,
  redacted INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_scores (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id),
  score REAL NOT NULL,
  category TEXT NOT NULL,
  priority_rank INTEGER,
  components TEXT NOT NULL,
  rationale TEXT NOT NULL,
  weights_version TEXT NOT NULL DEFAULT 'v1-research',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_risk_scores_score ON risk_scores(score DESC);

CREATE TABLE IF NOT EXISTS test_cases (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  finding_type TEXT NOT NULL,
  endpoint TEXT,
  parameter TEXT,
  expected_behavior TEXT,
  ground_truth INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS experiment_runs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  method TEXT NOT NULL,
  configuration TEXT NOT NULL,
  testbed_version TEXT,
  payload_dictionary TEXT,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  data_origin TEXT NOT NULL DEFAULT 'real'
);

CREATE TABLE IF NOT EXISTS experiment_results (
  id TEXT PRIMARY KEY,
  experiment_id TEXT NOT NULL REFERENCES experiment_runs(id),
  tp INTEGER NOT NULL DEFAULT 0,
  fp INTEGER NOT NULL DEFAULT 0,
  tn INTEGER NOT NULL DEFAULT 0,
  fn INTEGER NOT NULL DEFAULT 0,
  precision REAL,
  recall REAL,
  f1 REAL,
  false_positive_rate REAL,
  verification_rate REAL,
  execution_time REAL,
  crawl_coverage REAL,
  notes TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remediation_history (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id),
  old_status TEXT,
  new_status TEXT NOT NULL,
  note TEXT,
  actor TEXT NOT NULL DEFAULT 'local-user',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  application_id TEXT REFERENCES applications(id),
  scan_id TEXT REFERENCES scan_executions(id),
  report_type TEXT NOT NULL,
  file_name TEXT NOT NULL,
  file_path TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  details TEXT DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
