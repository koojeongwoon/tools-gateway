export interface Migration {
  version: number;
  name: string;
  sql: string;
}

export const migrations: readonly Migration[] = [
  {
    version: 1,
    name: "saas_core_tables",
    sql: `
CREATE TABLE users (
  id VARCHAR(64) PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(100) NOT NULL,
  system_role VARCHAR(20) NOT NULL DEFAULT 'USER'
    CHECK (system_role IN ('ADMIN', 'DEVELOPER', 'USER')),
  tier VARCHAR(20) NOT NULL DEFAULT 'FREE'
    CHECK (tier IN ('FREE', 'PRO', 'ENTERPRISE')),
  external_provider VARCHAR(50),
  external_subject_id VARCHAR(255),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_users_external_identity
  ON users (external_provider, external_subject_id)
  WHERE external_provider IS NOT NULL AND external_subject_id IS NOT NULL;

CREATE TABLE user_service_permissions (
  id VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  service_name VARCHAR(50) NOT NULL,
  allowed_actions JSONB NOT NULL DEFAULT '["read"]'::jsonb
    CHECK (jsonb_typeof(allowed_actions) = 'array'),
  granted_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, service_name)
);

CREATE TABLE api_keys (
  id VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  key_prefix VARCHAR(16) NOT NULL,
  key_hash VARCHAR(64) UNIQUE NOT NULL,
  allowed_scopes JSONB NOT NULL DEFAULT '["*"]'::jsonb
    CHECK (jsonb_typeof(allowed_scopes) = 'array'),
  rate_limit_per_minute INT NOT NULL DEFAULT 60
    CHECK (rate_limit_per_minute > 0),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  expires_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_mcp_upstreams (
  id VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool_prefix VARCHAR(50) NOT NULL
    CHECK (tool_prefix ~ '^[a-z][a-z0-9_]{0,49}$'),
  endpoint_url VARCHAR(500) NOT NULL,
  transport VARCHAR(20) NOT NULL DEFAULT 'streamable-http'
    CHECK (transport IN ('streamable-http', 'sse')),
  auth_type VARCHAR(20) NOT NULL DEFAULT 'bearer'
    CHECK (auth_type IN ('bearer', 'api_key', 'custom_header', 'none')),
  auth_header_name VARCHAR(100) NOT NULL DEFAULT 'Authorization',
  encrypted_auth_value TEXT,
  encryption_iv VARCHAR(32),
  encryption_tag VARCHAR(32),
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, tool_prefix),
  CHECK (
    (auth_type = 'none' AND encrypted_auth_value IS NULL
      AND encryption_iv IS NULL AND encryption_tag IS NULL)
    OR
    (auth_type <> 'none' AND encrypted_auth_value IS NOT NULL
      AND encryption_iv IS NOT NULL AND encryption_tag IS NOT NULL)
  )
);

CREATE TABLE tool_usage_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  api_key_id VARCHAR(64) REFERENCES api_keys(id) ON DELETE SET NULL,
  tool_name VARCHAR(100) NOT NULL,
  status VARCHAR(20) NOT NULL
    CHECK (status IN ('SUCCESS', 'FORBIDDEN', 'ERROR')),
  status_code INT NOT NULL,
  duration_ms INT NOT NULL CHECK (duration_ms >= 0),
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_lookup ON api_keys (key_prefix) WHERE is_active;
CREATE INDEX idx_user_perms ON user_service_permissions (user_id);
CREATE INDEX idx_usage_logs_user ON tool_usage_logs (user_id, created_at DESC);
`,
  },
  {
    version: 2,
    name: "tool_level_permissions",
    sql: `
CREATE TABLE user_tool_permissions (
  id VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool_pattern VARCHAR(150) NOT NULL
    CHECK (tool_pattern ~ '^[A-Za-z0-9_-]+\\.(\\*|[A-Za-z0-9_.-]+\\*?)$'),
  granted_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, tool_pattern)
);

CREATE INDEX idx_user_tool_permissions_user
  ON user_tool_permissions (user_id);
`,
  },
  {
    version: 3,
    name: "add_cost_and_capacity_metrics_to_tool_usage_logs",
    sql: `
ALTER TABLE tool_usage_logs
  ADD COLUMN request_bytes INT NOT NULL DEFAULT 0,
  ADD COLUMN response_bytes INT NOT NULL DEFAULT 0,
  ADD COLUMN input_tokens INT NOT NULL DEFAULT 0,
  ADD COLUMN output_tokens INT NOT NULL DEFAULT 0,
  ADD COLUMN credits_used NUMERIC(10, 4) NOT NULL DEFAULT 0.0000,
  ADD COLUMN arguments JSONB;
`,
  },
  {
    version: 4,
    name: "tool_semantic_search_and_embeddings",
    sql: `
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_search CASCADE;

CREATE TABLE tool_embeddings (
  id VARCHAR(64) PRIMARY KEY,
  tool_name VARCHAR(150) UNIQUE NOT NULL,
  upstream_prefix VARCHAR(50) NOT NULL,
  title VARCHAR(150) NOT NULL,
  description TEXT NOT NULL,
  input_schema JSONB,
  embedding VECTOR(1536),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tool_embeddings_hnsw
  ON tool_embeddings USING hnsw (embedding vector_cosine_ops);

CALL paradedb.create_bm25(
  index_name => 'idx_tool_embeddings_bm25',
  table_name => 'tool_embeddings',
  key_field  => 'id',
  text_fields => '{tool_name: {}, title: {}, description: {}}'
);
`,
  },
];

