CREATE UNLOGGED TABLE IF NOT EXISTS api_rate_limits (
  scope text NOT NULL CHECK (char_length(scope) BETWEEN 1 AND 64),
  identity_hash char(64) NOT NULL,
  window_start timestamptz NOT NULL,
  request_count integer NOT NULL CHECK (request_count > 0),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (scope, identity_hash, window_start)
);

CREATE INDEX IF NOT EXISTS api_rate_limits_expires_at_idx
  ON api_rate_limits (expires_at);
