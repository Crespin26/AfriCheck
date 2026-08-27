CREATE TABLE IF NOT EXISTS scan_history (
  id uuid PRIMARY KEY,
  hostname text NOT NULL CHECK (char_length(hostname) BETWEEN 1 AND 253),
  scanned_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  score smallint NOT NULL CHECK (score BETWEEN 0 AND 100),
  grade char(1) NOT NULL CHECK (grade IN ('A', 'B', 'C', 'D', 'E')),
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > scanned_at)
);

CREATE INDEX IF NOT EXISTS scan_history_hostname_scanned_at_idx
  ON scan_history (hostname, scanned_at DESC);

CREATE INDEX IF NOT EXISTS scan_history_expires_at_idx
  ON scan_history (expires_at);
