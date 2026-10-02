-- Relay initial schema. Compatible with MySQL 5.7+ / 8.x and MariaDB 10.3+.
-- All DATETIME values are stored in UTC. `messages.day` is the local calendar day
-- in RELAY_TIMEZONE, computed by the application at insert time.
-- Every statement is idempotent (IF NOT EXISTS) so a first run that stopped part
-- way can simply be re-run.
-- scripts/migrate.js splits statements on ";" at the end of a line; do not put
-- ";" at a line end inside a string or comment.

-- Admin emails are stored lowercased with a binary collation: a case/accent
-- insensitive collation would let "ADMÍN@x" and "admin@x" hit the same account
-- through different login rate-limit buckets.
CREATE TABLE IF NOT EXISTS admin_users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  email VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
  name VARCHAR(100) NOT NULL DEFAULT '',
  password_hash VARCHAR(100) NOT NULL,
  totp_secret_enc TEXT NULL,
  totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
  totp_last_step BIGINT NULL,
  -- Bumped on password/TOTP/disable changes; sessions from an older epoch are dropped.
  session_epoch INT UNSIGNED NOT NULL DEFAULT 0,
  disabled TINYINT(1) NOT NULL DEFAULT 0,
  last_login_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_admin_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS apps (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(150) NOT NULL,
  notes TEXT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  legacy_signing TINYINT(1) NOT NULL DEFAULT 0,
  smtp_host VARCHAR(255) NOT NULL,
  smtp_port SMALLINT UNSIGNED NOT NULL,
  smtp_encryption VARCHAR(10) NOT NULL,
  smtp_username VARCHAR(255) NOT NULL DEFAULT '',
  smtp_password_enc TEXT NULL,
  from_email VARCHAR(254) NOT NULL,
  from_name VARCHAR(150) NOT NULL DEFAULT '',
  allowed_from TEXT NULL,
  reply_to_default VARCHAR(254) NULL,
  limit_per_minute INT UNSIGNED NOT NULL DEFAULT 30,
  limit_per_day INT UNSIGNED NOT NULL DEFAULT 1000,
  max_message_bytes INT UNSIGNED NOT NULL DEFAULT 10485760,
  max_recipients INT UNSIGNED NOT NULL DEFAULT 50,
  ip_allowlist TEXT NULL,
  last_used_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  KEY ix_apps_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS api_keys (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  app_id INT UNSIGNED NOT NULL,
  prefix VARCHAR(32) NOT NULL,
  key_hash CHAR(64) NULL,
  key_enc TEXT NULL,
  created_by INT UNSIGNED NULL,
  created_at DATETIME NOT NULL,
  last_used_at DATETIME NULL,
  expires_at DATETIME NULL,
  revoked_at DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_api_keys_hash (key_hash),
  KEY ix_api_keys_app (app_id),
  CONSTRAINT fk_api_keys_app FOREIGN KEY (app_id) REFERENCES apps (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS messages (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  public_id VARCHAR(40) NOT NULL,
  app_id INT UNSIGNED NOT NULL,
  api_key_id INT UNSIGNED NULL,
  source VARCHAR(10) NOT NULL,
  client_message_id VARCHAR(191) NULL,
  status VARCHAR(10) NOT NULL,
  day DATE NOT NULL,
  created_at DATETIME(3) NOT NULL,
  completed_at DATETIME(3) NULL,
  from_email VARCHAR(254) NULL,
  to_addrs TEXT NULL,
  cc_addrs TEXT NULL,
  bcc_addrs TEXT NULL,
  recipient_count SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  subject VARCHAR(255) NULL,
  size_bytes INT UNSIGNED NOT NULL DEFAULT 0,
  attachment_count SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  smtp_message_id VARCHAR(255) NULL,
  smtp_response VARCHAR(1000) NULL,
  error VARCHAR(1000) NULL,
  http_status SMALLINT UNSIGNED NULL,
  client_ip VARCHAR(45) NULL,
  duration_ms INT UNSIGNED NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_messages_public_id (public_id),
  KEY ix_messages_app_created (app_id, created_at),
  KEY ix_messages_created (created_at),
  KEY ix_messages_day_app_status (day, app_id, status),
  KEY ix_messages_status_created (status, created_at),
  CONSTRAINT fk_messages_app FOREIGN KEY (app_id) REFERENCES apps (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS idempotency_keys (
  app_id INT UNSIGNED NOT NULL,
  idem_key VARCHAR(191) NOT NULL,
  message_id BIGINT UNSIGNED NOT NULL,
  created_at DATETIME(3) NOT NULL,
  PRIMARY KEY (app_id, idem_key),
  KEY ix_idempotency_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS rate_counters (
  k VARCHAR(191) NOT NULL,
  count INT UNSIGNED NOT NULL,
  expires_at DATETIME NOT NULL,
  PRIMARY KEY (k),
  KEY ix_rate_counters_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  created_at DATETIME NOT NULL,
  admin_user_id INT UNSIGNED NULL,
  admin_email VARCHAR(191) NULL,
  action VARCHAR(64) NOT NULL,
  target_type VARCHAR(32) NULL,
  target_id VARCHAR(64) NULL,
  details TEXT NULL,
  ip VARCHAR(45) NULL,
  PRIMARY KEY (id),
  KEY ix_audit_created (created_at),
  KEY ix_audit_target (target_type, target_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- session_id is the SHA-256 hex of the cookie's session id, never the id itself.
CREATE TABLE IF NOT EXISTS sessions (
  session_id VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
  expires INT UNSIGNED NOT NULL,
  data MEDIUMTEXT COLLATE utf8mb4_bin,
  PRIMARY KEY (session_id),
  KEY ix_sessions_expires (expires)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS kv (
  k VARCHAR(64) NOT NULL,
  v TEXT NULL,
  updated_at DATETIME NOT NULL,
  PRIMARY KEY (k)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
