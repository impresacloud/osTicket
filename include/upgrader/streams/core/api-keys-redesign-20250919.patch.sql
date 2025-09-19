-- API Keys Redesign: Add new columns to api_key table for enhanced security and flexibility
-- This patch removes mandatory IP binding, adds scoped permissions, expiration, and optional CIDRs
-- Also creates tables for HMAC nonce deduplication, multiple secrets for rotation, and rate limiting

-- Extend ost_api_key table with new fields
ALTER TABLE `%TABLE_PREFIX%api_key`
  ADD COLUMN `key_id` varchar(64) NULL UNIQUE AFTER `id` COMMENT 'Public key identifier, safe for logging',
  ADD COLUMN `secret_hash` varchar(255) NULL AFTER `key_id` COMMENT 'Hashed secret using password_hash',
  ADD COLUMN `name` varchar(128) NULL AFTER `secret_hash` COMMENT 'User-defined key name',
  ADD COLUMN `owner_type` enum('integration','user','system') NOT NULL DEFAULT 'integration' AFTER `name` COMMENT 'Type of key owner',
  ADD COLUMN `owner_id` int(10) unsigned NULL AFTER `owner_type` COMMENT 'ID of the owner entity',
  ADD COLUMN `scopes` varchar(255) NOT NULL DEFAULT 'tickets:create,cron:exec' AFTER `owner_id` COMMENT 'Comma-separated permissions',
  ADD COLUMN `expires_at` datetime NULL AFTER `scopes` COMMENT 'Optional expiration datetime',
  ADD COLUMN `revoked_at` datetime NULL AFTER `expires_at` COMMENT 'Datetime if revoked',
  ADD COLUMN `last_used_at` datetime NULL AFTER `revoked_at` COMMENT 'Last usage timestamp for audit',
  ADD COLUMN `allowed_cidrs` text NULL AFTER `last_used_at` COMMENT 'Optional CIDR list; empty means no IP restriction',
  ADD COLUMN `allowed_origins` text NULL AFTER `allowed_cidrs` COMMENT 'CORS origins for browser use',
  ADD COLUMN `rate_limit_min` int unsigned NULL AFTER `allowed_origins` COMMENT 'Requests per minute limit',
  ADD COLUMN `rate_limit_day` int unsigned NULL AFTER `rate_limit_min` COMMENT 'Requests per day limit';

-- Create table for HMAC nonce deduplication to prevent replay attacks
CREATE TABLE `%TABLE_PREFIX%api_nonce` (
  `id` int unsigned NOT NULL auto_increment,
  `key_id` varchar(64) NOT NULL COMMENT 'Key identifier using the nonce',
  `nonce` varchar(128) NOT NULL COMMENT 'Random nonce string to ensure uniqueness',
  `created` datetime NOT NULL COMMENT 'Timestamp when nonce was stored',
  PRIMARY KEY (`id`),
  UNIQUE KEY `key_nonce` (`key_id`,`nonce`) COMMENT 'Ensures nonce uniqueness per key within window'
) DEFAULT CHARSET=utf8 COMMENT='Stores nonces for HMAC replay prevention';

-- Optional: Table for multiple secrets per key to support rotation with overlap
CREATE TABLE `%TABLE_PREFIX%api_key_secret` (
  `id` int unsigned NOT NULL auto_increment,
  `key_id` varchar(64) NOT NULL COMMENT 'Foreign key to api_key.key_id',
  `secret_hash` varchar(255) NOT NULL COMMENT 'Hash of the secret',
  `created` datetime NOT NULL COMMENT 'When this secret was created',
  `disabled_at` datetime NULL COMMENT 'When this secret was disabled (for rotation)',
  PRIMARY KEY (`id`),
  KEY `key_id_idx` (`key_id`) COMMENT 'Index for quick lookup by key_id'
) DEFAULT CHARSET=utf8 COMMENT='Supports multiple active secrets for key rotation';

-- Optional: Table for rate limit tracking (minimal DB storage)
CREATE TABLE `%TABLE_PREFIX%api_rate_limit` (
  `key_id` varchar(64) NOT NULL COMMENT 'Key being rate-limited',
  `bucket` enum('min','day') NOT NULL COMMENT 'Time bucket for counting',
  `period_start` datetime NOT NULL COMMENT 'Start of the counting period',
  `count` int unsigned NOT NULL DEFAULT 0 COMMENT 'Number of requests in this period',
  PRIMARY KEY (`key_id`,`bucket`,`period_start`) COMMENT 'Unique per key, bucket, and period'
) DEFAULT CHARSET=utf8 COMMENT='Tracks rate limits by key; use Redis if preferred for performance';

-- Note: Legacy fields (apikey, ipaddr, can_create_tickets, can_exec_cron, isactive, notes, created, updated) are retained for backward compatibility.
-- New keys will use key_id/secret_hash/scopes; legacy will be migrated or deprecated.
