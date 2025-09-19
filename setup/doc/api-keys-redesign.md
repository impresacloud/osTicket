# API Keys Redesign — Auth, Scopes, and No-IP Strategy

## Document Overview
This document outlines a comprehensive refactoring of osTicket's API key management system to address the limitations of IP-based restrictions. The current system binds keys to static IP addresses, making it impractical for modern use cases involving dynamic networks, proxies, or multi-environment deployments. This proposal introduces flexible authentication, granular authorization, and robust lifecycle management while maintaining backward compatibility.

## Table of Contents
1. [Problem Statement](#problem-statement)
2. [Goals and Objectives](#goals-and-objectives)
3. [Credential Model](#credential-model)
4. [Authentication Schemes](#authentication-schemes)
5. [Authorization (Scopes)](#authorization-scopes)
6. [Key Lifecycle](#key-lifecycle)
7. [Alternatives to IP Filtering](#alternatives-to-ip-filtering)
8. [Rate Limiting and Quotas](#rate-limiting-and-quotas)
9. [Database Schema Changes](#database-schema-changes)
10. [Backward Compatibility and Migration](#backward-compatibility-and-migration)
11. [Implementation Steps](#implementation-steps)
12. [Security Considerations](#security-considerations)
13. [Operational Playbooks](#operational-playbooks)
14. [Appendix: Code Snippets](#appendix-code-snippets)

---

## 1. Problem Statement
- **Current Challenges**: API keys are generated as MD5 hashes stored in plaintext and tied to a single `ipaddr` field. Authentication requires `key->isActive() AND key->getIPAddr() == REMOTE_ADDR`, which fails for:
  - Cloud platforms with dynamic IPs (e.g., AWS, Kubernetes).
  - Automated scripts from multiple locations.
  - Clients behind proxies or in mobile environments.
- **Risks**: Plaintext storage increases leak risks; IP rigidity encourages insecure workarounds like wildcards or key sharing; lacks expiration, rotation, or fine-grained permissions.
- **Impact**: Limits integration possibilities and operational security.

---

## 2. Goals and Objectives
- **Flexibility**: Eliminate mandatory IP binding; support usage from any network with optional constraints.
- **Security**: Implement hashed secrets, expiration, rotation, and HMAC signing to prevent replay/mitm attacks.
- **Authorization**: Introduce granular scopes (e.g., tickets:create) to replace coarse boolean flags.
- **Observability**: Audit logging, last-used timestamps, and activity views for monitoring.
- **Compatibility**: Full backward compatibility during a transition period with configurable deprecation.
- **Simplicity**: Minimize dependencies; leverage existing PHP patterns; keep DB changes manageable.
- **Adoption**: Enable bearer authentication for quick wins; HMAC for sensitive operations.

---

## 3. Credential Model
Each API key is a pair of public (safe for logging) and private (secret) components:

- **key_id**: Public identifier (e.g., `ak_f7b2c9e4a1`), 64-char string. Generated as `ak_` + 12 random hex bytes.
- **secret**: Private string (e.g., `sk_f2341c9deadbeef`), 20+ random chars. Displayed only on creation; never again.
- **secret_hash**: Server-side storage of hashed secret (password_hash with PASSWORD_DEFAULT for future-proofing).
- **last4**: Last 4 chars of secret for user identification (e.g., in logs/UI).
- **Metadata**:
  - `name` (128 chars): User-defined label.
  - `owner_type`: integration|user|system.
  - `owner_id`: Reference to owning entity.
  - `notes`: Free-text description.
  - `created_by`: User who created the key.
- **Status Fields**:
  - `isactive`: Boolean (renamed from current, but semantics same).
  - `created`, `updated`, `last_used_at`: Timestamps.
  - `expires_at`: Optional expiry datetime.
  - `revoked_at`: Datetime if manually revoked.
- **Constraints (Optional)**:
  - `allowed_cidrs`: Comma-separated CIDR list (e.g., "192.168.0.0/24,10.0.0.0/8"). Empty/null = no IP restriction.
  - `allowed_origins`: CORS origins for browser use.
  - `rate_limit_min`, `rate_limit_day`: Integer quotas; null = unlimited.

Legacy fields (`apikey`, `ipaddr`) retained for compatibility.

---

## 4. Authentication Schemes
### Bearer Mode (Simple Adoption)
- **Headers**: `X-API-Key: <key_id>`, `X-API-Secret: <secret>` or `Authorization: Bearer <key_id>.<secret>`
- **Flow**:
  1. Server: Look up key by key_id, verify active/expiry.
  2. Verify secret via password_verify against secret_hash.
  3. Optional: Check REMOTE_ADDR against allowed_cidrs if set.
  4. Proceed if scopes permit the action.
- **Use Case**: Quick migration for scripts; less secure than HMAC.
- **Caveats**: Secret in headers; weaker against interception/replay.

### HMAC Signed Requests (Recommended)
- **Headers**:
  - `X-API-Key: <key_id>`
  - `X-API-Timestamp: <unix_timestamp>`
  - `X-API-Nonce: <uuid-v4 or random_string_16>`
  - `X-API-Signature: v1=<base64_encode(hmac_sha256(secret, canonical_string))>`
- **Canonical String**:
  ```
  METHOD\n             // e.g., POST
  PATH_WITH_QUERY\n   // e.g., /api/tickets.json?format=json
  TIMESTAMP\n         // unix seconds, e.g., 1695139200
  NONCE\n             // e.g., c3c0c1d8-0d7c-4e3a-91e3-6c0f4e2a7f93
  SHA256_HEX(BODY)    // hex digest of request body
  ```
  Example: `POST\n/api/tickets.json\n1695139200\nc3c0c1d8-...\n<hash>`

- **Server Verification** (PHP Sketch):
  ```php
  $keyId = $_SERVER['HTTP_X_API_KEY'] ?? '';
  $ts    = $_SERVER['HTTP_X_API_TIMESTAMP'] ?? '';
  $nonce = $_SERVER['HTTP_X_API_NONCE'] ?? '';
  $sig   = $_SERVER['HTTP_X_API_SIGNATURE'] ?? ''; // Extract v1=...
  $body  = file_get_contents('php://input');
  // Compute canonical
  $pathWithQuery = ($_SERVER['REQUEST_URI'] ?? ''); // Strip protocol/host if present
  $canon = $_SERVER['REQUEST_METHOD'] . "\n" . $pathWithQuery . "\n{$ts}\n{$nonce}\n" . hash('sha256', $body);
  // Lookup key: find by key_id, check active, expiry
  $key = API::lookupByKeyId($keyId);
  if (!$key || !$key->isActive() || ($key->getExpiresAt() && strtotime($key->getExpiresAt()) < time())) {
      return $this->exerr(403, 'Invalid or expired key');
  }
  // Check timestamp skew (e.g., 5 min)
  $now = time();
  if (abs($now - intval($ts)) > 300) {
      return $this->exerr(400, 'Request timestamp expired');
  }
  // Check nonce uniqueness
  if (!API::storeNonce($keyId, $nonce)) { // Store in api_nonce table; failure if duplicate
      return $this->exerr(400, 'Nonce already used');
  }
  // Optional CIDR check
  if ($key->getAllowedCidrs() && !$key->ipInAllowedCidr($_SERVER['REMOTE_ADDR'])) {
      return $this->exerr(403, 'IP not in allowed ranges');
  }
  // HMAC verify: compute sig using secret, compare using hash_equals
  $expectedSig = hash_hmac('sha256', $canon, $key->getSecret()); // Reconstruct secret from rotation table if needed
  $providedSig = // Extract from header (after v1=)
  if (!hash_equals($expectedSig, $providedSig)) {
      return $this->exerr(401, 'Invalid signature');
  }
  // Success: update last_used_at, apply scopes/rate limits
  ```
- **Client Example** (PHP for HMAC Computation):
  ```php
  $method = 'POST';
  $path   = '/api/tickets.json';
  $ts     = time(); // Unix timestamp
  $nonce  = bin2hex(random_bytes(8)); // Random 16-char string
  $body   = json_encode($data);
  $bodyHash = hash('sha256', $body); // Hex
  $canon = "{$method}\n{$path}\n{$ts}\n{$nonce}\n{$bodyHash}";
  $sig   = base64_encode(hash_hmac('sha256', $canon, $secret, true)); // Binary HMAC
  // Add to mini library for reuse
  class ApiClient {
      public static function signRequest($method, $path, $body, $keyId, $secret) {
          $ts    = time();
          $nonce = bin2hex(random_bytes(8));
          $bodyHash = hash('sha256', $body);
          $canon = "{$method}\n{$path}\n{$ts}\n{$nonce}\n{$bodyHash}";
          $sig   = base64_encode(hash_hmac('sha256', $canon, $secret, true));
          return [
              'ts'    => $ts,
              'nonce' => $nonce,
              'sig'   => "v1={$sig}",
          ];
      }
  }
  ```
- **Benefits**: Secret stays out of headers; resistance to replay/tampering.
- **Nonce Cleanup**: DB job to delete nonces older than TTL (e.g., 6 hours).

---

## 5. Authorization (Scopes)
Scopes replace boolean flags for granular control:

- **Current Mapping**:
  - `can_create_tickets` → `tickets:create`
  - `can_exec_cron` → `cron:exec`
- **Future Examples**: `tickets:read`, `tickets:update`, `users:create`, `kb:read`.
- **Enforcement**: Add to controllers (e.g., include/api.tickets.php):
  ```php
  if (!($key = $this->requireApiKey()) || !API::hasScope($key, 'tickets:create')) {
      return $this->exerr(403, __('Scope tickets:create required'));
  }
  ```
- **Helper Method** (in class.api.php):
  ```php
  public static function hasScope($key, $requiredScope) {
      return in_array($requiredScope, explode(',', $key->getScopes()));
  }
  ```
- **Admin UI**: Comma-separated input for scopes; validate against allowed list.

---

## 6. Key Lifecycle
- **Creation**: Generate key_id + secret; hash secret; store with last4 for logs.
- **Rotation**: Create new secret (overlap via api_key_secret table); old ones retain for short window.
- **Revocation**: Set revoked_at; rédition immediate denial.
- **Expiration**: Deny after expires_at.
- **Audit**: Log each request (key_id, IP, path, status, nonce if signed); update last_used_at.
- **Remediation**: On leak, revoke key; rotate for overlap; grep logs.

---

## 7. Alternatives to IP Filtering
- **Per-Key CIDR**: `allowed_cidrs` for flexibility; empty = no check.
- **CORS**: `allowed_origins` for browser APIs (discourage raw key exposure).
- **mTLS**: Optional system-wide for internal use.
- **No Mandatory IP**: Default to no restriction; add CIDRs as needed.

---

## 8. Rate Limiting and Quotas
- **Per-Minute and Per-Day**: Track counts per key.
- **Storage**: DB table for low-traffic; prefer Redis.
- **Enforcement** (Sketch in requireApiKey):
  ```php
  if ($limit = $key->getRateLimitMin()) {
      // Check api_rate_limit for key_id, 'min', floor(now/60)
      if (count > $limit) return $this->exerr(429, 'Minute limit exceeded');
      // Atomic increment
  }
  ```

---

## 9. Database Schema Changes
```sql
-- Extend %TABLE_PREFIX%api_key
ALTER TABLE %TABLE_PREFIX%api_key
  ADD COLUMN key_id VARCHAR(64) NULL UNIQUE AFTER id,
  ADD COLUMN secret_hash VARCHAR(255) NULL AFTER key_id,
  ADD COLUMN name VARCHAR(128) NULL AFTER secret_hash,
  ADD COLUMN owner_type ENUM('integration','user','system') NOT NULL DEFAULT 'integration' AFTER name,
  ADD COLUMN owner_id INT(10) UNSIGNED NULL AFTER owner_type,
  ADD COLUMN scopes VARCHAR(255) NOT NULL DEFAULT 'tickets:create,cron:exec' AFTER owner_id,
  ADD COLUMN expires_at DATETIME NULL AFTER scopes,
  ADD COLUMN revoked_at DATETIME NULL AFTER expires_at,
  ADD COLUMN last_used_at DATETIME NULL AFTER revoked_at,
  ADD COLUMN allowed_cidrs TEXT NULL AFTER last_used_at,
  ADD COLUMN allowed_origins TEXT NULL AFTER allowed_cidrs,
  ADD COLUMN rate_limit_min INT UNSIGNED NULL AFTER allowed_origins,
  ADD COLUMN rate_limit_day INT UNSIGNED NULL AFTER rate_limit_min;

-- New table for HMAC nonce deduplication
CREATE TABLE %TABLE_PREFIX%api_nonce (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  key_id VARCHAR(64) NOT NULL,
  nonce VARCHAR(128) NOT NULL,
  created DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY key_nonce (key_id, nonce)
) DEFAULT CHARSET=utf8;

-- Optional: Multiple secrets per key for rotation
CREATE TABLE %TABLE_PREFIX%api_key_secret (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  key_id VARCHAR(64) NOT NULL,
  secret_hash VARCHAR(255) NOT NULL,
  created DATETIME NOT NULL,
  disabled_at DATETIME NULL,
  PRIMARY KEY (id),
  KEY key_id_idx (key_id)
) DEFAULT CHARSET=utf8;

-- Optional: Rate limit tracking
CREATE TABLE %TABLE_PREFIX%api_rate_limit (
  key_id VARCHAR(64) NOT NULL,
  bucket ENUM('min','day') NOT NULL,
  period_start DATETIME NOT NULL,
  count INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (key_id, bucket, period_start)
) DEFAULT CHARSET=utf8;
```

---

## 10. Backward Compatibility and Migration
- **Flags**:
  - `api.legacy_enabled = true`: Accept old headers.
  - `api.legacy_ignore_ip = true`: Skip IP equality for legacy keys.
- **Migration Tool** (script or upgrade patch):
  - For each legacy apikey, generate key_id/secret_hash, map ipaddr to allowed_cidrs if present, set scopes from flags.
  - Update UI to show warning for legacy keys.
- **Dual-Stack**: Support both in Controllers; log deprecation notices.
- **EOL**: Set `api.legacy_eol_date`; disable thereafter.

---

## 11. Implementation Steps
1. Add schema via upgrader patch.
2. Extend class.api.php with new methods (lookupByKeyId, hasScope, etc.).
3. Update ApiController::requireApiKey for new logic.
4. Add HMAC verification.
5. Update UI (apikeys.php) for new fields.
6. Create migration script.
7. Update docs.

---

## 12. Security Considerations
- HTTPS mandatory.
- Hash_equals for signature checks.
- Rotate keys regularly.
- Audit logs; avoid displaying secrets.
- For CIP (customer initated payments), ensure PCI compliance.

---

## 13. Operational Playbooks
- **Leak Response**: Identify via prefix/last4; revoke; notify stakeholders.
- **Misuse Detection**: Monitor rate limits; review audit logs.
- **Forensics**: Use last_used_at, allowed_cidrs mismatches.

---

## Appendix: Code Snippets
See embedded examples in [Authentication Schemes](#4-authentication-schemes) and [Database Schema](#9-database-schema-changes).

This document is a living guide; update with implementation feedback.
