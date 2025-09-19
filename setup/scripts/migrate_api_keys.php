<?php
/**
 * API Keys Migration Script
 *
 * This script migrates existing legacy API keys to the new format.
 * Run this after applying the schema patch.
 */

require_once('../bootstrap.php');

echo "osTicket API Keys Migration\n";
echo "==========================\n";

// Check if table has new columns
$sql = 'DESCRIBE %TABLE_PREFIX%api_key';
if(!($res = db_query($sql) && db_num_rows($res))) {
    die("Error: api_key table not found or not accessible.\n");
}

$columns = [];
while ($row = db_fetch_row($res)) {
    $columns[] = $row[0];
}

// Check if migration already done
if (in_array('key_id', $columns) && !in_array('last4', $columns)) {
    die("Error: Schema not updated. Please apply the patch first.\n");
}

// Proceed with migration
echo "Migrating existing API keys...\n";

$sql = 'SELECT id, ipaddr, can_create_tickets, can_exec_cron, notes FROM %TABLE_PREFIX%api_key';
if(!($res = db_query($sql))) {
    die("Error: Unable to select existing keys.\n");
}

$migrated = 0;
while ($row = db_fetch_array($res)) {
    // Skip if already migrated (has key_id)
    $checkSql = 'SELECT key_id FROM %TABLE_PREFIX%api_key WHERE id='.db_input($row['id']);
    if (!($checkRes = db_query($checkSql))) continue;
    $exists = db_fetch_row($checkRes);
    if ($exists[0]) {
        echo "Skipping ID {$row['id']}: Already migrated.\n";
        continue;
    }

    // Generate new key_id and secret
    $keyId = 'ak_' . bin2hex(random_bytes(12));
    $secret = bin2hex(random_bytes(20));
    $secretHash = password_hash($secret, PASSWORD_DEFAULT);
    $last4 = substr($secret, -4);
    $ownerType = 'integration';
    $ownerId = null; // No owner mapping available
    $scopes = '';
    if ($row['can_create_tickets']) $scopes .= 'tickets:create,';
    if ($row['can_exec_cron']) $scopes .= 'cron:exec,';
    if (empty($scopes)) $scopes = 'tickets:create,cron:exec'; // Default
    $scopes = rtrim($scopes, ',');

    // Set allowed_cidrs from ipaddr if present
    $allowedCidrs = empty($row['ipaddr']) ? null : $row['ipaddr'];

    // Update the record
    $updateSql = 'UPDATE %TABLE_PREFIX%api_key '
        . 'SET key_id='.db_input($keyId).', '
        . 'secret_hash='.db_input($secretHash).', '
        . 'name='.db_input('Migrated Key').', '
        . 'owner_type='.db_input($ownerType).', '
        . 'scopes='.db_input($scopes).', '
        . 'allowed_cidrs='.db_input($allowedCidrs).' '
        . 'WHERE id='.db_input($row['id']);

    if (db_query($updateSql)) {
        echo "Migrated ID {$row['id']}: New key_id {$keyId}, secret last4: {$last4}\n";
        echo "NOTE: Secret shown once here: {$secret}\n";
        echo "IMPORTANT: Save the secret securely; it will not be displayed again!\n";
        $migrated++;
    } else {
        echo "Error migrating ID {$row['id']}\n";
    }
}

echo "\nMigration completed: $migrated keys migrated.\n";
echo "A summary of new secrets has been printed above.\n";
echo "It is critical to securely store these secrets as they cannot be recovered.\n";
?>
