<?php
require_once __DIR__ . '/../functions.php';

if (php_sapi_name() !== 'cli') {
    echo "Run from CLI: php data/tools/assign_owner.php [username]\n";
    exit;
}

$username = $argv[1] ?? 'Tenshi';
$pdo = get_pdo();
$stmt = $pdo->prepare('SELECT id FROM users WHERE username = ?');
$stmt->execute([$username]);
$userId = $stmt->fetchColumn();
if (!$userId) {
    echo "User {$username} not found\n";
    exit(1);
}

$pdo->exec('BEGIN');
$update = $pdo->prepare('UPDATE files SET user_id = ?');
$update->execute([$userId]);
$pdo->exec('COMMIT');

echo "All files now belong to user {$username} (id {$userId}).\n";
