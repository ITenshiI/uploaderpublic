<?php
// init_db.php — создаёт новую БД и добавляет первого администратора
require __DIR__ . '/functions.php';

if (php_sapi_name() !== 'cli') {
    echo "Run from CLI: php init_db.php\n";
    exit;
}

if (file_exists(DB_FILE)) {
    echo "DB already exists at " . DB_FILE . " — aborting (remove file to recreate).\n";
    exit;
}

$pdo = new PDO('sqlite:' . DB_FILE);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
ensure_schema($pdo);

echo "Create first admin user\nUsername: ";
$stdin = trim(fgets(STDIN));
if (!$stdin) { echo "Username required\n"; exit; }

echo "Password: ";
shell_exec('stty -echo');
$pwd = trim(fgets(STDIN));
shell_exec('stty echo');
echo "\n";
if (!$pwd) { echo "Password required\n"; exit; }

$hash = password_hash($pwd, PASSWORD_DEFAULT);
$stmt = $pdo->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')");
$stmt->execute([$stdin, $hash]);

echo "Done. DB created at " . DB_FILE . " and admin user '{$stdin}' added.\n";
