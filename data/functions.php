<?php
// functions.php
require_once __DIR__ . '/config.php';
@ini_set('log_errors', '1');
@ini_set('error_log', DATA_DIR . '/php_errors.log');

function ensure_schema(PDO $pdo){
    $pdo->exec('PRAGMA foreign_keys = ON');

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','user')),
            upload_limit_bytes INTEGER DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            saved_name TEXT NOT NULL UNIQUE,
            original_name TEXT NOT NULL,
            mime TEXT,
            size INTEGER,
            views INTEGER DEFAULT 0,
            downloads INTEGER DEFAULT 0,
            uploaded_ip TEXT,
            uploaded_via TEXT,
            last_viewed_at DATETIME,
            last_downloaded_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ");

    $hasEventsTable = (bool)$pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='file_events'")->fetchColumn();
    if (!$hasEventsTable) {
        $pdo->exec("
            CREATE TABLE file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                saved_name TEXT,
                original_name TEXT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE SET NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        ");
    } else {
        $eventsInfo = $pdo->query("PRAGMA table_info('file_events')")->fetchAll(PDO::FETCH_ASSOC) ?: [];
        $eventsCols = array_column($eventsInfo, 'name');
        $needRebuild = false;
        foreach ($eventsInfo as $col) {
            if ($col['name'] === 'file_id' && (int)$col['notnull'] === 1) {
                $needRebuild = true;
            }
        }
        if (!in_array('saved_name', $eventsCols, true) || !in_array('original_name', $eventsCols, true)) {
            $needRebuild = true;
        }
        $fkInfo = $pdo->query("PRAGMA foreign_key_list('file_events')")->fetchAll(PDO::FETCH_ASSOC) ?: [];
        foreach ($fkInfo as $fk) {
            if ($fk['table'] === 'files' && strtoupper($fk['on_delete']) !== 'SET NULL') {
                $needRebuild = true;
            }
        }
        if ($needRebuild) {
            $pdo->exec("
                CREATE TABLE file_events__new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER,
                    saved_name TEXT,
                    original_name TEXT,
                    user_id INTEGER,
                    event_type TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE SET NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
                )
            ");
            $pdo->exec("
                INSERT INTO file_events__new (id, file_id, user_id, event_type, ip_address, user_agent, created_at)
                SELECT id, file_id, user_id, event_type, ip_address, user_agent, created_at FROM file_events
            ");
            $pdo->exec("DROP TABLE file_events");
            $pdo->exec("ALTER TABLE file_events__new RENAME TO file_events");
        } else {
            if (!in_array('saved_name', $eventsCols, true)) {
                $pdo->exec("ALTER TABLE file_events ADD COLUMN saved_name TEXT");
            }
            if (!in_array('original_name', $eventsCols, true)) {
                $pdo->exec("ALTER TABLE file_events ADD COLUMN original_name TEXT");
            }
        }
    }

    $cols = [];
    $stmt = $pdo->query("PRAGMA table_info('users')");
    $cols = $stmt ? array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'name') : [];
    if (!in_array('upload_limit_bytes', $cols, true)) {
        $pdo->exec("ALTER TABLE users ADD COLUMN upload_limit_bytes INTEGER DEFAULT NULL");
    }

    $stmt = $pdo->query("PRAGMA table_info('files')");
    $fileInfo = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
    $fileCols = $fileInfo ? array_column($fileInfo, 'name') : [];
    $alterStatements = [
        'uploaded_ip' => "ALTER TABLE files ADD COLUMN uploaded_ip TEXT",
        'uploaded_via' => "ALTER TABLE files ADD COLUMN uploaded_via TEXT",
        'last_viewed_at' => "ALTER TABLE files ADD COLUMN last_viewed_at DATETIME",
        'last_downloaded_at' => "ALTER TABLE files ADD COLUMN last_downloaded_at DATETIME",
        'owner_snapshot' => "ALTER TABLE files ADD COLUMN owner_snapshot TEXT",
        'allow_bot_views' => "ALTER TABLE files ADD COLUMN allow_bot_views INTEGER DEFAULT 0",
        'view_cooldown_seconds' => "ALTER TABLE files ADD COLUMN view_cooldown_seconds INTEGER DEFAULT NULL"
    ];
    foreach ($alterStatements as $name => $sql) {
        if (!in_array($name, $fileCols, true)) {
            $pdo->exec($sql);
        }
    }
    $defaultOwner = DEFAULT_FILE_OWNER ?? 'owner';
    $stmt = $pdo->prepare("
        UPDATE files
        SET owner_snapshot = COALESCE(
            (SELECT username FROM users WHERE users.id = files.user_id),
            :fallback
        )
        WHERE owner_snapshot IS NULL
    ");
    $stmt->execute([':fallback' => $defaultOwner]);

    $filesFk = $pdo->query("PRAGMA foreign_key_list('files')")->fetchAll(PDO::FETCH_ASSOC) ?: [];
    $needFilesRebuild = false;
    foreach ($filesFk as $fk) {
        if ($fk['table'] === 'users' && strtoupper($fk['on_delete']) !== 'SET NULL') {
            $needFilesRebuild = true;
        }
    }
    if ($needFilesRebuild) {
        $pdo->exec("
            CREATE TABLE files__new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                saved_name TEXT NOT NULL UNIQUE,
                original_name TEXT NOT NULL,
                mime TEXT,
                size INTEGER,
                views INTEGER DEFAULT 0,
                downloads INTEGER DEFAULT 0,
                uploaded_ip TEXT,
                uploaded_via TEXT,
                last_viewed_at DATETIME,
                last_downloaded_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                owner_snapshot TEXT,
                allow_bot_views INTEGER DEFAULT 0,
                view_cooldown_seconds INTEGER DEFAULT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        ");
        $pdo->exec("
            INSERT INTO files__new (id, user_id, saved_name, original_name, mime, size, views, downloads, uploaded_ip, uploaded_via, last_viewed_at, last_downloaded_at, created_at, owner_snapshot, allow_bot_views, view_cooldown_seconds)
            SELECT id, user_id, saved_name, original_name, mime, size, views, downloads, uploaded_ip, uploaded_via, last_viewed_at, last_downloaded_at, created_at, owner_snapshot, COALESCE(allow_bot_views,0), view_cooldown_seconds
            FROM files
        ");
        $pdo->exec("DROP TABLE files");
        $pdo->exec("ALTER TABLE files__new RENAME TO files");
    }

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS file_event_archive (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            saved_name TEXT,
            original_name TEXT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            deleted_at DATETIME
        )
    ");

    $archiveCols = $pdo->query("PRAGMA table_info('file_event_archive')")->fetchAll(PDO::FETCH_ASSOC) ?: [];
    $archiveColNames = array_column($archiveCols, 'name');
    if (!in_array('deleted_at', $archiveColNames, true)) {
        $pdo->exec("ALTER TABLE file_event_archive ADD COLUMN deleted_at DATETIME");
    }

    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_file_events_file ON file_events(file_id, event_type, created_at)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_file_event_archive_file ON file_event_archive(file_id, event_type, created_at)");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS bot_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");

    $count = (int)$pdo->query("SELECT COUNT(*) FROM bot_patterns")->fetchColumn();
    if ($count === 0) {
        $defaults = [
            'bot',
            'crawler',
            'spider',
            'yandex',
            'googlebot',
            'bingbot',
            'duckduckbot',
            'baiduspider',
            'discordbot',
            'telegrambot',
            'slackbot',
            'facebookexternalhit',
            'whatsapp',
            'python-requests',
            'curl',
            'wget'
        ];
        $stmt = $pdo->prepare("INSERT INTO bot_patterns (pattern) VALUES (?)");
        foreach ($defaults as $pat) {
            $stmt->execute([$pat]);
        }
    }

    $pdo->exec("UPDATE files SET allow_bot_views = COALESCE(allow_bot_views,0)");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ");
}

function get_pdo(){
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO('sqlite:' . DB_FILE);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        ensure_schema($pdo);
    }
    return $pdo;
}

function record_file_event(PDO $pdo, int $fileId, ?int $userId, string $eventType, ?string $ip = null, ?string $userAgent = null, ?string $savedName = null, ?string $originalName = null): void {
    $stmt = $pdo->prepare("
        INSERT INTO file_events (file_id, user_id, event_type, ip_address, user_agent, saved_name, original_name)
        VALUES (:file_id, :user_id, :event_type, :ip, :ua, :saved, :orig)
    ");
    $params = [
        ':file_id' => $fileId,
        ':user_id' => $userId,
        ':event_type' => $eventType,
        ':ip' => $ip,
        ':ua' => $userAgent,
        ':saved' => $savedName,
        ':orig' => $originalName,
    ];
    $stmt->execute($params);

    $archive = $pdo->prepare("
        INSERT INTO file_event_archive (file_id, user_id, event_type, ip_address, user_agent, saved_name, original_name)
        VALUES (:file_id, :user_id, :event_type, :ip, :ua, :saved, :orig)
    ");
    $archive->execute($params);
}

function should_count_event(PDO $pdo, int $fileId, string $eventType, ?string $ip = null, ?string $userAgent = null, int $windowSeconds = 60): bool {
    if ($windowSeconds <= 0) {
        return true;
    }
    $clauses = ['file_id = ?', 'event_type = ?'];
    $params = [$fileId, $eventType];
    if ($ip) {
        $clauses[] = 'ip_address = ?';
        $params[] = $ip;
    }
    if ($userAgent) {
        $clauses[] = 'user_agent = ?';
        $params[] = $userAgent;
    }
    $clauses[] = "created_at >= datetime('now', ?)";
    $params[] = sprintf('-%d seconds', max(1, $windowSeconds));
    $sql = 'SELECT 1 FROM file_events WHERE ' . implode(' AND ', $clauses) . ' LIMIT 1';
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return !$stmt->fetchColumn();
}

function user_storage_usage(PDO $pdo, int $userId): array {
    $stmt = $pdo->prepare("SELECT COUNT(*) AS files, COALESCE(SUM(size),0) AS bytes FROM files WHERE user_id = ?");
    $stmt->execute([$userId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['files'=>0,'bytes'=>0];
    return ['files' => (int)$row['files'], 'bytes' => (int)$row['bytes']];
}

function current_user(PDO $pdo = null): ?array {
    $id = current_user_id();
    if (!$id) {
        return null;
    }
    if ($pdo === null) {
        $pdo = get_pdo();
    }
    $stmt = $pdo->prepare("SELECT id, username, role, upload_limit_bytes FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

function default_owner_id(PDO $pdo): ?int {
    static $cache = null;
    if ($cache !== null) return $cache;
    $username = defined('DEFAULT_FILE_OWNER') ? DEFAULT_FILE_OWNER : null;
    if (!$username) return null;
    $stmt = $pdo->prepare('SELECT id FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $cache = $stmt->fetchColumn();
    return $cache ? (int)$cache : null;
}

function ensure_default_owner(PDO $pdo): void {
    $ownerId = default_owner_id($pdo);
    if (!$ownerId) return;
    $pdo->prepare('UPDATE files SET user_id = :uid WHERE user_id IS NULL')->execute([':uid' => $ownerId]);
}

function is_ip_blocked(string $ip): bool {
    static $blocked = [];
    if ($ip === '') return false;
    if (array_key_exists($ip, $blocked)) return $blocked[$ip];
    $pdo = get_pdo();
    $stmt = $pdo->prepare('SELECT 1 FROM blocked_ips WHERE ip = ? LIMIT 1');
    $stmt->execute([$ip]);
    $blocked[$ip] = (bool)$stmt->fetchColumn();
    return $blocked[$ip];
}

function client_ip(): ?string {
    static $cached = null;
    if ($cached !== null) return $cached;
    $keys = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'REMOTE_ADDR'
    ];
    foreach ($keys as $key) {
        $value = $_SERVER[$key] ?? '';
        if (!$value) continue;
        if (strpos($value, ',') !== false) {
            $value = explode(',', $value)[0];
        }
        $value = trim($value);
        if ($value !== '' && filter_var($value, FILTER_VALIDATE_IP)) {
            return $cached = $value;
        }
    }
    return $cached = null;
}

function get_bot_patterns(bool $force = false): array {
    static $patterns = null;
    if ($force) {
        $patterns = null;
    }
    if ($patterns !== null) {
        return $patterns;
    }
    $pdo = get_pdo();
    $stmt = $pdo->query('SELECT pattern FROM bot_patterns ORDER BY pattern');
    $rows = $stmt ? $stmt->fetchAll(PDO::FETCH_COLUMN) : [];
    $patterns = array_map('strtolower', array_filter($rows, fn($p) => $p !== null && $p !== ''));
    return $patterns;
}

function refresh_bot_patterns_cache(): void {
    get_bot_patterns(true);
}

function is_known_bot(?string $userAgent): bool {
    if (!$userAgent) return false;
    $ua = strtolower($userAgent);
    foreach (get_bot_patterns() as $needle) {
        if ($needle !== '' && str_contains($ua, $needle)) {
            return true;
        }
    }
    return false;
}

function get_setting(string $key, $default = null) {
    static $cache = [];
    if (array_key_exists($key, $cache)) return $cache[$key];
    $pdo = get_pdo();
    $stmt = $pdo->prepare('SELECT value FROM app_settings WHERE key = ?');
    $stmt->execute([$key]);
    $value = $stmt->fetchColumn();
    if ($value === false) return $cache[$key] = $default;
    $decoded = json_decode($value, true);
    return $cache[$key] = ($decoded === null && $value !== 'null') ? $value : $decoded;
}

function set_setting(string $key, $value): void {
    $pdo = get_pdo();
    $stored = is_scalar($value) ? (string)$value : json_encode($value);
    $stmt = $pdo->prepare('INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
    $stmt->execute([$key, $stored]);
}

function block_background_url(): string {
    $value = get_setting('block_bg', '');
    if (is_array($value)) {
        $value = '';
    }
    $value = trim((string)$value);
    if ($value === '') {
        return rtrim(BASE_URL, '/') . '/public/block-default.png';
    }
    return $value;
}

function not_found_background_url(): string {
    $value = get_setting('not_found_bg', '');
    if (is_array($value)) {
        $value = '';
    }
    $value = trim((string)$value);
    if ($value === '') {
        return rtrim(BASE_URL, '/') . '/public/404-default.png';
    }
    return $value;
}

function render_custom_page(int $code, string $message, ?string $background = null, ?string $title = null, array $options = []): void {
    http_response_code($code);
    $errorCode = $code;
    $errorMessage = $message;
    $errorTitle = $title ?? match (true) {
        $code === 404 => 'Not Found',
        $code === 403, $code === 401 => 'Access Denied',
        default => 'Something went wrong',
    };
    $backgroundUrl = $background ?? ($code === 404 ? not_found_background_url() : block_background_url());
    $ctaUrl = $options['cta_url'] ?? rtrim(BASE_URL, '/') . '/';
    $ctaLabel = $options['cta_label'] ?? 'Go back';
    $extraDetails = $options['extra'] ?? [];
    $suppressText = !empty($options['suppress_text']);
    require __DIR__ . '/block_page.php';
    exit;
}

function render_block_page(string $reason = 'Access blocked'): void {
    render_custom_page(403, $reason, block_background_url(), 'Access Blocked', ['suppress_text' => true]);
}

function render_not_found_page(string $message = 'The requested resource could not be found'): void {
    render_custom_page(404, $message, not_found_background_url(), 'Not Found', ['suppress_text' => true]);
}

// auth
function is_logged(){ return !empty($_SESSION['user_id']); }
function current_user_id(){ return $_SESSION['user_id'] ?? null; }
function current_user_role(){ return $_SESSION['role'] ?? null; }
function require_login(){
    if(!is_logged()){
        if (is_json_expected()) {
            http_response_code(401);
            json_resp(['ok'=>false,'error'=>'auth_required']);
        }
        header('Location: login.php');
        exit;
    }
}
function require_admin(){
    if(!is_logged() || current_user_role() !== 'admin'){
        if (is_json_expected()) {
            http_response_code(403);
            json_resp(['ok'=>false,'error'=>'admin_required']);
        }
        http_response_code(403);
        echo "Forbidden";
        exit;
    }
}
function require_api_login(PDO $pdo): array {
    if (!is_logged()) {
        http_response_code(401);
        json_resp(['ok'=>false,'error'=>'auth_required']);
    }
    $user = current_user($pdo);
    if (!$user) {
        session_destroy();
        http_response_code(401);
        json_resp(['ok'=>false,'error'=>'auth_required']);
    }
    return $user;
}
function require_api_admin(PDO $pdo): array {
    $user = require_api_login($pdo);
    if (($user['role'] ?? '') !== 'admin') {
        http_response_code(403);
        json_resp(['ok'=>false,'error'=>'admin_required']);
    }
    return $user;
}
function is_json_expected(): bool {
    if (!empty($_SERVER['HTTP_ACCEPT']) && str_contains($_SERVER['HTTP_ACCEPT'], 'application/json')) {
        return true;
    }
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        return true;
    }
    if ((($_SERVER['HTTP_CONTENT_TYPE'] ?? '') === 'application/json') || str_contains($_SERVER['HTTP_CONTENT_TYPE'] ?? '', 'application/json')) {
        return true;
    }
    if (($_GET['format'] ?? '') === 'json' || ($_POST['format'] ?? '') === 'json') {
        return true;
    }
    return false;
}

// CSRF tokens
function csrf_token(){
    if(empty($_SESSION['_csrf'])) $_SESSION['_csrf'] = bin2hex(random_bytes(16));
    return hash_hmac('sha256', $_SESSION['_csrf'], APP_SECRET);
}
function csrf_check($token){
    return hash_equals(csrf_token(), $token);
}

// log_event
function log_event($msg){
    $line = '['.date('Y-m-d H:i:s').'] '.$msg.PHP_EOL;
    @file_put_contents(LOG_FILE, $line, FILE_APPEND | LOCK_EX);
}

// file name sanitization and safe save name
function sanitize_filename($name){
    $name = basename($name);
    // заменяем все проблемные символы на "_"
    $name = preg_replace('/[^\p{L}\p{N}\-_.() ]+/u', '_', $name);
    $name = mb_substr($name, 0, 200);
    return $name;
}

// исправленная генерация безопасного уникального имени
function generate_saved_name($orig){
    $safe = sanitize_filename($orig);
    $ext = pathinfo($safe, PATHINFO_EXTENSION);
    $base = pathinfo($safe, PATHINFO_FILENAME);
    $uniq = substr(bin2hex(random_bytes(6)),0,12); // короткий хеш
    return $base . '_' . $uniq . ($ext ? '.' . $ext : '');
}

// helper: respond json
function json_resp($data){ header('Content-Type: application/json'); echo json_encode($data); exit; }

function public_file_path(string $savedName): string {
    return rtrim(PUBLIC_DIR, '/') . '/' . $savedName;
}

function public_file_url(string $savedName): string {
    $base = rtrim(BASE_URL, '/');
    return $base . '/public/' . rawurlencode($savedName);
}

function ensure_public_file(string $savedName): bool {
    $source = rtrim(UPLOAD_DIR, '/') . '/' . $savedName;
    $dest = public_file_path($savedName);
    if (!is_file($source)) {
        return false;
    }
    if (is_link($dest) || is_file($dest)) {
        @unlink($dest);
    }
    if (@link($source, $dest)) {
        return true;
    }
    if (@symlink($source, $dest)) {
        return true;
    }
    if (@copy($source, $dest)) {
        @chmod($dest, 0644);
        return true;
    }
    return false;
}

function radio_config_path(): string {
    return __DIR__ . '/../radio/config.json';
}

function radio_load_config(bool $force = false): array {
    static $cache = null;
    if ($force) {
        $cache = null;
    }
    if ($cache !== null) {
        return $cache;
    }
    $defaults = [
        'chat_enabled' => true,
        'requests_enabled' => true,
        'show_requests_on_main' => true,
        'avatar' => 'assets/avatar.png',
        'favicon' => 'assets/favicon.png',
        'chat_ip_restriction' => false,
        'autodj_enabled' => true,
        'bans_enabled' => true,
        'requests_queue_only' => false,
        'allowed_chat_ips' => []
    ];
    $path = radio_config_path();
    if (!is_file($path)) {
        return $cache = $defaults;
    }
    $raw = @file_get_contents($path);
    if ($raw === false) {
        return $cache = $defaults;
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return $cache = $defaults;
    }
    $merged = array_merge($defaults, $data);
    if (!is_array($merged['allowed_chat_ips'])) {
        $merged['allowed_chat_ips'] = [];
    }
    return $cache = $merged;
}

function radio_save_config(array $config): bool {
    $path = radio_config_path();
    $encoded = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($encoded === false) {
        return false;
    }
    $result = @file_put_contents($path, $encoded);
    if ($result === false) {
        return false;
    }
    radio_load_config(true);
    return true;
}

function get_radio_pdo(): PDO {
    static $radioPdo = null;
    if ($radioPdo instanceof PDO) {
        return $radioPdo;
    }
    $connector = __DIR__ . '/../radio/utils/db.php';
    if (!is_file($connector)) {
        throw new RuntimeException('Radio database connector not found');
    }
    require_once $connector;
    $radioPdo = db_connect();
    $radioPdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $radioPdo;
}

function radio_table_has_column(PDO $pdo, string $table, string $column): bool {
    static $cache = [];
    $key = strtolower($table) . ':' . strtolower($column);
    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }
    $stmt = $pdo->prepare("SHOW COLUMNS FROM `$table` LIKE ?");
    $stmt->execute([$column]);
    return $cache[$key] = (bool)$stmt->fetch();
}

function radio_index_exists(PDO $pdo, string $table, string $index): bool {
    static $cache = [];
    $key = strtolower($table) . ':' . strtolower($index);
    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }
    $stmt = $pdo->prepare("SHOW INDEX FROM `$table` WHERE Key_name = ?");
    $stmt->execute([$index]);
    return $cache[$key] = (bool)$stmt->fetch();
}

function radio_ensure_schema(PDO $pdo): void {
    static $done = false;
    if ($done) {
        return;
    }
    if (!radio_table_has_column($pdo, 'users', 'uploader_user_id')) {
        $pdo->exec("ALTER TABLE users ADD COLUMN uploader_user_id INT NULL UNIQUE");
    }
    if (!radio_table_has_column($pdo, 'orders', 'uploader_user_id')) {
        $pdo->exec("ALTER TABLE orders ADD COLUMN uploader_user_id INT NULL");
    }
    if (!radio_index_exists($pdo, 'orders', 'idx_orders_uploader_user')) {
        $pdo->exec("CREATE INDEX idx_orders_uploader_user ON orders (uploader_user_id)");
    }
    if (!radio_table_has_column($pdo, 'orders', 'source_app')) {
        $pdo->exec("ALTER TABLE orders ADD COLUMN source_app VARCHAR(64) NULL");
    }
    if (!radio_table_has_column($pdo, 'track_history', 'cover_url')) {
        $pdo->exec("ALTER TABLE track_history ADD COLUMN cover_url VARCHAR(255) NULL");
    }
    if (!radio_table_has_column($pdo, 'track_history', 'source')) {
        $pdo->exec("ALTER TABLE track_history ADD COLUMN source VARCHAR(32) NULL");
    }
    if (!radio_table_has_column($pdo, 'track_history', 'artist')) {
        $pdo->exec("ALTER TABLE track_history ADD COLUMN artist VARCHAR(255) NULL");
    }
    if (!radio_table_has_column($pdo, 'track_history', 'track_title') && radio_table_has_column($pdo, 'track_history', 'track')) {
        $pdo->exec("ALTER TABLE track_history ADD COLUMN track_title VARCHAR(255) NULL");
        $pdo->exec("UPDATE track_history SET track_title = track WHERE track_title IS NULL");
    }
    $done = true;
}

function radio_unique_nickname(PDO $pdo, string $desired, ?int $ignoreId = null): string {
    $desired = trim($desired);
    if ($desired === '') {
        $desired = 'Listener';
    }
    $desired = mb_substr($desired, 0, 48);
    $base = $desired;
    $suffix = 0;
    while (true) {
        $candidate = $suffix === 0 ? $base : ($base . '#' . $suffix);
        $stmt = $pdo->prepare('SELECT id FROM users WHERE nickname = ?' . ($ignoreId ? ' AND id <> ?' : '') . ' LIMIT 1');
        $stmt->execute($ignoreId ? [$candidate, $ignoreId] : [$candidate]);
        if (!$stmt->fetchColumn()) {
            return $candidate;
        }
        $suffix++;
    }
}

function radio_sync_user(PDO $pdo, array $uploaderUser, ?string $preferredNick = null): array {
    radio_ensure_schema($pdo);
    $uploaderId = (int)$uploaderUser['id'];
    $isAdmin = ($uploaderUser['role'] ?? '') === 'admin';
    $preferredNick = trim((string)$preferredNick);
    if ($preferredNick === '') {
        $preferredNick = (string)$uploaderUser['username'];
    }
    if ($preferredNick === '') {
        $preferredNick = 'Listener';
    }
    $preferredNick = mb_substr($preferredNick, 0, 48);

    $stmt = $pdo->prepare('SELECT id, nickname, is_admin FROM users WHERE uploader_user_id = ? LIMIT 1');
    $stmt->execute([$uploaderId]);
    $existing = $stmt->fetch(PDO::FETCH_ASSOC);
    $ip = client_ip() ?? '0.0.0.0';

    if ($existing) {
        $nickname = radio_unique_nickname($pdo, $preferredNick, (int)$existing['id']);
        if ($nickname !== $existing['nickname'] || (int)$existing['is_admin'] !== ($isAdmin ? 1 : 0)) {
            $update = $pdo->prepare('UPDATE users SET nickname = ?, is_admin = ?, nick_verified = 1 WHERE id = ?');
            $update->execute([$nickname, $isAdmin ? 1 : 0, $existing['id']]);
        }
        return [
            'id' => (int)$existing['id'],
            'nickname' => $nickname,
            'is_admin' => (bool)$isAdmin
        ];
    }

    $nickname = radio_unique_nickname($pdo, $preferredNick);
    $insert = $pdo->prepare('INSERT INTO users (ip_address, nickname, nick_verified, is_admin, uploader_user_id) VALUES (?, ?, 1, ?, ?)');
    $insert->execute([$ip ?: '0.0.0.0', $nickname, $isAdmin ? 1 : 0, $uploaderId]);
    $id = (int)$pdo->lastInsertId();
    return ['id' => $id, 'nickname' => $nickname, 'is_admin' => (bool)$isAdmin];
}

function radio_is_banned(PDO $pdo, string $ip, string $type): bool {
    $ip = trim($ip);
    if ($ip === '') {
        return false;
    }
    $stmt = $pdo->prepare("SELECT 1 FROM bans WHERE ip_address = :ip AND type = :type AND (until IS NULL OR until > NOW()) LIMIT 1");
    $stmt->execute([':ip' => $ip, ':type' => $type]);
    return (bool)$stmt->fetchColumn();
}

function radio_is_ip_allowed(PDO $pdo, string $ip): bool {
    $config = radio_load_config();
    if (empty($config['chat_ip_restriction'])) {
        return true;
    }
    if (in_array($ip, $config['allowed_chat_ips'], true)) {
        return true;
    }
    $stmt = $pdo->prepare('SELECT 1 FROM allowed_ips WHERE ip_address = ? LIMIT 1');
    $stmt->execute([$ip]);
    return (bool)$stmt->fetchColumn();
}

function radio_env(): array {
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    $envFile = __DIR__ . '/../radio/.env';
    if (!is_file($envFile)) {
        return $cache = [];
    }
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $env = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        if (!str_contains($line, '=')) {
            continue;
        }
        [$key, $value] = explode('=', $line, 2);
        $env[trim($key)] = trim($value);
    }
    return $cache = $env;
}

function radio_send_request_mail(array $payload): bool {
    $env = radio_env();
    $host = $env['SMTP_HOST'] ?? null;
    $user = $env['SMTP_USER'] ?? null;
    $pass = $env['SMTP_PASS'] ?? null;
    $port = $env['SMTP_PORT'] ?? null;
    $from = $env['MAIL_FROM'] ?? null;
    $to   = $env['MAIL_TO'] ?? null;
    if (!$host || !$user || !$pass || !$port || !$from || !$to) {
        return false;
    }
    if (!class_exists(\PHPMailer\PHPMailer\PHPMailer::class)) {
        require_once __DIR__ . '/../radio/phpmailer/src/PHPMailer.php';
        require_once __DIR__ . '/../radio/phpmailer/src/SMTP.php';
        require_once __DIR__ . '/../radio/phpmailer/src/Exception.php';
    }
    $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host = $host;
        $mail->SMTPAuth = true;
        $mail->Username = $user;
        $mail->Password = $pass;
        $mail->SMTPSecure = $env['SMTP_SECURE'] ?? 'ssl';
        $mail->Port = (int)$port;
        $mail->CharSet = 'UTF-8';
        $mail->setFrom($from);
        $mail->addAddress($to);
        $mail->Subject = "Новая заявка от {$payload['name']}";
        $bodyLines = [
            "Пользователь: {$payload['name']}",
            "Трек: {$payload['track']}",
            "Комментарий: {$payload['comment']}",
            "IP: {$payload['ip']}",
            "Источник: {$payload['source']}",
            "Время отправки: " . date('Y-m-d H:i:s'),
        ];
        $mail->Body = implode("\n", $bodyLines);
        $mail->send();
        return true;
    } catch (Throwable $e) {
        log_event('MAIL_ERROR ' . $e->getMessage());
        return false;
    }
}
