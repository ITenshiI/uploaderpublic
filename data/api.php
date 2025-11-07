<?php
// api.php — основное API приложения (загрузка, список, выдача, админ-действия)
require_once __DIR__ . '/functions.php';
@ini_set('log_errors', '1');
@ini_set('error_log', DATA_DIR . '/php_errors.log');
$pdo = get_pdo();
ensure_default_owner($pdo);

$action = $_REQUEST['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$publicBuild = defined('PUBLIC_BUILD') && PUBLIC_BUILD;

$restrictedPublicActions = ['events','events_recent','blocked_ips','bot_patterns','ip_activity'];
if ($publicBuild && in_array($action, $restrictedPublicActions, true)) {
    fail('Endpoint unavailable', 404);
}
function fail(string $msg, int $code = 400): void {
    http_response_code($code);
    json_resp(['ok' => false, 'error' => $msg]);
}

function read_json_body(): array {
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

if ($action === 'login' && $method === 'POST') {
    $payload = $_POST;
    if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false) {
        $payload = read_json_body();
    }
    $username = trim($payload['username'] ?? '');
    $password = (string)($payload['password'] ?? '');
    if ($username === '' || $password === '') {
        fail('username and password required');
    }
    $stmt = $pdo->prepare('SELECT id, username, password_hash, role FROM users WHERE username = ? LIMIT 1');
    $stmt->execute([$username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || !password_verify($password, $row['password_hash'])) {
        http_response_code(401);
        json_resp(['ok'=>false,'error'=>'invalid_credentials']);
    }
    session_regenerate_id(true);
    $_SESSION['user_id'] = $row['id'];
    $_SESSION['username'] = $row['username'];
    $_SESSION['role'] = $row['role'];
    json_resp([
        'ok'=>true,
        'user'=>[
            'id'=>(int)$row['id'],
            'username'=>$row['username'],
            'role'=>$row['role']
        ]
    ]);
}

if ($action === 'logout') {
    session_destroy();
    json_resp(['ok'=>true]);
}

if ($action === 'profile' && $method === 'GET') {
    $user = require_api_login($pdo);
    json_resp([
        'ok'=>true,
        'user'=>[
            'id'=>(int)$user['id'],
            'username'=>$user['username'],
            'role'=>$user['role'],
        ]
    ]);
}

if ($action === 'upload' && $method === 'POST') {
    $user = require_api_login($pdo);
    if (empty($_FILES)) {
        fail('No files uploaded');
    }

    $filesQueue = [];
    foreach ($_FILES as $entry) {
        if (!isset($entry['name'])) {
            continue;
        }
        if (is_array($entry['name'])) {
            $count = count($entry['name']);
            for ($i = 0; $i < $count; $i++) {
                $name = $entry['name'][$i] ?? '';
                if ($name === '') continue;
                $filesQueue[] = [
                    'name' => $name,
                    'tmp_name' => $entry['tmp_name'][$i] ?? null,
                    'size' => $entry['size'][$i] ?? 0,
                    'error' => $entry['error'][$i] ?? UPLOAD_ERR_NO_FILE,
                ];
            }
        } else {
            if (($entry['name'] ?? '') !== '') {
                $filesQueue[] = [
                    'name' => $entry['name'],
                    'tmp_name' => $entry['tmp_name'] ?? null,
                    'size' => $entry['size'] ?? 0,
                    'error' => $entry['error'] ?? UPLOAD_ERR_NO_FILE,
                ];
            }
        }
    }

    if (!$filesQueue) {
        fail('No files uploaded');
    }

    $results = [];
    $blockedExt = ['php','phtml','phar','htaccess','htpasswd','exe','sh','cgi','pl','bat','cmd','com','js'];

    foreach ($filesQueue as $file) {
        $orig = $file['name'] ?? 'file';
        $size = (int)($file['size'] ?? 0);
        $err  = $file['error'] ?? UPLOAD_ERR_NO_FILE;

        if ($err !== UPLOAD_ERR_OK) {
            $results[] = ['ok'=>false,'name'=>$orig,'error'=>"PHP upload error code $err"];
            continue;
        }

        if ($size <= 0) {
            $results[] = ['ok'=>false,'name'=>$orig,'error'=>"File {$orig} is empty"];
            continue;
        }

        if ($size > MAX_FILE_SIZE) {
            $results[] = ['ok'=>false,'name'=>$orig,'error'=>"File {$orig} exceeds max size"];
            continue;
        }

        $tmp = $file['tmp_name'] ?? null;
        if (!$tmp || !is_uploaded_file($tmp)) {
            $results[] = ['ok'=>false,'name'=>$orig,'error'=>"Temp file missing for {$orig}"];
            continue;
        }

        $ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
        if ($ext && in_array($ext, $blockedExt, true)) {
            $results[] = ['ok'=>false,'name'=>$orig,'error'=>"Extension .{$ext} is not allowed"];
            continue;
        }

        $pdo->beginTransaction();
        if ($user['upload_limit_bytes'] !== null) {
            $stmt = $pdo->prepare("SELECT COALESCE(SUM(size),0) FROM files WHERE user_id = ?");
            $stmt->execute([$user['id']]);
            $usageBytes = (int)$stmt->fetchColumn();
            if ($usageBytes + $size > (int)$user['upload_limit_bytes']) {
                $pdo->rollBack();
                $results[] = ['ok'=>false,'name'=>$orig,'error'=>"Storage limit exceeded"];
                continue;
            }
        }

        $origSafe = sanitize_filename($orig);
        $saved = generate_saved_name($origSafe);
        $dest = UPLOAD_DIR . $saved;

        if (!move_uploaded_file($tmp, $dest)) {
            $pdo->rollBack();
            $results[] = ['ok'=>false,'name'=>$orig,'error'=>"Failed to save {$origSafe}"];
            continue;
        }

        @chmod($dest, 0644);
        $mime = mime_content_type($dest) ?: 'application/octet-stream';

        try {
            $stmt = $pdo->prepare("
                INSERT INTO files (user_id, saved_name, original_name, mime, size, uploaded_ip, uploaded_via, owner_snapshot)
                VALUES (:user_id, :saved_name, :original_name, :mime, :size, :uploaded_ip, :uploaded_via, :owner_snapshot)
            ");
            $stmt->execute([
                ':user_id' => $user['id'],
                ':saved_name' => $saved,
                ':original_name' => $orig,
                ':mime' => $mime,
                ':size' => $size,
                ':uploaded_ip' => client_ip(),
                ':uploaded_via' => $_SERVER['HTTP_USER_AGENT'] ?? 'api',
                ':owner_snapshot' => $user['username'] ?? null,
            ]);
            $id = (int)$pdo->lastInsertId();
            record_file_event(
                $pdo,
                $id,
                (int)$user['id'],
                'upload',
                client_ip(),
                $_SERVER['HTTP_USER_AGENT'] ?? 'api',
                $saved,
                $orig
            );
            $pdo->commit();

            ensure_public_file($saved);

            $results[] = [
                'ok' => true,
                'id' => $id,
                'saved' => $saved,
                'original' => $orig,
                'mime' => $mime,
                'size' => $size,
                'public_url' => public_file_url($saved),
                'download_url' => BASE_URL . 'api.php?action=download&id=' . $id,
                'views' => 0,
                'downloads' => 0,
            ];

            log_event("UPLOAD id={$id} saved={$saved} original={$orig} size={$size} ip=" . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . " mime={$mime} by_user=" . ($user['username'] ?? 'unknown'));
        } catch (Throwable $e) {
            $pdo->rollBack();
            @unlink($dest);
            $results[] = ['ok'=>false,'name'=>$orig,'error'=>"DB error: " . $e->getMessage()];
        }
    }

    json_resp(['ok'=>true,'results'=>$results]);
}

if ($action === 'list' && $method === 'GET') {
    $user = require_api_login($pdo);

    $search = trim($_GET['q'] ?? '');
    $type = trim($_GET['type'] ?? '');

    $where = [];
    $params = [];

    if ($user['role'] !== 'admin') {
        $where[] = 'f.user_id = :uid';
        $params[':uid'] = $user['id'];
    }

    if ($search !== '') {
        $where[] = '(f.original_name LIKE :q OR f.saved_name LIKE :q)';
        $params[':q'] = '%' . $search . '%';
    }

    if ($type !== '') {
        $type = strtolower($type);
        if (in_array($type, ['image','video','audio','text'], true)) {
            if ($type === 'text') {
                $where[] = "(f.mime LIKE 'text/%')";
            } else {
                $where[] = "(f.mime LIKE :typeprefix)";
                $params[':typeprefix'] = $type . '/%';
            }
        }
    }

    $sortKey = $_GET['sort'] ?? 'created_desc';
    $sortMap = [
        'created_desc'   => 'f.created_at DESC',
        'created_asc'    => 'f.created_at ASC',
        'name_asc'       => 'f.original_name COLLATE NOCASE ASC',
        'name_desc'      => 'f.original_name COLLATE NOCASE DESC',
        'size_desc'      => 'f.size DESC',
        'size_asc'       => 'f.size ASC',
        'views_desc'     => 'f.views DESC',
        'views_asc'      => 'f.views ASC',
        'downloads_desc' => 'f.downloads DESC',
        'downloads_asc'  => 'f.downloads ASC',
    ];
    $orderClause = $sortMap[$sortKey] ?? $sortMap['created_desc'];

    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = (int)($_GET['per_page'] ?? 30);
    if ($perPage < 5) $perPage = 5;
    if ($perPage > 200) $perPage = 200;
    $offset = ($page - 1) * $perPage;

    $sqlBase = "FROM files f
            LEFT JOIN users u ON u.id = f.user_id";
    $sqlWhere = $where ? (' WHERE ' . implode(' AND ', $where)) : '';
    $countStmt = $pdo->prepare("SELECT COUNT(*) {$sqlBase} {$sqlWhere}");
    $countStmt->execute($params);
    $total = (int)$countStmt->fetchColumn();

    $sql = "SELECT f.id, f.user_id, f.saved_name, f.original_name, f.mime, f.size,
                   f.views, f.downloads, f.uploaded_ip, f.uploaded_via,
                   f.last_viewed_at, f.last_downloaded_at, f.created_at,
                   f.allow_bot_views, f.view_cooldown_seconds,
                   COALESCE(f.owner_snapshot, u.username) AS owner
            {$sqlBase}
            {$sqlWhere}
            ORDER BY {$orderClause}
            LIMIT :limit OFFSET :offset";

    $stmt = $pdo->prepare($sql);
    foreach ($params as $k => $v) {
        $stmt->bindValue($k, $v);
    }
    $stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $files = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($files as &$f) {
        $f['size'] = (int)$f['size'];
        $f['views'] = (int)$f['views'];
        $f['downloads'] = (int)$f['downloads'];
        $f['allow_bot_views'] = (int)$f['allow_bot_views'];
        $f['view_cooldown_seconds'] = $f['view_cooldown_seconds'] !== null ? (int)$f['view_cooldown_seconds'] : null;
        ensure_public_file($f['saved_name']);
        $f['public_url'] = public_file_url($f['saved_name']);
        $f['download_url'] = BASE_URL . 'api.php?action=download&id=' . $f['id'];
    }
    unset($f);

    json_resp([
        'ok'=>true,
        'files'=>$files,
        'total'=>$total,
        'page'=>$page,
        'per_page'=>$perPage,
        'pages'=> (int)max(1, ceil($total / $perPage))
    ]);
}

if ($action === 'stats' && $method === 'GET') {
    $user = require_api_login($pdo);

    $usage = user_storage_usage($pdo, $user['id']);
    $limitBytes = $user['upload_limit_bytes'] !== null ? (int)$user['upload_limit_bytes'] : null;
    $remaining = $limitBytes !== null ? max(0, $limitBytes - $usage['bytes']) : null;

    $resp = [
        'ok' => true,
        'user' => [
            'id' => (int)$user['id'],
            'username' => $user['username'],
            'role' => $user['role'],
            'upload_limit_bytes' => $limitBytes,
            'usage_bytes' => $usage['bytes'],
            'usage_files' => $usage['files'],
            'remaining_bytes' => $remaining,
        ],
    ];

    if ($user['role'] === 'admin') {
        $stmt = $pdo->query("SELECT COUNT(*) AS files, COALESCE(SUM(size),0) AS bytes FROM files");
        $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['files'=>0,'bytes'=>0];
        $resp['totals'] = [
            'files' => (int)$row['files'],
            'bytes' => (int)$row['bytes'],
        ];
    }

    $diskTotal = @disk_total_space(PROJECT_ROOT) ?: 0;
    $diskFree = @disk_free_space(PROJECT_ROOT) ?: 0;
    $resp['disk'] = [
        'total_bytes' => $diskTotal,
        'free_bytes' => $diskFree,
        'used_bytes' => max(0, $diskTotal - $diskFree),
    ];

    $resp['csrf'] = csrf_token();

    json_resp($resp);
}



if ($action === 'delete' && $method === 'POST') {
    $user = require_api_login($pdo);

    $input = $_POST;
    if (!empty($_SERVER['CONTENT_TYPE']) && stripos($_SERVER['CONTENT_TYPE'], 'application/json') !== false) {
        $input = read_json_body();
    }

    $id = (int)($input['id'] ?? 0);
    $csrf = $input['csrf'] ?? '';
    if (!$id) {
        fail('File id required');
    }
    if (!csrf_check($csrf)) {
        fail('CSRF token invalid', 403);
    }

    $pdo->beginTransaction();
    $stmt = $pdo->prepare("SELECT * FROM files WHERE id = ?");
    $stmt->execute([$id]);
    $file = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$file) {
        $pdo->rollBack();
        fail('File not found', 404);
    }

    if ($user['role'] !== 'admin' && (int)$file['user_id'] !== (int)$user['id']) {
        $pdo->rollBack();
        fail('Forbidden', 403);
    }

    $path = UPLOAD_DIR . $file['saved_name'];
    if (is_file($path) && !@unlink($path)) {
        $pdo->rollBack();
        fail('Failed to delete file from disk', 500);
    }
    $publicPath = public_file_path($file['saved_name']);
    if (file_exists($publicPath)) {
        @unlink($publicPath);
    }

    $pdo->prepare("UPDATE file_event_archive SET deleted_at = CURRENT_TIMESTAMP WHERE file_id = ? AND deleted_at IS NULL")->execute([$id]);
    $pdo->prepare("DELETE FROM file_events WHERE file_id = ?")->execute([$id]);

    $stmt = $pdo->prepare("DELETE FROM files WHERE id = ?");
    $stmt->execute([$id]);
    $pdo->commit();

    log_event("DELETE id={$id} saved={$file['saved_name']} original={$file['original_name']} by_user=" . $user['username']);
    json_resp(['ok'=>true]);
}

if ($action === 'download' && $method === 'GET') {
    $id = (int)($_GET['id'] ?? 0);
    if (!$id) {
        http_response_code(404);
        echo "Not found";
        exit;
    }

    $stmt = $pdo->prepare("SELECT * FROM files WHERE id=?");
    $stmt->execute([$id]);
    $file = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$file) {
        http_response_code(404);
        echo "Not found";
        exit;
    }

    $path = UPLOAD_DIR . $file['saved_name'];
    if (!is_file($path)) {
        http_response_code(404);
        echo "Not found";
        exit;
    }

    $isView = isset($_GET['inline']) || (($_GET['as'] ?? '') === 'view');
    $currentId = current_user_id();
    $currentId = $currentId !== null ? (int)$currentId : null;
    if ($isView) {
        $pdo->prepare("UPDATE files SET views = views + 1, last_viewed_at = CURRENT_TIMESTAMP WHERE id=?")->execute([$id]);
        record_file_event($pdo, $id, $currentId, 'view', client_ip(), $_SERVER['HTTP_USER_AGENT'] ?? null, $file['saved_name'], $file['original_name']);
    } else {
        $pdo->prepare("UPDATE files SET downloads = downloads + 1, last_downloaded_at = CURRENT_TIMESTAMP WHERE id=?")->execute([$id]);
        record_file_event($pdo, $id, $currentId, 'download', client_ip(), $_SERVER['HTTP_USER_AGENT'] ?? null, $file['saved_name'], $file['original_name']);
    }

    $size = filesize($path);
    header('Accept-Ranges: bytes');
    header('Content-Type: ' . ($file['mime'] ?: 'application/octet-stream'));
    if (!$isView) {
        header('Content-Disposition: attachment; filename="' . str_replace('"','\\"',$file['original_name']) . '"');
    }

    $httpRange = $_SERVER['HTTP_RANGE'] ?? null;
    $start = 0;
    $end = $size - 1;
    if ($httpRange && preg_match('/bytes=(\d+)-(\d*)/', $httpRange, $m)) {
        $start = (int)$m[1];
        if ($m[2] !== '') {
            $end = (int)$m[2];
        }
        if ($start > $end || $end >= $size) {
            http_response_code(416);
            exit;
        }
        http_response_code(206);
        header("Content-Range: bytes {$start}-{$end}/{$size}");
    }

    $length = $end - $start + 1;
    header('Content-Length: ' . $length);

    $fp = fopen($path, 'rb');
    if ($fp === false) {
        http_response_code(500);
        exit;
    }
    fseek($fp, $start);
    $chunk = 8192;
    while (!feof($fp) && ftell($fp) <= $end) {
        $remaining = $end - ftell($fp) + 1;
        echo fread($fp, min($chunk, $remaining));
        flush();
        if (connection_aborted()) {
            break;
        }
    }
    fclose($fp);
    exit;
}

if ($action === 'users') {
    require_api_admin($pdo);
    switch ($method) {
        case 'GET':
            $stmt = $pdo->query("
                SELECT u.id, u.username, u.role, u.upload_limit_bytes,
                       u.created_at,
                       COUNT(f.id) AS file_count,
                       COALESCE(SUM(f.size),0) AS total_bytes,
                       MAX(f.created_at) AS last_upload
                FROM users u
                LEFT JOIN files f ON f.user_id = u.id
                GROUP BY u.id
                ORDER BY CASE WHEN u.role = 'admin' THEN 0 ELSE 1 END,
                         u.username COLLATE NOCASE
            ");
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$row) {
                $row['id'] = (int)$row['id'];
                $row['upload_limit_bytes'] = $row['upload_limit_bytes'] !== null ? (int)$row['upload_limit_bytes'] : null;
                $row['file_count'] = (int)$row['file_count'];
                $row['total_bytes'] = (int)$row['total_bytes'];
            }
            unset($row);
            json_resp(['ok'=>true,'users'=>$rows]);
            break;

        case 'POST':
            $payload = read_json_body();
            $username = trim($payload['username'] ?? '');
            $password = $payload['password'] ?? '';
            $role = ($payload['role'] ?? 'user') === 'admin' ? 'admin' : 'user';
            $limitMb = $payload['upload_limit_mb'] ?? null;
            if (!$username || !$password) {
                fail('username and password required');
            }
            $limitBytes = null;
            if ($limitMb !== null && $limitMb !== '') {
                if (!is_numeric($limitMb) || $limitMb < 0) {
                    fail('upload_limit_mb must be >= 0');
                }
                $limitBytes = (int)round((float)$limitMb * 1024 * 1024);
            }
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, role, upload_limit_bytes) VALUES (?,?,?,?)");
            try {
                $stmt->execute([$username, $hash, $role, $limitBytes]);
            } catch (Throwable $e) {
                fail('Failed to create user: ' . $e->getMessage());
            }
            json_resp(['ok'=>true]);
            break;

        case 'PUT':
            $payload = read_json_body();
            $id = (int)($payload['id'] ?? 0);
            if (!$id) {
                fail('User id required');
            }
            $role = ($payload['role'] ?? null);
            if ($role !== null) {
                $role = $role === 'admin' ? 'admin' : 'user';
            }
            $limitMb = $payload['upload_limit_mb'] ?? null;
            $limitBytes = null;
            $limitProvided = array_key_exists('upload_limit_mb', $payload) || array_key_exists('upload_limit_bytes', $payload);
            if (array_key_exists('upload_limit_bytes', $payload)) {
                $limitBytes = $payload['upload_limit_bytes'] !== null ? (int)$payload['upload_limit_bytes'] : null;
                $limitProvided = true;
            } elseif ($limitMb !== null && $limitMb !== '') {
                if (!is_numeric($limitMb) || $limitMb < 0) {
                    fail('upload_limit_mb must be >= 0');
                }
                $limitBytes = (int)round((float)$limitMb * 1024 * 1024);
                $limitProvided = true;
            } elseif ($limitMb === '') {
                $limitBytes = null;
                $limitProvided = true;
            }

            $password = $payload['password'] ?? null;

            $fields = [];
            $params = [];
            if ($role !== null) {
                $fields[] = 'role = ?';
                $params[] = $role;
            }
            if ($limitProvided) {
                $fields[] = 'upload_limit_bytes = ?';
                $params[] = $limitBytes;
            }
            if ($password) {
                $fields[] = 'password_hash = ?';
                $params[] = password_hash($password, PASSWORD_DEFAULT);
            }
            if (!$fields) {
                fail('Nothing to update');
            }
            $params[] = $id;
            $sql = 'UPDATE users SET ' . implode(', ', $fields) . ' WHERE id = ?';
            try {
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
            } catch (Throwable $e) {
                fail('Failed to update user: ' . $e->getMessage());
            }
            json_resp(['ok'=>true]);
            break;

        case 'DELETE':
            $payload = read_json_body();
            $id = (int)($payload['id'] ?? 0);
            if (!$id) {
                fail('User id required');
            }
            if ($id === current_user_id()) {
                fail('Cannot delete yourself');
            }
            $defaultOwnerId = default_owner_id($pdo);
            if ($defaultOwnerId !== null && $defaultOwnerId === $id) {
                fail('Cannot delete default owner');
            }
            try {
                $pdo->beginTransaction();
                if ($defaultOwnerId !== null) {
                    $reassign = $pdo->prepare("UPDATE files SET user_id = :new_owner WHERE user_id = :old_owner");
                    $reassign->execute([':new_owner' => $defaultOwnerId, ':old_owner' => $id]);
                } else {
                    $pdo->prepare("UPDATE files SET user_id = NULL WHERE user_id = ?")->execute([$id]);
                }
                $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
                $stmt->execute([$id]);
                $pdo->commit();
            } catch (Throwable $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                fail('Failed to delete user: ' . $e->getMessage());
            }
            json_resp(['ok'=>true]);
            break;

        default:
            break;
    }
}








if ($action === 'file_settings') {
    if ($method !== 'POST') {
        fail('Unsupported method', 405);
    }
    $currentUser = require_api_login($pdo);
    $payload = read_json_body();
    $id = (int)($payload['id'] ?? 0);
    if (!$id) fail('File id required');
    $stmt = $pdo->prepare("SELECT id, user_id, allow_bot_views, view_cooldown_seconds FROM files WHERE id = ?");
    $stmt->execute([$id]);
    $file = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$file) fail('File not found', 404);
    $role = $currentUser['role'] ?? null;
    if ($role !== 'admin' && (int)$file['user_id'] !== (int)$currentUser['id']) {
        fail('Forbidden', 403);
    }
    $fields = [];
    $params = [];
    if (array_key_exists('allow_bot_views', $payload)) {
        $fields[] = 'allow_bot_views = ?';
        $params[] = $payload['allow_bot_views'] ? 1 : 0;
    }
    if (array_key_exists('view_cooldown_seconds', $payload)) {
        $cooldown = $payload['view_cooldown_seconds'];
        if ($cooldown === '' || $cooldown === null) {
            $cooldown = null;
        } else {
            if (!is_numeric($cooldown) || $cooldown < 0) fail('Cooldown must be >= 0');
            $cooldown = (int)$cooldown;
        }
        $fields[] = 'view_cooldown_seconds = ?';
        $params[] = $cooldown;
    }
    if (!$fields) fail('Nothing to update');
    $params[] = $id;
    $sql = 'UPDATE files SET ' . implode(', ', $fields) . ' WHERE id = ?';
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    json_resp(['ok' => true]);
}


if ($action === 'settings') {
    require_api_admin($pdo);
    switch ($method) {
        case 'GET':
            $settings = [
                'block_bg'=>block_background_url(),
                'not_found_bg'=>not_found_background_url()
            ];
            json_resp(['ok'=>true,'settings'=>$settings]);
            break;
        case 'POST':
            if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'multipart/form-data') !== false) {
                $type = $_POST['upload_type'] ?? '';
                if (!$type || !isset($_FILES['image'])) fail('upload_type and image required');
                $file = $_FILES['image'];
                if ($file['error'] !== UPLOAD_ERR_OK) fail('Upload error');
                $targetDir = rtrim(PUBLIC_DIR, '/') . '/custom/';
                if (!is_dir($targetDir)) mkdir($targetDir, 0775, true);
                $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                if (!in_array($ext, ['png','jpg','jpeg','webp','gif'])) fail('Image required');
                $name = $type . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
                $dest = $targetDir . $name;
                if (!move_uploaded_file($file['tmp_name'], $dest)) fail('Failed to save');
                chmod($dest, 0644);
                $aliasDir = rtrim(PROJECT_ROOT, '/') . '/custom/';
                if (!is_dir($aliasDir)) {
                    mkdir($aliasDir, 0775, true);
                }
                $aliasPath = $aliasDir . $name;
                if (file_exists($aliasPath) || is_link($aliasPath)) {
                    @unlink($aliasPath);
                }
                if (!@link($dest, $aliasPath) && !@symlink($dest, $aliasPath)) {
                    if (@copy($dest, $aliasPath)) {
                        @chmod($aliasPath, 0644);
                    }
                }
                $url = rtrim(BASE_URL, '/') . '/public/custom/' . $name;
                if ($type === 'block_bg') set_setting('block_bg', $url);
                elseif ($type === 'not_found_bg') set_setting('not_found_bg', $url);
                else fail('Unknown upload_type');
                json_resp(['ok'=>true,'url'=>$url]);
            } else {
                $payload = read_json_body();
                if (isset($payload['block_bg'])) set_setting('block_bg', trim($payload['block_bg']));
                if (isset($payload['not_found_bg'])) set_setting('not_found_bg', trim($payload['not_found_bg']));
                json_resp(['ok'=>true]);
            }
            break;
        default:
            fail('Unsupported method', 405);
    }
}

if ($action === 'radio_history' && $method === 'GET') {
    require_api_login($pdo);
    try {
        $radio = get_radio_pdo();
    } catch (Throwable $e) {
        fail('Radio backend unavailable', 503);
    }
    radio_ensure_schema($radio);
    $limit = (int)($_GET['limit'] ?? 25);
    if ($limit < 1) $limit = 1;
    if ($limit > 200) $limit = 200;

    $hasTrackTitle = radio_table_has_column($radio, 'track_history', 'track_title');
    $hasTrackLegacy = radio_table_has_column($radio, 'track_history', 'track');
    $hasArtist = radio_table_has_column($radio, 'track_history', 'artist');
    $hasCover = radio_table_has_column($radio, 'track_history', 'cover_url');
    $hasSource = radio_table_has_column($radio, 'track_history', 'source');
    $hasPlayedAt = radio_table_has_column($radio, 'track_history', 'played_at');
    $hasCreatedAt = radio_table_has_column($radio, 'track_history', 'created_at');

    $columns = ['id'];
    if ($hasTrackTitle) {
        $columns[] = 'track_title AS track_title';
    } elseif ($hasTrackLegacy) {
        $columns[] = 'track AS track_title';
    } else {
        $columns[] = "'' AS track_title";
    }
    $columns[] = $hasArtist ? 'artist' : 'NULL AS artist';
    $columns[] = $hasCover ? 'cover_url' : 'NULL AS cover_url';
    $columns[] = $hasSource ? 'source' : 'NULL AS source';
    if ($hasPlayedAt) {
        $columns[] = 'played_at';
        $orderField = 'played_at';
    } elseif ($hasCreatedAt) {
        $columns[] = 'created_at AS played_at';
        $orderField = 'created_at';
    } else {
        $columns[] = 'NULL AS played_at';
        $orderField = 'id';
    }

    $sql = sprintf(
        'SELECT %s FROM track_history ORDER BY %s DESC LIMIT :limit',
        implode(', ', $columns),
        $orderField
    );
    $stmt = $radio->prepare($sql);
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as &$row) {
        $row['id'] = (int)$row['id'];
        $row['track_title'] = (string)($row['track_title'] ?? '');
        $row['artist'] = $row['artist'] !== null ? (string)$row['artist'] : null;
        $row['cover_url'] = $row['cover_url'] !== null ? (string)$row['cover_url'] : null;
        $row['source'] = $row['source'] !== null ? (string)$row['source'] : null;
        $row['played_at'] = $row['played_at'] !== null ? (string)$row['played_at'] : null;
    }
    unset($row);
    json_resp(['ok' => true, 'history' => $rows]);
}

if ($action === 'radio_listeners' && $method === 'GET') {
    $env = radio_env();
    $statsUrl = $env['AZURACAST_STATS'] ?? ($env['RADIO_STATS'] ?? ($env['RADIO_API'] ?? null));
    if (!$statsUrl) {
        fail('Radio stats URL not configured', 503);
    }
    $ch = curl_init($statsUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200 || $response === false) {
        fail('Failed to fetch listeners', 502);
    }
    $data = json_decode($response, true);
    if (!is_array($data)) {
        fail('Invalid listeners payload', 502);
    }
    $listeners = 0;
    if (isset($data['listeners']['current'])) {
        $listeners = (int)$data['listeners']['current'];
    } elseif (isset($data['total'])) {
        $listeners = (int)$data['total'];
    }
    json_resp(['ok' => true, 'listeners' => $listeners]);
}

if ($action === 'radio_requests') {
    $currentUser = require_api_login($pdo);
    $isAdmin = ($currentUser['role'] ?? '') === 'admin';
    try {
        $radio = get_radio_pdo();
    } catch (Throwable $e) {
        fail('Radio backend unavailable', 503);
    }
    radio_ensure_schema($radio);

    switch ($method) {
        case 'GET': {
            $status = strtolower(trim((string)($_GET['status'] ?? 'pending')));
            $allowedStatuses = ['pending', 'played', 'rejected', 'all'];
            if (!in_array($status, $allowedStatuses, true)) {
                $status = 'pending';
            }
            if (!$isAdmin && $status !== 'pending') {
                $status = 'pending';
            }
            $limit = (int)($_GET['limit'] ?? 50);
            if ($limit < 1) $limit = 1;
            if ($limit > 200) $limit = 200;
            $scope = $_GET['scope'] ?? 'all';
            $params = [];
            $where = [];
            if ($status !== 'all') {
                $where[] = 'o.status = :status';
                $params[':status'] = $status;
            }
            if (!$isAdmin) {
                if ($scope === 'mine') {
                    $where[] = 'o.uploader_user_id = :uid';
                    $params[':uid'] = (int)$currentUser['id'];
                } else {
                    $where[] = "o.status <> 'rejected'";
                }
            } elseif ($scope === 'mine') {
                $where[] = 'o.uploader_user_id = :uid';
                $params[':uid'] = (int)$currentUser['id'];
            }
            $sql = "
                SELECT o.id, o.track_title, o.artist, o.comment, o.status, o.created_at,
                       o.uploader_user_id, o.source_app,
                       u.nickname, u.id AS radio_user_id
                FROM orders o
                LEFT JOIN users u ON u.id = o.user_id
            ";
            if ($where) {
                $sql .= ' WHERE ' . implode(' AND ', $where);
            }
            $sql .= ' ORDER BY o.id DESC LIMIT :limit';
            $stmt = $radio->prepare($sql);
            foreach ($params as $name => $value) {
                $stmt->bindValue($name, $value);
            }
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->execute();
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$row) {
                $row['id'] = (int)$row['id'];
                $row['radio_user_id'] = $row['radio_user_id'] !== null ? (int)$row['radio_user_id'] : null;
                $row['uploader_user_id'] = $row['uploader_user_id'] !== null ? (int)$row['uploader_user_id'] : null;
            }
            unset($row);
            json_resp(['ok' => true, 'requests' => $rows]);
            break;
        }

        case 'POST': {
            $payload = read_json_body();
            $track = trim((string)($payload['track'] ?? ''));
            $artist = trim((string)($payload['artist'] ?? ''));
            $comment = trim((string)($payload['comment'] ?? ''));
            $displayName = trim((string)($payload['name'] ?? ''));
            $sourceApp = trim((string)($payload['source'] ?? 'app'));
            if ($track === '') {
                fail('Track title is required');
            }
            $config = radio_load_config();
            if (empty($config['requests_enabled'])) {
                fail('Requests are disabled', 503);
            }
            $ip = client_ip() ?? '';
            if ($ip !== '' && radio_is_banned($radio, $ip, 'order')) {
                fail('You are banned from requests', 403);
            }
            $radioUser = radio_sync_user($radio, $currentUser, $displayName !== '' ? $displayName : null);
            $insert = $radio->prepare("
                INSERT INTO orders (user_id, uploader_user_id, track_title, artist, comment, status, source_app, created_at)
                VALUES (:user_id, :uploader_user_id, :track_title, :artist, :comment, 'pending', :source_app, NOW())
            ");
            $insert->execute([
                ':user_id' => $radioUser['id'],
                ':uploader_user_id' => (int)$currentUser['id'],
                ':track_title' => $track,
                ':artist' => $artist !== '' ? $artist : null,
                ':comment' => $comment !== '' ? $comment : null,
                ':source_app' => $sourceApp !== '' ? $sourceApp : 'app',
            ]);
            $newId = (int)$radio->lastInsertId();
            $mailSent = radio_send_request_mail([
                'name' => $radioUser['nickname'],
                'track' => $track,
                'comment' => $comment,
                'ip' => $ip,
                'source' => $sourceApp,
            ]);
            json_resp([
                'ok' => true,
                'request' => [
                    'id' => $newId,
                    'track_title' => $track,
                    'artist' => $artist !== '' ? $artist : null,
                    'comment' => $comment !== '' ? $comment : null,
                    'status' => 'pending',
                    'created_at' => date('Y-m-d H:i:s'),
                    'nickname' => $radioUser['nickname'],
                    'radio_user_id' => $radioUser['id'],
                    'uploader_user_id' => (int)$currentUser['id'],
                    'source_app' => $sourceApp !== '' ? $sourceApp : 'app',
                ],
                'mail_sent' => $mailSent,
            ]);
            break;
        }

        case 'PUT': {
            if (!$isAdmin) {
                fail('Forbidden', 403);
            }
            $payload = read_json_body();
            $id = (int)($payload['id'] ?? 0);
            $status = strtolower(trim((string)($payload['status'] ?? '')));
            if (!$id) {
                fail('Request id required');
            }
            $allowed = ['pending', 'played', 'rejected'];
            if (!in_array($status, $allowed, true)) {
                fail('Unknown status');
            }
            $update = $radio->prepare('UPDATE orders SET status = :status WHERE id = :id');
            $update->execute([':status' => $status, ':id' => $id]);
            if (!empty($payload['comment'])) {
                $commentStmt = $radio->prepare('UPDATE orders SET comment = :comment WHERE id = :id');
                $commentStmt->execute([':comment' => trim((string)$payload['comment']), ':id' => $id]);
            }
            $stmt = $radio->prepare("
                SELECT o.id, o.track_title, o.artist, o.comment, o.status, o.created_at,
                       o.uploader_user_id, o.source_app,
                       u.nickname, u.id AS radio_user_id
                FROM orders o
                LEFT JOIN users u ON u.id = o.user_id
                WHERE o.id = :id
                LIMIT 1
            ");
            $stmt->execute([':id' => $id]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                fail('Request not found', 404);
            }
            $row['id'] = (int)$row['id'];
            $row['radio_user_id'] = $row['radio_user_id'] !== null ? (int)$row['radio_user_id'] : null;
            $row['uploader_user_id'] = $row['uploader_user_id'] !== null ? (int)$row['uploader_user_id'] : null;
            json_resp(['ok' => true, 'request' => $row]);
            break;
        }

        case 'DELETE': {
            if (!$isAdmin) {
                fail('Forbidden', 403);
            }
            $payload = read_json_body();
            $id = (int)($payload['id'] ?? 0);
            if (!$id) {
                fail('Request id required');
            }
            $radio->prepare('DELETE FROM orders WHERE id = ?')->execute([$id]);
            json_resp(['ok' => true]);
            break;
        }

        default:
            fail('Unsupported method', 405);
    }
}

if ($action === 'radio_chat') {
    $currentUser = require_api_login($pdo);
    try {
        $radio = get_radio_pdo();
    } catch (Throwable $e) {
        fail('Radio backend unavailable', 503);
    }
    radio_ensure_schema($radio);
    $config = radio_load_config();
    if (empty($config['chat_enabled'])) {
        fail('Chat disabled', 503);
    }

    switch ($method) {
        case 'GET': {
            $limit = (int)($_GET['limit'] ?? 50);
            if ($limit < 1) $limit = 1;
            if ($limit > 200) $limit = 200;
            $sinceId = isset($_GET['since_id']) ? (int)$_GET['since_id'] : null;

            $sql = "SELECT cm.id, cm.message, cm.reply_to, cm.created_at, u.nickname, u.nick_verified, u.is_admin\n                    FROM chat_messages cm\n                    JOIN users u ON cm.user_id = u.id";
            $params = [];
            if ($sinceId) {
                $sql .= " WHERE cm.id > :since";
                $params[':since'] = $sinceId;
            }
            $sql .= " ORDER BY cm.id DESC LIMIT :limit";
            $stmt = $radio->prepare($sql);
            foreach ($params as $name => $value) {
                $stmt->bindValue($name, $value, PDO::PARAM_INT);
            }
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->execute();
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $replyNeeded = [];
            foreach ($rows as $row) {
                if (!empty($row['reply_to'])) {
                    $replyNeeded[(int)$row['reply_to']] = true;
                }
            }
            $replyData = [];
            if ($replyNeeded) {
                $placeholders = implode(',', array_fill(0, count($replyNeeded), '?'));
                $stmt = $radio->prepare("SELECT cm.id, cm.message, u.nickname FROM chat_messages cm JOIN users u ON cm.user_id = u.id WHERE cm.id IN ($placeholders)");
                $stmt->execute(array_keys($replyNeeded));
                foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $replyRow) {
                    $replyData[(int)$replyRow['id']] = $replyRow;
                }
            }

            $messages = array_reverse(array_map(function ($row) use ($replyData) {
                $item = [
                    'id' => (int)$row['id'],
                    'message' => $row['message'],
                    'created_at' => $row['created_at'],
                    'nickname' => $row['nickname'],
                    'nick_verified' => (bool)$row['nick_verified'],
                    'is_admin' => (bool)$row['is_admin'],
                    'reply_to' => $row['reply_to'] ? (int)$row['reply_to'] : null,
                ];
                if ($item['reply_to'] && isset($replyData[$item['reply_to']])) {
                    $item['reply'] = $replyData[$item['reply_to']];
                }
                return $item;
            }, $rows));

            json_resp(['ok' => true, 'messages' => $messages]);
            break;
        }

        case 'POST': {
            $payload = read_json_body();
            $message = trim((string)($payload['message'] ?? ''));
            if ($message === '') {
                fail('Message is empty');
            }
            $nickname = trim((string)($payload['nickname'] ?? ($currentUser['username'] ?? 'Listener')));
            $replyTo = isset($payload['reply_to']) ? (int)$payload['reply_to'] : null;
            $fingerprint = isset($payload['fingerprint']) ? substr(trim((string)$payload['fingerprint']), 0, 180) : null;
            $ip = client_ip() ?? '0.0.0.0';

            if (radio_is_banned($radio, $ip, 'chat')) {
                http_response_code(403);
                json_resp(['ok'=>false,'error'=>'banned']);
            }
            if (!radio_is_ip_allowed($radio, $ip)) {
                http_response_code(403);
                json_resp(['ok'=>false,'error'=>'ip_not_allowed']);
            }

            $radioUser = radio_sync_user($radio, $currentUser, $nickname);
            if ($fingerprint) {
                // Bind fingerprint to the radio user for future identification
                try {
                    $stmt = $radio->prepare('INSERT INTO user_identifiers (user_id, ip_address, fingerprint) VALUES (:uid, :ip, :fp) ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), ip_address = VALUES(ip_address)');
                    $stmt->execute([':uid' => $radioUser['id'], ':ip' => $ip, ':fp' => $fingerprint]);
                } catch (Throwable $ignored) {}
            }

            if ($replyTo) {
                $stmt = $radio->prepare('SELECT 1 FROM chat_messages WHERE id = ?');
                $stmt->execute([$replyTo]);
                if (!$stmt->fetchColumn()) {
                    $replyTo = null;
                }
            }

            $stmt = $radio->prepare('INSERT INTO chat_messages (user_id, message, reply_to) VALUES (:uid, :msg, :reply)');
            $stmt->execute([
                ':uid' => $radioUser['id'],
                ':msg' => $message,
                ':reply' => $replyTo ?: null,
            ]);

            $insertedId = (int)$radio->lastInsertId();
            json_resp([
                'ok' => true,
                'message' => [
                    'id' => $insertedId,
                    'nickname' => $radioUser['nickname'],
                    'message' => $message,
                    'reply_to' => $replyTo,
                    'created_at' => date('Y-m-d H:i:s'),
                    'nick_verified' => true,
                    'is_admin' => !empty($radioUser['is_admin']),
                ],
            ]);
            break;
        }

        default:
            fail('Unsupported method', 405);
    }
}

if ($action === 'radio_config') {
    $currentUser = require_api_login($pdo);
    $isAdmin = ($currentUser['role'] ?? '') === 'admin';
    $config = radio_load_config(true);
    if ($method === 'GET') {
        if ($isAdmin) {
            json_resp(['ok' => true, 'config' => $config]);
        } else {
            $exposed = [
                'chat_enabled' => (bool)$config['chat_enabled'],
                'requests_enabled' => (bool)$config['requests_enabled'],
                'requests_queue_only' => (bool)$config['requests_queue_only'],
                'show_requests_on_main' => (bool)$config['show_requests_on_main'],
                'autodj_enabled' => (bool)$config['autodj_enabled'],
            ];
            json_resp(['ok' => true, 'config' => $exposed]);
        }
    }
    if (!$isAdmin) {
        fail('Forbidden', 403);
    }
    $payload = read_json_body();
    $allowedKeys = [
        'chat_enabled',
        'requests_enabled',
        'show_requests_on_main',
        'requests_queue_only',
        'chat_ip_restriction',
        'autodj_enabled',
        'bans_enabled',
    ];
    $changed = false;
    foreach ($allowedKeys as $key) {
        if (array_key_exists($key, $payload)) {
            $config[$key] = (bool)$payload[$key];
            $changed = true;
        }
    }
    if (isset($payload['allowed_chat_ips']) && is_array($payload['allowed_chat_ips'])) {
        $config['allowed_chat_ips'] = array_values(array_unique(array_map('strval', $payload['allowed_chat_ips'])));
        $changed = true;
    }
    if (isset($payload['avatar']) && is_string($payload['avatar'])) {
        $config['avatar'] = trim($payload['avatar']) !== '' ? trim($payload['avatar']) : $config['avatar'];
        $changed = true;
    }
    if (isset($payload['favicon']) && is_string($payload['favicon'])) {
        $config['favicon'] = trim($payload['favicon']) !== '' ? trim($payload['favicon']) : $config['favicon'];
        $changed = true;
    }
    if (!$changed) {
        json_resp(['ok' => true, 'config' => $config, 'changed' => false]);
    }
    if (!radio_save_config($config)) {
        fail('Failed to save config', 500);
    }
    json_resp(['ok' => true, 'config' => $config, 'changed' => true]);
}

fail('Unknown action', 404);
