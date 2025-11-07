<?php
require_once __DIR__ . '/functions.php';

/*
 * public_proxy.php — используется nginx rewrite'ом:
 * location ^~ /public/ {
 *     alias /var/www/uploader/public/;
 *     try_files $uri /data/public_proxy.php?file=$uri&$args;
 * }
 */

$requested = $_GET['file'] ?? '';
$requested = urldecode(trim($requested));
$requested = preg_replace('#^/+#', '', $requested);
if (stripos($requested, 'public/') === 0) {
    $requested = substr($requested, strlen('public/'));
}
$requested = trim($requested, '/');
if ($requested === '' || strpos($requested, '..') !== false) {
    render_not_found_page('File not found');
}

$customPrefix = 'custom/';
if (str_starts_with($requested, $customPrefix)) {
    $customName = basename($requested);
    $customPath = rtrim(PUBLIC_DIR, '/') . '/custom/' . $customName;
    if (!is_file($customPath)) {
        render_not_found_page('File not found');
    }
    $mime = mime_content_type($customPath) ?: 'application/octet-stream';
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($customPath));
    header('Cache-Control: public, max-age=86400');
    header('X-Robots-Tag: noindex, nofollow');
    readfile($customPath);
    exit;
}

$pdo = get_pdo();
$clientIp = client_ip();
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
$isBot = is_known_bot($userAgent);
if ($clientIp && is_ip_blocked($clientIp)) {
    render_block_page('Your IP has been blocked');
}

$stmt = $pdo->prepare("SELECT * FROM files WHERE saved_name = ?");
$stmt->execute([basename($requested)]);
$file = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$file) {
    render_not_found_page('File not found');
}

$allowBot = (int)($file['allow_bot_views'] ?? 0) === 1;
if ($isBot && !$allowBot) {
    http_response_code(403);
    header('X-Robots-Tag: noindex, nofollow');
    exit('Bots not allowed');
}
if ($isBot) {
    header('X-Robots-Tag: noindex, nofollow');
}

$path = UPLOAD_DIR . $file['saved_name'];
if (!is_file($path)) {
    render_not_found_page('File not found');
}

$download = isset($_GET['download']);
$inline = !$download && (isset($_GET['inline']) || preg_match('/^(image|video|audio)\//i', $file['mime']));
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;

if ($inline) {
    $cooldown = $file['view_cooldown_seconds'] !== null ? (int)$file['view_cooldown_seconds'] : 120;
    $shouldCount = should_count_event($pdo, (int)$file['id'], 'view', $clientIp, $userAgent, $cooldown);
    if ($shouldCount) {
        $pdo->prepare("UPDATE files SET views = views + 1, last_viewed_at = CURRENT_TIMESTAMP WHERE id=?")->execute([$file['id']]);
        record_file_event($pdo, (int)$file['id'], current_user_id(), 'view', $clientIp, $userAgent, $file['saved_name'], $file['original_name']);
    } else {
        $pdo->prepare("UPDATE files SET last_viewed_at = CURRENT_TIMESTAMP WHERE id=?")->execute([$file['id']]);
    }
} else {
    $pdo->prepare("UPDATE files SET downloads = downloads + 1, last_downloaded_at = CURRENT_TIMESTAMP WHERE id=?")->execute([$file['id']]);
    record_file_event($pdo, (int)$file['id'], current_user_id(), 'download', $clientIp, $userAgent, $file['saved_name'], $file['original_name']);
}

$size = filesize($path);
$fp = fopen($path, 'rb');
if (!$fp) {
    http_response_code(500);
    exit('Failed to open file');
}

header('Accept-Ranges: bytes');
header('Content-Type: ' . ($file['mime'] ?: 'application/octet-stream'));
if (!$inline) {
    header('Content-Disposition: attachment; filename="' . str_replace('"','\\"',$file['original_name']) . '"');
}

$httpRange = $_SERVER['HTTP_RANGE'] ?? null;
$start = 0;
$end = $size - 1;
if ($httpRange && preg_match('/bytes=(\d+)-(\d*)/', $httpRange, $m)) {
    $start = (int)$m[1];
    if ($m[2] !== '') $end = (int)$m[2];
    if ($start > $end || $end >= $size) {
        http_response_code(416);
        exit;
    }
    http_response_code(206);
    header("Content-Range: bytes {$start}-{$end}/{$size}");
}

$length = $end - $start + 1;
header('Content-Length: ' . $length);
fseek($fp, $start);
$chunk = 8192;
while (!feof($fp) && ftell($fp) <= $end) {
    $remaining = $end - ftell($fp) + 1;
    echo fread($fp, min($chunk, $remaining));
    flush();
    if (connection_aborted()) break;
}
fclose($fp);
exit;
