<?php
// migrate_legacy.php — переносит данные из JSON (uploads_meta, uploads.json, downloads.json) в БД
require_once __DIR__ . '/functions.php';

if (php_sapi_name() !== 'cli') {
    echo "Run from CLI: php migrate_legacy.php\n";
    exit;
}

$pdo = get_pdo();
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$pdo->exec('PRAGMA busy_timeout = 5000');

$uploadsPath    = DATA_DIR . '/uploads.json';
$metaPath       = DATA_DIR . '/uploads_meta.json';
$filesMetaPath  = DATA_DIR . '/files_meta.json';
$downloadsPath  = DATA_DIR . '/downloads.json';
$logPath        = DATA_DIR . '/uploads.log';

$uploadsData = [];
if (is_file($uploadsPath)) {
    $uploadsData = json_decode(file_get_contents($uploadsPath), true);
    if (!is_array($uploadsData)) {
        echo "uploads.json has invalid format\n";
        $uploadsData = [];
    }
} else {
    echo "uploads.json not found — skipping this source.\n";
}

$metaMap = [];
if (is_file($metaPath)) {
    $metaDecoded = json_decode(file_get_contents($metaPath), true);
    if (is_array($metaDecoded)) {
        if (array_values($metaDecoded) === $metaDecoded) {
            foreach ($metaDecoded as $row) {
                if (!is_array($row)) continue;
                $stored = $row['stored_name'] ?? null;
                $original = $row['original_name'] ?? null;
                if ($stored && $original) $metaMap[$stored] = $original;
            }
        } else {
            foreach ($metaDecoded as $stored => $original) {
                if ($stored) {
                    $metaMap[$stored] = $original ?: $stored;
                }
            }
        }
    }
} else {
    echo "uploads_meta.json not found — some files may remain unmapped.\n";
}

$filesMetaData = [];
if (is_file($filesMetaPath)) {
    $filesMetaData = json_decode(file_get_contents($filesMetaPath), true);
    if (!is_array($filesMetaData)) {
        echo "files_meta.json has invalid format\n";
        $filesMetaData = [];
    }
} else {
    echo "files_meta.json not found — skipping this source.\n";
}

$downloadStats = [];
if (is_file($downloadsPath)) {
    $downloadsDecoded = json_decode(file_get_contents($downloadsPath), true);
    if (is_array($downloadsDecoded)) {
        foreach ($downloadsDecoded as $name => $stats) {
            if (!is_array($stats)) {
                continue;
            }
            $downloadStats[$name] = [
                'views' => (int)($stats['views'] ?? 0),
                'downloads' => (int)($stats['downloads'] ?? 0),
            ];
        }
    }
}

$logEntries = [];
if (is_file($logPath)) {
    $handle = fopen($logPath, 'r');
    if ($handle) {
        while (($line = fgets($handle)) !== false) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            if (preg_match('/^\[(.+?)\]\s+UPLOAD\s+saved=(.+?)\s+original=(.+?)\s+size=(\d+)(?:\s+ip=([^\s]+))?(?:\s+mime=([^\s]+))?/u', $line, $m)) {
                $logEntries[] = [
                    'time' => $m[1],
                    'stored_name' => $m[2],
                    'original_name' => $m[3],
                    'size' => (int)$m[4],
                    'uploaded_ip' => $m[5] ?? null,
                    'mime' => $m[6] ?? null,
                ];
            } elseif (preg_match('/^\[(.+?)\]\s+IMPORT\s+file=(.+?)\s+size=(\d+)/u', $line, $m)) {
                $logEntries[] = [
                    'time' => $m[1],
                    'stored_name' => $m[2],
                    'original_name' => $m[2],
                    'size' => (int)$m[3],
                    'uploaded_ip' => null,
                    'mime' => null,
                ];
            }
        }
        fclose($handle);
    }
} else {
    echo "uploads.log not found — skipping this source.\n";
}

if (!is_dir(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0775, true);
}

$legacySearchDirs = [
    PROJECT_ROOT . '/public', // на случай, если файлы лежат в public
    PROJECT_ROOT,             // исторически лежали в корне
];

$insertFile = $pdo->prepare("
    INSERT INTO files (user_id, saved_name, original_name, mime, size, views, downloads, uploaded_ip, uploaded_via, created_at)
    VALUES (:user_id, :saved_name, :original_name, :mime, :size, :views, :downloads, :uploaded_ip, :uploaded_via, :created_at)
");
$insertEvent = $pdo->prepare("
    INSERT INTO file_events (file_id, saved_name, original_name, user_id, event_type, ip_address, user_agent, created_at)
    VALUES (:file_id, :saved_name, :original_name, :user_id, :event_type, :ip_address, :user_agent, :created_at)
");

$existingNames = [];
$stmt = $pdo->query("SELECT saved_name FROM files");
while ($row = $stmt->fetch()) {
    if (!empty($row['saved_name'])) {
        $existingNames[$row['saved_name']] = true;
    }
}

$pdo->beginTransaction();

$stats = [
    'files_meta'   => ['total'=>0,'imported'=>0,'missing'=>0,'exists'=>0],
    'uploads_json' => ['total'=>0,'imported'=>0,'missing'=>0,'exists'=>0],
    'uploads_meta' => ['total'=>0,'imported'=>0,'missing'=>0,'exists'=>0],
    'uploads_log'  => ['total'=>0,'imported'=>0,'missing'=>0,'exists'=>0],
];

$processRecord = function(string $source, string $stored, string $original, array $extra = []) use (
    &$stats, &$existingNames, $legacySearchDirs, $insertFile, $insertEvent, $downloadStats, $pdo
) {
    $stats[$source]['total']++;
    if (isset($existingNames[$stored])) {
        $stats[$source]['exists']++;
        return;
    }

    $filePath = rtrim(UPLOAD_DIR, '/') . '/' . $stored;
    if (!is_file($filePath)) {
        $relocated = false;
        foreach ($legacySearchDirs as $dir) {
            $legacyPath = rtrim($dir, '/') . '/' . $stored;
            if (!is_file($legacyPath)) {
                continue;
            }
            if (@rename($legacyPath, $filePath)) {
                $relocated = true;
                break;
            }
            if (@copy($legacyPath, $filePath)) {
                @unlink($legacyPath);
                $relocated = true;
                break;
            }
        }
        if (!$relocated || !is_file($filePath)) {
            $stats[$source]['missing']++;
            return;
        }
        @chmod($filePath, 0644);
    }

    ensure_public_file($stored);

    $views = $extra['views'] ?? null;
    $downloads = $extra['downloads'] ?? null;
    if ($views === null || $downloads === null) {
        if (isset($downloadStats[$stored])) {
            $views = $views ?? $downloadStats[$stored]['views'];
            $downloads = $downloads ?? $downloadStats[$stored]['downloads'];
        } elseif (isset($downloadStats[$original])) {
            $views = $views ?? $downloadStats[$original]['views'];
            $downloads = $downloads ?? $downloadStats[$original]['downloads'];
        }
    }
    $views = (int)($views ?? 0);
    $downloads = (int)($downloads ?? 0);

    $size = isset($extra['size']) ? (int)$extra['size'] : filesize($filePath);
    $mime = $extra['mime'] ?? mime_content_type($filePath) ?: 'application/octet-stream';

    $timeValue = $extra['time'] ?? null;
    if (is_numeric($timeValue)) {
        $timestamp = (int)$timeValue;
        if ($timestamp > 1000000000000) {
            $timestamp = (int)round($timestamp / 1000);
        }
    } elseif ($timeValue) {
        $timestamp = strtotime($timeValue) ?: filemtime($filePath) ?: time();
    } else {
        $timestamp = filemtime($filePath) ?: time();
    }
    if ($timestamp < 0) {
        $timestamp = time();
    }
    $createdAt = date('Y-m-d H:i:s', $timestamp);

    $uploadedIp = $extra['uploaded_ip'] ?? $extra['ip'] ?? null;
    $uploadedVia = $extra['uploaded_via'] ?? $extra['user_agent'] ?? null;

    $insertFile->execute([
        ':user_id'       => null,
        ':saved_name'    => $stored,
        ':original_name' => $original,
        ':mime'          => $mime,
        ':size'          => $size,
        ':views'         => $views,
        ':downloads'     => $downloads,
        ':uploaded_ip'   => $uploadedIp,
        ':uploaded_via'  => $uploadedVia,
        ':created_at'    => $createdAt,
    ]);

    $fileId = $pdo->lastInsertId();

    $insertEvent->execute([
        ':file_id'       => $fileId,
        ':saved_name'    => $stored,
        ':original_name' => $original,
        ':user_id'       => null,
        ':event_type'    => 'upload',
        ':ip_address'    => $uploadedIp,
        ':user_agent'    => $uploadedVia,
        ':created_at'    => $createdAt,
    ]);

    $existingNames[$stored] = true;
    $stats[$source]['imported']++;
};

foreach ($filesMetaData as $entry) {
    if (!is_array($entry)) {
        continue;
    }
    $stored = $entry['stored_name'] ?? null;
    $original = $entry['original_name'] ?? ($stored ? ($metaMap[$stored] ?? $stored) : null);
    if (!$stored || !$original) {
        continue;
    }
    $processRecord('files_meta', $stored, $original, [
        'size' => $entry['size'] ?? null,
        'mime' => $entry['mime'] ?? null,
        'time' => $entry['time'] ?? null,
        'views' => $entry['views'] ?? null,
        'uploaded_ip' => $entry['uploader_ip'] ?? null,
        'uploaded_via' => $entry['user_agent'] ?? null,
    ]);
}

foreach ($uploadsData as $entry) {
    if (!is_array($entry)) {
        continue;
    }
    $stored = $entry['stored_name'] ?? null;
    $original = $entry['original_name'] ?? ($stored ? ($metaMap[$stored] ?? $stored) : null);
    if (!$stored || !$original) {
        continue;
    }
    $processRecord('uploads_json', $stored, $original, [
        'size' => $entry['size'] ?? null,
        'mime' => $entry['mime'] ?? null,
        'time' => $entry['time'] ?? null,
        'views' => null,
        'uploaded_ip' => $entry['uploader_ip'] ?? null,
        'uploaded_via' => $entry['user_agent'] ?? null,
    ]);
}

foreach ($metaMap as $stored => $original) {
    if (!$stored || !$original) {
        continue;
    }
    $processRecord('uploads_meta', $stored, $original, []);
}

foreach ($logEntries as $entry) {
    $stored = $entry['stored_name'] ?? null;
    $original = $entry['original_name'] ?? ($stored ? ($metaMap[$stored] ?? $stored) : null);
    if (!$stored || !$original) {
        continue;
    }
    $processRecord('uploads_log', $stored, $original, [
        'size' => $entry['size'] ?? null,
        'mime' => $entry['mime'] ?? null,
        'time' => $entry['time'] ?? null,
        'uploaded_ip' => $entry['uploaded_ip'] ?? null,
    ]);
}

$pdo->commit();

foreach ($stats as $source => $info) {
    echo strtoupper($source) . ": processed {$info['total']}, imported {$info['imported']}, already_in_db {$info['exists']}, missing {$info['missing']}\n";
}
