<?php
// config.php — основные настройки (public build)

define('PUBLIC_BUILD', true);

// Корень проекта (на уровень выше папки data)
define('PROJECT_ROOT', realpath(__DIR__ . '/..'));

// Подготовим полезные пути
define('DATA_DIR', PROJECT_ROOT . '/data');
define('LOGS_DIR', PROJECT_ROOT . '/logs');
define('PUBLIC_DIR', PROJECT_ROOT . '/public');
define('SESSION_DIR', DATA_DIR . '/sessions');

// Путь к sqlite БД
define('DB_FILE', DATA_DIR . '/db.sqlite');

// Папка для загруженных файлов (должна быть недоступна для выполнения PHP)
define('UPLOAD_DIR', PROJECT_ROOT . '/uploads/');

// Базовый URL для прямых ссылок (замени на свой домен/поддомен)
define('BASE_URL', 'https://test.tenshiowl.live/');

// Максимальный размер (в байтах). Можно поставить 20000*1024*1024 для 20GB
define('MAX_FILE_SIZE', 20000 * 1024 * 1024);

// Секрет для формирования CSRF токенов (изменить на случайную строку)
define('APP_SECRET', 'change_this_to_a_random_secret_please');

// Пользователь по умолчанию, к которому будут привязаны файлы без владельца
define('DEFAULT_FILE_OWNER', 'admin');

// Лог-файл
define('LOG_FILE', LOGS_DIR . '/uploads.log');

// Инициализация: создаём папки, если их нет
foreach ([UPLOAD_DIR, LOGS_DIR, DATA_DIR, PUBLIC_DIR, SESSION_DIR] as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0775, true);
    }
    @chmod($dir, 0777);
}

if (is_dir(SESSION_DIR) && is_writable(SESSION_DIR)) {
    @ini_set('session.save_path', SESSION_DIR);
    @ini_set('session.gc_maxlifetime', 60 * 60 * 24 * 7); // 7 days
}

// Старт сессии (пропускаем в CLI, чтобы не ловить permission denied)
if (php_sapi_name() !== 'cli' && session_status() === PHP_SESSION_NONE) {
    session_start();
}
