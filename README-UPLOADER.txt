==============================
Uploader Deployment Guide / Инструкция по развёртыванию
==============================

English
-------
1. Clone repository
   git clone <repo> /var/www/uploader   # replace <repo> with your own source

2. Install requirements
   sudo apt update
   sudo apt install nginx php8.1-fpm php8.1-sqlite3 php8.1-curl php8.1-xml php8.1-mbstring

3. Create directories & permissions
   sudo mkdir -p /var/www/uploader/{uploads,logs,public/custom}
   sudo chown -R <user>:www-data /var/www/uploader
   sudo chmod -R 775 /var/www/uploader
   # If PHP later reports "attempt to write a readonly database",
   # chmod 777 /var/www/uploader/{data,uploads,logs,public} and chmod 666 data/db.sqlite
   # (the app also creates data/sessions for PHP sessions — keep it writable).

4. Update config (`data/config.php`)
   - Set `BASE_URL` to `https://your-domain/`.
   - Set `DEFAULT_FILE_OWNER` to the username that should keep orphaned files.

5. nginx config -> /var/www/uploader/nginx-uploader.conf  (see snippet below; replace domain with yours)
6. Enable site
   sudo ln -s /var/www/uploader/nginx-uploader.conf /etc/nginx/sites-enabled/uploader.conf
   sudo nginx -t && sudo systemctl reload nginx

7. Initialize SQLite database
   cd /var/www/uploader
   rm -f data/db.sqlite
   php data/init_db.php    # default admin: login `admin`, password `admin123!` (change later)

8. Optional cleanup (fresh install)
   rm -rf uploads/*
   : > data/uploads.json
   : > data/uploads_meta.json
   : > data/files_meta.json
   : > data/downloads.json
   : > data/uploads.log
   : > logs/uploads.log
   : > data/php_errors.log

9. Start services
   sudo systemctl enable --now php8.1-fpm nginx

10. Change default admin
    - After logging in with `admin/admin123!`, go to “Manage Users”, change the password, or create a new admin and delete the default user.

9. Useful commands
   sudo journalctl -u nginx -f
   sudo tail -f /var/log/nginx/uploader.error.log
   sudo tail -f /var/www/uploader/data/php_errors.log
   sudo systemctl reload nginx
   php -l data/file.php
   sqlite3 data/db.sqlite
   sudo certbot --nginx -d example.com    # use your domain

nginx snippet
-------------
server {
    listen 80;
    server_name example.com;   # replace with your domain
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com;   # replace with your domain

    root /var/www/uploader;
    index index.php data/index.php;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    client_max_body_size 20000M;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param HTTPS on;
    }

    location ^~ /uploads/ { deny all; }
    location ~* \.(json|log|sqlite|db|bak)$ { deny all; }
    location ~* /\. { deny all; }

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header X-XSS-Protection "1; mode=block" always;
}

Русский
-------
1. Клонировать репозиторий
   git clone <repo> /var/www/uploader   # замените <repo> на свой адрес

2. Установить пакеты
   sudo apt update
   sudo apt install nginx php8.1-fpm php8.1-sqlite3 php8.1-curl php8.1-xml php8.1-mbstring

3. Каталоги и права
   sudo mkdir -p /var/www/uploader/{uploads,logs,public/custom}
   sudo chown -R <user>:www-data /var/www/uploader
   sudo chmod -R 775 /var/www/uploader
   # Если увидите ошибку "attempt to write a readonly database",
   # выполните chmod 777 /var/www/uploader/{data,uploads,logs,public} и chmod 666 data/db.sqlite
   # (приложение создаёт также папку data/sessions для PHP-сессий — ей тоже нужны права на запись).

4. Обновить `data/config.php`
   - Поставьте `BASE_URL` = `https://ваш-домен/`.
   - `DEFAULT_FILE_OWNER` укажите на пользователя, которому должны принадлежать “ничейные” файлы.

5. Конфиг nginx — /var/www/uploader/nginx-uploader.conf (см. сниппет выше; замените домен на свой)
6. Включить сайт
   sudo ln -s /var/www/uploader/nginx-uploader.conf /etc/nginx/sites-enabled/uploader.conf
   sudo nginx -t && sudo systemctl reload nginx

7. Создать SQLite-базу
   cd /var/www/uploader
   rm -f data/db.sqlite
   php data/init_db.php   # стандартный админ: логин `admin`, пароль `admin123!` (сразу смените)

8. Очистка (по желанию)
   rm -rf uploads/*
   : > data/uploads.json
   : > data/uploads_meta.json
   : > data/files_meta.json
   : > data/downloads.json
   : > data/uploads.log
   : > logs/uploads.log
   : > data/php_errors.log

9. Запустить сервисы
   sudo systemctl enable --now php8.1-fpm nginx

10. Сменить администратора
    - После входа под `admin/admin123!` откройте “Manage Users”, смените пароль или создайте нового администратора и удалите стандартного.

9. Полезные команды
   sudo journalctl -u nginx -f
   sudo tail -f /var/log/nginx/uploader.error.log
   sudo tail -f /var/www/uploader/data/php_errors.log
   sudo systemctl reload nginx
   php -l data/имяФайла.php
   sqlite3 data/db.sqlite
   sudo certbot --nginx -d example.com   # используйте свой домен
