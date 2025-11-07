<?php
require_once __DIR__ . '/functions.php';
if (is_logged()) { header('Location: index.php'); exit; }

$err = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';
    if (!$u || !$p) $err = 'Provide username and password.';
    else {
        $pdo = get_pdo();
        $stmt = $pdo->prepare('SELECT id, password_hash, role FROM users WHERE username = ?');
        $stmt->execute([$u]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row && password_verify($p, $row['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['username'] = $u;
            $_SESSION['role'] = $row['role'];
            header('Location: index.php'); exit;
        } else {
            $err = 'Invalid credentials';
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Uploader · Login</title>
    <style>
        :root {
            color-scheme: dark;
            --bg: #14151a;
            --panel: #1e1f26;
            --accent: #4c8dff;
            --text: #f1f1f5;
            --muted: #8a8da0;
            --border: #2a2b35;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            display: flex;
            min-height: 100vh;
            align-items: center;
            justify-content: center;
            background: var(--bg);
            font-family: "Segoe UI", Arial, sans-serif;
            color: var(--text);
        }
        .box {
            width: 320px;
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 28px;
            box-shadow: 0 12px 32px rgba(0,0,0,0.35);
        }
        h1 {
            margin: 0 0 18px;
            font-size: 22px;
            text-align: center;
        }
        label {
            display: block;
            margin-bottom: 14px;
            font-size: 13px;
        }
        input {
            width: 100%;
            padding: 10px 12px;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: #121318;
            color: var(--text);
            margin-top: 6px;
        }
        button {
            width: 100%;
            padding: 12px;
            background: var(--accent);
            border: none;
            border-radius: 10px;
            color: #fff;
            font-size: 15px;
            cursor: pointer;
            margin-top: 10px;
        }
        .error {
            background: rgba(239, 71, 111, 0.12);
            border: 1px solid rgba(239, 71, 111, 0.4);
            color: #ffb3c6;
            padding: 10px 12px;
            border-radius: 8px;
            font-size: 13px;
            margin-bottom: 14px;
        }
        .meta {
            margin-top: 12px;
            font-size: 12px;
            color: var(--muted);
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="box">
        <h1>Uploader</h1>
        <?php if($err): ?><div class="error"><?=$err?></div><?php endif; ?>
        <form method="post" autocomplete="on">
            <label>
                Username
                <input name="username" autofocus>
            </label>
            <label>
                Password
                <input name="password" type="password">
            </label>
            <button type="submit">Login</button>
        </form>
        <div class="meta">
            Need an account? Ask an administrator.
        </div>
    </div>
</body>
</html>
