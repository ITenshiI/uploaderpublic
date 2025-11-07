<?php
$errorCode = $errorCode ?? ($code ?? 0);
$errorTitle = $errorTitle ?? 'Something went wrong';
$errorMessage = $errorMessage ?? 'The request could not be completed.';
$backgroundUrl = $backgroundUrl ?? block_background_url();
$ctaUrl = $ctaUrl ?? (rtrim(BASE_URL, '/') . '/');
$ctaLabel = $ctaLabel ?? 'Go back';
$extraDetails = isset($extraDetails) && is_array($extraDetails) ? $extraDetails : [];
$host = parse_url(rtrim(BASE_URL, '/'), PHP_URL_HOST) ?: 'Uploader';
$suppressText = !empty($suppressText);
$cardClass = 'card' . ($suppressText ? ' card--minimal' : '');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title><?=htmlspecialchars($errorTitle)?> · <?=htmlspecialchars($host)?></title>
<style>
:root {
    color-scheme: dark;
}
html, body {
    margin: 0;
    min-height: 100vh;
    font-family: "Inter","Segoe UI",sans-serif;
    color: #f8f3e9;
    background: #0b0d10;
}
.cover {
    display: block;
    min-height: 100vh;
    background-image: url('<?=htmlspecialchars($backgroundUrl, ENT_QUOTES)?>');
    background-size: cover;
    background-position: center;
    position: relative;
    text-decoration: none;
    color: inherit;
}
a.cover { cursor: pointer; }
.overlay {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: flex-end;
    justify-content: flex-end;
    padding: clamp(24px, 8vw, 120px) clamp(18px, 7vw, 80px);
    pointer-events: none;
}
.overlay > * {
    pointer-events: auto;
}
.card {
    width: min(460px, 92vw);
    padding: clamp(20px, 3.6vw, 30px);
    border-radius: 22px;
    backdrop-filter: blur(16px);
    background: rgba(12, 14, 20, 0.32);
    border: 1px solid rgba(221, 192, 124, 0.28);
    box-shadow: 0 22px 55px rgba(10,8,5,0.45);
    text-align: left;
    margin-left: auto;
}
.card--minimal {
    width: auto;
    max-width: min(360px, 90vw);
    padding: clamp(12px, 2.8vw, 20px);
    background: rgba(15, 17, 24, 0.35);
    border: 1px solid rgba(223, 199, 148, 0.18);
    display: inline-flex;
    flex-direction: column;
    gap: clamp(10px, 2vw, 16px);
}
.badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: clamp(60px, 10vw, 74px);
    height: clamp(60px, 10vw, 74px);
    border-radius: 24px;
    background: rgba(229, 194, 120, 0.18);
    font-weight: 700;
    font-size: clamp(24px, 4vw, 28px);
    margin-bottom: clamp(12px, 2vw, 20px);
    backdrop-filter: blur(18px);
    color: #f6e4c8;
}
h1 {
    margin: 0;
    font-size: clamp(26px, 4.4vw, 32px);
    letter-spacing: 0.4px;
    color: #fdf3dd;
}
.message {
    margin-top: clamp(10px, 1.8vw, 16px);
    font-size: clamp(15px, 3.4vw, 18px);
    line-height: 1.65;
    color: rgba(249, 238, 214, 0.9);
    white-space: pre-line;
}
.details {
    margin-top: clamp(16px, 2.4vw, 22px);
    padding-top: clamp(14px, 2.2vw, 20px);
    border-top: 1px solid rgba(244,215,148,0.18);
    font-size: clamp(13px, 2.8vw, 15px);
    color: rgba(251,236,210,0.78);
}
.details div {
    margin-bottom: 6px;
}
.actions {
    margin-top: clamp(20px, 3.6vw, 30px);
}
.btn {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: clamp(10px, 2vw, 14px) clamp(18px, 3.5vw, 24px);
    border-radius: 14px;
    border: none;
    cursor: pointer;
    font-weight: 600;
    text-decoration: none;
    color: #1b1b20;
    background: linear-gradient(135deg, #ffd66b, #ffba4c);
    box-shadow: 0 18px 44px rgba(180,124,48,0.45);
}
.btn:hover {
    background: linear-gradient(135deg, #ffd27a, #ffb040);
}
.hint {
    margin-top: clamp(12px, 2vw, 16px);
    font-size: clamp(12px, 2.4vw, 13px);
    color: rgba(245,220,175,0.58);
}
</style>
</head>
<body>
    <?php
        $wrapperTag = (!empty($ctaUrl) && $suppressText) ? 'a' : 'div';
        $wrapperAttrs = 'class="cover"';
        if ($wrapperTag === 'a') {
            $label = htmlspecialchars($ctaLabel ?? 'Go back', ENT_QUOTES);
            $wrapperAttrs .= ' href="' . htmlspecialchars($ctaUrl, ENT_QUOTES) . '" aria-label="' . $label . '"';
        }
    ?>
    <<?=$wrapperTag?> <?=$wrapperAttrs?>>
        <div class="overlay">
            <?php if (!$suppressText): ?>
            <div class="<?=$cardClass?>">
                <div class="badge"><?=htmlspecialchars((string)$errorCode)?></div>
                <h1><?=htmlspecialchars($errorTitle)?></h1>
                <p class="message"><?=htmlspecialchars($errorMessage)?></p>
                <?php if (!empty($extraDetails)): ?>
                    <div class="details">
                        <?php foreach ($extraDetails as $detail): ?>
                            <?php if (is_array($detail) && isset($detail['label'], $detail['value'])): ?>
                                <div><strong><?=htmlspecialchars((string)$detail['label'])?>:</strong> <?=htmlspecialchars((string)$detail['value'])?></div>
                            <?php elseif (is_string($detail)): ?>
                                <div><?=htmlspecialchars($detail)?></div>
                            <?php endif; ?>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                <?php if (!empty($ctaUrl)): ?>
                    <div class="actions">
                        <a class="btn" href="<?=htmlspecialchars($ctaUrl, ENT_QUOTES)?>">🔙 <?=htmlspecialchars($ctaLabel ?? 'Go back')?></a>
                    </div>
                <?php endif; ?>
                <div class="hint">Request handled by <?=htmlspecialchars($host)?>.</div>
            </div>
            <?php endif; ?>
        </div>
    </<?=$wrapperTag?>>
</body>
</html>
