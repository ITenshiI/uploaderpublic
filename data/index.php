<?php
require_once __DIR__ . '/functions.php';
require_login();
$pdo = get_pdo();
ensure_default_owner($pdo);
$user = current_user($pdo);
$csrf = csrf_token();
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Uploader Control Panel</title>
<style>
:root {
    color-scheme: dark;
    --bg: #17171f;
    --panel: #1f2030;
    --panel-alt: #27283a;
    --accent: #5f86ff;
    --accent-muted: rgba(95,134,255,0.15);
    --warn: #ff6e7a;
    --text: #f4f5ff;
    --text-muted: #a0a7c5;
    --border: rgba(255,255,255,0.08);
}
* { box-sizing: border-box; }
body {
    margin: 0;
    font-family: "Inter","Segoe UI",sans-serif;
    background: #11121a;
    color: var(--text);
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.container {
    max-width: 1100px;
    margin: 0 auto;
    padding: 24px;
}
header {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: 12px;
    align-items: center;
    margin-bottom: 20px;
}
.panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 22px;
    margin-bottom: 20px;
    box-shadow: 0 18px 40px rgba(0,0,0,0.35);
}
.panel h2 {
    margin: 0 0 12px;
    font-size: 19px;
}
.panel h2 span.sub { font-size: 13px; color: var(--text-muted); }
form.upload { display: flex; flex-direction: column; gap: 14px; }
button, .btn {
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 10px;
    padding: 9px 16px;
    cursor: pointer;
    font-weight: 600;
}
button.secondary {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text);
}
button.danger { background: var(--warn); }
button:disabled { opacity: 0.55; cursor: not-allowed; }
.upload input[type="file"] { display: none; }
.drop-zone {
    border: 2px dashed var(--border);
    border-radius: 14px;
    padding: 28px;
    text-align: center;
    background: rgba(255,255,255,0.03);
}
.drop-zone:hover,
.drop-zone.active {
    border-color: var(--accent);
    background: var(--accent-muted);
}
.drop-zone__icon { font-size: 32px; margin-bottom: 6px; }
.drop-zone__title { font-size: 18px; font-weight: 600; }
.drop-zone__hint { font-size: 13px; color: var(--text-muted); margin-bottom: 10px; }
.upload-actions { display: flex; gap: 10px; }
.upload-actions button { flex: 1; }
.controls {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 12px;
}
.controls input,
.controls select {
    background: var(--panel-alt);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 9px 11px;
    border-radius: 10px;
    font-size: 13px;
}
.controls button { padding: 8px 12px; }
.actions-row,
.admin-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}
.action-button {
    background: var(--panel-alt);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 10px;
    padding: 8px 14px;
    cursor: pointer;
    font-weight: 600;
}
.action-button:hover {
    background: var(--accent-muted);
}
.modal-body {
    padding: 20px;
    background: var(--panel);
    overflow: auto;
    max-height: 70vh;
    display: flex;
    flex-direction: column;
    gap: 16px;
}
.pager {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    margin: 12px 0;
}
.pager-info {
    font-size: 12px;
    color: var(--text-muted);
}
.pager-controls {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
}
.pager-controls label {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-muted);
}
.pager-controls input[type="number"] {
    width: 68px;
    background: rgba(30,32,46,0.8);
    border: 1px solid rgba(255,255,255,0.06);
    color: var(--text);
    border-radius: 8px;
    padding: 5px 8px;
    font-size: 12px;
}
.list-box {
    background: var(--panel-alt);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px;
    max-height: 220px;
    overflow: auto;
    font-size: 12px;
}
.list-box .row {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 6px 0;
    border-bottom: 1px solid rgba(255,255,255,0.05);
}
.list-box .row:last-child {
    border-bottom: none;
}
.help-block {
    font-size: 11px;
    color: var(--text-muted);
    line-height: 1.5;
}
.help-block code {
    background: rgba(255,255,255,0.08);
    padding: 1px 4px;
    border-radius: 4px;
}
.file-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill,minmax(240px,1fr));
    gap: 16px;
}
.card {
    background: linear-gradient(145deg, rgba(36,38,56,0.65), rgba(32,34,48,0.82));
    border: 1px solid rgba(255,255,255,0.04);
    border-radius: 16px;
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    box-shadow: 0 12px 28px rgba(0,0,0,0.32);
}
.card header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
}
.card .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}
.card .meta-right {
    font-size: 12px;
    color: var(--text-muted);
}
.card .name {
    font-weight: 600;
    font-size: 14px;
}
.card .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}
.card .actions button {
    background: rgba(255,255,255,0.12);
    border-radius: 8px;
    padding: 5px 10px;
    border: none;
}
.card .actions button.danger { background: var(--warn); }
.meta { font-size: 12px; color: var(--text-muted); }
.progress { height: 10px; border-radius: 999px; background: rgba(255,255,255,0.08); margin-top: 8px; }
.progress span { display: block; height: 100%; background: linear-gradient(135deg,#5f86ff,#a16bff); border-radius: inherit; }
.stats { margin-top: 10px; }
.stat-grid { display: flex; flex-wrap: wrap; gap: 10px; }
.stat-tile { background: rgba(255,255,255,0.04); border:1px solid var(--border); border-radius: 12px; padding: 10px 14px; min-width: 150px; }
.stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: var(--text-muted); }
.stat-value { font-size: 15px; font-weight: 600; }
.mini-upload input { background: var(--panel-alt); color: var(--text); border:1px solid var(--border); border-radius:8px; padding:7px; }
.mini-upload input[type="file"] { background: transparent; border: none; padding: 0; color: var(--text-muted); }
.modal {
    position: fixed;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background: rgba(7, 8, 13, 0.65);
    backdrop-filter: blur(6px);
    z-index: 1000;
}
.modal[hidden] { display: none !important; }
.modal-content {
    background: var(--panel-alt);
    border-radius: 18px;
    border: 1px solid var(--border);
    box-shadow: 0 32px 60px rgba(0,0,0,0.55);
    max-width: min(900px, 90vw);
    max-height: 85vh;
    width: 100%;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}
.modal-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 16px 20px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    font-weight: 600;
}
.modal-top .close {
    background: transparent;
    border: none;
    color: var(--text-muted);
    font-size: 24px;
    line-height: 1;
    padding: 4px 8px;
    cursor: pointer;
}
.modal-top .close:hover { color: var(--text); }
.preview-body {
    padding: 18px 20px 24px;
    background: var(--panel-alt);
    display: flex;
    flex-direction: column;
    gap: 16px;
    overflow: auto;
    flex: 1;
}
.preview-body img,
.preview-body video,
.preview-body iframe,
.preview-body audio {
    border-radius: 14px;
    width: 100%;
    max-height: 60vh;
    object-fit: contain;
    background: rgba(0,0,0,0.2);
}
.preview-body audio {
    max-height: none;
    background: transparent;
}
.preview-link {
    display: inline-block;
    padding: 8px 0;
    color: var(--accent);
}
body.modal-open { overflow: hidden; }
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>Uploader</h1>
        <div class="session">
            <?=htmlspecialchars($user['username'])?> · <?=htmlspecialchars($user['role'])?>
            &nbsp;|&nbsp;
            <a href="logout.php">Logout</a>
        </div>
    </header>

    <section class="panel">
        <h2>Upload <span class="sub">Drag & drop or choose files</span></h2>
        <form id="uploadForm" class="upload" enctype="multipart/form-data">
            <div class="drop-zone" id="dropZone">
                <div class="drop-zone__icon">📤</div>
                <div class="drop-zone__title">Drop files here</div>
                <div class="drop-zone__hint">Supported: images, video, audio, archives (up to 20GB)</div>
                <button type="button" class="secondary" id="browseBtn">Browse files</button>
                <input type="file" id="fileInput" name="files[]" multiple>
            </div>
            <div class="meta" id="selectedFiles">Files selected: 0</div>
            <div class="upload-actions">
                <button type="submit">Upload</button>
                <button type="button" class="secondary" id="clearFiles">Clear</button>
            </div>
        </form>
        <div id="uploadMessage" class="meta" style="margin-top:6px;"></div>
        <div class="stats" id="usageStats"></div>
        <div class="stats" id="serverStats" hidden></div>
        <div class="progress" id="usageBar" hidden><span style="width:0%"></span></div>
    </section>

    <section class="panel">
        <h2>Your Files</h2>
        <div class="controls">
            <input type="text" id="searchInput" placeholder="Search by name">
            <select id="typeSelect">
                <option value="">All types</option>
                <option value="image">Images</option>
                <option value="video">Videos</option>
                <option value="audio">Audio</option>
                <option value="text">Text</option>
            </select>
            <select id="sortSelect">
                <option value="created_desc">Newest first</option>
                <option value="created_asc">Oldest first</option>
                <option value="name_asc">Name A → Z</option>
                <option value="name_desc">Name Z → A</option>
                <option value="size_desc">Size ↓</option>
                <option value="size_asc">Size ↑</option>
                <option value="views_desc">Views ↓</option>
                <option value="views_asc">Views ↑</option>
                <option value="downloads_desc">Downloads ↓</option>
                <option value="downloads_asc">Downloads ↑</option>
            </select>
            <button type="button" id="refreshBtn">Refresh</button>
        </div>
        <div class="pager">
            <div class="pager-info" data-role="pager-info">Page 1 / 1</div>
            <div class="pager-controls">
                <button type="button" data-role="prev-page">Prev</button>
                <button type="button" data-role="next-page">Next</button>
                <label>Page
                    <input type="number" value="1" min="1" data-role="pager-input">
                </label>
            </div>
        </div>
        <div id="filesContainer" class="file-grid"></div>
        <div id="emptyState" class="empty" hidden>No files yet.</div>
        <div class="pager pager-bottom">
            <div class="pager-info" data-role="pager-info">Page 1 / 1</div>
            <div class="pager-controls">
                <button type="button" data-role="prev-page">Prev</button>
                <button type="button" data-role="next-page">Next</button>
                <label>Page
                    <input type="number" value="1" min="1" data-role="pager-input">
                </label>
            </div>
        </div>
    </section>

    <?php if ($user['role'] === 'admin'): ?>
    <section class="panel">
        <h2>Manage Users</h2>
        <form id="createUserForm" style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;">
            <input style="flex:1;min-width:160px;" type="text" id="newUserName" placeholder="Username" required>
            <input style="flex:1;min-width:160px;" type="password" id="newUserPassword" placeholder="Password" required>
            <select id="newUserRole" style="width:140px;">
                <option value="user">user</option>
                <option value="admin">admin</option>
            </select>
            <input style="width:140px;" type="number" id="newUserLimit" placeholder="Limit MB (blank=∞)" min="0" step="1">
            <button type="submit">Create user</button>
        </form>
        <div id="userMessage" class="meta"></div>
        <div class="admin-grid">
            <table id="usersTable">
                <thead>
                    <tr>
                        <th>User</th>
                        <th>Role</th>
                        <th>Files</th>
                        <th>Used</th>
                        <th>Limit</th>
                        <th>Last upload</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </section>
    <?php endif; ?>
</div>

<div class="modal" id="previewModal" hidden>
    <div class="modal-content">
        <div class="modal-top">
            <div id="previewTitle">Preview</div>
            <button class="close" type="button" onclick="closePreview()">×</button>
        </div>
        <div id="previewContent" class="preview-body"></div>
    </div>
</div>

<script>
const csrfToken = <?=json_encode($csrf)?>;
const currentUserId = <?=json_encode((int)$user['id'])?>;
const currentUsername = <?=json_encode($user['username'])?>;
const isAdmin = <?=json_encode($user['role'] === 'admin')?>;
const uploadForm = document.getElementById('uploadForm');
const fileInput = document.getElementById('fileInput');
const clearFilesBtn = document.getElementById('clearFiles');
const browseBtn = document.getElementById('browseBtn');
const dropZone = document.getElementById('dropZone');
const selectedFilesInfo = document.getElementById('selectedFiles');
const uploadMessage = document.getElementById('uploadMessage');
const usageStats = document.getElementById('usageStats');
const serverStats = document.getElementById('serverStats');
const usageBar = document.getElementById('usageBar');
const filesContainer = document.getElementById('filesContainer');
const emptyState = document.getElementById('emptyState');
const searchInput = document.getElementById('searchInput');
const typeSelect = document.getElementById('typeSelect');
const refreshBtn = document.getElementById('refreshBtn');
const sortSelect = document.getElementById('sortSelect');
const previewModal = document.getElementById('previewModal');
const previewContent = document.getElementById('previewContent');
const previewTitle = document.getElementById('previewTitle');
const pagerInfos = Array.from(document.querySelectorAll('[data-role="pager-info"]'));
const prevPageButtons = Array.from(document.querySelectorAll('[data-role="prev-page"]'));
const nextPageButtons = Array.from(document.querySelectorAll('[data-role="next-page"]'));
const pagerInputs = Array.from(document.querySelectorAll('[data-role="pager-input"]'));
serverStats.hidden = true;
let currentPage = 1;
let totalPages = 1;
let cachedUsers = [];
let modalElements = [];

function syncModalState() {
    const hasModal = modalElements.some(modal => !modal.hidden);
    document.body.classList.toggle('modal-open', hasModal);
}

function refreshPagerUI() {
    const label = `Page ${currentPage} / ${totalPages}`;
    pagerInfos.forEach(el => (el.textContent = label));
    prevPageButtons.forEach(btn => (btn.disabled = currentPage <= 1));
    nextPageButtons.forEach(btn => (btn.disabled = currentPage >= totalPages));
    pagerInputs.forEach(input => {
        input.value = currentPage;
        input.min = 1;
        input.max = Math.max(1, totalPages);
    });
}

const modalOpenButtons = Array.from(document.querySelectorAll('[data-open-modal]'));
const modalCloseButtons = Array.from(document.querySelectorAll('[data-close-modal]'));
modalElements = Array.from(document.querySelectorAll('.modal'));

function openModalElement(modal) {
    if (!modal) return;
    modal.hidden = false;
    syncModalState();
}

function closeModalElement(modal) {
    if (!modal) return;
    modal.hidden = true;
    syncModalState();
}

modalOpenButtons.forEach(btn => {
    const targetId = btn.dataset.openModal;
    btn.addEventListener('click', () => openModalElement(document.getElementById(targetId)));
});

modalCloseButtons.forEach(btn => {
    btn.addEventListener('click', () => closeModalElement(btn.closest('.modal')));
});

modalElements.forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeModalElement(modal);
        }
    });
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        modalElements.forEach(modal => {
            if (!modal.hidden && modal.id !== 'previewModal') {
                closeModalElement(modal);
            }
        });
    }
});

function updateSelectedFiles() {
    const count = fileInput.files ? fileInput.files.length : 0;
    selectedFilesInfo.textContent = `Files selected: ${count}`;
}

function humanSize(bytes) {
    if (bytes === null || bytes === undefined) return '—';
    const units = ['B','KB','MB','GB','TB'];
    let i = 0;
    let num = Number(bytes);
    while (num >= 1024 && i < units.length - 1) { num /= 1024; i++; }
    return num.toFixed(num >= 10 || i === 0 ? 0 : 1) + ' ' + units[i];
}

function fmtDate(isoString) {
    if (!isoString) return '—';
    const d = new Date(isoString + 'Z');
    return d.toLocaleString();
}

async function fetchJSON(url, options = {}) {
    const res = await fetch(url, options);
    const data = await res.json();
    if (!res.ok || data.ok === false) {
        throw new Error(data.error || res.statusText);
    }
    return data;
}

async function loadStats() {
    try {
        const data = await fetchJSON('api.php?action=stats');
        const u = data.user;
        const limit = u.upload_limit_bytes;
        const tiles = [];
        tiles.push({ label: 'Used', value: humanSize(u.usage_bytes) });
        tiles.push({ label: 'My Files', value: u.usage_files });
        if (limit !== null) {
            const remaining = u.remaining_bytes < 0 ? 0 : u.remaining_bytes;
            tiles.push({ label: 'Limit', value: humanSize(limit) });
            tiles.push({ label: 'Free', value: humanSize(remaining) });
            usageBar.hidden = false;
            const pct = limit === 0 ? 0 : Math.min(100, Math.round((u.usage_bytes / limit) * 100));
            usageBar.querySelector('span').style.width = pct + '%';
        } else {
            usageBar.hidden = true;
            usageBar.querySelector('span').style.width = '0%';
            tiles.push({ label: 'Limit', value: '∞' });
        }
        if (data.totals && isAdmin) {
            tiles.push({ label: 'Workspace', value: `${humanSize(data.totals.bytes)} · ${data.totals.files} files` });
        }
        usageStats.innerHTML = `<div class="stat-grid">${tiles.map(t => `<div class=\"stat-tile\"><span class=\"stat-label\">${t.label}</span><span class=\"stat-value\">${t.value}</span></div>`).join('')}</div>`;

        if (data.disk) {
            const disk = data.disk;
            const used = humanSize(disk.used_bytes);
            const total = humanSize(disk.total_bytes);
            const free = humanSize(disk.free_bytes);
            serverStats.hidden = false;
            serverStats.innerHTML = `<div class="stat-grid"><div class=\"stat-tile\"><span class=\"stat-label\">Server Used</span><span class=\"stat-value\">${used} / ${total}</span></div><div class=\"stat-tile\"><span class=\"stat-label\">Free</span><span class=\"stat-value\">${free}</span></div></div>`;
        } else {
            serverStats.hidden = true;
        }
    } catch (err) {
        usageStats.textContent = 'Failed to load stats: ' + err.message;
        serverStats.hidden = true;
    }
}

async function loadFiles() {
    const params = new URLSearchParams();
    if (searchInput.value.trim()) params.set('q', searchInput.value.trim());
    if (typeSelect.value) params.set('type', typeSelect.value);
    if (sortSelect.value) params.set('sort', sortSelect.value);
    params.set('page', currentPage);
    const query = params.toString();
    const url = 'api.php?action=list' + (query ? '&' + query : '');
    try {
        const data = await fetchJSON(url);
        totalPages = data.pages || 1;
        currentPage = data.page || 1;
        filesContainer.innerHTML = '';
        refreshPagerUI();
        if (!data.files.length) {
            emptyState.hidden = false;
            return;
        }
        emptyState.hidden = true;
        for (const f of data.files) {
            const card = document.createElement('div');
            card.className = 'card';
            const ownerName = f.owner ? f.owner : '';
            const uploadedMeta = ownerName ? `${ownerName} • ${fmtDate(f.created_at)}` : fmtDate(f.created_at);
            const publicUrl = f.public_url || f.download_url;
            const linkBlock = publicUrl
                ? `<div class="meta" style="word-break:break-all;">
                        <a href="${escapeAttr(publicUrl)}" target="_blank" rel="noopener">${escapeHtml(publicUrl)}</a>
                   </div>`
                : '';
            card.innerHTML = `
                <header>
                    <div class="name" title="${escapeHtml(f.original_name)}">${escapeHtml(f.original_name)}</div>
                    <div class="meta-right">${escapeHtml(humanSize(f.size))}</div>
                </header>
                <div class="meta">${escapeHtml(f.mime || 'unknown')}</div>
                <div class="meta">${escapeHtml(uploadedMeta)}</div>
                <div class="meta">👁 ${f.views} · ⬇ ${f.downloads}</div>
                ${linkBlock}
                <div class="actions">
                    <button type="button" onclick='openPreview(${f.id}, ${JSON.stringify(f.original_name)}, ${JSON.stringify(f.mime)}, ${JSON.stringify(publicUrl)})'>Preview</button>
                    <button type="button" onclick="downloadFile(${f.id})">Download</button>
                    <button type="button" onclick='copyLink(${JSON.stringify(publicUrl)})'>Copy link</button>
                    <button type="button" class="danger" onclick="deleteFile(${f.id})">Delete</button>
                </div>
            `;
            filesContainer.appendChild(card);
        }
    } catch (err) {
        filesContainer.innerHTML = '';
        emptyState.hidden = false;
        emptyState.textContent = 'Failed to load files: ' + err.message;
        refreshPagerUI();
    }
}

function escapeHtml(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function escapeAttr(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;');
}

uploadForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!fileInput.files.length) {
        uploadMessage.textContent = 'Choose at least one file.';
        return;
    }
    const fd = new FormData(uploadForm);
    uploadMessage.textContent = 'Uploading...';
    try {
        const res = await fetchJSON('api.php?action=upload', {
            method: 'POST',
            body: fd,
        });
        const success = res.results.filter(r => r.ok);
        const failures = res.results.filter(r => !r.ok);
        let parts = [];
        if (success.length) parts.push(`Uploaded: ${success.length}`);
        if (failures.length) {
            parts.push(`Failed: ${failures.length}`);
            failures.slice(0,3).forEach(f => {
                parts.push(`${f.name}: ${f.error}`);
            });
        }
        uploadMessage.innerHTML = parts.join('<br>');
        fileInput.value = '';
        updateSelectedFiles();
        await loadStats();
        await loadFiles();
    } catch (err) {
        uploadMessage.textContent = 'Upload failed: ' + err.message;
    }
});

clearFilesBtn.addEventListener('click', () => {
    fileInput.value = '';
    updateSelectedFiles();
});

if (browseBtn) {
    browseBtn.addEventListener('click', () => fileInput.click());
}

if (dropZone) {
    ['dragenter','dragover'].forEach(evt => dropZone.addEventListener(evt, e => {
        e.preventDefault();
        dropZone.classList.add('active');
    }));
    ['dragleave','drop'].forEach(evt => dropZone.addEventListener(evt, e => {
        if (evt === 'drop') return;
        dropZone.classList.remove('active');
    }));
    dropZone.addEventListener('drop', e => {
        e.preventDefault();
        dropZone.classList.remove('active');
        if (e.dataTransfer?.files?.length) {
            fileInput.files = e.dataTransfer.files;
            updateSelectedFiles();
        }
    });
}

if (fileInput) {
    fileInput.addEventListener('change', updateSelectedFiles);
    updateSelectedFiles();
}

refreshBtn.addEventListener('click', () => {
    currentPage = 1;
    loadFiles();
});

searchInput.addEventListener('input', debounce(() => {
    currentPage = 1;
    loadFiles();
}, 300));
typeSelect.addEventListener('change', () => { currentPage = 1; loadFiles(); });
sortSelect.addEventListener('change', () => { currentPage = 1; loadFiles(); });
prevPageButtons.forEach(btn => btn.addEventListener('click', () => {
    if (currentPage > 1) {
        currentPage--;
        loadFiles();
    }
}));
nextPageButtons.forEach(btn => btn.addEventListener('click', () => {
    if (currentPage < totalPages) {
        currentPage++;
        loadFiles();
    }
}));
pagerInputs.forEach(input => {
    const submit = () => {
        let target = Number(input.value) || currentPage;
        if (target < 1) target = 1;
        if (target > totalPages) target = totalPages;
        if (target !== currentPage) {
            currentPage = target;
            loadFiles();
        } else {
            refreshPagerUI();
        }
    };
    input.addEventListener('change', submit);
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            submit();
        }
    });
});

function debounce(fn, delay) {
    let t;
    return (...args) => {
        clearTimeout(t);
        t = setTimeout(() => fn(...args), delay);
    };
}

window.copyLink = async function(url) {
    if (!url) {
        alert('No public link available');
        return;
    }
    try {
        await navigator.clipboard.writeText(url);
        alert('Link copied to clipboard');
    } catch (err) {
        alert('Failed to copy link');
    }
};

window.openPreview = function(id, name = '', mime = '', publicUrl = '') {
    previewTitle.textContent = name ? `Preview · ${name}` : 'Preview';
    previewContent.innerHTML = '';
    const viewUrl = `api.php?action=download&id=${id}&inline=1&as=view`;
    const type = (mime || '').toLowerCase();
    let element;
    if (type.startsWith('image/')) {
        element = document.createElement('img');
        element.src = viewUrl;
        element.alt = name;
    } else if (type.startsWith('video/')) {
        element = document.createElement('video');
        element.src = viewUrl;
        element.controls = true;
        element.autoplay = true;
        element.loop = true;
    } else if (type.startsWith('audio/')) {
        element = document.createElement('audio');
        element.src = viewUrl;
        element.controls = true;
        element.autoplay = true;
    } else {
        element = document.createElement('iframe');
        element.src = publicUrl || viewUrl;
    }
    previewContent.appendChild(element);
    if (publicUrl) {
        const link = document.createElement('a');
        link.href = publicUrl;
        link.target = '_blank';
        link.rel = 'noopener';
        link.textContent = 'Open original link';
        link.className = 'preview-link';
        previewContent.appendChild(link);
    }
    previewModal.hidden = false;
    syncModalState();
};

window.downloadFile = function(id) {
    window.open(`api.php?action=download&id=${id}`, '_blank');
};

window.deleteFile = async function(id) {
    if (!confirm('Delete this file?')) return;
    try {
        await fetchJSON('api.php?action=delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, csrf: csrfToken })
        });
        await loadStats();
        await loadFiles();
    } catch (err) {
        alert('Failed to delete: ' + err.message);
    }
};

window.closePreview = function() {
    previewContent.innerHTML = '';
    previewModal.hidden = true;
    syncModalState();
};

previewModal.addEventListener('click', (e) => {
    if (e.target === previewModal) {
        closePreview();
    }
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !previewModal.hidden) {
        closePreview();
    }
});

async function loadUsers() {
    if (!isAdmin) return;
    const tbody = document.querySelector('#usersTable tbody');
    try {
        const data = await fetchJSON('api.php?action=users');
        tbody.innerHTML = '';
        cachedUsers = data.users;
        for (const u of data.users) {
            const tr = document.createElement('tr');
            const limitMb = u.upload_limit_bytes !== null ? Math.round(u.upload_limit_bytes / 1024 / 1024) : '';
            tr.innerHTML = `
                <td>${escapeHtml(u.username)}</td>
                <td>${escapeHtml(u.role)}</td>
                <td>${u.file_count}</td>
                <td>${humanSize(u.total_bytes)}</td>
                <td><input type="number" value="${limitMb}" min="0" step="1" data-field="limit" style="width:90px;background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px;"></td>
                <td>${u.last_upload ? fmtDate(u.last_upload) : '—'}</td>
                <td class="actions-cell">
                    <button type="button" data-action="set-password">Password</button>
                    <button type="button" data-action="save">Save</button>
                    <button type="button" class="danger" data-action="delete">Delete</button>
                </td>
            `;
            tr.dataset.id = u.id;
            tbody.appendChild(tr);
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7">Failed to load users: ${err.message}</td></tr>`;
    }
}

if (isAdmin) {
    const createUserForm = document.getElementById('createUserForm');
    const userMessage = document.getElementById('userMessage');

    createUserForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
            username: document.getElementById('newUserName').value.trim(),
            password: document.getElementById('newUserPassword').value,
            role: document.getElementById('newUserRole').value,
        };
        const limitVal = document.getElementById('newUserLimit').value;
        if (limitVal !== '') payload.upload_limit_mb = Number(limitVal);
        userMessage.textContent = 'Creating user...';
        try {
            await fetchJSON('api.php?action=users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            userMessage.textContent = 'User created.';
            createUserForm.reset();
            await loadUsers();
        } catch (err) {
            userMessage.textContent = 'Failed: ' + err.message;
        }
    });

    document.querySelector('#usersTable tbody').addEventListener('click', async (e) => {
        const btn = e.target.closest('button');
        if (!btn) return;
        const tr = btn.closest('tr');
        const userId = Number(tr.dataset.id);
        if (btn.dataset.action === 'delete') {
            if (!confirm('Delete this user?')) return;
            try {
                await fetchJSON('api.php?action=users', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id: userId }),
                });
                await loadUsers();
            } catch (err) {
                alert('Delete failed: ' + err.message);
            }
            return;
        }
        if (btn.dataset.action === 'save') {
            const limitInput = tr.querySelector('input[data-field="limit"]');
            const limitVal = limitInput.value;
            const payload = { id: userId };
            payload.upload_limit_mb = limitVal === '' ? '' : Number(limitVal);
            try {
                await fetchJSON('api.php?action=users', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                limitInput.style.borderColor = '#3fb950';
                setTimeout(() => (limitInput.style.borderColor = 'var(--border)'), 1500);
            } catch (err) {
                alert('Update failed: ' + err.message);
            }
            return;
        }
        if (btn.dataset.action === 'set-password') {
            const pwd = prompt('Enter new password');
            if (!pwd) return;
            try {
                await fetchJSON('api.php?action=users', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id: userId, password: pwd })
                });
                alert('Password updated');
            } catch (err) {
                alert('Failed: ' + err.message);
            }
        }
    });


}

(async function init(){
    await loadStats();
    await loadFiles();
    if (isAdmin) {
        await loadUsers();
    }
})();
</script>
</body>
</html>
