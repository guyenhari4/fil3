<?php
/**
 * Simple PHP File Manager dengan Login
 * --------------------------------------
 * - Login session-based (username & password di bawah)
 * - Setelah login: lihat, tambah, edit, hapus file & folder
 * - Folder yang dikelola: BASE_DIR (default: folder "storage" di samping file ini)
 *
 * CARA PAKAI:
 * 1. Upload file ini ke server (hosting/cPanel/VPS) yang sudah ada PHP.
 * 2. Akses lewat browser, contoh: https://domainkamu.com/filemanager.php
 * 3. Login dengan username & password di bawah.
 *
 * PENTING (KEAMANAN):
 * - GANTI password di bawah sebelum dipakai di server publik.
 * - Sebaiknya akses file ini lewat HTTPS, jangan HTTP biasa.
 * - File ini hanya mengelola folder BASE_DIR, BUKAN seluruh server (supaya aman).
 *   Kalau mau mengelola folder lain, ubah nilai BASE_DIR di bawah.
 */

session_start();
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);

// ============================================================
// 1. KONFIGURASI — UBAH SESUAI KEBUTUHAN
// ============================================================
define('AUTH_USER', 'admin');
define('AUTH_PASS', '@AdminGanteng123');

// Folder yang akan dikelola (default: subfolder "storage" di sebelah file ini)
define('BASE_DIR', __DIR__ . '/storage');
if (!is_dir(BASE_DIR)) {
    @mkdir(BASE_DIR, 0755, true);
}

// Batas ukuran upload (bytes) — default 20MB
define('MAX_UPLOAD_SIZE', 20 * 1024 * 1024);

// Ekstensi yang dianggap "teks" dan boleh dibuka/diedit langsung di browser
$EDITABLE_EXT = ['txt','md','html','htm','css','js','json','xml','php','ini','conf',
                  'log','sql','csv','yml','yaml','sh','py','java','c','cpp','h','env'];

// Ekstensi yang bisa di-PREVIEW langsung (gambar, video, PDF)
$IMAGE_EXT = ['jpg','jpeg','png','gif','webp','svg','bmp','ico'];
$VIDEO_EXT = ['mp4','webm','ogg','mov','mkv','avi'];
$PDF_EXT   = ['pdf'];

// Mapping ekstensi -> MIME type (dipakai saat streaming file untuk preview/download)
$MIME_MAP = [
    'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png',
    'gif' => 'image/gif', 'webp' => 'image/webp', 'svg' => 'image/svg+xml',
    'bmp' => 'image/bmp', 'ico' => 'image/x-icon',
    'mp4' => 'video/mp4', 'webm' => 'video/webm', 'ogg' => 'video/ogg',
    'mov' => 'video/quicktime', 'mkv' => 'video/x-matroska', 'avi' => 'video/x-msvideo',
    'pdf' => 'application/pdf',
];

function get_file_kind($ext) {
    global $IMAGE_EXT, $VIDEO_EXT, $PDF_EXT;
    $ext = strtolower($ext);
    if (in_array($ext, $IMAGE_EXT)) return 'image';
    if (in_array($ext, $VIDEO_EXT)) return 'video';
    if (in_array($ext, $PDF_EXT)) return 'pdf';
    return null;
}

// ============================================================
// 2. CSRF TOKEN
// ============================================================
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
function csrf_field() {
    return '<input type="hidden" name="csrf" value="' . htmlspecialchars($_SESSION['csrf_token']) . '">';
}
function csrf_ok() {
    return isset($_POST['csrf']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf']);
}

// ============================================================
// 3. LOGIN / LOGOUT
// ============================================================
function is_logged_in() {
    return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
}

$login_error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['do_login'])) {
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';
    if (hash_equals(AUTH_USER, $u) && hash_equals(AUTH_PASS, $p)) {
        session_regenerate_id(true);
        $_SESSION['logged_in'] = true;
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = 'Username atau password salah!';
    }
}

if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// ============================================================
// 4. HELPER PATH (anti path-traversal)
// ============================================================
// Membersihkan path relatif dari segmen ".." / kosong / titik
function clean_rel_path($path) {
    $path = str_replace('\\', '/', (string)$path);
    $parts = explode('/', $path);
    $clean = [];
    foreach ($parts as $p) {
        if ($p === '' || $p === '.' || $p === '..') continue;
        $clean[] = $p;
    }
    return implode('/', $clean);
}

// Mengubah path relatif menjadi path absolut di dalam BASE_DIR, lalu memastikan
// hasilnya benar-benar masih di dalam BASE_DIR (mencegah keluar folder).
function resolve_path($rel) {
    $rel = clean_rel_path($rel);
    $full = BASE_DIR . ($rel !== '' ? '/' . $rel : '');
    $baseReal = realpath(BASE_DIR);

    if (file_exists($full)) {
        $fullReal = realpath($full);
        if ($fullReal === false || strpos($fullReal, $baseReal) !== 0) {
            return false;
        }
        return $fullReal;
    } else {
        // Untuk file/folder yang belum ada (misalnya baru mau dibuat),
        // cek dulu parent-nya valid dan masih di dalam BASE_DIR.
        $parentReal = realpath(dirname($full));
        if ($parentReal === false || strpos($parentReal, $baseReal) !== 0) {
            return false;
        }
        return $full;
    }
}

function human_size($bytes) {
    $units = ['B','KB','MB','GB','TB'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    return round($bytes, 2) . ' ' . $units[$i];
}

function is_valid_name($name) {
    // Nama file/folder tidak boleh kosong, tidak boleh berisi karakter path
    return $name !== '' && !preg_match('/[\/\\\\]/', $name) && $name !== '.' && $name !== '..';
}

function delete_recursive($path) {
    if (is_dir($path) && !is_link($path)) {
        $items = scandir($path);
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            delete_recursive($path . '/' . $item);
        }
        return rmdir($path);
    }
    return unlink($path);
}

// ============================================================
// 5. PROSES AKSI (hanya boleh jalan kalau sudah login)
// ============================================================
$message = '';
$message_type = 'success'; // success | error

if (is_logged_in()) {
    $curRel = clean_rel_path($_GET['dir'] ?? '');

    // ---- Buat folder baru ----
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'mkdir') {
        if (!csrf_ok()) {
            $message = 'Token keamanan tidak valid.'; $message_type = 'error';
        } else {
            $name = trim($_POST['name'] ?? '');
            $dir = clean_rel_path($_POST['dir'] ?? '');
            if (!is_valid_name($name)) {
                $message = 'Nama folder tidak valid.'; $message_type = 'error';
            } else {
                $target = resolve_path($dir . '/' . $name);
                if ($target === false) {
                    $message = 'Path tidak valid.'; $message_type = 'error';
                } elseif (file_exists($target)) {
                    $message = 'Nama tersebut sudah dipakai.'; $message_type = 'error';
                } elseif (mkdir($target, 0755)) {
                    $message = "Folder \"$name\" berhasil dibuat."; $message_type = 'success';
                } else {
                    $message = 'Gagal membuat folder.'; $message_type = 'error';
                }
            }
        }
    }

    // ---- Buat file baru (kosong) ----
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'mkfile') {
        if (!csrf_ok()) {
            $message = 'Token keamanan tidak valid.'; $message_type = 'error';
        } else {
            $name = trim($_POST['name'] ?? '');
            $dir = clean_rel_path($_POST['dir'] ?? '');
            if (!is_valid_name($name)) {
                $message = 'Nama file tidak valid.'; $message_type = 'error';
            } else {
                $target = resolve_path($dir . '/' . $name);
                if ($target === false) {
                    $message = 'Path tidak valid.'; $message_type = 'error';
                } elseif (file_exists($target)) {
                    $message = 'Nama tersebut sudah dipakai.'; $message_type = 'error';
                } elseif (file_put_contents($target, '') !== false) {
                    $message = "File \"$name\" berhasil dibuat."; $message_type = 'success';
                } else {
                    $message = 'Gagal membuat file.'; $message_type = 'error';
                }
            }
        }
    }

    // ---- Simpan hasil edit file ----
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'save') {
        if (!csrf_ok()) {
            $message = 'Token keamanan tidak valid.'; $message_type = 'error';
        } else {
            $rel = $_POST['target'] ?? '';
            $target = resolve_path($rel);
            if ($target === false || !is_file($target)) {
                $message = 'File tidak ditemukan.'; $message_type = 'error';
            } else {
                $content = $_POST['content'] ?? '';
                if (file_put_contents($target, $content) !== false) {
                    $message = 'File berhasil disimpan.'; $message_type = 'success';
                } else {
                    $message = 'Gagal menyimpan file.'; $message_type = 'error';
                }
            }
        }
    }

    // ---- Rename file/folder ----
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'rename') {
        if (!csrf_ok()) {
            $message = 'Token keamanan tidak valid.'; $message_type = 'error';
        } else {
            $rel = $_POST['target'] ?? '';
            $newName = trim($_POST['new_name'] ?? '');
            $old = resolve_path($rel);
            if ($old === false || !file_exists($old)) {
                $message = 'Item tidak ditemukan.'; $message_type = 'error';
            } elseif (!is_valid_name($newName)) {
                $message = 'Nama baru tidak valid.'; $message_type = 'error';
            } else {
                $newTarget = dirname($old) . '/' . $newName;
                if (file_exists($newTarget)) {
                    $message = 'Nama tersebut sudah dipakai.'; $message_type = 'error';
                } elseif (rename($old, $newTarget)) {
                    $message = 'Berhasil diubah nama.'; $message_type = 'success';
                } else {
                    $message = 'Gagal mengubah nama.'; $message_type = 'error';
                }
            }
        }
    }

    // ---- Hapus file/folder ----
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete') {
        if (!csrf_ok()) {
            $message = 'Token keamanan tidak valid.'; $message_type = 'error';
        } else {
            $rel = $_POST['target'] ?? '';
            $target = resolve_path($rel);
            if ($target === false || !file_exists($target) || $target === realpath(BASE_DIR)) {
                $message = 'Item tidak ditemukan / tidak boleh dihapus.'; $message_type = 'error';
            } elseif (delete_recursive($target)) {
                $message = 'Berhasil dihapus.'; $message_type = 'success';
            } else {
                $message = 'Gagal menghapus.'; $message_type = 'error';
            }
        }
    }

    // ---- Upload file ----
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'upload') {
        if (!csrf_ok()) {
            $message = 'Token keamanan tidak valid.'; $message_type = 'error';
        } elseif (!isset($_FILES['upload_file']) || $_FILES['upload_file']['error'] === UPLOAD_ERR_NO_FILE) {
            $message = 'Tidak ada file yang dipilih.'; $message_type = 'error';
        } else {
            $dir = clean_rel_path($_POST['dir'] ?? '');
            $f = $_FILES['upload_file'];
            $name = basename($f['name']);
            if ($f['error'] !== UPLOAD_ERR_OK) {
                $message = 'Upload gagal (kode error: ' . $f['error'] . ').'; $message_type = 'error';
            } elseif ($f['size'] > MAX_UPLOAD_SIZE) {
                $message = 'Ukuran file terlalu besar (maks ' . human_size(MAX_UPLOAD_SIZE) . ').'; $message_type = 'error';
            } elseif (!is_valid_name($name)) {
                $message = 'Nama file tidak valid.'; $message_type = 'error';
            } else {
                $target = resolve_path($dir . '/' . $name);
                if ($target === false) {
                    $message = 'Path tujuan tidak valid.'; $message_type = 'error';
                } elseif (move_uploaded_file($f['tmp_name'], $target)) {
                    $message = "File \"$name\" berhasil diupload."; $message_type = 'success';
                } else {
                    $message = 'Gagal menyimpan file upload.'; $message_type = 'error';
                }
            }
        }
    }
}

// ============================================================
// 6. MODE STREAM (untuk preview gambar/video/PDF langsung di browser)
// ============================================================
if (is_logged_in() && isset($_GET['stream'])) {
    $target = resolve_path($_GET['stream']);
    if ($target !== false && is_file($target)) {
        $ext = strtolower(pathinfo($target, PATHINFO_EXTENSION));
        $mime = $MIME_MAP[$ext] ?? 'application/octet-stream';
        $size = filesize($target);

        header('Content-Type: ' . $mime);
        header('Content-Disposition: inline; filename="' . basename($target) . '"');
        header('Accept-Ranges: bytes');

        // Dukung "range request" supaya video bisa di-seek (maju/mundur)
        if (isset($_SERVER['HTTP_RANGE'])) {
            $range = $_SERVER['HTTP_RANGE'];
            list(, $range) = explode('=', $range, 2);
            list($start, $end) = explode('-', $range) + [1 => ''];
            $start = (int)$start;
            $end = ($end === '' ) ? $size - 1 : (int)$end;
            $length = $end - $start + 1;

            http_response_code(206);
            header("Content-Range: bytes $start-$end/$size");
            header('Content-Length: ' . $length);

            $fp = fopen($target, 'rb');
            fseek($fp, $start);
            $remaining = $length;
            while ($remaining > 0 && !feof($fp)) {
                $chunk = min(8192, $remaining);
                echo fread($fp, $chunk);
                $remaining -= $chunk;
            }
            fclose($fp);
        } else {
            header('Content-Length: ' . $size);
            readfile($target);
        }
        exit;
    }
}

// ============================================================
// 7. MODE DOWNLOAD (langsung output file, lalu exit)
// ============================================================
if (is_logged_in() && isset($_GET['download'])) {
    $target = resolve_path($_GET['download']);
    if ($target !== false && is_file($target)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($target) . '"');
        header('Content-Length: ' . filesize($target));
        readfile($target);
        exit;
    }
}

// ============================================================
// 7. TAMPILAN (HTML)
// ============================================================
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= is_logged_in() ? 'File Manager' : 'Login - File Manager' ?></title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f172a; color: #e2e8f0; min-height: 100vh;
  }
  a { color: #60a5fa; text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* ---- Login page ---- */
  .login-wrap {
    display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px;
  }
  .login-box {
    background: #1e293b; padding: 36px 32px; border-radius: 14px; width: 100%; max-width: 380px;
    box-shadow: 0 10px 40px rgba(0,0,0,.4);
  }
  .login-box h1 { font-size: 20px; margin: 0 0 6px; text-align: center; }
  .login-box p.sub { text-align: center; color: #94a3b8; font-size: 13px; margin: 0 0 24px; }
  .field { margin-bottom: 16px; }
  .field label { display: block; font-size: 13px; margin-bottom: 6px; color: #cbd5e1; }
  .field input {
    width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid #334155;
    background: #0f172a; color: #e2e8f0; font-size: 14px;
  }
  .field input:focus { outline: none; border-color: #60a5fa; }
  .btn {
    width: 100%; padding: 11px; border-radius: 8px; border: none; background: #2563eb;
    color: white; font-size: 14px; font-weight: 600; cursor: pointer;
  }
  .btn:hover { background: #1d4ed8; }
  .alert {
    padding: 10px 14px; border-radius: 8px; font-size: 13px; margin-bottom: 16px;
  }
  .alert.error { background: #7f1d1d; color: #fecaca; }
  .alert.success { background: #14532d; color: #bbf7d0; }

  /* ---- File manager page ---- */
  .topbar {
    display: flex; align-items: center; justify-content: space-between; padding: 14px 22px;
    background: #1e293b; border-bottom: 1px solid #334155;
  }
  .topbar h1 { font-size: 17px; margin: 0; }
  .topbar .logout { font-size: 13px; color: #f87171; }
  .container { padding: 22px; max-width: 1000px; margin: 0 auto; }
  .breadcrumb { margin-bottom: 16px; font-size: 14px; color: #94a3b8; }
  .breadcrumb a { margin-right: 2px; }

  .toolbar { display: flex; gap: 10px; margin-bottom: 18px; flex-wrap: wrap; }
  .toolbar button, .toolbar label.btn-like {
    background: #334155; color: #e2e8f0; border: none; padding: 8px 14px; border-radius: 7px;
    font-size: 13px; cursor: pointer;
  }
  .toolbar button:hover, .toolbar label.btn-like:hover { background: #475569; }

  table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; }
  th, td { padding: 10px 14px; text-align: left; font-size: 13.5px; border-bottom: 1px solid #283548; }
  th { color: #94a3b8; font-weight: 600; font-size: 12px; text-transform: uppercase; }
  tr:last-child td { border-bottom: none; }
  td.actions { white-space: nowrap; text-align: right; }
  td.actions form { display: inline; }
  td.actions button, td.actions a.act {
    background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 12.5px;
    margin-left: 10px; padding: 0;
  }
  td.actions a.act.edit { color: #60a5fa; }
  td.actions button.delete { color: #f87171; }
  td.actions button.rename { color: #fbbf24; }
  .icon { margin-right: 8px; }
  .empty-row { text-align: center; color: #64748b; padding: 30px; }

  .modal-overlay {
    display: none; position: fixed; inset: 0; background: rgba(0,0,0,.6);
    align-items: center; justify-content: center; z-index: 50; padding: 20px;
  }
  .modal-overlay.show { display: flex; }
  .modal-box {
    background: #1e293b; border-radius: 12px; padding: 24px; width: 100%; max-width: 420px;
  }
  .modal-box h3 { margin: 0 0 16px; font-size: 16px; }
  .modal-box input[type=text] {
    width: 100%; padding: 9px 11px; border-radius: 7px; border: 1px solid #334155;
    background: #0f172a; color: #e2e8f0; margin-bottom: 14px; font-size: 13.5px;
  }
  .modal-actions { display: flex; gap: 10px; justify-content: flex-end; }
  .modal-actions button { padding: 8px 16px; border-radius: 7px; border: none; font-size: 13px; cursor: pointer; }
  .modal-actions .cancel { background: #334155; color: #e2e8f0; }
  .modal-actions .confirm { background: #2563eb; color: white; }

  textarea.editor {
    width: 100%; min-height: 420px; background: #0f172a; color: #e2e8f0; border: 1px solid #334155;
    border-radius: 8px; padding: 14px; font-family: 'Courier New', monospace; font-size: 13.5px;
    line-height: 1.5; resize: vertical;
  }
  .editor-actions { margin-top: 14px; display: flex; gap: 10px; }
  .editor-actions a, .editor-actions button {
    padding: 9px 18px; border-radius: 7px; border: none; font-size: 13.5px; cursor: pointer;
  }
  .editor-actions button { background: #2563eb; color: white; }
  .editor-actions a { background: #334155; color: #e2e8f0; }

  /* ---- Preview gambar / video / PDF ---- */
  .preview-box {
    background: #0f172a; border: 1px solid #334155; border-radius: 10px;
    padding: 16px; display: flex; align-items: center; justify-content: center;
    min-height: 300px;
  }
  .preview-box img {
    max-width: 100%; max-height: 75vh; border-radius: 6px; display: block;
  }
  .preview-box video {
    max-width: 100%; max-height: 75vh; border-radius: 6px;
  }
  .preview-box iframe {
    width: 100%; height: 80vh; border: none; border-radius: 6px; background: #fff;
  }
</style>
</head>
<body>

<?php if (!is_logged_in()): ?>

  <!-- ============== HALAMAN LOGIN ============== -->
  <div class="login-wrap">
    <div class="login-box">
      <h1>🔒 File Manager</h1>
      <p class="sub">Silakan login untuk melanjutkan</p>
      <?php if ($login_error): ?>
        <div class="alert error"><?= htmlspecialchars($login_error) ?></div>
      <?php endif; ?>
      <form method="post">
        <div class="field">
          <label>Username</label>
          <input type="text" name="username" autocomplete="username" required autofocus>
        </div>
        <div class="field">
          <label>Password</label>
          <input type="password" name="password" autocomplete="current-password" required>
        </div>
        <input type="hidden" name="do_login" value="1">
        <button class="btn" type="submit">Masuk</button>
      </form>
    </div>
  </div>

<?php else: ?>

  <?php
  // ---------- Mode edit file ----------
  $editTarget = null;
  $editContent = '';
  if (isset($_GET['edit'])) {
      $t = resolve_path($_GET['edit']);
      if ($t !== false && is_file($t)) {
          $editTarget = $t;
          $editContent = file_get_contents($t);
      }
  }

  // ---------- Mode preview file (gambar/video/PDF) ----------
  $previewTarget = null;
  $previewKind = null;
  $previewRel = '';
  if (isset($_GET['preview'])) {
      $t = resolve_path($_GET['preview']);
      if ($t !== false && is_file($t)) {
          $ext = strtolower(pathinfo($t, PATHINFO_EXTENSION));
          $kind = get_file_kind($ext);
          if ($kind !== null) {
              $previewTarget = $t;
              $previewKind = $kind;
              $previewRel = ltrim(substr($t, strlen(realpath(BASE_DIR))), '/');
          }
      }
  }
  ?>

  <div class="topbar">
    <h1>📁 File Manager</h1>
    <a class="logout" href="?logout=1">Logout</a>
  </div>

  <div class="container">

    <?php if ($message): ?>
      <div class="alert <?= $message_type ?>"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <?php if ($previewTarget !== null): ?>

      <!-- ============== HALAMAN PREVIEW FILE (GAMBAR/VIDEO/PDF) ============== -->
      <?php $backDir = dirname($previewRel) === '.' ? '' : dirname($previewRel); ?>
      <h2 style="font-size:15px;margin-bottom:14px;">Lihat: <?= htmlspecialchars($previewRel) ?></h2>

      <div class="preview-box">
        <?php if ($previewKind === 'image'): ?>
          <img src="?stream=<?= urlencode($previewRel) ?>" alt="<?= htmlspecialchars($previewRel) ?>">
        <?php elseif ($previewKind === 'video'): ?>
          <video controls preload="metadata">
            <source src="?stream=<?= urlencode($previewRel) ?>">
            Browser kamu tidak mendukung pemutaran video ini.
          </video>
        <?php elseif ($previewKind === 'pdf'): ?>
          <iframe src="?stream=<?= urlencode($previewRel) ?>"></iframe>
        <?php endif; ?>
      </div>

      <div class="editor-actions">
        <a href="?stream=<?= urlencode($previewRel) ?>" target="_blank">🔗 Buka di Tab Baru</a>
        <a href="?download=<?= urlencode($previewRel) ?>">⬇️ Unduh</a>
        <a href="?dir=<?= urlencode($backDir) ?>">Kembali</a>
      </div>

    <?php elseif ($editTarget !== null): ?>

      <!-- ============== HALAMAN EDIT FILE ============== -->
      <?php $relEdit = ltrim(substr($editTarget, strlen(realpath(BASE_DIR))), '/'); ?>
      <h2 style="font-size:15px;margin-bottom:14px;">Edit: <?= htmlspecialchars($relEdit) ?></h2>
      <form method="post">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="save">
        <input type="hidden" name="target" value="<?= htmlspecialchars($relEdit) ?>">
        <textarea class="editor" name="content"><?= htmlspecialchars($editContent) ?></textarea>
        <div class="editor-actions">
          <button type="submit">💾 Simpan</button>
          <a href="?dir=<?= urlencode(dirname($relEdit) === '.' ? '' : dirname($relEdit)) ?>">Batal / Kembali</a>
        </div>
      </form>

    <?php else: ?>

      <!-- ============== HALAMAN DAFTAR FILE/FOLDER ============== -->
      <?php
      $curFull = resolve_path($curRel);
      if ($curFull === false || !is_dir($curFull)) {
          $curRel = '';
          $curFull = realpath(BASE_DIR);
      }

      // Breadcrumb
      echo '<div class="breadcrumb"><a href="?dir=">🏠 Root</a>';
      if ($curRel !== '') {
          $accum = '';
          foreach (explode('/', $curRel) as $seg) {
              $accum .= ($accum === '' ? '' : '/') . $seg;
              echo ' / <a href="?dir=' . urlencode($accum) . '">' . htmlspecialchars($seg) . '</a>';
          }
      }
      echo '</div>';
      ?>

      <div class="toolbar">
        <button onclick="openModal('mkdirModal')">📁 Folder Baru</button>
        <button onclick="openModal('mkfileModal')">📄 File Baru</button>
        <label class="btn-like" for="uploadInput">⬆️ Upload File</label>
        <form id="uploadForm" method="post" enctype="multipart/form-data" style="display:inline">
          <?= csrf_field() ?>
          <input type="hidden" name="action" value="upload">
          <input type="hidden" name="dir" value="<?= htmlspecialchars($curRel) ?>">
          <input type="file" id="uploadInput" name="upload_file" style="display:none" onchange="document.getElementById('uploadForm').submit()">
        </form>
      </div>

      <table>
        <tr><th>Nama</th><th>Ukuran</th><th>Diubah</th><th></th></tr>

        <?php
        $items = scandir($curFull);
        $folders = []; $files = [];
        foreach ($items as $it) {
            if ($it === '.' || $it === '..') continue;
            $p = $curFull . '/' . $it;
            if (is_dir($p)) $folders[] = $it; else $files[] = $it;
        }
        natcasesort($folders); natcasesort($files);

        if (empty($folders) && empty($files)) {
            echo '<tr><td colspan="4" class="empty-row">Folder ini kosong.</td></tr>';
        }

        foreach ($folders as $name):
            $rel = ($curRel !== '' ? $curRel . '/' : '') . $name;
        ?>
          <tr>
            <td><a href="?dir=<?= urlencode($rel) ?>"><span class="icon">📁</span><?= htmlspecialchars($name) ?></a></td>
            <td>—</td>
            <td><?= date('d M Y H:i', filemtime($curFull . '/' . $name)) ?></td>
            <td class="actions">
              <button type="button" class="rename" onclick="openRename('<?= htmlspecialchars(addslashes($rel)) ?>','<?= htmlspecialchars(addslashes($name)) ?>')">Rename</button>
              <form method="post" onsubmit="return confirm('Hapus folder \'<?= htmlspecialchars(addslashes($name)) ?>\' beserta isinya?');">
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="target" value="<?= htmlspecialchars($rel) ?>">
                <button type="submit" class="delete">Hapus</button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>

        <?php foreach ($files as $name):
            $rel = ($curRel !== '' ? $curRel . '/' : '') . $name;
            $fullF = $curFull . '/' . $name;
            $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
            $canEdit = in_array($ext, $EDITABLE_EXT) || $ext === '';
            $fileKind = get_file_kind($ext);
        ?>
          <tr>
            <td><span class="icon"><?= $fileKind ? ($fileKind === 'image' ? '🖼️' : ($fileKind === 'video' ? '🎬' : '📕')) : '📄' ?></span><?= htmlspecialchars($name) ?></td>
            <td><?= human_size(filesize($fullF)) ?></td>
            <td><?= date('d M Y H:i', filemtime($fullF)) ?></td>
            <td class="actions">
              <?php if ($fileKind !== null): ?>
                <a class="act edit" href="?preview=<?= urlencode($rel) ?>">Lihat</a>
              <?php endif; ?>
              <?php if ($canEdit): ?>
                <a class="act edit" href="?edit=<?= urlencode($rel) ?>">Edit</a>
              <?php endif; ?>
              <a class="act" href="?download=<?= urlencode($rel) ?>">Unduh</a>
              <button type="button" class="rename" onclick="openRename('<?= htmlspecialchars(addslashes($rel)) ?>','<?= htmlspecialchars(addslashes($name)) ?>')">Rename</button>
              <form method="post" onsubmit="return confirm('Hapus file \'<?= htmlspecialchars(addslashes($name)) ?>\'?');">
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="target" value="<?= htmlspecialchars($rel) ?>">
                <button type="submit" class="delete">Hapus</button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
      </table>

      <!-- ===== Modal: Folder Baru ===== -->
      <div class="modal-overlay" id="mkdirModal">
        <div class="modal-box">
          <h3>📁 Buat Folder Baru</h3>
          <form method="post">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="mkdir">
            <input type="hidden" name="dir" value="<?= htmlspecialchars($curRel) ?>">
            <input type="text" name="name" placeholder="Nama folder" required autofocus>
            <div class="modal-actions">
              <button type="button" class="cancel" onclick="closeModal('mkdirModal')">Batal</button>
              <button type="submit" class="confirm">Buat</button>
            </div>
          </form>
        </div>
      </div>

      <!-- ===== Modal: File Baru ===== -->
      <div class="modal-overlay" id="mkfileModal">
        <div class="modal-box">
          <h3>📄 Buat File Baru</h3>
          <form method="post">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="mkfile">
            <input type="hidden" name="dir" value="<?= htmlspecialchars($curRel) ?>">
            <input type="text" name="name" placeholder="contoh: catatan.txt" required autofocus>
            <div class="modal-actions">
              <button type="button" class="cancel" onclick="closeModal('mkfileModal')">Batal</button>
              <button type="submit" class="confirm">Buat</button>
            </div>
          </form>
        </div>
      </div>

      <!-- ===== Modal: Rename ===== -->
      <div class="modal-overlay" id="renameModal">
        <div class="modal-box">
          <h3>✏️ Ubah Nama</h3>
          <form method="post">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="rename">
            <input type="hidden" name="target" id="renameTarget" value="">
            <input type="text" name="new_name" id="renameNewName" placeholder="Nama baru" required>
            <div class="modal-actions">
              <button type="button" class="cancel" onclick="closeModal('renameModal')">Batal</button>
              <button type="submit" class="confirm">Simpan</button>
            </div>
          </form>
        </div>
      </div>

      <script>
        function openModal(id) { document.getElementById(id).classList.add('show'); }
        function closeModal(id) { document.getElementById(id).classList.remove('show'); }
        function openRename(target, currentName) {
          document.getElementById('renameTarget').value = target;
          document.getElementById('renameNewName').value = currentName;
          openModal('renameModal');
        }
        document.querySelectorAll('.modal-overlay').forEach(function(ov){
          ov.addEventListener('click', function(e){
            if (e.target === ov) ov.classList.remove('show');
          });
        });
      </script>

    <?php endif; ?>

  </div>

<?php endif; ?>

</body>
</html>