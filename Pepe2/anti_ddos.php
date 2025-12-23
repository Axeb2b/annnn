<?php

session_start();

// Rate Limiting
if (!isset($_SESSION['requests'])) {
    $_SESSION['requests'] = [];
}

$currentTime = time();
$_SESSION['requests'][] = $currentTime;

// Remove requests older than 10 seconds
$_SESSION['requests'] = array_filter($_SESSION['requests'], function ($time) use ($currentTime) {
    return ($currentTime - $time) < 10;
});

// Block if too many requests in 10 seconds
if (count($_SESSION['requests']) > 10) {
    header('HTTP/1.1 429 Too Many Requests');
    die('You are making requests too quickly.');
}

// Bot Detection by User-Agent
$botPatterns = [
    'curl', 'wget', 'bot', 'spider', 'crawler', 'python', 'php', 'httpclient', 'libwww'
];

$userAgent = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');

if (empty($userAgent) || preg_match('/' . implode('|', $botPatterns) . '/i', $userAgent)) {
    header('HTTP/1.1 403 Forbidden');
    die('Access denied. Bots are not allowed.');
}

// JavaScript Challenge
if (!isset($_SESSION['js_verified'])) {
    if (empty($_GET['js_token'])) {
        // Generate a unique token
        $token = base64_encode(hash('sha256', session_id() . microtime(), true));
        
        // Get the current URL
        $currentUrl = $_SERVER['REQUEST_URI'];

        // Check if there are existing query parameters
        $separator = strpos($currentUrl, '?') !== false ? '&' : '?';
        
        // Redirect to the same URL with the js_token parameter
        echo "
        <script>
            document.location.href = '$currentUrl$separator" . "js_token=$token';
        </script>
        ";
        exit;
    } else {
        // Validate the token and mark session as verified
        $_SESSION['js_verified'] = true;
    }
}

// Maintain a List of Known Malicious IPs
$maliciousIPs = [
    '123.456.789.000', // Replace with known bad IPs or ranges
    '111.222.333.0/24' // CIDR notation for ranges
];

$clientIP = $_SERVER['REMOTE_ADDR'];

// Function to check IP against malicious list
function isMaliciousIP($ip, $maliciousIPs)
{
    foreach ($maliciousIPs as $maliciousIP) {
        if (strpos($maliciousIP, '/') !== false) {
            list($range, $netmask) = explode('/', $maliciousIP, 2);
            if ((ip2long($ip) & ~((1 << (32 - $netmask)) - 1)) == ip2long($range)) {
                return true;
            }
        } elseif ($ip === $maliciousIP) {
            return true;
        }
    }
    return false;
}

if (isMaliciousIP($clientIP, $maliciousIPs)) {
    header('HTTP/1.1 403 Forbidden');
    die('Access denied. Your IP is blacklisted.');
}

// Honeypot Detection
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['honeypot'])) {
    header('HTTP/1.1 403 Forbidden');
    die('Access denied. Bot activity detected.');
}

// VPN Detection Function
function isVPN($ip) {
    // Use an IP intelligence API (e.g., ipinfo.io, ipstack, etc.) to detect VPNs/proxies
    $access_key = '992340268ea2d5'; // Replace with your API key from the chosen service

    // Construct the API URL
    $url = "http://ipinfo.io/{$ip}/json?token={$access_key}";

    // Make the request to the API
    $response = file_get_contents($url);
    $data = json_decode($response, true);

    // Check if the IP is flagged as a VPN or proxy
    if (isset($data['privacy']) && isset($data['privacy']['vpn']) && $data['privacy']['vpn']) {
        return true;  // VPN detected
    }
    
    return false;  // No VPN detected
}

// Check if the user's IP is a VPN
if (isVPN($clientIP)) {
    header('HTTP/1.1 403 Forbidden');
    die('Access denied. VPN detected.');
}

?>
