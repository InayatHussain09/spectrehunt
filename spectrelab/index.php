<?php
// SpectreLab v1.1 - Optimized for SpectreHunt Testing
// Author: Inayat Hussain

header('Content-Type: text/html; charset=utf-8');

echo "<html><head><title>SpectreLab</title></head><body>";
echo "<h1>SpectreLab v1.1</h1>";
echo "<p>Welcome to the vulnerable test environment.</p>";

// Expose parameters in HTML so the Crawler finds them
echo "<ul>";
echo "<li><a href='?page=home.php'>Home (LFI)</a></li>";
echo "<li><a href='?page=admin.php'>Admin (LFI)</a></li>";
echo "<li><a href='?cmd=whoami'>System Info (RCE)</a></li>";
echo "<li><a href='?remote=http://localhost:8000/secret.txt'>Load Remote (RFI)</a></li>";
echo "<li><a href='?file=secret.txt'>View File (Traversal)</a></li>";
echo "</ul>";
echo "<hr>";

// 1. LFI / Path Traversal Vector
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    echo "<h3>LFI/Path Traversal Endpoint</h3>";
    echo "<p>Current Page Parameter: " . htmlspecialchars($page) . "</p>";
    
    // VULNERABILITY: LFI
    // We check if the file exists to avoid PHP warnings, but we still include it
    if (file_exists($page)) {
        include($page);
    } else {
        // If it's a path traversal attempt that doesn't exist, show the path
        echo "<p>File not found, but attempting to read: " . htmlspecialchars($page) . "</p>";
        // For testing purposes, if 'etc/passwd' is in the string, we simulate the read
        if (strpos($page, 'etc/passwd') !== false) {
            echo "<pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin</pre>";
        }
    }
} 

// 2. RCE / Command Injection Vector
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo "<h3>RCE/Command Injection Endpoint</h3>";
    echo "<p>Command Parameter: " . htmlspecialchars($cmd) . "</p>";
    
    // VULNERABILITY: Command Injection
    $output = shell_exec($cmd);
    echo "<pre>" . htmlspecialchars($output) . "</pre>";
}

// 3. RFI Vector
if (isset($_GET['remote'])) {
    $remote = $_GET['remote'];
    echo "<h3>RFI Endpoint</h3>";
    echo "<p>Remote URL: " . htmlspecialchars($remote) . "</p>";
    
    // VULNERABILITY: RFI
    // We simulate RFI by fetching the content. If 'php' is in the URL, we execute it (simulated)
    if (filter_var($remote, FILTER_VALIDATE_URL)) {
        // Check if it's a local file or remote
        if (strpos($remote, 'localhost') !== false || strpos($remote, '127.0.0.1') !== false) {
            // Simulate local include
            $path = parse_url($remote, PHP_URL_PATH);
            if (file_exists($path)) {
                echo "<pre>" . htmlspecialchars(file_get_contents($path)) . "</pre>";
            } else {
                echo "<p>Local file not found.</p>";
            }
        } else {
            // Simulate remote fetch
            $content = @file_get_contents($remote);
            if ($content !== false) {
                echo "<pre>" . htmlspecialchars($content) . "</pre>";
            } else {
                echo "<p>Failed to fetch remote content.</p>";
            }
        }
    } else {
        echo "<p>Invalid URL.</p>";
    }
}

// 4. Path Traversal / File Read Vector
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    echo "<h3>File Read Endpoint</h3>";
    echo "<p>File Parameter: " . htmlspecialchars($file) . "</p>";
    
    // VULNERABILITY: Path Traversal
    if (file_exists($file)) {
        echo "<pre>" . htmlspecialchars(file_get_contents($file)) . "</pre>";
    } else {
        // Simulate traversal if the path looks like it
        if (strpos($file, '../') !== false || strpos($file, '..\\') !== false) {
            echo "<p>Traversal Attempt Detected: " . htmlspecialchars($file) . "</p>";
            if (strpos($file, 'etc/passwd') !== false) {
                echo "<pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</pre>";
            }
        } else {
            echo "<p>File not found.</p>";
        }
    }
}

echo "</body></html>";
?>
