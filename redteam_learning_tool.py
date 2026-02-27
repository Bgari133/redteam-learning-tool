#!/usr/bin/env python3
"""
============================================================
  RED TEAM LEARNING TOOL - For Beginners (VulnHub / HTB)
  Educational use only. Only use on VMs you own or have
  explicit permission to test.
============================================================
"""

import socket
import subprocess
import sys
import os

# Try to import optional libraries
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import ftplib
    HAS_FTP = True
except ImportError:
    HAS_FTP = False

# ─────────────────────────────────────────────
#  COLORS FOR TERMINAL OUTPUT
# ─────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def banner():
    print(f"""
{C.RED}{C.BOLD}
██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗
██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║
██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
{C.RESET}
{C.YELLOW}  LEARNING TOOL — VulnHub / HackTheBox Helper for Beginners{C.RESET}
{C.RED}  ⚠  Only use on VMs you own or have written permission to test!{C.RESET}
""")

def explain(title, text):
    """Print a colored explanation block."""
    print(f"\n{C.CYAN}{C.BOLD}📚 EXPLANATION — {title}{C.RESET}")
    print(f"{C.BLUE}{text}{C.RESET}\n")

def step(num, desc):
    print(f"\n{C.GREEN}{C.BOLD}[STEP {num}] {desc}{C.RESET}")

def info(msg):
    print(f"  {C.YELLOW}[*]{C.RESET} {msg}")

def found(msg):
    print(f"  {C.GREEN}[+]{C.RESET} {msg}")

def warn(msg):
    print(f"  {C.RED}[-]{C.RESET} {msg}")

# ─────────────────────────────────────────────
#  STEP 1: PING / HOST DISCOVERY
# ─────────────────────────────────────────────
def host_discovery(target):
    step(1, "Host Discovery (Is the target alive?)")
    explain("Host Discovery", 
        "Before anything else, we check if the target machine is online.\n"
        "We use ICMP ping — if it replies, the host is up.\n"
        "On a VulnHub VM, it should always respond since it's on your LAN.")
    
    info(f"Pinging {target}...")
    param = "-n" if sys.platform == "win32" else "-c"
    result = subprocess.run(["ping", param, "3", target],
                            capture_output=True, text=True)
    if result.returncode == 0:
        found(f"{target} is ALIVE!")
    else:
        warn(f"{target} did not respond to ping (may still be up, could block ICMP)")
    
    print(f"\n{C.BOLD}  💡 TIP:{C.RESET} On your network, run 'arp-scan -l' or 'netdiscover -r 192.168.1.0/24'")
    print("         to find your VulnHub VM's IP address first.\n")

# ─────────────────────────────────────────────
#  STEP 2: PORT SCANNING
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
}

def port_scan(target):
    step(2, "Port Scanning (What services are running?)")
    explain("Port Scanning",
        "Ports are like doors on a building. Each open port = a running service.\n"
        "Attackers scan ports to find which services are available to attack.\n\n"
        "Common findings:\n"
        "  Port 21  (FTP)   → File transfer, often misconfigured (anonymous login!)\n"
        "  Port 22  (SSH)   → Remote shell, try weak passwords\n"
        "  Port 80  (HTTP)  → Web server, look for web vulnerabilities\n"
        "  Port 445 (SMB)   → Windows file sharing, EternalBlue exploits\n"
        "  Port 3306(MySQL) → Database, try default credentials\n\n"
        "Real tool: nmap -sV -sC -A <target>  (nmap does this WAY better!)")
    
    open_ports = {}
    info(f"Scanning {len(COMMON_PORTS)} common ports on {target}...")
    
    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            found(f"Port {port:5d} ({service:15s}) OPEN")
            open_ports[port] = service
        sock.close()
    
    if not open_ports:
        warn("No common ports found open. Try nmap for a full scan.")
    
    return open_ports

# ─────────────────────────────────────────────
#  STEP 3: BANNER GRABBING
# ─────────────────────────────────────────────
def banner_grab(target, open_ports):
    step(3, "Banner Grabbing (What software & version is running?)")
    explain("Banner Grabbing",
        "Many services announce themselves with a 'banner' when you connect.\n"
        "This reveals the software name AND version number.\n"
        "Version numbers are critical — you can search that exact version for CVEs!\n\n"
        "Example banner: 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8'\n"
        "→ Search: 'OpenSSH 7.2p2 exploit' on exploit-db.com or searchsploit")
    
    banners = {}
    for port in open_ports:
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((target, port))
            # Send HTTP GET for web ports
            if port in [80, 8080, 443, 8443]:
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
            banner = s.recv(1024).decode(errors='ignore').strip()
            if banner:
                found(f"Port {port} banner: {banner[:120]}")
                banners[port] = banner
            s.close()
        except Exception:
            pass
    
    return banners

# ─────────────────────────────────────────────
#  STEP 4: FTP ANONYMOUS LOGIN CHECK
# ─────────────────────────────────────────────
def check_ftp_anonymous(target):
    if not HAS_FTP:
        return
    step(4, "FTP Anonymous Login Check")
    explain("FTP Anonymous Login",
        "Some FTP servers allow login with username 'anonymous' and any password.\n"
        "This is a misconfiguration that lets anyone browse/download files!\n\n"
        "How to exploit manually:\n"
        "  ftp <target-ip>\n"
        "  Username: anonymous\n"
        "  Password: anything (or blank)\n"
        "  Then: ls, get <filename>, put <file> (if writable!)\n\n"
        "If writable, you may upload a reverse shell or SSH key!")
    
    try:
        ftp = ftplib.FTP(target, timeout=5)
        ftp.login("anonymous", "anonymous@test.com")
        found("ANONYMOUS FTP LOGIN SUCCESSFUL!")
        info("Files found:")
        ftp.retrlines("LIST")
        ftp.quit()
        
        print(f"\n{C.RED}{C.BOLD}  🔥 EXPLOITATION PATH:{C.RESET}")
        print("  1. Browse files for credentials, config files, SSH keys")
        print("  2. If writable: upload a PHP/bash reverse shell")
        print("  3. Check if FTP root overlaps with web root (/var/www/html)")
        print("  4. Upload shell.php → visit http://<target>/shell.php")
    except Exception as e:
        warn(f"Anonymous FTP failed: {e}")

# ─────────────────────────────────────────────
#  STEP 5: HTTP ENUMERATION
# ─────────────────────────────────────────────
def http_enumeration(target, open_ports):
    if not HAS_REQUESTS:
        warn("requests library not installed. Run: pip install requests")
        return
    
    web_ports = [p for p in open_ports if p in [80, 8080, 443, 8443]]
    if not web_ports:
        return
    
    step(5, "Web Enumeration (Finding hidden pages & misconfigurations)")
    explain("Web Enumeration",
        "Web servers often have hidden pages like /admin, /backup, /config.\n"
        "Directory brute-forcing finds these hidden paths.\n\n"
        "What to look for:\n"
        "  /admin, /administrator  → Admin panels (try default creds)\n"
        "  /backup, /.git          → Leaked source code or credentials\n"
        "  /phpinfo.php            → Reveals server config (goldmine!)\n"
        "  /robots.txt             → Lists paths the owner wants hidden!\n"
        "  /login, /wp-login.php   → Login pages to brute force\n\n"
        "Real tools: gobuster, dirb, feroxbuster, nikto")
    
    wordlist = [
        "", "admin", "administrator", "login", "dashboard", "portal",
        "backup", "config", "test", "dev", "uploads", "files", "images",
        "robots.txt", "sitemap.xml", ".htaccess", "phpinfo.php",
        "wp-login.php", "wp-admin", "shell.php", "index.php",
        "README.md", ".git/HEAD", "server-status", "phpmyadmin",
        "cms", "blog", "api", "v1", "console", "manager"
    ]
    
    for port in web_ports:
        scheme = "https" if port == 443 else "http"
        base = f"{scheme}://{target}:{port}" if port not in [80, 443] else f"{scheme}://{target}"
        info(f"Scanning web paths on {base}")
        
        for path in wordlist:
            url = f"{base}/{path}"
            try:
                r = requests.get(url, timeout=3, verify=False, 
                               allow_redirects=False)
                if r.status_code in [200, 201, 301, 302, 403]:
                    status_color = C.GREEN if r.status_code == 200 else C.YELLOW
                    print(f"  {status_color}[{r.status_code}]{C.RESET} {url}")
            except Exception:
                pass

# ─────────────────────────────────────────────
#  STEP 6: SSH DEFAULT CREDENTIALS
# ─────────────────────────────────────────────
def check_ssh_defaults(target, open_ports):
    if 22 not in open_ports:
        return
    
    step(6, "SSH Default Credential Check")
    explain("Default Credentials",
        "Many VulnHub machines use weak or default SSH credentials.\n"
        "This is the #1 misconfiguration in the real world too!\n\n"
        "Common credential pairs to try:\n"
        "  root:root, root:toor, root:password\n"
        "  admin:admin, admin:password\n"
        "  user:user, vagrant:vagrant\n\n"
        "Real tool: hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target>\n"
        "           medusa -h <target> -u admin -P passwords.txt -M ssh\n\n"
        "If you get in with SSH:\n"
        "  Run 'id' → check if you're root already!\n"
        "  Run 'sudo -l' → see what you can run as root\n"
        "  Run 'uname -a' → kernel version (check for kernel exploits)")
    
    # We only check connectivity here (not actual brute force for safety)
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target, 22))
        banner_data = s.recv(1024).decode(errors='ignore').strip()
        found(f"SSH is accessible: {banner_data}")
        s.close()
        
        print(f"\n{C.YELLOW}  💡 Manual commands to try:{C.RESET}")
        print(f"     ssh root@{target}          (try password: root, toor, password)")
        print(f"     ssh admin@{target}         (try password: admin, password)")
        print(f"     hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target}")
    except Exception as e:
        warn(f"Cannot connect to SSH: {e}")

# ─────────────────────────────────────────────
#  STEP 7: VULNERABILITY HINTS & NEXT STEPS
# ─────────────────────────────────────────────
def exploitation_guide(target, open_ports, banners):
    step(7, "Exploitation Guide & Next Steps")
    
    print(f"\n{C.BOLD}{C.CYAN}{'='*60}")
    print("  ATTACK SURFACE SUMMARY")
    print(f"{'='*60}{C.RESET}\n")
    
    if open_ports:
        print(f"{C.BOLD}  Open ports found:{C.RESET}")
        for port, service in open_ports.items():
            print(f"    • {service} on port {port}")
    
    print(f"\n{C.BOLD}{C.YELLOW}  🗺  RECOMMENDED NEXT STEPS:{C.RESET}\n")
    
    if 80 in open_ports or 8080 in open_ports:
        print(f"  {C.GREEN}[WEB]{C.RESET} Run Nikto:   nikto -h http://{target}")
        print(f"  {C.GREEN}[WEB]{C.RESET} Dir bust:   gobuster dir -u http://{target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
        print(f"  {C.GREEN}[WEB]{C.RESET} Check for SQLi, XSS in any login forms")
        print(f"  {C.GREEN}[WEB]{C.RESET} Look for CMS: WPScan if WordPress → wpscan --url http://{target}\n")
    
    if 22 in open_ports:
        print(f"  {C.CYAN}[SSH]{C.RESET} Brute force: hydra -L users.txt -P rockyou.txt ssh://{target}")
        print(f"  {C.CYAN}[SSH]{C.RESET} Try manually: ssh root@{target}\n")
    
    if 21 in open_ports:
        print(f"  {C.YELLOW}[FTP]{C.RESET} Try anonymous login: ftp {target}")
        print(f"  {C.YELLOW}[FTP]{C.RESET} Brute force: hydra -l admin -P rockyou.txt ftp://{target}\n")
    
    if 445 in open_ports:
        print(f"  {C.RED}[SMB]{C.RESET} Enumerate: enum4linux -a {target}")
        print(f"  {C.RED}[SMB]{C.RESET} Check EternalBlue: nmap --script smb-vuln-ms17-010 {target}")
        print(f"  {C.RED}[SMB]{C.RESET} Use Metasploit: use exploit/windows/smb/ms17_010_eternalblue\n")
    
    if 3306 in open_ports:
        print(f"  {C.BLUE}[MySQL]{C.RESET} Try: mysql -h {target} -u root -p  (blank password!)")
        print(f"  {C.BLUE}[MySQL]{C.RESET} Try: mysql -h {target} -u root (no password)\n")
    
    print(f"\n{C.BOLD}{C.CYAN}  📖 LEARNING RESOURCES:{C.RESET}")
    print("  • https://exploit-db.com       → Search service versions for exploits")
    print("  • https://nvd.nist.gov         → CVE database")
    print("  • https://gtfobins.github.io   → Privilege escalation via binaries")
    print("  • https://book.hacktricks.xyz  → Huge pentesting wiki")
    print("  • https://www.vulnhub.com      → More vulnerable VMs to practice")
    
    print(f"\n{C.BOLD}{C.YELLOW}  🔑 PRIVILEGE ESCALATION (after getting a shell):{C.RESET}")
    print("  1. sudo -l                          → Can you run something as root?")
    print("  2. find / -perm -4000 2>/dev/null   → SUID binaries")
    print("  3. cat /etc/crontab                 → Cron jobs running as root?")
    print("  4. uname -a                         → Kernel exploits?")
    print("  5. Run linpeas.sh / winpeas.exe     → Automated priv esc scanner")

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    banner()
    
    if len(sys.argv) < 2:
        target = input(f"{C.BOLD}Enter target IP (your VulnHub VM): {C.RESET}").strip()
    else:
        target = sys.argv[1]
    
    if not target:
        print("No target provided. Exiting.")
        sys.exit(1)
    
    print(f"\n{C.BOLD}Target: {C.GREEN}{target}{C.RESET}")
    print(f"{C.RED}⚠  Only proceed if this is YOUR VM or you have written permission!{C.RESET}\n")
    confirm = input("Continue? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Exiting. Smart choice — always get permission first!")
        sys.exit(0)
    
    # Run all steps
    host_discovery(target)
    open_ports = port_scan(target)
    banners = banner_grab(target, open_ports)
    check_ftp_anonymous(target)
    http_enumeration(target, open_ports)
    check_ssh_defaults(target, open_ports)
    exploitation_guide(target, open_ports, banners)
    
    print(f"\n{C.GREEN}{C.BOLD}✓ Scan complete! Read the explanations above to understand each finding.{C.RESET}\n")

if __name__ == "__main__":
    main()
