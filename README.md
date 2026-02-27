# Red Team Learning Tool v2.0

A beginner-friendly red team / penetration testing learning tool for **VulnHub**, **HackTheBox**, **TryHackMe**, **DVWA**, and similar lab environments. It runs a sequence of common checks and teaches you how each step works and how to exploit findings yourself.

**Use only on machines you own or have explicit permission to test.**

---

## Features

- **Host discovery** — Check if the target is up (ping / TCP probe).
- **Port scanning** — Find open ports (21, 22, 80, 443, 8080, 8443, etc.).
- **Banner grabbing** — Read service banners to identify software and versions.
- **FTP** — Anonymous login and brute force with default credentials.
- **Web** — Path enumeration, CMS detection (WordPress, Joomla, Drupal), security headers.
- **SQL injection** — Time-based and error-based checks on login and common parameters.
- **XSS** — Reflected XSS checks on common parameters.
- **LFI** — Local file inclusion / path traversal checks.
- **SSH / FTP / HTTP login** — Brute force with default credential lists.
- **SMB** — Port and basic enumeration.
- **Other services** — MySQL, Redis, MongoDB, Telnet (default or no auth).
- **Reverse shell generator** — Ready-to-use payloads (bash, Python, etc.).
- **Post-exploitation** — Short checklist and next steps.
- **HTML report** — Summary of findings saved to disk.

### Learning-oriented behavior

- **Step-by-step mode** — After each step the tool pauses, explains how that step works, and waits for you to press Enter before continuing.
- **Stop on first vuln** — When a **CRITICAL** or **HIGH** finding is detected, the scan pauses and shows:
  - What was found and how to exploit it yourself (with copy-paste examples).
  - Links to search for CVEs (NVD, Exploit-DB); optional “open in browser”.
  - Choice to **continue the rest of the scan** or **exit** (and still get a partial HTML report).

---

## Requirements

- **Python 3.6+**
- **Optional** (recommended for full functionality):
  - `requests` — HTTP requests (web checks, SQLi, XSS, LFI, login brute).
  - `paramiko` — SSH brute force.

---

## Installation

```bash
git clone <your-repo-url>
cd Test_project
pip install -r requirements.txt
```

---

## Usage

Run the script and pass the target IP, or enter it when prompted:

```bash
python redteam_learning_tool_v2.py 192.168.1.100
```

Or without arguments (you will be asked for the target and to confirm):

```bash
python redteam_learning_tool_v2.py
```

1. Enter the target IP (e.g. your VulnHub VM).
2. Confirm you have permission to test.
3. The tool runs each step, then **pauses and explains** how it works. Press **Enter** to go to the next step.
4. If a **CRITICAL** or **HIGH** vulnerability is found, it will:
   - Show what was found and how to try it yourself.
   - Print NVD and Exploit-DB search URLs and optionally open them in your browser.
   - Ask **“Continue with the rest of the scan? (y/n)”** — choose **y** to keep scanning or **n** to stop and get a partial HTML report.
5. At the end, an **HTML report** is written (path is printed). Open it in a browser for a full overview.

---

## Output

- **Console** — Colored output, explanations, and “how to do it yourself” hints.
- **HTML report** — Saved under `/mnt/user-data/outputs/` (or the path set in the script) as `redteam_report_<target>_<timestamp>.html`. The script creates the directory if it does not exist.

---

## Configuration (in code)

- **Stop on vuln** — `STOP_ON_VULN = True` and `STOP_SEVERITIES = ("CRITICAL", "HIGH")` near the top of `redteam_learning_tool_v2.py`. You can change these to disable stopping or to include other severities.

---

## Resources

The tool and report point you to:

- [exploit-db.com](https://exploit-db.com) — Search exploits by service/version.
- [gtfobins.github.io](https://gtfobins.github.io) — Privilege escalation via binaries.
- [book.hacktricks.xyz](https://book.hacktricks.xyz) — Pentesting wiki.
- [nvd.nist.gov](https://nvd.nist.gov) — CVE database.

---

## Disclaimer

This tool is for **education and authorized testing only**. Only run it against systems you own or have written permission to test. Unauthorized access to computer systems is illegal.
