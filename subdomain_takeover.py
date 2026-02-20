#!/usr/bin/env python3

import re
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

print(
    "\033[1;32m"
    "███╗   ██╗██╗██╗  ██╗██╗██╗     ██╗\n"
    "████╗  ██║██║██║ ██╔╝██║██║     ██║\n"
    "██╔██╗ ██║██║█████╔╝ ██║██║     ██║\n"
    "██║╚██╗██║██║██╔═██╗ ██║██║     ██║\n"
    "██║ ╚████║██║██║  ██╗██║███████╗███████╗\n"
    "╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝"
    "\033[0m"
)


def run_cmd(cmd, cwd=None, allow_fail=False):
    p = subprocess.run(
        cmd,
        shell=True,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if p.stdout:
        print(p.stdout.strip())
    if p.stderr:
        print(p.stderr.strip())
    if p.returncode != 0 and not allow_fail:
        raise RuntimeError(f"Command failed: {cmd}")
    return p.returncode


def have(tool):
    return shutil.which(tool) is not None


def validate_domain(domain):
    if domain.startswith("http://") or domain.startswith("https://"):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", domain))


def nuclei_takeover_path():
    # Most common default path in Kali/Linux
    home = str(Path.home())
    p1 = Path(home) / ".local" / "nuclei-templates" / "http" / "takeovers"
    p2 = Path(home) / "nuclei-templates" / "http" / "takeovers"
    if p1.exists():
        return str(p1)
    if p2.exists():
        return str(p2)
    return ""


def main():
    print("\nSubdomain Takeover Scanner using Nuclei\n")

    domain = input("Enter target domain (example.com): ").strip()
    if not validate_domain(domain):
        print("Invalid domain format")
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    workdir = Path(f"takeover_scan_{domain}_{ts}").resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    print(f"\nWorkspace: {workdir}\n")

    # Basic requirements
    if not have("jq"):
        print("Missing jq. Install: sudo apt update && sudo apt install -y jq")
        return

    if not have("httprobe"):
        print("[+] Installing httprobe")
        run_cmd("go install github.com/tomnomnom/httprobe@latest")
        run_cmd("sudo cp ~/go/bin/httprobe /usr/local/bin/")

    if not have("nuclei"):
        print("[+] Installing nuclei")
        run_cmd("go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        run_cmd("sudo cp ~/go/bin/nuclei /usr/local/bin/")

    print("[+] Updating nuclei templates")
    run_cmd("nuclei -update-templates", allow_fail=True)

    takeover_dir = nuclei_takeover_path()
    if not takeover_dir:
        print("\n❌ Could not find takeover templates folder.")
        print("Run these and retry:")
        print("  nuclei -update-templates")
        print("  ls ~/.local/nuclei-templates/http/takeovers/")
        return

    print(f"[+] Using takeover templates path: {takeover_dir}\n")

    # CRT.SH
    print("[+] Fetching crt.sh subdomains")
    crt_cmd = (
        f'curl -s -H "User-Agent: Mozilla/5.0" "https://crt.sh/?q=%25.{domain}&output=json" '
        f'| jq -r \'.[].name_value\' '
        f'| sed \'s/\\*\\.//g\' '
        f'| sort -u > crt.txt'
    )
    run_cmd(crt_cmd, workdir, allow_fail=True)

    # Parallel enumeration
    print("[+] Running enumeration tools in parallel\n")
    commands = {
        "subfinder": f"subfinder -d {domain} -o subfinder.txt",
        "assetfinder": f"assetfinder --subs-only {domain} > assetfinder.txt",
        "sublist3r": f"sublist3r -d {domain} -o sublist3r.txt",
        "amass": f"amass enum -passive -d {domain} -o amass.txt",
    }

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(run_cmd, cmd, workdir, True): name for name, cmd in commands.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                future.result()
                print(f"[+] {name} completed (or skipped if blocked).")
            except Exception as e:
                print(f"[!] {name} error: {e}")

    # Combine
    print("\n[+] Combining results")
    run_cmd("cat crt.txt subfinder.txt assetfinder.txt sublist3r.txt amass.txt 2>/dev/null > master.txt || true", workdir, allow_fail=True)

    # Clean + unique
    print("[+] Cleaning + dedupe")
    run_cmd("sed 's/^\\*\\.//g' master.txt | sed 's/^www\\.//' | sed '/^$/d' > cleaned.txt", workdir, allow_fail=True)
    run_cmd("sort -u cleaned.txt > unique.txt", workdir, allow_fail=True)

    # Live check (httprobe)
    print("[+] Finding live subdomains (httprobe)")
    run_cmd("cat unique.txt | httprobe > final_live_subdomains.txt", workdir, allow_fail=True)

    # Nuclei takeover scans (FIXED PATH)
    print("\n[+] Running Nuclei takeover scan (ALL unique)")
    run_cmd(f"nuclei -l unique.txt -t {takeover_dir} | tee nuclei_takeover_results.txt", workdir, allow_fail=True)

    print("\n[+] Running Nuclei takeover scan (LIVE only)")
    run_cmd(f"nuclei -l final_live_subdomains.txt -t {takeover_dir} | tee nuclei_live_takeover_results.txt", workdir, allow_fail=True)

    # Extract (don’t crash if empty)
    run_cmd("grep -i takeover nuclei_takeover_results.txt > vulnerable_subdomains.txt || true", workdir, allow_fail=True)
    run_cmd("grep -i takeover nuclei_live_takeover_results.txt >> vulnerable_subdomains.txt || true", workdir, allow_fail=True)

    vuln_file = workdir / "vulnerable_subdomains.txt"
    print("\n===================================")
    print("VULNERABLE SUBDOMAINS")
    print("===================================\n")
    if vuln_file.exists() and vuln_file.stat().st_size > 0:
        print(vuln_file.read_text(encoding="utf-8", errors="ignore"))
    else:
        print("No takeover vulnerabilities found (or templates returned none).")

    print("\nResults saved at:", workdir)


if __name__ == "__main__":
    main()
