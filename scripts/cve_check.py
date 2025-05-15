import os
import socket
import platform
import subprocess
import psutil
import ctypes
import wmi
from datetime import datetime
import requests
import json

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Fetch API key
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")


report_lines = []

def log(line):
    print(line)
    report_lines.append(line)

def save_report():
    filename = f"vuln_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    print(f"\n[+] Report saved to {filename}")


def get_os_info():
    log("==== OS Information ====")
    log(f"System: {platform.system()}")
    log(f"Release: {platform.release()}")
    log(f"Version: {platform.version()}")
    log("")

def check_firewall_status():
    log("==== Firewall Status ====")
    try:
        output = subprocess.check_output("netsh advfirewall show allprofiles", shell=True).decode()
        if "State ON" in output:
            log("[+] Firewall is Enabled")
        else:
            log("[-] Firewall may be Disabled")
    except Exception as e:
        log(f"[!] Error checking firewall: {e}")
    log("")

def check_smbv1():
    log("==== SMBv1 Check ====")
    try:
        cmd = 'powershell "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"'
        output = subprocess.check_output(cmd, shell=True).decode()
        if "Enabled" in output:
            log("[-] SMBv1 is ENABLED (Vulnerable)")
        else:
            log("[+] SMBv1 is Disabled")
    except Exception:
        log("[!] PowerShell access required to check SMBv1")
    log("")

def grab_banner(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=2) as sock:
            sock.sendall(b"\r\n")
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner
    except Exception:
        return ""

def search_cves_vulners(banner):
    if not VULNERS_API_KEY or VULNERS_API_KEY == "YOUR_API_KEY_HERE":
        return ["[!] Vulners API key not configured."]
    try:
        url = "https://vulners.com/api/v3/search/lucene/"
        params = {
            "query": banner,
            "apiKey": VULNERS_API_KEY
        }
        res = requests.get(url, params=params)
        data = res.json()

        if data.get("result") != "OK" or "data" not in data:
            return ["[!] No CVEs found or API error."]

        cves = []
        for doc in data["data"].get("search", [])[:3]:  # top 3 CVEs
            title = doc.get("title", "")
            cve_id = doc.get("id", "")
            cves.append(f"{cve_id} - {title}")

        return cves if cves else ["[!] No relevant CVEs found."]
    except Exception as e:
        return [f"[!] CVE lookup error: {e}"]

def check_open_ports_with_banner():
    log("==== Open Ports, Banners, and CVE Check ====")
    localhost = "127.0.0.1"

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN' and conn.laddr.ip == localhost:
            port = conn.laddr.port
            banner = grab_banner(localhost, port)
            log(f"[+] Port {port} open (PID {conn.pid})")
            if banner:
                log(f"    └─ Banner: {banner}")
                cve_list = search_cves_vulners(banner)
                for cve in cve_list:
                    log(f"       └─ CVE: {cve}")
            else:
                log(f"    └─ Banner: Not available")
    log("")

def check_admin():
    log("==== Privilege Check ====")
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if is_admin:
            log("[+] Running as Administrator")
        else:
            log("[-] Not running as Administrator")
    except:
        log("[!] Could not determine admin status")
    log("")

def list_services():
    log("==== Running Services ====")
    try:
        c = wmi.WMI()
        for service in c.Win32_Service(StartMode="Auto", State="Running"):
            log(f"[+] {service.Name} - {service.Caption}")
    except Exception as e:
        log(f"[!] Error listing services: {e}")
    log("")

def main():
    log("==== Local Windows Vulnerability Report ====\n")
    get_os_info()
    check_firewall_status()
    check_smbv1()
    check_open_ports_with_banner()
    list_services()
    check_admin()
    save_report()

if __name__ == "__main__":
    main()
