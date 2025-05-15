import platform
import subprocess
import socket
import psutil
import wmi
import ctypes
from datetime import datetime

report_lines = []

def log(line):
    print(line)
    report_lines.append(line)

def save_report():
    filename = f"vuln_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
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

def check_open_ports():
    log("==== Open Ports ====")
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            log(f"[+] Port {conn.laddr.port} open (PID {conn.pid})")
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
    check_open_ports()
    list_services()
    check_admin()
    save_report()

if __name__ == "__main__":
    main()
