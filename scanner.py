from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import shutil
import subprocess
import logging
import ipaddress
import socket
import sys
import json
import ctypes
from datetime import datetime, timezone
import nmap

app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
HISTORY_FILE = os.path.join(app.root_path, "scan_history.json")

COMMON_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Nmap",
    "/usr/bin",
    "/usr/local/bin",
]

RISKY_PORTS = {
    21: ("medium", "FTP is often unencrypted. Avoid sending credentials over plain FTP."),
    23: ("high", "Telnet sends traffic in plaintext and should be disabled or replaced with SSH."),
    25: ("medium", "SMTP exposed to untrusted networks can be abused if misconfigured."),
    53: ("medium", "Public DNS services can be abused for amplification if recursion is enabled."),
    80: ("low", "HTTP is unencrypted. Prefer HTTPS for sensitive traffic."),
    110: ("medium", "POP3 is often plaintext unless protected with TLS."),
    139: ("high", "NetBIOS/SMB exposure can leak Windows file-sharing information."),
    143: ("medium", "IMAP is often plaintext unless protected with TLS."),
    445: ("high", "SMB should not be exposed to untrusted networks."),
    3306: ("high", "MySQL should normally be restricted to trusted hosts only."),
    3389: ("high", "RDP exposure is a common brute-force and remote-access risk."),
    5432: ("high", "PostgreSQL should normally be restricted to trusted hosts only."),
    5900: ("high", "VNC exposure can allow remote desktop access if weakly protected."),
    6379: ("critical", "Redis should not be exposed without strict authentication and network controls."),
    9200: ("high", "Elasticsearch exposure can leak or alter indexed data if unsecured."),
    27017: ("high", "MongoDB should not be exposed without authentication and network controls."),
}


def is_running_as_admin():
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def parse_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("1", "true", "yes", "on")


def assess_vulnerabilities(open_ports):
    findings = []
    seen = set()

    for port in open_ports:
        port_number = port.get("port")
        service = (port.get("service") or "unknown").lower()
        product = port.get("product") or ""
        version = port.get("version") or ""
        cpe = port.get("cpe") or ""

        if port_number in RISKY_PORTS:
            severity, description = RISKY_PORTS[port_number]
            title = f"Exposed {service.upper()} service on port {port_number}"
            key = (title, severity)
            if key not in seen:
                findings.append({
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "port": port_number,
                    "service": service,
                    "evidence": f"{product} {version}".strip() or cpe or "Open service detected"
                })
                seen.add(key)

        if cpe or version:
            title = f"Version information disclosed for {service.upper()}"
            key = (title, "info", port_number)
            if key not in seen:
                findings.append({
                    "severity": "info",
                    "title": title,
                    "description": "The service reveals product/version details. Check this exact version against CVE databases or vendor advisories.",
                    "port": port_number,
                    "service": service,
                    "evidence": f"{product} {version} {cpe}".strip()
                })
                seen.add(key)

        scripts = port.get("scripts", {})
        for script_id, output in scripts.items():
            lower_output = str(output).lower()
            if "vulnerable" not in lower_output and "cve-" not in lower_output:
                severity = "info"
            elif "critical" in lower_output:
                severity = "critical"
            elif "high" in lower_output:
                severity = "high"
            elif "medium" in lower_output:
                severity = "medium"
            else:
                severity = "high"

            title = f"Nmap script finding: {script_id}"
            key = (title, port_number)
            if key not in seen:
                findings.append({
                    "severity": severity,
                    "title": title,
                    "description": "Nmap vulnerability script returned a finding for this service.",
                    "port": port_number,
                    "service": service,
                    "evidence": str(output)[:600]
                })
                seen.add(key)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda item: (severity_order.get(item["severity"], 5), item["port"]))


def summarize_vulnerabilities(hosts):
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for host in hosts:
        for finding in host.get("vulnerabilities", []):
            severity = finding.get("severity", "info")
            summary[severity] = summary.get(severity, 0) + 1
    return summary


def save_scan_history(report):
    history_item = {
        "timestamp": report["timestamp"],
        "target": report["target"],
        "mode": report["mode"],
        "host_count": len(report["hosts"]),
        "summary": report["summary"]
    }
    history = []
    try:
        if os.path.isfile(HISTORY_FILE):
            with open(HISTORY_FILE, "r", encoding="utf-8") as file:
                history = json.load(file)
    except Exception:
        history = []

    history.insert(0, history_item)
    history = history[:25]

    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as file:
            json.dump(history, file, indent=2)
    except Exception as e:
        logger.debug("Could not save scan history: %s", e)

def ensure_nmap_on_path():
    exe = shutil.which("nmap")
    if exe:
        return exe
    for folder in COMMON_NMAP_PATHS:
        candidate = os.path.join(folder, "nmap.exe" if os.name == "nt" else "nmap")
        if os.path.isfile(candidate):
            os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + folder
            logger.info("Appended %s to PATH for this process", folder)
            return candidate
    return None

@app.route('/')
def index():
    if os.path.isfile(os.path.join(app.root_path, 'index.html')):
        return send_from_directory(app.root_path, 'index.html')
    return "Network Scanner API. Use /scan or /diag."

@app.route('/diag')
def diag():
    nmap_path = shutil.which("nmap") or ensure_nmap_on_path()
    ver = None
    ver_err = None
    try:
        if nmap_path:
            ver = subprocess.check_output([nmap_path, "-V"], stderr=subprocess.STDOUT, text=True).splitlines()[0]
    except Exception as e:
        ver_err = str(e)
    return jsonify({
        "python_executable": sys.executable,
        "nmap_path_shutil": shutil.which("nmap"),
        "nmap_candidate": nmap_path,
        "nmap_version_line": ver,
        "nmap_version_error": ver_err,
        "running_as_admin": is_running_as_admin(),
        "PATH_sample_tail": os.environ.get("PATH","").split(os.pathsep)[-5:]
    })

@app.route('/history')
def history():
    try:
        if os.path.isfile(HISTORY_FILE):
            with open(HISTORY_FILE, "r", encoding="utf-8") as file:
                return jsonify(json.load(file))
    except Exception as e:
        logger.debug("Could not read scan history: %s", e)
    return jsonify([])

@app.route('/scan', methods=['GET', 'POST'])
def scan_network():
    if request.method == 'GET':
        target_raw = request.args.get('ip')
        mode = request.args.get('mode', 'quick').lower()
        fast = parse_bool(request.args.get('fast'), mode == 'quick')
        skip_ping = parse_bool(request.args.get('skip_ping'), False)
        os_detection = parse_bool(request.args.get('os_detection'), False)
    else:
        body = request.get_json(silent=True) or {}
        target_raw = body.get('ip')
        mode = str(body.get('mode', 'quick')).lower()
        fast = parse_bool(body.get('fast'), mode == 'quick')
        skip_ping = parse_bool(body.get('skip_ping'), False)
        os_detection = parse_bool(body.get('os_detection'), False)

    if not target_raw:
        return jsonify({"error": "No IP/hostname provided."}), 400

    if mode not in ("quick", "full", "vuln"):
        return jsonify({"error": "Invalid scan mode. Use quick, full, or vuln."}), 400

    target_raw = target_raw.strip()
    ip_obj = None
    network_obj = None
    is_ipv6 = False
    is_private = False

    try:
        if "/" in target_raw:
            network_obj = ipaddress.ip_network(target_raw, strict=False)
            is_ipv6 = network_obj.version == 6
            is_private = network_obj.is_private
        else:
            ip_obj = ipaddress.ip_address(target_raw)
            is_ipv6 = ip_obj.version == 6
            is_private = ip_obj.is_private
    except ValueError:
        try:
            resolved = socket.getaddrinfo(target_raw, None)[0][4][0]
            ip_obj = ipaddress.ip_address(resolved)
            is_ipv6 = ip_obj.version == 6
            is_private = ip_obj.is_private
        except Exception:
            return jsonify({"error": "Invalid IP or hostname provided."}), 400

    nmap_exe = shutil.which("nmap") or ensure_nmap_on_path()
    if not nmap_exe:
        return jsonify({"error": "nmap binary not found. Install Nmap and ensure it's on PATH."}), 500

    if target_raw.lower() in ('127.0.0.1', 'localhost', '::1'):
        skip_ping = True
        is_private = True
    if is_ipv6:
        skip_ping = True

    scanner = nmap.PortScanner()

    mac_by_host = {}
    if is_private and not is_ipv6:
        try:
            arp_target = target_raw
            logger.info("Performing ARP pre-scan for %s", arp_target)
            scanner.scan(hosts=arp_target, arguments='-sn -PR -n')
            for host in scanner.all_hosts():
                try:
                    mac = scanner[host].get('addresses', {}).get('mac')
                    if mac:
                        mac_by_host[host] = mac
                except Exception:
                    continue
        except Exception as e:
            logger.debug("ARP pre-scan failed or returned no MACs: %s", e)

    args = ['-sT', '-sV']
    warnings = []
    running_as_admin = is_running_as_admin()

    if os_detection and not is_ipv6 and running_as_admin:
        args.append('-O')
    elif os_detection and not running_as_admin:
        warnings.append("OS detection was skipped because it usually requires Administrator privileges.")

    if fast:
        args.append('-F')
    elif mode == "full":
        args.extend(['-p', '1-65535'])

    if mode == "vuln":
        args.extend(['--script', 'vuln'])

    if skip_ping or is_ipv6:
        args.append('-Pn')
    if is_ipv6:
        args.append('-6')

    arg_string = ' '.join(args)
    logger.info("Scanning %s with args: %s", target_raw, arg_string)

    try:
        scanner.scan(hosts=target_raw, arguments=arg_string)
    except nmap.nmap.PortScannerError as e:
        logger.exception("Nmap error")
        return jsonify({"error": f"Nmap scan failed: {str(e)}"}), 500
    except Exception as e:
        logger.exception("Unexpected error during scan")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

    hosts_found = scanner.all_hosts()
    if not hosts_found:
        return jsonify({"status": "down", "message": "Host(s) down or unreachable."})

    results = []
    for host in hosts_found:
        host_info = scanner[host]
        host_status = host_info.get('status', {}).get('state', 'unknown')
        addresses = host_info.get('addresses', {})
        mac_address = addresses.get('mac') or mac_by_host.get(host, 'Not Found')
        vendor = host_info.get('vendor', {})
        open_ports = []
        for proto in ('tcp', 'udp'):
            if proto in host_info:
                for port, info in host_info[proto].items():
                    if info.get('state') == 'open':
                        scripts = info.get('script', {}) or {}
                        open_ports.append({
                            "port": port,
                            "protocol": proto,
                            "state": info.get('state'),
                            "service": info.get('name','unknown'),
                            "product": info.get('product',''),
                            "version": info.get('version',''),
                            "extrainfo": info.get('extrainfo',''),
                            "cpe": info.get('cpe',''),
                            "scripts": scripts
                        })
        sorted_ports = sorted(open_ports, key=lambda x: (x['protocol'], x['port']))
        host_result = {
            "host": host,
            "status": host_status,
            "addresses": addresses,
            "mac_address": mac_address,
            "vendor": vendor,
            "ports": sorted_ports,
            "vulnerabilities": assess_vulnerabilities(sorted_ports)
        }
        if 'hostscript' in host_info:
            host_result["host_scripts"] = host_info.get('hostscript', [])
        results.append(host_result)

    report = {
        "target": target_raw,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "scan_arguments": arg_string,
        "running_as_admin": running_as_admin,
        "warnings": warnings,
        "summary": summarize_vulnerabilities(results),
        "hosts": results
    }
    save_scan_history(report)

    if len(results) == 1:
        single_host_report = dict(results[0])
        single_host_report.update({
            "target": report["target"],
            "timestamp": report["timestamp"],
            "mode": report["mode"],
            "scan_arguments": report["scan_arguments"],
            "running_as_admin": report["running_as_admin"],
            "warnings": report["warnings"],
            "summary": report["summary"],
            "hosts": report["hosts"]
        })
        return jsonify(single_host_report)
    return jsonify(report)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)
