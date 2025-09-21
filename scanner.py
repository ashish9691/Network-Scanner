# scanner.py
print(">>> Running scanner.py from:", __file__)

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import shutil
import subprocess
import logging
import ipaddress
import socket
import sys
import nmap

app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

COMMON_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Nmap",
    "/usr/bin",
    "/usr/local/bin",
]

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
    if os.path.isfile('index.html'):
        return send_from_directory('.', 'index.html')
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
        "PATH_sample_tail": os.environ.get("PATH","").split(os.pathsep)[-5:]
    })

@app.route('/scan', methods=['GET', 'POST'])
def scan_network():
    # Get target IP/hostname
    if request.method == 'GET':
        target_raw = request.args.get('ip')
        fast = request.args.get('fast', 'false').lower() in ('1','true','yes')
        skip_ping = request.args.get('skip_ping', 'false').lower() in ('1','true','yes')
    else:
        body = request.get_json(silent=True) or {}
        target_raw = body.get('ip')
        fast = body.get('fast', False)
        skip_ping = body.get('skip_ping', False)

    if not target_raw:
        return jsonify({"error": "No IP/hostname provided."}), 400

    target_raw = target_raw.strip()
    ip_obj = None
    is_ipv6 = False
    is_private = False

    # Try parsing as IP or hostname
    try:
        ip_obj = ipaddress.ip_address(target_raw)
        is_ipv6 = ip_obj.version == 6
        is_private = ip_obj.is_private
    except ValueError:
        # Try hostname resolution
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

    # Skip ping automatically for IPv6 or localhost
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

    # Build nmap arguments
    args = ['-sT', '-sV']

    # Skip OS detection on IPv6 to avoid Windows interface errors
    if not is_ipv6:
        args.append('-O')

    if fast:
        args.append('-F')
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
                        open_ports.append({
                            "port": port,
                            "protocol": proto,
                            "state": info.get('state'),
                            "service": info.get('name','unknown'),
                            "product": info.get('product',''),
                            "version": info.get('version',''),
                            "extrainfo": info.get('extrainfo',''),
                            "cpe": info.get('cpe','')
                        })
        results.append({
            "host": host,
            "status": host_status,
            "addresses": addresses,
            "mac_address": mac_address,
            "vendor": vendor,
            "ports": sorted(open_ports, key=lambda x: (x['protocol'], x['port']))
        })

    if len(results) == 1:
        return jsonify(results[0])
    return jsonify({"hosts": results})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)
