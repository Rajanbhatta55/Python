import socket
import ipaddress
import argparse
import os
import threading
import platform
import subprocess
import time
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from prettytable import PrettyTable
import re

stop_scan = threading.Event()

def is_host_up(ip, verbose):
    param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
    if verbose:
        print(f"[*] Checking if host {ip} is up...")
    response = os.system(f"ping {param} -w 1 {ip} > /dev/null 2>&1")
    return response == 0

def detect_os(ip, verbose):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(["ping", param, "1", ip], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            ttl_match = re.search(r'TTL=.*?(\d+)', line, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                os_detected = "Linux/Unix" if ttl <= 64 else "Windows" if ttl <= 128 else "Unknown"
                if verbose:
                    print(f"[*] Detected OS for {ip}: {os_detected}")
                return os_detected
    except:
        return "Unknown"
    return "Unknown"

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode().strip()
            return banner if banner else "N/A"
    except:
        return "N/A"

def scan_host(ip, ports, verbose, version_detection, os_detection):
    if verbose:
        print(f"[*] Starting scan on {ip}...")
    os_info = detect_os(ip, verbose) if os_detection else "N/A"
    open_ports = []

    for port in ports:
        if stop_scan.is_set():
            break
        result = scan_port(ip, port, version_detection, verbose)
        if result:
            open_ports.append(result)
            if verbose:
                print(f"[+] Found open port: {port} on {ip}")
    return os_info, open_ports

def scan_port(ip, port, version_detection, verbose):
    if stop_scan.is_set():
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"
                version = grab_banner(ip, port) if version_detection else "N/A"
                if verbose:
                    print(f"[*] Scanned port {port}: Open ({service})")
                return (port, "Open", service, version)
    except:
        pass
    return None

def network_scan(ip_range, ports, no_ping, verbose, version_detection, os_detection):
    start_time = time.time()
    live_hosts = []
    ip_queue = Queue()

    for ip in ipaddress.IPv4Network(ip_range, strict=False):
        ip_queue.put(str(ip))

    def discover_worker():
        while not ip_queue.empty() and not stop_scan.is_set():
            ip = ip_queue.get()
            if no_ping or is_host_up(ip, verbose):
                live_hosts.append(ip)
            ip_queue.task_done()

    if verbose:
        print("[*] Starting network scan ...")

    threads = [threading.Thread(target=discover_worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        stop_scan.set()
        print("\n[!] Scan interrupted. Exiting ...")
        return {}

    scan_results = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_host = {executor.submit(scan_host, host, ports, verbose, version_detection, os_detection): host
                          for host in live_hosts}
        try:
            for future in future_to_host:
                host = future_to_host[future]
                try:
                    scan_results[host] = future.result()
                except:
                    scan_results[host] = ("N/A", [])
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted. Exiting ...")
            stop_scan.set()

    end_time = time.time()
    if verbose:
        print(f"[*] Scan completed in {end_time - start_time:.2f} seconds.")
    return scan_results

def print_results(scan_results):
    table = PrettyTable(["Host", "OS", "Port", "State", "Service", "Version"])
    for host, (os_info, ports) in scan_results.items():
        if ports:
            for port, state, service, version in ports:
                table.add_row([host, os_info, port, state, service, version])
        else:
            table.add_row([host, os_info, "N/A", "N/A", "N/A", "N/A"])
    print(table)

def parse_ports(port_string):
    ports = set()
    parts = port_string.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
            except:
                continue
        else:
            try:
                ports.add(int(part))
            except:
                continue
    return sorted(list(ports))

def main():
    parser = argparse.ArgumentParser(description="Network Scanner with multiple features.")
    parser.add_argument("-t", "--target", help="Target IP or range (e.g. 192.168.1.0/24)", required=True)
    parser.add_argument("-p", "--ports", help="Specify ports (e.g. 22,80,443 or 10-100 or 'all' or 'common')", default="common")
    parser.add_argument("-n", "--no-ping", action="store_true", help="No ping mode (assume all hosts as up)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-V", "--version", action="store_true", help="Version detection")
    parser.add_argument("-o", "--os", action="store_true", help="Enable OS detection")
    args = parser.parse_args()

    # Handle port input formats
    if args.ports.lower() == "all":
        ports = range(1, 65536)
    elif args.ports.lower() == "common":
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389]
    else:
        ports = parse_ports(args.ports)

    try:
        ipaddress.IPv4Address(args.target)
        scan_results = network_scan(args.target, ports, args.no_ping, args.verbose, args.version, args.os)
    except ipaddress.AddressValueError:
        scan_results = network_scan(args.target, ports, args.no_ping, args.verbose, args.version, args.os)

    print_results(scan_results)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stop_scan.set()
        print("\n[!] Scan interrupted by user. Exiting ...")
