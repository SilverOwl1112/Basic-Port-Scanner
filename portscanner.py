import nmap  # Import the nmap module (you need to install python-nmap via pip)
import sys   # For exiting on error
import socket  # For basic hostname resolution and IP validation

def is_valid_ip(host):
    """Check if the provided host is a valid IP address."""
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        return False

def resolve_host(target):
    """Resolve the target to an IP address if it's a hostname."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print("[!] Error: Invalid hostname or IP address.")
        sys.exit(1)

def scan_ports(target, start_port, end_port):
    """Scan ports on a given target using nmap with enhanced options."""
    print(f"\n[+] Starting scan on {target} from port {start_port} to {end_port}...\n")

    scanner = nmap.PortScanner()

    try:
        # Perform the scan with service version detection and default scripts
        scanner.scan(
            host=target,
            arguments=f"-p {start_port}-{end_port} -sS -sV -T4 --script=default"
        )
    except Exception as e:
        print(f"[!] Nmap scan failed: {e}")
        sys.exit(1)

    # Check if the host is up
    if target not in scanner.all_hosts():
        print("[!] Target host is down or unreachable.")
        return

    print(f"[+] Scan Results for {target}:\n")

    for port in range(start_port, end_port + 1):
        try:
            port_info = scanner[target]['tcp'][port]
            state = port_info['state']
            name = port_info.get('name', 'unknown')
            product = port_info.get('product', '')
            version = port_info.get('version', '')
            extrainfo = port_info.get('extrainfo', '')

            print(f"Port {port}/tcp: {state}")
            if state == "open":
                print(f"  Service: {name} {product} {version}")
                if extrainfo:
                    print(f"  Extra Info: {extrainfo}")
        except KeyError:
            # Port not in result, likely because it is closed or filtered and not reported
            continue

if __name__ == "__main__":
    print("==== Advanced Python Port Scanner ====")
    target = input("Enter your target IP or hostname: ").strip()

    # Validate and resolve IP
    if not is_valid_ip(target):
        target = resolve_host(target)

    try:
        start_port = int(input("Enter start port [default=1]: ") or "1")
        end_port = int(input("Enter end port [default=1024]: ") or "1024")

        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
            raise ValueError("Invalid port range.")
    except ValueError as ve:
        print(f"[!] Error: {ve}")
        sys.exit(1)

    scan_ports(target, start_port, end_port)
