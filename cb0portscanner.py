import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Constants
num_threads = 100 # How much threats to use
timeout = 1 # Timeout value
min_port = 1 # Min port to scan (Min: 1)
max_port = 65536 # Max port to scan (Max: 65536)

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return port, True
            else:
                return port, False
    except Exception as e:
        return port, False

def port_scanner(ip, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning Ports", unit="port"):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    return open_ports

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple but fast port scanner.")
    parser.add_argument("ip", help="The IP address to scan.")
    args = parser.parse_args()

    target_ip = args.ip

    target_ports = range(min_port, max_port)
    open_ports = port_scanner(target_ip, target_ports)
if open_ports:
    print(f"Open ports on {target_ip}: {open_ports}")
else:
    print(f"No open ports found on {target_ip}.")

