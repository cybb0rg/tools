import os
import subprocess
import datetime

def get_current_time():
    """Get current date and time in DDMMYYYYHHMM format"""
    return datetime.datetime.now().strftime("%d%m%Y%H%M")

def run_nmap(scan_type, target, output_file):
    """Run nmap scan and save output to a file"""
    nmap_cmd = f"sudo nmap -{scan_type} -T5 -sV -Pn -p- {target} -oN {output_file}"
    subprocess.run(nmap_cmd, shell=True)

def save_port_scan(target, port, output_file):
    """Run nmap scan on specific port and save output to a file"""
    nmap_cmd = f"nmap -Pn -sV -sC -p{port} {target} -oN {output_file}"
    subprocess.run(nmap_cmd, shell=True)

def extract_ports(nmap_output_file):
    """Extract open ports from nmap output file"""
    ports = []
    with open(nmap_output_file, 'r') as file:
        for line in file:
            if '/tcp' in line or '/udp' in line:
                port = line.split('/')[0].strip()
                ports.append(port)
    return ports

def main():
    foldername = input("Enter the folder name to save the results: ")
    target = input("Enter the domain/IP to scan: ")
    askscantype = input("Enter the scan type you wish (SYN(sS), FULL(sT), UDP(sU), ALL) (default: SYN): ")
    askscanforports = input("Do you want to scan for ports? (Y/n) (default: Y): ")

    setscantype = askscantype.upper() if askscantype else "SYN"
    scanforports = askscanforports.upper() if askscanforports else "Y"
    
    # Create necessary directories
    base_dir = f"{foldername}/enum/portscanners/nmap"
    port_dir = f"{foldername}/enum/ports"
    os.makedirs(base_dir, exist_ok=True)
    os.makedirs(port_dir, exist_ok=True)

    # Define nmap scan types
    scan_types = {'SYN': 'sS', 'FULL': 'sT', 'UDP': 'sU'}

    all_ports = set()
    scanned_ports = set()

    if setscantype == "ALL":
        for scan, scan_type in scan_types.items():
            date_hour = get_current_time()
            nmapfile = f"nmap_{scan_type}_{target}_{date_hour}"
            output_file = f"{base_dir}/{nmapfile}.nmap"
            
            run_nmap(scan_type, target, output_file)
            
            # Extract open ports from the nmap output
            ports = extract_ports(output_file)
            all_ports.update(ports)
    elif setscantype in scan_types:
        date_hour = get_current_time()
        scan = scan_types[setscantype]
        nmapfile = f"nmap_{setscantype}_{target}_{date_hour}"
        output_file = f"{base_dir}/{nmapfile}.nmap"

        run_nmap(scan, target, output_file)
        
        # Extract open ports from the nmap output
        ports = extract_ports(output_file)
        all_ports.update(ports)

    print(f"All extracted ports after initial scans: {all_ports}")

    if scanforports == "Y":
        # Perform additional scans for each unique open port
        for port in all_ports:
            # Check if a scan for this port already exists in /enum/ports
            existing_port_files = [f for f in os.listdir(port_dir) if f"nmap_port_{port}_" in f]
            if existing_port_files:
                print(f"Port {port} already has a scan file {existing_port_files[0]}, skipping...")
                continue

            port_nmapfile = f"nmap_port_{port}_{get_current_time()}.nmap"
            output_file = f"{port_dir}/{port_nmapfile}"
            print(f"Scanning port {port} and saving to {output_file}")
            save_port_scan(target, port, output_file)
            scanned_ports.add(port)
            
if __name__ == "__main__":
    main()
