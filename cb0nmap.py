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
            
            run_nmap(scan, target, output_file)
            
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

    if scanforports == "Y":
        # Read every nmap output file and add ports to the scanned_ports set
        for file_name in os.listdir(base_dir):
            if file_name.endswith(".nmap"):
                file_path = os.path.join(base_dir, file_name)
                scanned_ports.update(extract_ports(file_path))
    
        # Perform additional scans for each unique open port
        for port in all_ports:
            if port not in scanned_ports:
                port_nmapfile = f"nmap_port_{port}_{get_current_time()}.nmap"
                output_file = f"{port_dir}/{port_nmapfile}"
                save_port_scan(target, port, output_file)
                scanned_ports.add(port)
            
if __name__ == "__main__":
    main()
