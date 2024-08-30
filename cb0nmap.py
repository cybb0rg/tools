import os
import subprocess
import datetime

def get_current_time():
    """Get current date and time in DDMMYYYYHHMM format"""
    return datetime.datetime.now().strftime("%d%m%Y%H%M")

def run_nmap(scan_type, target, output_file):
    """Run nmap scan and save output to a file"""
    nmap_cmd = f"sudo nmap -{scan_type} -A -T4 -sV -Pn -p- {target} -oN {output_file}"
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
    target = input("Enter the domain/IP or path to the file with IPs: ")

    # Create necessary directories
    base_dir = f"{foldername}/enum/portscanners/nmap"
    port_dir = f"{foldername}/enum/ports"
    os.makedirs(base_dir, exist_ok=True)
    os.makedirs(port_dir, exist_ok=True)

    # Define nmap scan types
    scan_types = {'sS': 'SYN', 'sT': 'FULL', 'sU': 'UDP'}
    
    for scan, scan_type in scan_types.items():
        date_hour = get_current_time()
        nmapfile = f"nmap_{scan_type}_{date_hour}"
        output_file = f"{base_dir}/{nmapfile}.nmap"
        
        run_nmap(scan, target, output_file)
        
        # Extract open ports from the nmap output
        ports = extract_ports(output_file)
        
        # Perform additional scans for each open port
        for port in ports:
            port_nmapfile = f"{port_dir}/nmap_{scan_type}_{port}_{date_hour}.nmap"
            save_port_scan(target, port, port_nmapfile)

if __name__ == "__main__":
    main()
