#!/usr/bin/env python

import os
import subprocess
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
from libnmap.parser import NmapParser
import shutil
import tempfile
from threading import Lock

# Use a lock for thread safety when writing to files
write_lock = Lock()

# Constants
COLORS = {
    "blue": "\033[1;34m",
    "green": "\033[1;32m",
    "red": "\033[1;31m",
    "yellow": "\033[1;33m",
    "reset": "\033[0m"
}
SYMBOLS = {
    "plus": f"{COLORS['blue']}[{COLORS['reset']}{COLORS['green']}+{COLORS['reset']}{COLORS['blue']}]",
    "cross": f"{COLORS['blue']}[{COLORS['reset']}{COLORS['red']}x{COLORS['reset']}{COLORS['blue']}]",
    "star": f"{COLORS['blue']}[*]{COLORS['reset']}",
    "warn": f"{COLORS['blue']}[{COLORS['reset']}{COLORS['yellow']}!{COLORS['reset']}{COLORS['blue']}]"
}


# Print the banner with some information about the script
def banner():
    banner_text = f"""
    {COLORS['yellow']}
              _                _                         
   __ _ _   _| |_ ___  ___ ___| |__  ___  ___ __ _ _ __  
  / _` | | | | __/ _ \/ __/ __| '_ \/ __|/ __/ _` | '_ \ 
 | (_| | |_| | || (_) \__ \__ \ | | \__ \ (_| (_| | | | |
  \__,_|\__,_|\__\___/|___/___/_| |_|___/\___\__,_|_| |_|
                                                         
    @BeeSec
    Helping you Bee Secure
    
    usage: auto-sshscan.py -i [nmap-ouput.xml] -o [output-directory] -t [num-threads]{COLORS['reset']}
    """
    print(banner_text)


# Function to perform the SSH scan using ssh_scan
def perform_ssh_scan(ip, port, sshscan_folder):
    try:
        # Search for the 'sshscan.py' script in common locations
        possible_paths = [
            "/opt/SSHScan/sshscan.py",
            "/usr/local/bin/sshscan.py",
            "/usr/bin/sshscan.py",
            "sshscan.py"  # Assuming it's in the system PATH
        ]

        sshscan_script = None
        for path in possible_paths:
            if os.path.isfile(path):
                sshscan_script = path
                break

        if not sshscan_script:
            print(f"{SYMBOLS['warn']} sshscan.py not found. Cloning from the repository...")
            sshscan_script = clone_sshscan_repository()

        cmd = ["python3", sshscan_script, "-t", ip, ":", str(port)]

        result = subprocess.run(cmd, capture_output=True, text=True)
        ssh_scan_output = result.stdout

        output_filename = f"sshscan-{ip}-{port}.txt"
        output_filepath = os.path.join(sshscan_folder, output_filename)
        with open(output_filepath, 'w') as output_file:
            output_file.write(ssh_scan_output)

        print(f"{SYMBOLS['plus']} SSHScan successful for {ip}:{port}")
        return ssh_scan_output
    except Exception as e:
        print(f"{SYMBOLS['cross']} Error performing ssh_scan for {ip}:{port}: {e}")
        return None


# Function to clone SSHScan repository
def clone_sshscan_repository():
    temp_dir = tempfile.mkdtemp()
    try:
        # Clone the SSHScan repository into the temporary directory
        clone_cmd = ["git", "clone", "https://github.com/evict/SSHScan.git", temp_dir]
        subprocess.run(clone_cmd, check=True)

        # Move the 'sshscan.py' script to the expected location
        sshscan_script = os.path.join(temp_dir, "sshscan.py")
        destination_path = "/opt/SSHScan/sshscan.py"
        shutil.move(sshscan_script, destination_path)

        print(f"{SYMBOLS['plus']} Successfully cloned SSHScan repository to {destination_path}")
        return destination_path
    except Exception as e:
        print(f"{SYMBOLS['cross']} Error cloning SSHScan repository: {e}")
        return None
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)


# Function to check weak components and extract information
def check_weak_components(ssh_scan_output, identifier):
    weak_components = []
    identifier_lower = identifier.lower()

    start_index = ssh_scan_output.lower().find(identifier_lower)

    if start_index != -1:
        start_index += len(identifier_lower)
        end_index = ssh_scan_output.lower().find("\n", start_index)
        weak_components_text = ssh_scan_output[start_index:end_index].strip()

        # Check for weak HostKey, weak ciphers, weak KEX and weak MACs 
        if identifier == "Detected the following weak HostKey algorithms:":
            weak_components = [comp.strip() for comp in weak_components_text.split(",")]
        elif identifier == "Detected the following weak ciphers:" or \
                identifier == "Detected the following weak KEX algorithms:" or \
                identifier == "Detected the following weak MACs:":
            weak_components = [comp.strip() for comp in weak_components_text.split("\n")]

    return weak_components


# Function to save IP and port combination to corresponding results file
def save_weak_component(ip, port, components, filename, sshscan_folder):
    if components:
        file_path = os.path.join(sshscan_folder, filename)

        # Use lock to ensure thread safety when writing to files
        with write_lock:
            try:
                with open(file_path, 'a') as file:
                    for comp in components:
                        file.write(f"{ip}:{port}\n")
            except Exception as e:
                print(f"DEBUG: Error saving components for {ip}:{port}: {e}")


# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Auto-sslscan - SSL scanning for open ports in Nmap XML report.")
    parser.add_argument("-i", "--input", dest="nmapxml", required=True, help="Path to the Nmap XML output file")
    parser.add_argument("-o", "--output", dest="output_directory", required=True, help="Path to the output directory")
    parser.add_argument("-t", "--threads", dest="num_threads", type=int, default=10,
                        help="Number of threads for parallel execution")
    return parser.parse_args()


# Main function that performs the SSH scanning and analysis
def main():
    banner()
    args = parse_args()
    nmapxml = args.nmapxml
    output_directory = args.output_directory
    num_threads = args.num_threads

    # Create a 'sshscan' folder if it doesn't exist
    sshscan_folder = os.path.join(output_directory, "sshscan")
    os.makedirs(sshscan_folder, exist_ok=True)

    # Create result files if they don't exist
    weak_configs = {
        "weak_ciphers.txt": "Detected the following weak ciphers:",
        "weak_kex.txt": "Detected the following weak KEX algorithms:",
        "weak_hostkeys.txt": "Detected the following weak HostKey algorithms:",
        "weak_macs.txt": "Detected the following weak MACs:"
    }

    for filename in weak_configs.keys():
        file_path = os.path.join(sshscan_folder, filename)
        if not os.path.exists(file_path):
            with open(file_path, 'w'):
                pass

    # Count the total number of SSH services to be scanned
    total_services = sum(1 for host in NmapParser.parse_fromfile(nmapxml).hosts for s in host.services if
                         s.open() and "ssh" in s.service.lower())

    print(f"{SYMBOLS['star']} Performing SSH Scanning against {total_services} services...\n")

    current_scan = 0
    total_scans = 0

    component_counts = {filename: 0 for filename in weak_configs}

    # Create a ThreadPoolExecutor for parallel execution
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for host in NmapParser.parse_fromfile(nmapxml).hosts:
            ip = host.address
            ssh_ports = {s.port for s in host.services if s.open() and "ssh" in s.service.lower()}

            if ssh_ports:
                total_scans += len(ssh_ports)

            # Store futures in a list
            futures = []

            for i, ssh_port in enumerate(ssh_ports, start=1):
                port = ssh_port
                print(f"{SYMBOLS['star']} Performing sshscan {total_scans} of {total_services} on {ip}:{ssh_port}")

                try:
                    future = executor.submit(perform_ssh_scan, ip, ssh_port, sshscan_folder)
                    futures.append((ip, port, future))
                except RuntimeError as e:
                    print(f"{SYMBOLS['cross']} Error scheduling sshscan for {ip}:{ssh_port}: {e}")
                    continue

                if current_scan % num_threads == 0 or current_scan == total_scans:
                    for ip, port, future in futures:
                        try:
                            ssh_scan_output = future.result()

                            if ssh_scan_output:
                                for filename, identifier in weak_configs.items():
                                    components = check_weak_components(ssh_scan_output, identifier)
                                    save_weak_component(ip, port, components, filename, sshscan_folder)
                                    component_counts[filename] += len(components)

                        except Exception as e:
                            print(f"{SYMBOLS['cross']} Error performing sshscan for {ip}:{port}: {e}")

                    futures = []

        print("\nSummary:")
        for filename, identifier in weak_configs.items():
            print(f"{SYMBOLS['star']} {identifier} {component_counts[filename]} Hosts")

        print(f"\n{SYMBOLS['star']} Program has finished.")


if __name__ == "__main__":
    main()
