# Auto-SSHScan

A tool for automating SSH vulnerability scans on open ports discovered in an Nmap scan report. This tool utilises [sshscan](https://github.com/evict/SSHScan) for SSH scanning, and processes results to identify weak ciphers, weak HostKey algorithms, weak KEX algorithms, and weak MACs.

# Features
- Parses Nmap XML output to identify open SSH ports
- Uses sshscan.py to assess each open SSH port for vulnerabilities
- Automatically clones the SSHScan repository if sshscan.py is missing
- Saves results of weak ciphers, HostKey algorithms, KEX algorithms, and MACs in organised files Installation

# Usage
```
git clone https://github.com/BeeSec-UK/autosshscan
cd autosshscan
pip install -r requirements.txt
python auto-sshscan.py -i <nmap-output.xml> -o <output-directory> -t <num-threads>
```

# Arguments
```
-i, --input: Path to the Nmap XML output file
-o, --output: Directory to store SSHScan results
-t, --threads: Number of threads for parallel execution (default: 10)
```

# Example
```
python auto-sshscan.py -i nmap_scan.xml -o results -t 5
```