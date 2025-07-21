#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Auto SSH Auditor with Live Reporting
# Author: Anonymous (For Authorized Testing Only)

import paramiko
import socket
import nmap3
import netifaces
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import warnings
import json
import time
import os
from datetime import datetime

warnings.filterwarnings("ignore")

class LiveSSHAuditor:
    def __init__(self):
        self.report = {
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "network_scan": {},
            "ssh_servers": []
        }
        self.log_file = f"ssh_audit_{time.strftime('%Y%m%d_%H%M%S')}.json"
        self.update_ui("Initializing SSH Auditor...")

    def update_ui(self, message, status="INFO"):
        """Display live updates with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{status}] {message}")
        self.save_progress()

    def save_progress(self):
        """Auto-save results to JSON file"""
        with open(self.log_file, 'w') as f:
            json.dump(self.report, f, indent=4)

    def get_local_network(self):
        """Automatically detect local network range"""
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr_info in addrs[netifaces.AF_INET]:
                    if 'addr' in addr_info and 'netmask' in addr_info:
                        ip = addr_info['addr']
                        if not ip.startswith('127.'):
                            netmask = addr_info['netmask']
                            network = self.calculate_network(ip, netmask)
                            return f"{network}/24"
        return "192.168.1.0/24"  # Fallback

    def calculate_network(self, ip, netmask):
        """Calculate network address from IP and netmask"""
        ip_parts = list(map(int, ip.split('.')))
        mask_parts = list(map(int, netmask.split('.')))
        network_parts = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
        return '.'.join(network_parts)

    def network_discovery(self):
        """Find all live hosts with SSH open"""
        network = self.get_local_network()
        self.update_ui(f"Scanning network: {network}")
        
        nmap = nmap3.Nmap()
        results = nmap.scan_top_ports(network, args="-p 22 --open")
        
        found_hosts = 0
        for host in results:
            if host == "runtime" or host == "stats":
                continue
            
            if 'ports' in results[host]:
                for port in results[host]['ports']:
                    if port['portid'] == '22' and port['state'] == 'open':
                        found_hosts += 1
                        host_info = {
                            "ip": host,
                            "mac": results[host].get('macaddress', {}).get('addr', 'unknown'),
                            "hostname": results[host].get('hostnames', [{}])[0].get('name', ''),
                            "ssh_service": port['service']['name']
                        }
                        self.report["network_scan"][host] = host_info
                        self.update_ui(f"Found SSH server: {host} ({host_info['hostname']})")

        self.update_ui(f"Network scan complete. Found {found_hosts} SSH servers.")

    def ssh_audit(self, host):
        """Comprehensive SSH server audit"""
        host_report = {
            "ip": host,
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "banner": "",
            "vulnerabilities": [],
            "auth_methods": [],
            "brute_status": "not attempted"
        }

        try:
            # Banner grabbing
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((host, 22))
                banner = s.recv(1024).decode().strip()
                host_report["banner"] = banner
                self.update_ui(f"{host} - Banner: {banner[:50]}...")

                # Check for known vulnerabilities
                if "OpenSSH" in banner:
                    if "7.2" in banner:
                        host_report["vulnerabilities"].append("CVE-2017-15906")
                    if "8.3" in banner:
                        host_report["vulnerabilities"].append("CVE-2021-41617")

            # Auth methods check
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, port=22, timeout=3, username='invalid', password='invalid')
            except paramiko.AuthenticationException:
                transport = ssh.get_transport()
                if transport:
                    host_report["auth_methods"] = transport.auth_methods(host)
                    self.update_ui(f"{host} - Auth methods: {host_report['auth_methods']}")
            except Exception as e:
                self.update_ui(f"{host} - Auth check failed: {str(e)}", "WARNING")
            finally:
                if 'ssh' in locals():
                    ssh.close()

            # Brute force simulation (DEMO ONLY - DISABLED BY DEFAULT)
            if os.getenv('ALLOW_BRUTE') == "1":
                host_report["brute_status"] = self.simulate_brute(host)

        except Exception as e:
            self.update_ui(f"Audit failed for {host}: {str(e)}", "ERROR")

        self.report["ssh_servers"].append(host_report)
        self.update_ui(f"Completed audit for {host}")

    def simulate_brute(self, host):
        """Controlled brute force simulation (for authorized tests)"""
        self.update_ui(f"Starting brute force simulation on {host}", "WARNING")
        
        common_logins = [
            ("admin", "admin"),
            ("root", "123456"),
            ("user", "password")
        ]
        
        for user, passwd in common_logins:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, port=22, username=user, password=passwd, timeout=2)
                ssh.close()
                self.update_ui(f"[CRITICAL] {host} - Valid credentials: {user}/{passwd}", "CRITICAL")
                return {"found": True, "credentials": f"{user}:{passwd}"}
            except:
                continue
        
        self.update_ui(f"{host} - No weak credentials found", "INFO")
        return {"found": False}

    def run_audits(self):
        """Main execution flow"""
        self.network_discovery()
        
        if not self.report["network_scan"]:
            self.update_ui("No SSH servers found. Exiting.", "WARNING")
            return

        self.update_ui("Starting comprehensive SSH audits...")
        
        # Threaded auditing for all found hosts
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for host in self.report["network_scan"].keys():
                futures.append(executor.submit(self.ssh_audit, host))
            
            for future in futures:
                future.result()  # Wait for completion

        self.update_ui("All audits completed!", "SUCCESS")
        self.save_progress()
        print(f"\nFinal report saved to: {os.path.abspath(self.log_file)}")

if __name__ == "__main__":
    print("""
    ███████╗███████╗██╗  ██╗   ███████╗ ██████╗ ██████╗ ██╗   ██╗██╗████████╗
    ╚══███╔╝██╔════╝██║  ██║   ██╔════╝██╔═══██╗██╔══██╗██║   ██║██║╚══██╔══╝
      ███╔╝ ███████╗███████║   ███████╗██║   ██║██████╔╝██║   ██║██║   ██║   
     ███╔╝  ╚════██║██╔══██║   ╚════██║██║   ██║██╔══██╗╚██╗ ██╔╝██║   ██║   
    ███████╗███████║██║  ██║██╗███████║╚██████╔╝██║  ██║ ╚████╔╝ ██║   ██║   
    ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝   ╚═╝   
    """)
    print("[!] LEGAL NOTICE: Use only on networks you own or have explicit permission to test!\n")

    auditor = LiveSSHAuditor()
    try:
        auditor.run_audits()
    except KeyboardInterrupt:
        auditor.update_ui("Scan interrupted by user", "WARNING")
    except Exception as e:
        auditor.update_ui(f"Fatal error: {str(e)}", "CRITICAL")
