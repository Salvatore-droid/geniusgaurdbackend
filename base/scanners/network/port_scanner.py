# base/scanners/network/port_scanner.py
import asyncio
import socket
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor
import nmap

from ..base import BaseScanner, Vulnerability

class PortScanner(BaseScanner):
    """Advanced port scanner with service detection"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.nm = nmap.PortScanner()
        self.port_ranges = self.config.get('port_ranges', '1-10000')
        self.scan_speed = self.config.get('scan_speed', 'T4')  # T0-T5
        
        # Common ports for quick scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888
        ]
        
        # Dangerous ports
        self.dangerous_ports = {
            21: "FTP - Cleartext credentials",
            23: "Telnet - Unencrypted",
            445: "SMB - Vulnerable to EternalBlue",
            3389: "RDP - BlueKeep vulnerability",
            5900: "VNC - Often misconfigured",
        }
        
    async def scan(self) -> 'ScanResult':
        """Execute port scan"""
        
        # Quick scan first
        await self._quick_scan()
        
        # Full scan if configured
        if self.config.get('full_scan', False):
            await self._full_scan()
        
        # Service detection
        await self._detect_services()
        
        # Check for dangerous ports
        await self._check_dangerous_ports()
        
        return self.result
    
    async def _quick_scan(self):
        """Quick scan of common ports"""
        self.logger.info(f"Starting quick port scan on {self.target}")
        
        open_ports = []
        tasks = []
        
        for port in self.common_ports:
            tasks.append(self._check_port(port))
        
        results = await asyncio.gather(*tasks)
        
        for port, is_open, service in results:
            if is_open:
                port_info = {
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': service,
                    'banner': ''
                }
                open_ports.append(port_info)
                self.result.open_ports.append(port_info)
        
        self.add_info('quick_scan_ports', open_ports)
        self.logger.info(f"Quick scan found {len(open_ports)} open ports")
    
    async def _full_scan(self):
        """Full port scan using nmap"""
        self.logger.info(f"Starting full port scan on {self.target}")
        
        try:
            # Run nmap in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as pool:
                result = await loop.run_in_executor(
                    pool,
                    lambda: self.nm.scan(
                        self.target,
                        self.port_ranges,
                        f'-sV -sC -{self.scan_speed}'
                    )
                )
            
            # Parse results
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        port_info = {
                            'port': port,
                            'protocol': proto,
                            'state': service['state'],
                            'service': service.get('name', 'unknown'),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', ''),
                            'cpe': service.get('cpe', '')
                        }
                        
                        # Check if already in quick scan results
                        existing = next(
                            (p for p in self.result.open_ports if p['port'] == port),
                            None
                        )
                        if existing:
                            existing.update(port_info)
                        else:
                            self.result.open_ports.append(port_info)
            
            self.add_info('full_scan_completed', True)
            
        except Exception as e:
            self.logger.error(f"Full scan failed: {str(e)}")
    
    async def _check_port(self, port: int) -> tuple:
        """Check if a single port is open"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            # Connect
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # Try to get banner
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    banner = ''
                
                sock.close()
                
                # Detect service
                service = self._detect_service(port, banner)
                return (port, True, service)
            
            sock.close()
            return (port, False, '')
            
        except:
            return (port, False, '')
    
    async def _detect_services(self):
        """Detect services on open ports"""
        for port_info in self.result.open_ports:
            if not port_info.get('service') or port_info['service'] == 'unknown':
                port_info['service'] = self._detect_service(
                    port_info['port'],
                    port_info.get('banner', '')
                )
    
    def _detect_service(self, port: int, banner: str) -> str:
        """Detect service based on port and banner"""
        # Port-based detection
        port_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
            139: 'netbios-ssn', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
            993: 'imaps', 995: 'pop3s', 1723: 'pptp', 3306: 'mysql',
            3389: 'ms-wbt-server', 5432: 'postgresql', 5900: 'vnc',
            6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt'
        }
        
        if port in port_services:
            return port_services[port]
        
        # Banner-based detection
        banner_lower = banner.lower()
        if 'ssh' in banner_lower:
            return 'ssh'
        elif 'ftp' in banner_lower:
            return 'ftp'
        elif 'http' in banner_lower:
            return 'http'
        elif 'mysql' in banner_lower:
            return 'mysql'
        
        return 'unknown'
    
    async def _check_dangerous_ports(self):
        """Check for dangerous open ports"""
        for port_info in self.result.open_ports:
            port = port_info['port']
            if port in self.dangerous_ports:
                vuln = Vulnerability(
                    name=f"Dangerous Port Open: {port}",
                    description=f"Port {port} is open: {self.dangerous_ports[port]}",
                    severity="high",
                    cvss_score=7.5,
                    affected_component="Network Infrastructure",
                    remediation=f"Close port {port} if not needed, or implement strong security controls",
                    evidence=f"Open port detected: {port}",
                    references=[
                        "https://www.cisa.gov/uscert/ncas/alerts",
                        f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=port+{port}"
                    ],
                    tags=['dangerous-port', f'port-{port}']
                )
                self.add_vulnerability(vuln)