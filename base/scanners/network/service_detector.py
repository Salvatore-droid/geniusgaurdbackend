# base/scanners/network/service_detector.py
import asyncio
import socket
import ssl
from typing import Dict, List
import re

from ..base import BaseScanner

class ServiceDetector(BaseScanner):
    """Advanced service fingerprinting and version detection"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        
        # Service fingerprints
        self.fingerprints = {
            'ssh': {
                'patterns': [r'SSH-\d+\.\d+', r'OpenSSH'],
                'banner_grabbing': True
            },
            'ftp': {
                'patterns': [r'220.*FTP', r'530.*FTP', r'FTP server'],
                'banner_grabbing': True,
                'commands': ['HELP', 'SYST']
            },
            'http': {
                'patterns': [r'HTTP/\d\.\d', r'Server:', r'<html'],
                'banner_grabbing': True,
                'headers': ['Server', 'X-Powered-By', 'X-AspNet-Version']
            },
            'smtp': {
                'patterns': [r'220.*SMTP', r'ESMTP'],
                'banner_grabbing': True,
                'commands': ['EHLO test.com', 'HELP']
            },
            'mysql': {
                'patterns': [r'mysql', r'MariaDB'],
                'banner_grabbing': True
            },
            'postgresql': {
                'patterns': [r'PostgreSQL', r'PSQL'],
                'banner_grabbing': True
            },
            'redis': {
                'patterns': [r'+OK', r'-ERR'],
                'banner_grabbing': True,
                'commands': ['INFO', 'PING']
            },
            'mongodb': {
                'patterns': [r'MongoDB', r'wire version'],
                'banner_grabbing': True
            }
        }
    
    async def scan(self) -> 'ScanResult':
        """Perform service detection"""
        
        for port_info in self.result.open_ports:
            await self._analyze_service(port_info)
        
        return self.result
    
    async def _analyze_service(self, port_info: Dict):
        """Analyze service on specific port"""
        port = port_info['port']
        protocol = port_info.get('protocol', 'tcp')
        
        # Try to connect and get banner
        banner = await self._get_banner(port, protocol)
        if banner:
            port_info['banner'] = banner
            service = self._identify_service(banner, port)
            port_info['service'] = service.get('name', 'unknown')
            port_info['version'] = service.get('version', '')
            port_info['extrainfo'] = service.get('extra', '')
            
            # Try service-specific probes
            await self._service_probes(port_info)
    
    async def _get_banner(self, port: int, protocol: str) -> str:
        """Get service banner"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # Connect
            sock.connect((self.target, port))
            
            # Send probe
            probes = [
                b'\r\n',
                b'HEAD / HTTP/1.0\r\n\r\n',
                b'HELP\r\n',
                b'INFO\r\n',
                b'STATUS\r\n'
            ]
            
            for probe in probes:
                try:
                    sock.send(probe)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    if banner:
                        sock.close()
                        return banner.strip()
                except:
                    continue
            
            sock.close()
            
        except Exception as e:
            self.logger.debug(f"Banner grab failed for port {port}: {str(e)}")
        
        return ''
    
    def _identify_service(self, banner: str, port: int) -> Dict:
        """Identify service from banner"""
        result = {
            'name': 'unknown',
            'version': '',
            'extra': ''
        }
        
        banner_lower = banner.lower()
        
        # Try to extract version
        version_patterns = [
            r'version[\s]+([\d\.]+)',
            r'v([\d\.]+)',
            r'([\d\.]+)[\s]*\(',
            r'/([\d\.]+)'
        ]
        
        for service, fp in self.fingerprints.items():
            for pattern in fp.get('patterns', []):
                if re.search(pattern, banner, re.IGNORECASE):
                    result['name'] = service
                    
                    # Try to extract version
                    for vpattern in version_patterns:
                        version_match = re.search(vpattern, banner, re.IGNORECASE)
                        if version_match:
                            result['version'] = version_match.group(1)
                            break
                    
                    break
        
        # Port-based fallback
        if result['name'] == 'unknown':
            port_services = {
                21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 80: 'http',
                110: 'pop3', 443: 'https', 3306: 'mysql', 5432: 'postgresql',
                6379: 'redis', 27017: 'mongodb'
            }
            result['name'] = port_services.get(port, 'unknown')
        
        return result
    
    async def _service_probes(self, port_info: Dict):
        """Send service-specific probes"""
        service = port_info.get('service', 'unknown')
        port = port_info['port']
        
        if service in self.fingerprints:
            fp = self.fingerprints[service]
            commands = fp.get('commands', [])
            
            for cmd in commands:
                response = await self._send_command(port, cmd)
                if response:
                    if 'version' in response.lower() or 'server' in response.lower():
                        port_info['service_info'] = response