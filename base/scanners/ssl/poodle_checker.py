# base/scanners/ssl/poodle_checker.py
import socket
import ssl
from typing import Dict

from ..base import BaseScanner, Vulnerability

class PoodleChecker(BaseScanner):
    """POODLE vulnerability (CVE-2014-3566) checker"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        
        # Extract hostname and port
        if ':' in self.target:
            self.hostname, port_str = self.target.split(':')
            self.port = int(port_str)
        else:
            self.hostname = self.target
            self.port = 443
    
    async def scan(self) -> 'ScanResult':
        """Check for POODLE vulnerability"""
        
        if await self._check_poodle():
            vuln = Vulnerability(
                name="POODLE Vulnerability (CVE-2014-3566)",
                description="Server supports SSL 3.0, vulnerable to POODLE attack",
                severity="high",
                cvss_score=7.5,
                cve_id="CVE-2014-3566",
                cwe_id="CWE-310",
                affected_component="SSL 3.0",
                remediation="Disable SSL 3.0 support, use TLS 1.0 or higher",
                evidence="SSL 3.0 protocol is enabled",
                references=[
                    "https://www.openssl.org/~bodo/ssl-poodle.pdf",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566"
                ],
                tags=['poodle', 'ssl', 'ssl3']
            )
            self.add_vulnerability(vuln)
        
        return self.result
    
    async def _check_poodle(self) -> bool:
        """Check if SSL 3.0 is supported"""
        try:
            # Try SSL 3.0 connection
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # If connection succeeds, SSL 3.0 is supported
                    return True
                    
        except (ssl.SSLError, ConnectionError, socket.timeout):
            pass
        
        return False