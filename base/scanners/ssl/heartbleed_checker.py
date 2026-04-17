# base/scanners/ssl/heartbleed_checker.py
import socket
import struct
import asyncio
from typing import Dict

from ..base import BaseScanner, Vulnerability

class HeartbleedChecker(BaseScanner):
    """Heartbleed vulnerability (CVE-2014-0160) checker"""
    
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
        """Check for Heartbleed vulnerability"""
        
        if await self._check_heartbleed():
            vuln = Vulnerability(
                name="Heartbleed Vulnerability (CVE-2014-0160)",
                description="Server is vulnerable to Heartbleed attack",
                severity="critical",
                cvss_score=9.8,
                cve_id="CVE-2014-0160",
                cwe_id="CWE-119",
                affected_component="OpenSSL",
                remediation="Update OpenSSL to version 1.0.1g or later",
                evidence="Heartbeat extension supports oversized payload",
                references=[
                    "https://heartbleed.com/",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160"
                ],
                exploit_available=True,
                tags=['heartbleed', 'ssl', 'critical']
            )
            self.add_vulnerability(vuln)
        
        return self.result
    
    async def _check_heartbleed(self) -> bool:
        """Test for Heartbleed vulnerability"""
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.hostname, self.port))
            
            # Send TLS heartbeat request
            await self._send_heartbeat(sock)
            
            # Try to receive response
            try:
                response = sock.recv(1024)
                if len(response) > 3:
                    # Check if we got more data than expected
                    return True
            except:
                pass
            
            sock.close()
            
        except Exception as e:
            self.logger.debug(f"Heartbleed check failed: {str(e)}")
        
        return False
    
    async def _send_heartbeat(self, sock):
        """Send malicious heartbeat request"""
        # TLS Heartbeat Request structure
        heartbeat_record = bytes([
            0x18,  # Heartbeat
            0x03, 0x01,  # TLS version
            0x00, 0x03,  # Length
            0x01,  # HeartbeatRequest
            0x40, 0x00  # Payload length (16384) - malicious oversized
        ])
        
        sock.send(heartbeat_record)