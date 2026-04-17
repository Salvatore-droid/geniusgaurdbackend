# base/scanners/ssl/ssl_analyzer.py
import ssl
import socket
import asyncio
from typing import Dict, List
from datetime import datetime
import OpenSSL
import certifi

from ..base import BaseScanner, Vulnerability

class SSLAnalyzer(BaseScanner):
    """Comprehensive SSL/TLS analyzer"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        
        # Extract hostname and port
        if ':' in self.target:
            self.hostname, port_str = self.target.split(':')
            self.port = int(port_str)
        else:
            self.hostname = self.target
            self.port = 443
        
        # SSL/TLS versions
        self.tls_versions = {
            'SSLv2': ssl.PROTOCOL_SSLv23,  # Legacy
            'SSLv3': ssl.PROTOCOL_SSLv3,
            'TLSv1': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.3': ssl.PROTOCOL_TLS  # Latest
        }
        
        # Weak protocols
        self.weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        
        # Certificate issues
        self.cert_issues = []
    
    async def scan(self) -> 'ScanResult':
        """Perform comprehensive SSL/TLS analysis"""
        
        # Get certificate information
        cert_info = await self._get_certificate_info()
        if cert_info:
            self.result.ssl_info['certificate'] = cert_info
            
            # Check certificate issues
            await self._check_certificate(cert_info)
        
        # Check supported protocols
        protocols = await self._check_protocols()
        self.result.ssl_info['supported_protocols'] = protocols
        
        # Check cipher suites
        ciphers = await self._check_ciphers()
        self.result.ssl_info['cipher_suites'] = ciphers
        
        # Check for specific vulnerabilities
        await self._check_vulnerabilities()
        
        return self.result
    
    async def _get_certificate_info(self) -> Dict:
        """Get SSL certificate information"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Get certificate in PEM format for OpenSSL
                    pem_cert = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(binary_form=True))
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
                    
                    # Extract certificate details
                    cert_info = {
                        'subject': dict(x509.get_subject().get_components()),
                        'issuer': dict(x509.get_issuer().get_components()),
                        'version': x509.get_version(),
                        'serial_number': x509.get_serial_number(),
                        'not_before': x509.get_notBefore().decode('ascii'),
                        'not_after': x509.get_notAfter().decode('ascii'),
                        'signature_algorithm': x509.get_signature_algorithm().decode('ascii'),
                        'extensions': []
                    }
                    
                    # Get extensions
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        cert_info['extensions'].append({
                            'name': ext.get_short_name().decode('ascii'),
                            'critical': ext.get_critical(),
                            'value': str(ext)
                        })
                    
                    # Parse dates
                    cert_info['valid_from'] = datetime.strptime(
                        cert_info['not_before'], '%Y%m%d%H%M%SZ'
                    )
                    cert_info['valid_until'] = datetime.strptime(
                        cert_info['not_after'], '%Y%m%d%H%M%SZ'
                    )
                    cert_info['days_until_expiry'] = (
                        cert_info['valid_until'] - datetime.now()
                    ).days
                    
                    return cert_info
                    
        except Exception as e:
            self.logger.error(f"Failed to get certificate: {str(e)}")
            return None
    
    async def _check_certificate(self, cert_info: Dict):
        """Check certificate for issues"""
        
        # Check expiration
        if cert_info['days_until_expiry'] < 0:
            vuln = Vulnerability(
                name="SSL Certificate Expired",
                description="SSL certificate has expired",
                severity="critical",
                cvss_score=8.5,
                affected_component="SSL/TLS",
                remediation="Renew SSL certificate immediately",
                evidence=f"Certificate expired on: {cert_info['not_after']}",
                tags=['ssl', 'certificate']
            )
            self.add_vulnerability(vuln)
            
        elif cert_info['days_until_expiry'] < 30:
            vuln = Vulnerability(
                name="SSL Certificate Expiring Soon",
                description=f"SSL certificate expires in {cert_info['days_until_expiry']} days",
                severity="medium",
                cvss_score=5.0,
                affected_component="SSL/TLS",
                remediation="Renew SSL certificate before expiry",
                evidence=f"Expiry date: {cert_info['not_after']}",
                tags=['ssl', 'certificate']
            )
            self.add_vulnerability(vuln)
        
        # Check signature algorithm
        if 'md5' in cert_info['signature_algorithm'].lower():
            vuln = Vulnerability(
                name="Weak Certificate Signature Algorithm",
                description=f"Certificate uses weak signature algorithm: {cert_info['signature_algorithm']}",
                severity="high",
                cvss_score=7.0,
                affected_component="SSL/TLS",
                remediation="Use SHA-256 or stronger signature algorithm",
                evidence=f"Algorithm: {cert_info['signature_algorithm']}",
                tags=['ssl', 'certificate', 'weak-crypto']
            )
            self.add_vulnerability(vuln)
        
        # Check for wildcard certificate
        subject = cert_info['subject'].get(b'CN', b'').decode()
        if '*.' in subject:
            self.result.ssl_info['wildcard'] = True
    
    async def _check_protocols(self) -> Dict:
        """Check which SSL/TLS protocols are supported"""
        protocols = {}
        
        for protocol_name, protocol_version in self.tls_versions.items():
            try:
                context = ssl.SSLContext(protocol_version)
                with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        protocols[protocol_name] = True
                        
                        # Check if protocol is weak
                        if protocol_name in self.weak_protocols:
                            vuln = Vulnerability(
                                name=f"Weak SSL/TLS Protocol: {protocol_name}",
                                description=f"Server supports outdated {protocol_name} protocol",
                                severity="high",
                                cvss_score=7.0,
                                affected_component="SSL/TLS",
                                remediation=f"Disable {protocol_name} and use TLS 1.2 or 1.3",
                                evidence=f"Protocol {protocol_name} is enabled",
                                tags=['ssl', 'weak-protocol', protocol_name.lower()]
                            )
                            self.add_vulnerability(vuln)
                            
            except:
                protocols[protocol_name] = False
        
        return protocols
    
    async def _check_ciphers(self) -> List[Dict]:
        """Check supported cipher suites"""
        ciphers = []
        
        # Common cipher suites to test
        test_ciphers = [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-ECDSA-AES256-SHA384',
            'ECDHE-RSA-AES128-SHA256',
            'ECDHE-ECDSA-AES128-SHA256',
            'DHE-RSA-AES256-GCM-SHA384',
            'DHE-DSS-AES256-GCM-SHA384',
            'DHE-RSA-AES128-GCM-SHA256',
            'DHE-DSS-AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
            'AES128-GCM-SHA256',
            'AES256-SHA256',
            'AES128-SHA256',
            'AES256-SHA',
            'AES128-SHA',
            'RC4-SHA',
            'RC4-MD5',
            'DES-CBC3-SHA',
            'DES-CBC-SHA',
            'EXP-RC4-MD5',
            'EXP-DES-CBC-SHA'
        ]
        
        weak_ciphers = ['RC4', 'DES', 'EXP', 'MD5', 'NULL', 'anon', 'EXPORT']
        
        for cipher_name in test_ciphers:
            try:
                context = ssl.create_default_context()
                context.set_ciphers(cipher_name)
                
                with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        cipher = ssock.cipher()
                        if cipher:
                            cipher_info = {
                                'name': cipher[0],
                                'protocol': cipher[1],
                                'bits': cipher[2]
                            }
                            ciphers.append(cipher_info)
                            
                            # Check if cipher is weak
                            if any(weak in cipher[0] for weak in weak_ciphers):
                                vuln = Vulnerability(
                                    name="Weak Cipher Suite Supported",
                                    description=f"Server supports weak cipher: {cipher[0]}",
                                    severity="high",
                                    cvss_score=7.0,
                                    affected_component="SSL/TLS",
                                    remediation="Disable weak ciphers, use strong ciphers only",
                                    evidence=f"Cipher: {cipher[0]}, Bits: {cipher[2]}",
                                    tags=['ssl', 'weak-cipher']
                                )
                                self.add_vulnerability(vuln)
                                
            except:
                continue
        
        return ciphers
    
    async def _check_vulnerabilities(self):
        """Check for specific SSL/TLS vulnerabilities"""
        
        # Check Heartbleed
        heartbleed_checker = HeartbleedChecker(self.target, self.config)
        await heartbleed_checker.scan()
        for vuln in heartbleed_checker.result.vulnerabilities:
            self.add_vulnerability(vuln)
        
        # Check Poodle
        poodle_checker = PoodleChecker(self.target, self.config)
        await poodle_checker.scan()
        for vuln in poodle_checker.result.vulnerabilities:
            self.add_vulnerability(vuln)