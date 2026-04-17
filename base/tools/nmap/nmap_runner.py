# base/tools/nmap/nmap_runner.py
import re
import xml.etree.ElementTree as ET
import tempfile
import os
from typing import Dict, List
from ..base import BaseToolRunner

class NmapRunner(BaseToolRunner):
    """Nmap - Network discovery and security scanning"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.nmap_path = self.config.get('nmap_path', 'nmap')
        # Extract domain/ip from URL
        self.host = self._extract_host(target)
        
    def _extract_host(self, url: str) -> str:
        """Extract hostname from URL"""
        import re
        match = re.search(r'https?://([^/:]+)', url)
        if match:
            return match.group(1)
        return url.split('/')[0]
    
    async def scan(self) -> Dict:
        """Run nmap scan"""
        # Create temp file for XML output
        with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as tmp:
            output_file = tmp.name
        
        try:
            # Run nmap with service detection and scripts
            cmd = [
                self.nmap_path,
                '-sV',  # Version detection
                '-sC',  # Default scripts
                '-O',   # OS detection
                '--script', 'vuln',  # Vulnerability scripts
                '-p', '1-1000',  # Common ports
                '-oX', output_file,
                self.host
            ]
            
            stdout, stderr = await self.run_command(cmd, timeout=600)
            
            # Parse XML output
            return self.parse_xml_output(output_file)
            
        finally:
            # Cleanup
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def parse_xml_output(self, xml_file: str) -> Dict:
        """Parse nmap XML output"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            hosts = []
            findings = []
            
            for host in root.findall('host'):
                host_info = self._parse_host(host)
                hosts.append(host_info)
                
                # Check for vulnerabilities
                for port in host_info.get('ports', []):
                    if port.get('script'):
                        for script_output in port['script']:
                            if 'VULNERABLE' in script_output.upper():
                                findings.append({
                                    'name': f"Vulnerability on port {port['port']}",
                                    'description': script_output,
                                    'severity': 'high',
                                    'affected_component': port['service'],
                                    'port': port['port'],
                                    'tool': 'nmap'
                                })
            
            return {
                'tool': 'nmap',
                'hosts': hosts,
                'findings': findings,
                'total_hosts': len(hosts)
            }
            
        except Exception as e:
            return {'tool': 'nmap', 'error': str(e), 'hosts': []}
    
    def _parse_host(self, host_elem) -> Dict:
        """Parse host element"""
        host_info = {
            'addresses': [],
            'ports': [],
            'os': []
        }
        
        # Get addresses
        for addr in host_elem.findall('address'):
            host_info['addresses'].append({
                'addr': addr.get('addr'),
                'type': addr.get('addrtype')
            })
        
        # Get ports
        ports_elem = host_elem.find('ports')
        if ports_elem:
            for port in ports_elem.findall('port'):
                port_info = {
                    'port': port.get('portid'),
                    'protocol': port.get('protocol'),
                    'state': port.find('state').get('state') if port.find('state') else 'unknown',
                    'service': self._parse_service(port.find('service'))
                }
                
                # Get script output
                scripts = []
                for script in port.findall('script'):
                    scripts.append(script.get('output', ''))
                if scripts:
                    port_info['script'] = scripts
                
                host_info['ports'].append(port_info)
        
        # Get OS info
        os_elem = host_elem.find('os')
        if os_elem:
            for osmatch in os_elem.findall('osmatch'):
                host_info['os'].append(osmatch.get('name'))
        
        return host_info
    
    def _parse_service(self, service_elem) -> Dict:
        """Parse service element"""
        if service_elem is None:
            return {'name': 'unknown'}
        
        return {
            'name': service_elem.get('name', 'unknown'),
            'product': service_elem.get('product', ''),
            'version': service_elem.get('version', ''),
            'extrainfo': service_elem.get('extrainfo', '')
        }