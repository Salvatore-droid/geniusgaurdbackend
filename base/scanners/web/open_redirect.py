# base/scanners/web/open_redirect.py
import asyncio
import aiohttp
from typing import Dict, List
from urllib.parse import urlparse, urlencode, parse_qs

from ..base import BaseScanner, Vulnerability

class OpenRedirectScanner(BaseScanner):
    """Open Redirect vulnerability scanner"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        
        # Redirect payloads
        self.redirect_payloads = [
            '//evil.com',
            'https://evil.com',
            'http://evil.com',
            '//evil.com@google.com',
            '//google.com@evil.com',
            '\\evil.com',
            'https:evil.com',
            'http:evil.com',
            '//evil.com/%2F..',
            '/\\evil.com',
            'javascript:alert(1)//',
            'data:text/html,<script>alert(1)</script>',
            'https://evil.com?valid=true',
            'https://evil.com#valid.com'
        ]
        
        # Redirect parameters
        self.redirect_params = [
            'redirect', 'url', 'next', 'return', 'returnTo', 'return_to',
            'goto', 'forward', 'forwardTo', 'target', 'destination',
            'out', 'view', 'dir', 'to', 'path', 'continue', 'return_path',
            'return_url', 'return_uri', 'redirect_url', 'redirect_uri',
            'callback', 'callback_url', 'callback_uri', 'next_url',
            'next_uri', 'referer', 'referrer', 'origUrl', 'originUrl',
            'image_url', 'img_url', 'load_file', 'file', 'document'
        ]
    
    async def scan(self) -> 'ScanResult':
        """Scan for open redirect vulnerabilities"""
        
        # Find all redirect parameters
        params = await self._find_redirect_parameters()
        
        # Test each parameter
        for param_info in params:
            await self._test_parameter_redirect(param_info)
        
        return self.result
    
    async def _find_redirect_parameters(self) -> List[Dict]:
        """Find potential redirect parameters"""
        params = []
        
        # Check URL parameters
        parsed = urlparse(self.target)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for param_name in query_params.keys():
                if any(rp in param_name.lower() for rp in self.redirect_params):
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
                if any(rp in input_name for rp in self.redirect_params):
                    params.append({
                        'type': 'form',
                        'name': input_field['name'],
                        'form': form,
                        'original_value': ''
                    })
        
        return params
    
    async def _test_parameter_redirect(self, param_info: Dict):
        """Test a parameter for open redirect"""
        
        for payload in self.redirect_payloads:
            result = await self._send_payload(param_info, payload)
            if result and await self._check_redirect_success(result, payload):
                await self._report_redirect(param_info, payload)
                return  # Found vulnerability, no need to test more
    
    async def _send_payload(self, param_info: Dict, payload: str) -> aiohttp.ClientResponse:
        """Send redirect payload"""
        try:
            async with aiohttp.ClientSession() as session:
                if param_info['type'] == 'url':
                    # Modify URL parameter
                    parsed = urlparse(param_info['url'])
                    params = parse_qs(parsed.query)
                    params[param_info['name']] = [payload]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                    
                    # Don't follow redirects
                    async with session.get(test_url, ssl=False, allow_redirects=False) as response:
                        return response
                
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
                        async with session.post(action, data=data, ssl=False, allow_redirects=False) as response:
                            return response
                    else:
                        async with session.get(action, params=data, ssl=False, allow_redirects=False) as response:
                            return response
                            
        except Exception as e:
            self.logger.debug(f"Redirect payload failed: {str(e)}")
        
        return None
    
    async def _check_redirect_success(self, response: aiohttp.ClientResponse, payload: str) -> bool:
        """Check if redirect was successful"""
        
        # Check for redirect status codes
        if response.status in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            
            # Check if redirect goes to our payload
            if any(evil in location for evil in ['evil.com', 'javascript:', 'data:']):
                return True
            
            # Check for open redirect patterns
            if location.startswith('//') or location.startswith('\\'):
                return True
            
            # Check for protocol-relative redirects
            if location.startswith('/') and 'evil.com' in location:
                return True
        
        return False
    
    async def _report_redirect(self, param_info: Dict, payload: str):
        """Report open redirect vulnerability"""
        
        vuln = Vulnerability(
            name="Open Redirect",
            description="Application is vulnerable to open redirect attacks",
            severity="medium",
            cvss_score=5.5,
            cwe_id="CWE-601",
            affected_component="URL Redirect Handler",
            remediation="Validate and whitelist redirect URLs, avoid user-controlled redirects",
            evidence=f"Parameter: {param_info['name']}\nPayload: {payload}",
            proof_of_concept=f"Access: {self.target}?{param_info['name']}={payload}",
            references=[
                "https://owasp.org/www-community/attacks/Open_redirect",
                "https://cwe.mitre.org/data/definitions/601.html"
            ],
            tags=['redirect', 'open-redirect']
        )
        
        self.add_vulnerability(vuln)