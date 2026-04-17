# base/scanners/web/csrf_tester.py
import asyncio
import aiohttp
from typing import Dict, List
import re
from urllib.parse import urljoin

from ..base import BaseScanner, Vulnerability

class CSRTester(BaseScanner):
    """Cross-Site Request Forgery (CSRF) vulnerability tester"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        
        # CSRF token patterns
        self.csrf_patterns = [
            r'csrf[_-]?token',
            r'xsrf[_-]?token',
            r'csrfmiddlewaretoken',
            r'__RequestVerificationToken',
            r'csrf',
            r'xsrf',
            r'nonce',
            r'state'
        ]
        
        # State-changing HTTP methods
        self.state_changing_methods = ['POST', 'PUT', 'DELETE', 'PATCH']
    
    async def scan(self) -> 'ScanResult':
        """Test for CSRF vulnerabilities"""
        
        # Find all forms
        forms = self.result.forms
        
        for form in forms:
            await self._test_form_csrf(form)
        
        # Test AJAX endpoints
        await self._test_ajax_endpoints()
        
        return self.result
    
    async def _test_form_csrf(self, form: Dict):
        """Test a form for CSRF vulnerability"""
        method = form.get('method', 'get').upper()
        
        # Only test state-changing methods
        if method in self.state_changing_methods:
            # Check if form has CSRF token
            has_csrf = self._check_csrf_token(form)
            
            if not has_csrf:
                # Try to submit without token
                vulnerable = await self._test_without_token(form)
                
                if vulnerable:
                    vuln = Vulnerability(
                        name="Cross-Site Request Forgery (CSRF)",
                        description="Form is vulnerable to CSRF attacks - no CSRF token protection",
                        severity="medium",
                        cvss_score=6.5,
                        cwe_id="CWE-352",
                        affected_component="Web Form",
                        remediation="Implement CSRF tokens for all state-changing operations",
                        evidence=f"Form action: {form.get('action', 'unknown')}\nMethod: {method}",
                        references=[
                            "https://owasp.org/www-community/attacks/csrf",
                            "https://cwe.mitre.org/data/definitions/352.html"
                        ],
                        tags=['csrf', 'web']
                    )
                    self.add_vulnerability(vuln)
    
    def _check_csrf_token(self, form: Dict) -> bool:
        """Check if form contains CSRF token"""
        for input_field in form.get('inputs', []):
            name = input_field.get('name', '').lower()
            for pattern in self.csrf_patterns:
                if re.search(pattern, name):
                    return True
        return False
    
    async def _test_without_token(self, form: Dict) -> bool:
        """Test if form accepts requests without CSRF token"""
        action = form.get('action', '')
        if not action.startswith('http'):
            action = urljoin(self.target, action)
        
        try:
            async with aiohttp.ClientSession() as session:
                # Submit form without CSRF token
                data = {}
                for input_field in form.get('inputs', []):
                    if not self._check_csrf_token({'inputs': [input_field]}):
                        data[input_field['name']] = 'test'
                
                if data:
                    async with session.post(action, data=data, ssl=False) as response:
                        # Check if request succeeded
                        return response.status < 400
                        
        except:
            pass
        
        return False
    
    async def _test_ajax_endpoints(self):
        """Test AJAX endpoints for CSRF"""
        # Look for endpoints that might be vulnerable
        # This would require JavaScript analysis
        pass