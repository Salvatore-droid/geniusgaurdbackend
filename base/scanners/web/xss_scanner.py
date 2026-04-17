# base/scanners/web/xss_scanner.py
import asyncio
import aiohttp
import re
from typing import List, Dict
from urllib.parse import urlparse, urlencode, parse_qs

from ..base import BaseScanner, Vulnerability

class XSSScanner(BaseScanner):
    """Advanced Cross-Site Scripting (XSS) vulnerability scanner"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        
        # XSS payloads by type
        self.payloads = {
            'reflected': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "\"><script>alert('XSS')</script>",
                "'><script>alert('XSS')</script>",
                "</script><script>alert('XSS')</script>",
                "<svg/onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<iframe src=\"javascript:alert('XSS')\">",
                "<input type=\"text\" value=\"\" onfocus=alert('XSS') autofocus>",
                "<details open ontoggle=alert('XSS')>",
                "<video src=x onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "';alert('XSS')//",
                "\";alert('XSS')//",
                "{{constructor.constructor('alert(1)')()}}",  # AngularJS
                "${{constructor.constructor('alert(1)')()}}",  # Vue.js
            ],
            'stored': [
                "<script>alert('StoredXSS')</script>",
                "<img src=x onerror=alert('StoredXSS')>",
                "javascript:alert('StoredXSS')",
            ],
            'dom': [
                "#<script>alert('DOMXSS')</script>",
                "#javascript:alert('DOMXSS')",
                "#onerror=alert('DOMXSS')",
            ]
        }
        
        # Context-specific payloads
        self.context_payloads = {
            'attribute': [
                "\" onmouseover=alert('XSS') \"",
                "' onmouseover=alert('XSS') '",
                "javascript:alert('XSS')",
            ],
            'script': [
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "</script><script>alert('XSS')</script>",
            ],
            'style': [
                "expression(alert('XSS'))",
                "javascript:alert('XSS')",
            ],
            'url': [
                "javascript:alert('XSS')",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            ]
        }
        
        # XSS evasion techniques
        self.evasion_techniques = [
            lambda p: p.replace('<', '&lt;').replace('>', '&gt;'),  # HTML encode
            lambda p: p.replace('<', '<\\u003c').replace('>', '<\\u003e'),  # Unicode escape
            lambda p: p.replace('alert', 'prompt'),  # Alternative functions
            lambda p: p.upper(),  # Uppercase
            lambda p: p.lower(),  # Lowercase
            lambda p: p.replace('script', 'scr<script>ipt'),  # Nested tags
            lambda p: p.replace(' ', '/**/'),  # Comment injection
            lambda p: p.replace('alert', '\\u0061\\u006c\\u0065\\u0072\\u0074'),  # Unicode encoding
        ]
    
    async def scan(self) -> 'ScanResult':
        """Execute comprehensive XSS scan"""
        
        # Find all injection points
        injection_points = await self._find_injection_points()
        
        # Test each injection point
        for point in injection_points:
            await self._test_injection_point(point)
        
        return self.result
    
    async def _find_injection_points(self) -> List[Dict]:
        """Find all potential XSS injection points"""
        points = []
        
        async with aiohttp.ClientSession() as session:
            try:
                # Get main page
                async with session.get(self.target, ssl=False) as response:
                    html = await response.text()
                    
                    # Find forms
                    forms = await self._extract_forms(html)
                    for form in forms:
                        points.append({
                            'type': 'form',
                            'url': self.target,
                            'method': form.get('method', 'get'),
                            'inputs': form.get('inputs', [])
                        })
                    
                    # Find URL parameters
                    parsed = urlparse(self.target)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        points.append({
                            'type': 'url_param',
                            'url': self.target,
                            'params': list(params.keys())
                        })
                    
                    # Find hash parameters (DOM-based)
                    if parsed.fragment:
                        points.append({
                            'type': 'hash',
                            'url': self.target,
                            'fragment': parsed.fragment
                        })
                    
            except Exception as e:
                self.logger.error(f"Failed to find injection points: {str(e)}")
        
        return points
    
    async def _test_injection_point(self, point: Dict):
        """Test a single injection point for XSS vulnerabilities"""
        
        if point['type'] == 'form':
            await self._test_form_xss(point)
        elif point['type'] == 'url_param':
            await self._test_url_param_xss(point)
        elif point['type'] == 'hash':
            await self._test_dom_xss(point)
    
    async def _test_form_xss(self, point: Dict):
        """Test form for XSS vulnerabilities"""
        
        async with aiohttp.ClientSession() as session:
            for payload in self.payloads['reflected']:
                # Try each evasion technique
                for evasion in self.evasion_techniques:
                    test_payload = evasion(payload)
                    
                    form_data = {}
                    for input_field in point['inputs']:
                        form_data[input_field['name']] = test_payload
                    
                    try:
                        if point['method'].lower() == 'post':
                            async with session.post(point['url'], data=form_data, ssl=False) as response:
                                html = await response.text()
                                if test_payload in html:
                                    await self._report_xss(
                                        point=point,
                                        payload=test_payload,
                                        type='reflected',
                                        context='form'
                                    )
                        else:
                            async with session.get(point['url'], params=form_data, ssl=False) as response:
                                html = await response.text()
                                if test_payload in html:
                                    await self._report_xss(
                                        point=point,
                                        payload=test_payload,
                                        type='reflected',
                                        context='form'
                                    )
                    except:
                        continue
    
    async def _test_url_param_xss(self, point: Dict):
        """Test URL parameters for XSS"""
        
        async with aiohttp.ClientSession() as session:
            parsed = urlparse(point['url'])
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            for param in point['params']:
                for payload in self.payloads['reflected']:
                    for evasion in self.evasion_techniques:
                        test_payload = evasion(payload)
                        
                        # Build test URL
                        params = {param: test_payload}
                        test_url = f"{base_url}?{urlencode(params)}"
                        
                        try:
                            async with session.get(test_url, ssl=False) as response:
                                html = await response.text()
                                if test_payload in html:
                                    await self._report_xss(
                                        point=point,
                                        payload=test_payload,
                                        type='reflected',
                                        context='url_param',
                                        param=param
                                    )
                        except:
                            continue
    
    async def _test_dom_xss(self, point: Dict):
        """Test DOM-based XSS"""
        
        for payload in self.payloads['dom']:
            # Test in URL fragment
            test_url = f"{point['url']}#{payload}"
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, ssl=False) as response:
                        html = await response.text()
                        # Check for DOM XSS indicators
                        if self._check_dom_xss(html, payload):
                            await self._report_xss(
                                point=point,
                                payload=payload,
                                type='dom',
                                context='hash'
                            )
            except:
                continue
    
    async def _test_stored_xss(self, point: Dict):
        """Test for stored XSS (requires multiple requests)"""
        # Implement stored XSS testing logic
        pass
    
    async def _report_xss(self, point: Dict, payload: str, type: str, context: str, param: str = None):
        """Report XSS vulnerability"""
        
        # Check if already reported
        for existing in self.result.vulnerabilities:
            if existing.name == f"Cross-Site Scripting (XSS) - {type}" and existing.evidence == payload:
                return
        
        # Determine severity based on context
        severity = 'high' if type == 'reflected' else 'critical' if type == 'stored' else 'medium'
        
        # Build evidence
        evidence = f"Payload: {payload}\n"
        evidence += f"Context: {context}\n"
        evidence += f"URL: {point['url']}\n"
        if param:
            evidence += f"Parameter: {param}\n"
        
        vuln = Vulnerability(
            name=f"Cross-Site Scripting (XSS) - {type.title()}",
            description=f"A {type} Cross-Site Scripting vulnerability was detected.",
            severity=severity,
            cvss_score=7.5 if severity == 'high' else 8.5 if severity == 'critical' else 5.0,
            cvss_vector=f"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            cwe_id="CWE-79",
            affected_component="Web Application",
            remediation=self._get_xss_remediation(context),
            evidence=evidence,
            proof_of_concept=f"Visit: {point['url']} with payload: {payload}",
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cwe.mitre.org/data/definitions/79.html"
            ],
            tags=['xss', type, context]
        )
        
        self.add_vulnerability(vuln)
        self.logger.warning(f"XSS vulnerability found: {type} at {point['url']}")
    
    async def _extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        pattern = r'<form.*?>(.*?)</form>'
        
        for form_match in re.finditer(pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(1)
            form = {
                'action': self._extract_attribute(form_match.group(0), 'action'),
                'method': self._extract_attribute(form_match.group(0), 'method', 'get'),
                'inputs': []
            }
            
            # Extract inputs
            input_pattern = r'<input.*?>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_type = self._extract_attribute(input_match.group(0), 'type', 'text')
                input_name = self._extract_attribute(input_match.group(0), 'name')
                if input_name:
                    form['inputs'].append({
                        'type': input_type,
                        'name': input_name
                    })
            
            forms.append(form)
        
        return forms
    
    async def _extract_attribute(self, tag: str, attr: str, default: str = '') -> str:
        """Extract attribute value from HTML tag"""
        pattern = f'{attr}=[\'"](.*?)[\'"]'
        match = re.search(pattern, tag, re.IGNORECASE)
        return match.group(1) if match else default
    
    async def _check_dom_xss(self, html: str, payload: str) -> bool:
        """Check for DOM XSS indicators"""
        # Look for unsafe JavaScript patterns
        unsafe_patterns = [
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'location\s*=',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
        ]
        
        for pattern in unsafe_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        return False
    
    def _get_xss_remediation(self, context: str) -> str:
        """Get XSS remediation advice based on context"""
        remediations = {
            'form': """
                1. Implement input validation on both client and server side
                2. Use output encoding when displaying user input
                3. Implement Content Security Policy (CSP)
                4. Use HTTP-only cookies
                5. Consider using X-XSS-Protection header
            """,
            'url_param': """
                1. Validate and sanitize all URL parameters
                2. Use parameterized queries
                3. Implement proper URL encoding
                4. Consider using URL rewriting
                5. Implement Content Security Policy (CSP)
            """,
            'hash': """
                1. Avoid using document.write or innerHTML with untrusted data
                2. Use textContent instead of innerHTML when possible
                3. Implement proper output encoding
                4. Use Content Security Policy (CSP) with script-src restrictions
                5. Consider using framework's built-in XSS protections
            """
        }
        
        return remediations.get(context, "Implement proper input validation and output encoding.")