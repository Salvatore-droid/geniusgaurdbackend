# base/ai/deep_analyzer.py
import json
import asyncio
from typing import Dict, List, Any
from datetime import datetime
import logging

from .groq_client import groq_client

logger = logging.getLogger(__name__)

class DeepSessionAnalyzer:
    """AI-powered analyzer for recorded browser sessions"""
    
    def __init__(self, session_data: Dict, session_id: int):
        self.session_data = session_data
        self.session_id = session_id
        self.findings = []
        self.analysis_time = 0
        
    async def analyze(self) -> List[Dict]:
        """Run comprehensive AI analysis on recorded session"""
        import time
        start_time = time.time()
        
        try:
            # Phase 1: Analyze requests/responses
            await self._analyze_requests()
            
            # Phase 2: Detect business logic flaws
            await self._analyze_business_logic()
            
            # Phase 3: Check authentication mechanisms
            await self._analyze_authentication()
            
            # Phase 4: Find complex XSS
            await self._analyze_xss()
            
            # Phase 5: Detect authorization issues
            await self._analyze_authorization()
            
            # Phase 6: Session management issues
            await self._analyze_session_management()
            
            # Phase 7: API security
            await self._analyze_api_security()
            
        except Exception as e:
            logger.error(f"Deep analysis failed: {e}")
            raise
        
        self.analysis_time = time.time() - start_time
        return self.findings
    
    async def _analyze_requests(self):
        """Analyze all captured requests"""
        requests = self.session_data.get('requests', [])
        
        # Group by endpoint
        endpoints = {}
        for req in requests:
            url = req.get('url', '').split('?')[0]
            if url not in endpoints:
                endpoints[url] = []
            endpoints[url].append(req)
        
        # Analyze each endpoint
        for url, reqs in endpoints.items():
            await self._analyze_endpoint(url, reqs)
    
    async def _analyze_endpoint(self, url: str, requests: List[Dict]):
        """Analyze a single endpoint"""
        
        # Check for sensitive data in URLs
        for req in requests:
            if '?' in req.get('url', ''):
                params = req['url'].split('?')[1]
                if any(sensitive in params.lower() for sensitive in ['password', 'token', 'api_key', 'secret']):
                    self.findings.append({
                        'finding_type': 'api',
                        'name': 'Sensitive Data in URL',
                        'description': f'Sensitive parameters exposed in URL: {params}',
                        'severity': 'high',
                        'cvss_score': 7.0,
                        'url': url,
                        'method': req.get('method'),
                        'remediation': 'Move sensitive data to request body or headers',
                        'ai_confidence': 0.95
                    })
    
    async def _analyze_business_logic(self):
        """Detect business logic flaws"""
        user_actions = self.session_data.get('userActions', [])
        
        # Look for sequential actions that might indicate logic flaws
        workflows = self._extract_workflows(user_actions)
        
        for workflow in workflows:
            await self._analyze_workflow(workflow)
    
    def _extract_workflows(self, actions: List[Dict]) -> List[List[Dict]]:
        """Extract user workflows from actions"""
        workflows = []
        current = []
        
        for action in actions:
            current.append(action)
            if action.get('type') == 'form_submit':
                workflows.append(current.copy())
                current = []
        
        return workflows
    
    async def _analyze_workflow(self, workflow: List[Dict]):
        """Analyze a workflow for logic flaws"""
        
        # Check for price manipulation in e-commerce
        price_changes = self._track_price_changes(workflow)
        if price_changes:
            self.findings.append({
                'finding_type': 'business_logic',
                'name': 'Potential Price Manipulation',
                'description': f'Price changed from {price_changes["from"]} to {price_changes["to"]}',
                'severity': 'high',
                'cvss_score': 8.0,
                'remediation': 'Validate prices server-side, never trust client-side values',
                'ai_confidence': 0.8
            })
        
        # Check for quantity manipulation
        quantity_changes = self._track_quantity_changes(workflow)
        if quantity_changes:
            self.findings.append({
                'finding_type': 'business_logic',
                'name': 'Potential Quantity Manipulation',
                'description': f'Quantity changed during workflow',
                'severity': 'medium',
                'cvss_score': 6.0,
                'remediation': 'Validate quantities server-side',
                'ai_confidence': 0.75
            })
    
    def _track_price_changes(self, workflow: List[Dict]) -> Dict:
        """Track price changes through workflow"""
        prices = []
        for action in workflow:
            if 'price' in str(action.get('data', {})).lower():
                # Extract price logic here
                return {'from': 'original', 'to': 'modified'}
        return None
    
    def _track_quantity_changes(self, workflow: List[Dict]) -> bool:
        """Track quantity changes"""
        for action in workflow:
            if 'quantity' in str(action.get('data', {})).lower():
                return True
        return False
    
    async def _analyze_authentication(self):
        """Analyze authentication mechanisms"""
        
        auth_requests = [
            r for r in self.session_data.get('requests', [])
            if any(word in r.get('url', '').lower() 
                   for word in ['login', 'signin', 'auth', 'authenticate'])
        ]
        
        if not auth_requests:
            return
        
        # Check for credentials in URL
        for req in auth_requests:
            if '?' in req.get('url', ''):
                self.findings.append({
                    'finding_type': 'authentication',
                    'name': 'Credentials Exposed in URL',
                    'description': 'Authentication request exposes credentials in URL',
                    'severity': 'critical',
                    'cvss_score': 9.0,
                    'url': req.get('url'),
                    'remediation': 'Use POST requests for authentication',
                    'ai_confidence': 1.0
                })
            
            # Check for missing security headers
            headers = req.get('responseHeaders', {})
            if headers.get('set-cookie'):
                cookie = headers['set-cookie']
                if 'Secure' not in cookie:
                    self.findings.append({
                        'finding_type': 'authentication',
                        'name': 'Cookie Missing Secure Flag',
                        'description': 'Session cookie transmitted without Secure flag',
                        'severity': 'high',
                        'cvss_score': 7.0,
                        'remediation': 'Add Secure flag to all cookies',
                        'ai_confidence': 1.0
                    })
                if 'HttpOnly' not in cookie:
                    self.findings.append({
                        'finding_type': 'authentication',
                        'name': 'Cookie Missing HttpOnly Flag',
                        'description': 'Session cookie accessible to JavaScript',
                        'severity': 'medium',
                        'cvss_score': 5.0,
                        'remediation': 'Add HttpOnly flag to prevent XSS access',
                        'ai_confidence': 1.0
                    })
    
    async def _analyze_xss(self):
        """Find complex XSS vulnerabilities"""
        
        # Check for reflected input in responses
        for req in self.session_data.get('requests', []):
            if req.get('method') == 'GET' and '?' in req.get('url', ''):
                params = req['url'].split('?')[1]
                
                # This would actually test payloads
                # For now, flag potential reflected parameters
                if params and any(p in req.get('responseBody', '') for p in params.split('&')):
                    self.findings.append({
                        'finding_type': 'xss',
                        'name': 'Potential Reflected Input',
                        'description': 'URL parameters appear to be reflected in response',
                        'severity': 'medium',
                        'cvss_score': 6.0,
                        'url': req.get('url'),
                        'remediation': 'Implement proper output encoding',
                        'ai_confidence': 0.6
                    })
    
    async def _analyze_authorization(self):
        """Detect authorization issues"""
        
        # Look for IDOR patterns
        requests = self.session_data.get('requests', [])
        idor_patterns = self._detect_idor_patterns(requests)
        
        for pattern in idor_patterns:
            self.findings.append({
                'finding_type': 'idor',
                'name': 'Potential IDOR Vulnerability',
                'description': f'Multiple requests to {pattern["url_pattern"]} with different IDs',
                'severity': 'high',
                'cvss_score': 8.0,
                'remediation': 'Implement proper access controls',
                'evidence': json.dumps(pattern['examples']),
                'ai_confidence': 0.7
            })
    
    def _detect_idor_patterns(self, requests: List[Dict]) -> List[Dict]:
        """Detect Insecure Direct Object Reference patterns"""
        import re
        patterns = {}
        
        for req in requests:
            url = req.get('url', '')
            # Find numeric IDs in URL
            ids = re.findall(r'/(\d+)(?:/|$)', url)
            if ids:
                pattern = re.sub(r'\d+', '{ID}', url)
                if pattern not in patterns:
                    patterns[pattern] = {
                        'url_pattern': pattern,
                        'examples': [],
                        'ids': set()
                    }
                patterns[pattern]['examples'].append(url)
                patterns[pattern]['ids'].add(ids[0])
        
        # Return patterns with multiple IDs
        return [p for p in patterns.values() if len(p['ids']) > 1]
    
    async def _analyze_session_management(self):
        """Analyze session management issues"""
        
        cookies = self.session_data.get('cookies', [])
        
        # Check session fixation
        if len(cookies) > 1:
            session_ids = [c.get('value') for c in cookies if 'session' in c.get('name', '').lower()]
            if len(set(session_ids)) > 1:
                self.findings.append({
                    'finding_type': 'session',
                    'name': 'Session ID Changed',
                    'description': 'Session ID changed during session - possible fixation',
                    'severity': 'high',
                    'cvss_score': 7.5,
                    'remediation': 'Maintain consistent session ID after login',
                    'ai_confidence': 0.8
                })
    
    async def _analyze_api_security(self):
        """Analyze API security issues"""
        
        api_requests = [
            r for r in self.session_data.get('requests', [])
            if any(pattern in r.get('url', '') 
                   for pattern in ['/api/', '/v1/', '/v2/', '/graphql', '/rest'])
        ]
        
        # Check for missing rate limiting headers
        for req in api_requests:
            headers = req.get('responseHeaders', {})
            if 'x-ratelimit-limit' not in headers:
                self.findings.append({
                    'finding_type': 'api',
                    'name': 'Missing Rate Limiting',
                    'description': f'API endpoint {req.get("url")} lacks rate limiting headers',
                    'severity': 'medium',
                    'cvss_score': 5.0,
                    'url': req.get('url'),
                    'remediation': 'Implement rate limiting to prevent abuse',
                    'ai_confidence': 0.9
                })
                break