# base/tools/zap/zap_runner.py
import json
import time
import requests
from typing import Dict, List
from ..base import BaseToolRunner
import asyncio


class ZAPRunner(BaseToolRunner):
    """OWASP ZAP - Web application security scanner"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.zap_api_key = self.config.get('zap_api_key', '')
        self.zap_host = self.config.get('zap_host', 'localhost')
        self.zap_port = self.config.get('zap_port', 8080)
        self.zap_url = f"http://{self.zap_host}:{self.zap_port}"
        
    async def scan(self) -> Dict:
        """Run ZAP scan"""
        try:
            # Start ZAP session
            await self._start_session()
            
            # Spider the target
            await self._spider_target()
            
            # Active scan
            await self._active_scan()
            
            # Get results
            alerts = await self._get_alerts()
            
            return self.parse_output(alerts)
        except Exception as e:
            return {'tool': 'zap', 'error': str(e), 'findings': []}
    
    async def _start_session(self):
        """Start new ZAP session"""
        url = f"{self.zap_url}/JSON/core/action/newSession/"
        params = {
            'apikey': self.zap_api_key,
            'name': f'scan_{int(time.time())}',
            'overwrite': 'true'
        }
        response = requests.get(url, params=params)
        return response.json()
    
    async def _spider_target(self):
        """Spider the target URL"""
        url = f"{self.zap_url}/JSON/spider/action/scan/"
        params = {
            'apikey': self.zap_api_key,
            'url': self.target,
            'maxChildren': 10
        }
        
        response = requests.get(url, params=params)
        scan_id = response.json().get('scan')
        
        # Wait for spider to complete
        while True:
            status_url = f"{self.zap_url}/JSON/spider/view/status/"
            status_params = {'apikey': self.zap_api_key, 'scanId': scan_id}
            status = requests.get(status_url, params=status_params).json().get('status')
            if status == '100':
                break
            await asyncio.sleep(2)
    
    async def _active_scan(self):
        """Run active scan"""
        url = f"{self.zap_url}/JSON/ascan/action/scan/"
        params = {
            'apikey': self.zap_api_key,
            'url': self.target,
            'recurse': 'true',
            'inScopeOnly': 'false',
            'scanPolicyName': 'Default Policy',
            'method': 'GET',
            'postData': ''
        }
        
        response = requests.get(url, params=params)
        scan_id = response.json().get('scan')
        
        # Wait for scan to complete
        while True:
            status_url = f"{self.zap_url}/JSON/ascan/view/status/"
            status_params = {'apikey': self.zap_api_key, 'scanId': scan_id}
            status = requests.get(status_url, params=status_params).json().get('status')
            if status == '100':
                break
            await asyncio.sleep(5)
    
    async def _get_alerts(self) -> List[Dict]:
        """Get scan alerts"""
        url = f"{self.zap_url}/JSON/core/view/alerts/"
        params = {
            'apikey': self.zap_api_key,
            'baseurl': self.target,
            'start': 0,
            'count': 1000
        }
        
        response = requests.get(url, params=params)
        return response.json().get('alerts', [])
    
    def parse_output(self, alerts: List[Dict]) -> Dict:
        """Parse ZAP alerts"""
        findings = []
        
        # Severity mapping
        severity_map = {
            '0': 'info',
            '1': 'low',
            '2': 'medium',
            '3': 'high'
        }
        
        for alert in alerts:
            findings.append({
                'name': alert.get('name', 'Unknown'),
                'description': alert.get('description', ''),
                'severity': severity_map.get(alert.get('riskcode', '0'), 'info'),
                'remediation': alert.get('solution', ''),
                'evidence': alert.get('evidence', ''),
                'proof_of_concept': alert.get('cweid', ''),
                'cwe_id': f"CWE-{alert.get('cweid', '')}" if alert.get('cweid') else '',
                'url': alert.get('url', ''),
                'parameter': alert.get('param', ''),
                'tool': 'zap',
                'reference': alert.get('reference', '')
            })
        
        return {
            'tool': 'zap',
            'findings': findings,
            'total': len(findings)
        }