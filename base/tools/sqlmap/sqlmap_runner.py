# base/tools/sqlmap/sqlmap_runner.py
import json
import re
from typing import Dict, List
from ..base import BaseToolRunner

class SQLMapRunner(BaseToolRunner):
    """SQLMap - Automatic SQL injection tool"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.sqlmap_path = self.config.get('sqlmap_path', 'sqlmap')
        
    async def scan(self) -> Dict:
        """Run sqlmap scan"""
        # SQLMap can be noisy, so we'll run a basic test
        cmd = [
            self.sqlmap_path,
            '-u', self.target,
            '--batch',
            '--random-agent',
            '--level', '1',
            '--risk', '1',
            '--dbs'  # Try to enumerate databases
        ]
        
        stdout, stderr = await self.run_command(cmd, timeout=600)
        
        return self.parse_output(stdout)
    
    def parse_output(self, output: str) -> Dict:
        """Parse sqlmap output"""
        findings = []
        
        # Check for vulnerabilities
        if 'vulnerable' in output.lower():
            # Extract injection points
            injection_pattern = r"Parameter: (.+?) \((.+?)\)"
            matches = re.findall(injection_pattern, output)
            
            for param, method in matches:
                findings.append({
                    'name': 'SQL Injection',
                    'description': f"Parameter '{param}' is vulnerable to SQL injection",
                    'severity': 'critical',
                    'affected_component': param,
                    'remediation': "Use parameterized queries and input validation",
                    'evidence': f"Method: {method}",
                    'cwe_id': 'CWE-89',
                    'tool': 'sqlmap'
                })
        
        # Extract databases found
        db_pattern = r"available databases \[(\d+)\]:\n(.+?)(?=\n\n|\Z)"
        db_match = re.search(db_pattern, output, re.DOTALL)
        
        databases = []
        if db_match:
            db_text = db_match.group(2)
            databases = re.findall(r'\[\*\] (.+)', db_text)
        
        return {
            'tool': 'sqlmap',
            'vulnerable': len(findings) > 0,
            'findings': findings,
            'databases': databases,
            'total': len(findings)
        }