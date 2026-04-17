# base/tools/nuclei/nuclei_runner.py
import json
import re
from typing import Dict, List
from ..base import BaseToolRunner

class NucleiRunner(BaseToolRunner):
    """Nuclei - Fast and customisable vulnerability scanner"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.nuclei_path = self.config.get('nuclei_path', 'nuclei')
        self.templates = self.config.get('templates', [
            'cves',
            'vulnerabilities',
            'misconfiguration',
            'exposures',
            'technologies'
        ])
    
    async def scan(self) -> Dict:
        """Run nuclei scan"""
        cmd = [
            self.nuclei_path,
            '-u', self.target,
            '-json',
            '-silent',
            '-stats',
            '-timeout', '5'
        ]
        
        # Add templates
        for template in self.templates:
            cmd.extend(['-t', template])
        
        # Add severity filter
        if self.config.get('severity'):
            cmd.extend(['-severity', self.config['severity']])
        
        stdout, stderr = await self.run_command(cmd, timeout=600)
        
        return self.parse_output(stdout)
    
    def parse_output(self, output: str) -> Dict:
        """Parse nuclei JSON output"""
        findings = []
        
        for line in output.split('\n'):
            if line.strip():
                try:
                    finding = json.loads(line)
                    
                    # Map severity
                    severity_map = {
                        'critical': 'critical',
                        'high': 'high',
                        'medium': 'medium',
                        'low': 'low',
                        'info': 'info'
                    }
                    
                    findings.append({
                        'name': finding.get('info', {}).get('name', 'Unknown'),
                        'description': finding.get('info', {}).get('description', ''),
                        'severity': severity_map.get(finding.get('info', {}).get('severity', '').lower(), 'info'),
                        'cvss_score': finding.get('info', {}).get('classification', {}).get('cvss-score', 0),
                        'cve_id': finding.get('info', {}).get('classification', {}).get('cve-id', ''),
                        'cwe_id': finding.get('info', {}).get('classification', {}).get('cwe-id', ''),
                        'remediation': finding.get('info', {}).get('remediation', ''),
                        'evidence': finding.get('matched-at', ''),
                        'proof_of_concept': finding.get('curl-command', ''),
                        'tags': finding.get('info', {}).get('tags', []),
                        'tool': 'nuclei',
                        'template': finding.get('template-id', '')
                    })
                except:
                    continue
        
        return {
            'tool': 'nuclei',
            'findings': findings,
            'total': len(findings)
        }