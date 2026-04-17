# base/tools/nikto/nikto_runner.py
import asyncio
import json
import re
from typing import Dict, List

class NiktoRunner:
    """Nikto web server scanner integration"""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.nikto_path = self.config.get('nikto_path', '/usr/bin/nikto')
    
    async def run(self) -> Dict:
        """Run Nikto scan"""
        try:
            # Build command
            cmd = [
                'perl', self.nikto_path,
                '-h', self.target,
                '-Format', 'json',
                '-ssl' if self.target.startswith('https') else '',
                '-Tuning', '123456789abc',
                '-timeout', '10'
            ]
            
            # Remove empty arguments
            cmd = [c for c in cmd if c]
            
            # Run process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse output
            output = stdout.decode()
            return self._parse_output(output)
            
        except Exception as e:
            return {'error': str(e), 'findings': []}
    
    def _parse_output(self, output: str) -> Dict:
        """Parse Nikto output"""
        findings = []
        
        # Try JSON format first
        try:
            data = json.loads(output)
            return data
        except:
            pass
        
        # Parse text output
        lines = output.split('\n')
        for line in lines:
            if '+ ' in line and ':' in line:
                finding = self._parse_finding(line)
                if finding:
                    findings.append(finding)
        
        return {
            'target': self.target,
            'findings': findings,
            'raw_output': output
        }
    
    def _parse_finding(self, line: str) -> Dict:
        """Parse a single finding line"""
        parts = line.split(':', 1)
        if len(parts) == 2:
            return {
                'type': parts[0].strip('+ '),
                'description': parts[1].strip(),
                'severity': self._determine_severity(line)
            }
        return None
    
    def _determine_severity(self, line: str) -> str:
        """Determine severity of finding"""
        critical_indicators = ['critical', 'vulnerable', 'exploit']
        high_indicators = ['high', 'dangerous', 'warning']
        medium_indicators = ['medium', 'caution']
        
        line_lower = line.lower()
        
        if any(i in line_lower for i in critical_indicators):
            return 'critical'
        elif any(i in line_lower for i in high_indicators):
            return 'high'
        elif any(i in line_lower for i in medium_indicators):
            return 'medium'
        
        return 'info'