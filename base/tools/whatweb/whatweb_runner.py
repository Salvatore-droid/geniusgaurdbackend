# base/tools/whatweb/whatweb_runner.py
import json
import re
from typing import Dict, List
from ..base import BaseToolRunner

class WhatWebRunner(BaseToolRunner):
    """WhatWeb - Next generation web scanner for technology detection"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.whatweb_path = self.config.get('whatweb_path', 'whatweb')
        
    async def scan(self) -> Dict:
        """Run whatweb scan"""
        cmd = [
            self.whatweb_path,
            self.target,
            '--log-json', f"{self.temp_dir}/whatweb.json",
            '--colour', 'never',
            '--quiet'
        ]
        
        stdout, stderr = await self.run_command(cmd, timeout=120)
        
        return self.parse_output()
    
    def parse_output(self) -> Dict:
        """Parse whatweb JSON output"""
        try:
            with open(f"{self.temp_dir}/whatweb.json", 'r') as f:
                data = json.load(f)
            
            if isinstance(data, list) and data:
                target_data = data[0]
                
                technologies = []
                findings = []
                
                # Extract detected technologies
                for plugin_name, plugin_data in target_data.get('plugins', {}).items():
                    tech = {
                        'name': plugin_name,
                        'version': plugin_data.get('version', [''])[0] if plugin_data.get('version') else '',
                        'certainty': plugin_data.get('certainty', 100),
                        'description': plugin_data.get('description', '')
                    }
                    technologies.append(tech)
                    
                    # Check for outdated versions (simplified - would need version DB)
                    if tech['version'] and self._is_outdated(plugin_name, tech['version']):
                        findings.append({
                            'name': f"Outdated {plugin_name}",
                            'description': f"Version {tech['version']} may be outdated",
                            'severity': 'medium',
                            'affected_component': plugin_name,
                            'affected_version': tech['version'],
                            'tool': 'whatweb',
                            'remediation': f"Update {plugin_name} to the latest version"
                        })
                
                return {
                    'tool': 'whatweb',
                    'url': target_data.get('target', ''),
                    'technologies': technologies,
                    'findings': findings,
                    'total': len(technologies)
                }
                
        except Exception as e:
            return {'tool': 'whatweb', 'error': str(e), 'technologies': []}
        
        return {'tool': 'whatweb', 'technologies': []}
    
    def _is_outdated(self, tech: str, version: str) -> bool:
        """Check if technology version is outdated"""
        # Simplified - in production, would check against version database
        outdated_map = {
            'WordPress': ['4.9', '5.0', '5.1'],
            'jQuery': ['1.12', '2.2', '3.0'],
            'Bootstrap': ['3', '4.0'],
            'PHP': ['5.6', '7.0', '7.1']
        }
        
        for outdated_ver in outdated_map.get(tech, []):
            if version.startswith(outdated_ver):
                return True
        return False