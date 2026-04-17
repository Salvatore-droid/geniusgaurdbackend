# base/tools/wpscan/wpscan_runner.py
import asyncio
import json
import re
import aiohttp
from typing import Dict, List
from urllib.parse import urlparse

class WPScanRunner:
    """WordPress vulnerability scanner integration"""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.wpscan_path = self.config.get('wpscan_path', '/usr/bin/wpscan')
    
    async def is_wordpress(self) -> bool:
        """Check if target is WordPress without running full scan"""
        try:
            async with aiohttp.ClientSession() as session:
                # Check for wp-content
                wp_content = f"{self.target.rstrip('/')}/wp-content/"
                async with session.get(wp_content, ssl=False, timeout=5) as response:
                    if response.status != 404:
                        return True
                
                # Check for wp-includes
                wp_includes = f"{self.target.rstrip('/')}/wp-includes/"
                async with session.get(wp_includes, ssl=False, timeout=5) as response:
                    if response.status != 404:
                        return True
                
                # Check for wp-json
                wp_json = f"{self.target.rstrip('/')}/wp-json/"
                async with session.get(wp_json, ssl=False, timeout=5) as response:
                    if response.status != 404:
                        return True
                        
        except Exception as e:
            print(f"WordPress detection error: {str(e)}")
        
        return False
    
    async def run(self) -> Dict:
        """Run WPScan"""
        try:
            # Build command
            cmd = [
                self.wpscan_path,
                '--url', self.target,
                '--format', 'json',
                '--random-user-agent',
                '--plugins-detection', 'mixed'
            ]
            
            # Add API token if available
            if self.config.get('wpscan_api_token'):
                cmd.extend(['--api-token', self.config['wpscan_api_token']])
            
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
            
        except FileNotFoundError:
            # WPScan not installed, return empty results
            return {
                'target': self.target,
                'wordpress_version': 'unknown',
                'vulnerabilities': [],
                'error': 'WPScan not installed'
            }
        except Exception as e:
            return {
                'target': self.target,
                'wordpress_version': 'unknown',
                'vulnerabilities': [],
                'error': str(e)
            }
    
    def _parse_output(self, output: str) -> Dict:
        """Parse WPScan output"""
        try:
            data = json.loads(output)
            
            # Extract vulnerabilities
            vulnerabilities = []
            
            # Check version vulnerabilities
            if 'version' in data:
                version = data['version']
                if 'vulnerabilities' in version:
                    for vuln in version['vulnerabilities']:
                        vulnerabilities.append(self._format_vuln(vuln, 'version'))
            
            # Check plugin vulnerabilities
            if 'plugins' in data:
                for plugin_name, plugin_data in data['plugins'].items():
                    if 'vulnerabilities' in plugin_data:
                        for vuln in plugin_data['vulnerabilities']:
                            vulnerabilities.append(
                                self._format_vuln(vuln, 'plugin', plugin_name)
                            )
            
            # Check theme vulnerabilities
            if 'themes' in data:
                for theme_name, theme_data in data['themes'].items():
                    if 'vulnerabilities' in theme_data:
                        for vuln in theme_data['vulnerabilities']:
                            vulnerabilities.append(
                                self._format_vuln(vuln, 'theme', theme_name)
                            )
            
            return {
                'target': self.target,
                'wordpress_version': data.get('version', {}).get('number', 'unknown'),
                'vulnerabilities': vulnerabilities,
                'raw_output': data
            }
            
        except json.JSONDecodeError:
            return self._parse_text_output(output)
    
    def _format_vuln(self, vuln: Dict, vuln_type: str, component: str = '') -> Dict:
        """Format vulnerability data"""
        return {
            'title': vuln.get('title', 'Unknown Vulnerability'),
            'description': vuln.get('description', ''),
            'severity': vuln.get('severity', 'medium'),
            'cvss_score': vuln.get('cvss', {}).get('score', 0),
            'cve_id': vuln.get('cve', ''),
            'fixed_in': vuln.get('fixed_in', ''),
            'type': vuln_type,
            'component': component,
            'references': vuln.get('references', {}),
            'exploit_available': 'exploit-db' in str(vuln.get('references', {}))
        }
    
    def _parse_text_output(self, output: str) -> Dict:
        """Parse text output when JSON fails"""
        vulnerabilities = []
        lines = output.split('\n')
        
        current_vuln = {}
        for line in lines:
            if '[!]' in line:
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                current_vuln = {'description': line}
            elif current_vuln and ':' in line:
                key, value = line.split(':', 1)
                current_vuln[key.strip().lower()] = value.strip()
        
        if current_vuln:
            vulnerabilities.append(current_vuln)
        
        return {
            'target': self.target,
            'vulnerabilities': vulnerabilities,
            'raw_output': output
        }