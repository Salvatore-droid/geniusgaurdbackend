# base/tools/dirbuster/dirbuster_runner.py
import re
from typing import Dict, List
from ..base import BaseToolRunner

class DirBusterRunner(BaseToolRunner):
    """Directory and file enumeration tool"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.wordlist = self.config.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        self.extensions = self.config.get('extensions', ['php', 'asp', 'aspx', 'jsp', 'txt', 'bak', 'old'])
        
    async def run_gobuster(self) -> Dict:
        """Run gobuster if available"""
        cmd = [
            'gobuster', 'dir',
            '-u', self.target,
            '-w', self.wordlist,
            '-t', '50',
            '-s', '200,204,301,302,307,403',
            '-b', '404'
        ]
        
        # Add extensions
        if self.extensions:
            cmd.extend(['-x', ','.join(self.extensions)])
        
        stdout, stderr = await self.run_command(cmd, timeout=300)
        return self.parse_gobuster_output(stdout)
    
    async def run_ffuf(self) -> Dict:
        """Run ffuf (faster alternative)"""
        cmd = [
            'ffuf',
            '-u', f"{self.target}/FUZZ",
            '-w', self.wordlist,
            '-t', '100',
            '-fc', '404',
            '-ac'
        ]
        
        stdout, stderr = await self.run_command(cmd, timeout=300)
        return self.parse_ffuf_output(stdout)
    
    async def scan(self) -> Dict:
        """Run directory enumeration"""
        # Try gobuster first, then ffuf, fallback to built-in
        try:
            return await self.run_gobuster()
        except:
            try:
                return await self.run_ffuf()
            except:
                return await self.run_builtin()
    
    async def run_builtin(self) -> Dict:
        """Built-in directory scanner"""
        import aiohttp
        import asyncio
        
        directories = []
        wordlist_path = self.wordlist
        
        # Read wordlist
        try:
            with open(wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
        except:
            # Fallback common directories
            words = [
                'admin', 'login', 'wp-admin', 'wp-content', 'backup',
                'config', 'css', 'js', 'images', 'img', 'uploads',
                'files', 'download', 'api', 'v1', 'v2', 'test', 'dev',
                'private', 'secure', 'hidden', 'temp', 'tmp', 'old',
                'backup.zip', 'backup.tar.gz', 'config.php.bak', '.env'
            ]
        
        # Test directories
        async with aiohttp.ClientSession() as session:
            tasks = []
            for word in words[:100]:  # Limit to 100 for performance
                test_url = f"{self.target.rstrip('/')}/{word}"
                if self.extensions:
                    for ext in self.extensions:
                        test_url_ext = f"{test_url}.{ext}"
                        tasks.append(self._check_url(session, test_url_ext))
                tasks.append(self._check_url(session, test_url))
            
            results = await asyncio.gather(*tasks)
            directories = [r for r in results if r]
        
        # Identify sensitive directories
        vulnerabilities = []
        sensitive_patterns = ['admin', 'backup', 'config', 'private', 'secret', 'hidden']
        
        for dir_info in directories:
            url = dir_info['url']
            if any(pattern in url.lower() for pattern in sensitive_patterns):
                vulnerabilities.append({
                    'name': f"Sensitive Directory Exposed",
                    'description': f"Potentially sensitive directory found: {url}",
                    'severity': 'medium',
                    'remediation': "Restrict access to this directory or remove if not needed",
                    'evidence': url,
                    'cwe_id': 'CWE-548',
                    'tool': 'dirbuster'
                })
        
        return {
            'tool': 'dirbuster',
            'directories': directories,
            'findings': vulnerabilities,
            'total': len(directories)
        }
    
    async def _check_url(self, session, url: str) -> Dict:
        """Check if URL exists"""
        try:
            async with session.get(url, timeout=3, ssl=False, allow_redirects=False) as response:
                if response.status != 404:
                    return {
                        'url': url,
                        'status': response.status,
                        'size': len(await response.read())
                    }
        except:
            pass
        return None
    
    def parse_gobuster_output(self, output: str) -> Dict:
        """Parse gobuster output"""
        directories = []
        
        for line in output.split('\n'):
            # Gobuster format: /path (Status: 200) [Size: 1234]
            match = re.search(r'(/[^\s]+)\s+\(Status:\s+(\d+)\)', line)
            if match:
                directories.append({
                    'url': match.group(1),
                    'status': int(match.group(2))
                })
        
        return {
            'tool': 'gobuster',
            'directories': directories,
            'total': len(directories)
        }
    
    def parse_ffuf_output(self, output: str) -> Dict:
        """Parse ffuf output"""
        directories = []
        
        for line in output.split('\n'):
            # ffuf format: /path [Status: 200, Size: 1234]
            match = re.search(r'(/[^\s]+)\s+\[Status:\s+(\d+)', line)
            if match:
                directories.append({
                    'url': match.group(1),
                    'status': int(match.group(2))
                })
        
        return {
            'tool': 'ffuf',
            'directories': directories,
            'total': len(directories)
        }