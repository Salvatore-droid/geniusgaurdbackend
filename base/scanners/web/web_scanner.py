# base/scanners/web/web_scanner.py
import asyncio
import aiohttp
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin
import re

from ..base import BaseScanner, Vulnerability
from .xss_scanner import XSSScanner
from .sqli_scanner import SQLIScanner
from .csrf_tester import CSRTester
from .lfi_rfi_scanner import LFI_RFIScanner
from .ssrf_scanner import SSRFScanner
from .open_redirect import OpenRedirectScanner
# from .command_injection import CommandInjectionScanner
from ...tools.nikto.nikto_runner import NiktoRunner
from ...tools.wpscan.wpscan_runner import WPScanRunner
from ...tools.dirbuster.dirbuster_runner import DirBusterRunner
from ...tools.whatweb.whatweb_runner import WhatWebRunner
from ...tools.orchestrator import SecurityToolsOrchestrator

class WebApplicationScanner(BaseScanner):
    """Comprehensive web application security scanner"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.session = None
        self.parsed_url = urlparse(target)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        
        # Initialize component scanners
        self.xss_scanner = XSSScanner(target, config)
        self.sqli_scanner = SQLIScanner(target, config)
        self.csrf_tester = CSRTester(target, config)
        self.lfi_scanner = LFI_RFIScanner(target, config)
        self.ssrf_scanner = SSRFScanner(target, config)
        self.open_redirect_scanner = OpenRedirectScanner(target, config)
        # self.command_injection_scanner = CommandInjectionScanner(target, config)
        
        # Initialize external tools
        self.nikto = NiktoRunner(target, config)
        self.wpscan = WPScanRunner(target, config) if self._is_wordpress() else None
        self.dirbuster = DirBusterRunner(target, config)
        self.whatweb = WhatWebRunner(target, config)
    
    async def scan(self) -> 'ScanResult':
        """Execute comprehensive web application scan"""
        
        # Phase 1: Information Gathering
        await self._gather_information()
        
        # Phase 2: Technology Detection
        await self._detect_technologies()
        
        # Phase 3: Directory Enumeration
        await self._enumerate_directories()
        
        # Phase 4: Vulnerability Scanning (run in parallel)
        vuln_tasks = [
            self.xss_scanner.scan(),
            self.sqli_scanner.scan(),
            self.csrf_tester.scan(),
            self.lfi_scanner.scan(),
            self.ssrf_scanner.scan(),
            self.open_redirect_scanner.scan(),
            self.command_injection_scanner.scan(),
            self._run_nikto_scan(),
            self._run_wpscan() if self.wpscan else None
        ]
        
        # Filter out None tasks
        vuln_tasks = [t for t in vuln_tasks if t]
        
        # Run all vulnerability scans concurrently
        results = await asyncio.gather(*vuln_tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Scan component failed: {str(result)}")
            elif result and hasattr(result, 'vulnerabilities'):
                self.result.vulnerabilities.extend(result.vulnerabilities)
        
        # Phase 5: Manual Verification
        await self._verify_findings()
        
        return self.result
    
    async def _gather_information(self):
        """Gather initial information about the target"""
        async with aiohttp.ClientSession() as session:
            try:
                # Fetch main page
                async with session.get(self.target, ssl=False) as response:
                    self.result.headers = dict(response.headers)
                    self.result.info_gathering['status_code'] = response.status
                    self.result.info_gathering['server'] = response.headers.get('Server', 'Unknown')
                    
                    # Parse HTML
                    html = await response.text()
                    
                    # Extract forms
                    self.result.forms = await self._extract_forms(html)
                    
                    # Extract links
                    self.result.info_gathering['links'] = await self._extract_links(html)
                    
                    # Extract cookies
                    self.result.cookies = [
                        {'name': k, 'value': v} for k, v in response.cookies.items()
                    ]
                    
            except Exception as e:
                self.logger.error(f"Information gathering failed: {str(e)}")
    
    async def _detect_technologies(self):
        """Detect technologies using WhatWeb"""
        try:
            tech_results = await self.whatweb.run()
            self.result.technologies = tech_results.get('technologies', [])
            
            # Check for known vulnerable versions
            await self._check_vulnerable_versions()
            
        except Exception as e:
            self.logger.error(f"Technology detection failed: {str(e)}")
    
    async def _enumerate_directories(self):
        """Enumerate directories using DirBuster"""
        try:
            dir_results = await self.dirbuster.run()
            self.result.directories = dir_results.get('directories', [])
            
            # Check for exposed sensitive directories
            sensitive_dirs = ['/admin', '/backup', '/config', '/.git', '/.env']
            for directory in self.result.directories:
                if any(sens in directory for sens in sensitive_dirs):
                    self.add_vulnerability(Vulnerability(
                        name="Sensitive Directory Exposed",
                        description=f"Sensitive directory exposed: {directory}",
                        severity="high",
                        cvss_score=7.5,
                        cwe_id="CWE-548",
                        affected_component="Web Server",
                        remediation="Restrict access to sensitive directories",
                        evidence=f"Directory accessible at: {directory}"
                    ))
                    
        except Exception as e:
            self.logger.error(f"Directory enumeration failed: {str(e)}")
    
    async def _run_nikto_scan(self):
        """Run Nikto web server scanner"""
        try:
            nikto_results = await self.nikto.run()
            
            for finding in nikto_results.get('findings', []):
                vuln = Vulnerability(
                    name=finding.get('name', 'Unknown Vulnerability'),
                    description=finding.get('description', ''),
                    severity=self._map_nikto_severity(finding.get('severity', 'medium')),
                    cvss_score=finding.get('cvss', 5.0),
                    cve_id=finding.get('cve', ''),
                    remediation=finding.get('remediation', ''),
                    evidence=finding.get('evidence', ''),
                    references=finding.get('references', [])
                )
                self.add_vulnerability(vuln)
                
        except Exception as e:
            self.logger.error(f"Nikto scan failed: {str(e)}")
    
    async def _run_wpscan(self):
        """Run WordPress vulnerability scan"""
        try:
            wp_results = await self.wpscan.run()
            
            for vuln in wp_results.get('vulnerabilities', []):
                vulnerability = Vulnerability(
                    name=vuln.get('title', 'WordPress Vulnerability'),
                    description=vuln.get('description', ''),
                    severity=vuln.get('severity', 'medium'),
                    cvss_score=vuln.get('cvss', 0.0),
                    cve_id=vuln.get('cve', ''),
                    affected_component="WordPress",
                    affected_version=vuln.get('version', ''),
                    remediation=vuln.get('fix', ''),
                    references=vuln.get('references', []),
                    exploit_available=vuln.get('exploit_available', False)
                )
                self.add_vulnerability(vulnerability)
                
        except Exception as e:
            self.logger.error(f"WPScan failed: {str(e)}")
    
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
    
    async def _extract_links(self, html: str) -> List[str]:
        """Extract links from HTML"""
        links = []
        pattern = r'href=[\'"](.*?)[\'"]'
        
        for match in re.finditer(pattern, html, re.IGNORECASE):
            link = match.group(1)
            if link and not link.startswith(('javascript:', 'mailto:', 'tel:')):
                # Convert relative to absolute URLs
                if link.startswith('/'):
                    link = urljoin(self.base_url, link)
                elif not link.startswith(('http://', 'https://')):
                    link = urljoin(self.target, link)
                
                if link.startswith(self.base_url):
                    links.append(link)
        
        return list(set(links))  # Remove duplicates
    
    async def _extract_attribute(self, tag: str, attr: str, default: str = '') -> str:
        """Extract attribute value from HTML tag"""
        pattern = f'{attr}=[\'"](.*?)[\'"]'
        match = re.search(pattern, tag, re.IGNORECASE)
        return match.group(1) if match else default
    
    async def _is_wordpress(self) -> bool:
        """Check if target is WordPress"""
        try:
            async with aiohttp.ClientSession() as session:
                # Check for wp-content
                wp_content = urljoin(self.base_url, '/wp-content/')
                async with session.get(wp_content, ssl=False) as response:
                    if response.status == 200 or response.status == 403:
                        return True
                
                # Check for wp-includes
                wp_includes = urljoin(self.base_url, '/wp-includes/')
                async with session.get(wp_includes, ssl=False) as response:
                    if response.status == 200 or response.status == 403:
                        return True
        except:
            pass
        
        return False
    
    async def _map_nikto_severity(self, severity: str) -> str:
        """Map Nikto severity to standard severity"""
        mapping = {
            '0': 'info',
            '1': 'low',
            '2': 'medium',
            '3': 'high',
            '4': 'critical'
        }
        return mapping.get(str(severity), 'medium')
    
    async def _check_vulnerable_versions(self):
        """Check for known vulnerable versions of detected technologies"""
        # This would integrate with CVE database
        pass
    
    async def _verify_findings(self):
        """Manual verification of findings"""
        # Implement verification logic
        pass

    async def _run_security_tools(self):
        """Run all external security tools"""
        orchestrator = SecurityToolsOrchestrator(self.target, self.config)
        tool_results = await orchestrator.run_all()
        
        # Add findings from tools
        for finding in tool_results.get('findings', []):
            vuln = Vulnerability(
                name=finding.get('name', 'Unknown'),
                description=finding.get('description', ''),
                severity=finding.get('severity', 'info'),
                cvss_score=finding.get('cvss_score', 0),
                cve_id=finding.get('cve_id', ''),
                cwe_id=finding.get('cwe_id', ''),
                remediation=finding.get('remediation', ''),
                evidence=finding.get('evidence', ''),
                proof_of_concept=finding.get('proof_of_concept', ''),
                tags=[finding.get('source_tool', 'tool')] + finding.get('tags', [])
            )
            self.add_vulnerability(vuln)
        
        # Store tool results in info gathering
        self.add_info('security_tools', tool_results)