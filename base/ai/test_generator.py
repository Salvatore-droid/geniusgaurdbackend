# base/ai/test_generator.py
import asyncio
from typing import Dict, List
from datetime import datetime, timedelta
import feedparser
import requests

from .groq_client import groq_client

class AITestGenerator:
    """AI-powered vulnerability test generator"""
    
    def __init__(self):
        self.generated_tests = []
        self.last_update = None
        
    async def update_from_cve_feed(self):
        """Pull latest CVEs and generate tests"""
        
        # Fetch recent CVEs from NVD
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'startIndex': 0,
            'resultsPerPage': 10,
            'pubStartDate': (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        }
        
        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln['cve']
                    cve_id = cve['id']
                    
                    # Extract relevant info
                    description = cve['descriptions'][0]['value'] if cve['descriptions'] else ''
                    
                    # Get affected software
                    software = []
                    for config in cve.get('configurations', []):
                        for node in config.get('nodes', []):
                            for cpe in node.get('cpeMatch', []):
                                if 'criteria' in cpe:
                                    software.append(cpe['criteria'])
                    
                    # Generate test using AI
                    test = await self._generate_test_for_cve(
                        cve_id=cve_id,
                        description=description,
                        software=software
                    )
                    
                    if test:
                        self.generated_tests.append(test)
                        
        except Exception as e:
            print(f"CVE feed error: {e}")
    
    async def _generate_test_for_cve(self, cve_id: str, description: str, software: List[str]) -> Dict:
        """Generate a test for a specific CVE using AI"""
        
        prompt = f"""Create a vulnerability test for {cve_id}.
        
        Description: {description}
        Affected software: {', '.join(software)}
        
        Generate a Nuclei-compatible YAML template that tests for this vulnerability.
        Include:
        - HTTP request with proper method and path
        - Matchers to identify vulnerable instances
        - Extractor for version information if applicable
        
        Return only the YAML template."""
        
        try:
            completion = await groq_client.client.chat.completions.create(
                model=groq_client.model,
                messages=[
                    {"role": "system", "content": "You are a security researcher creating vulnerability tests."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=3000
            )
            
            template = completion.choices[0].message.content
            
            return {
                'cve_id': cve_id,
                'template': template,
                'generated_at': datetime.now().isoformat(),
                'software': software
            }
            
        except Exception as e:
            print(f"Test generation error for {cve_id}: {e}")
            return None
    
    def get_tests_for_technology(self, technology: str) -> List[Dict]:
        """Get generated tests for specific technology"""
        tests = []
        for test in self.generated_tests:
            if any(tech in ' '.join(test.get('software', [])) for tech in [technology]):
                tests.append(test)
        return tests

# Singleton
ai_test_generator = AITestGenerator()