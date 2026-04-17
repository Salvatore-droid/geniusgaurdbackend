# base/intelligence/cve_database.py
import json
import aiohttp
import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta

class CVEDatabase:
    """CVE database integration with NVD"""
    
    def __init__(self):
        self.nvd_api_key = None  # Optional API key for higher rate limits
        self.cache = {}
        self.cache_duration = timedelta(hours=24)
        
    async def lookup_cve(self, cve_id: str) -> Optional[Dict]:
        """Look up CVE details from NVD"""
        # Check cache first
        if cve_id in self.cache:
            cache_entry = self.cache[cve_id]
            if datetime.now() - cache_entry['timestamp'] < self.cache_duration:
                return cache_entry['data']
        
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {'cveId': cve_id}
            
            if self.nvd_api_key:
                params['apiKey'] = self.nvd_api_key
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        cve_data = self._parse_nvd_response(data)
                        
                        # Cache the result
                        self.cache[cve_id] = {
                            'timestamp': datetime.now(),
                            'data': cve_data
                        }
                        
                        return cve_data
        except Exception as e:
            print(f"Error looking up CVE {cve_id}: {str(e)}")
        
        return None
    
    async def search_cves(self, keyword: str, limit: int = 50) -> List[Dict]:
        """Search CVEs by keyword"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': limit
            }
            
            if self.nvd_api_key:
                params['apiKey'] = self.nvd_api_key
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_nvd_response_bulk(data)
        except Exception as e:
            print(f"Error searching CVEs: {str(e)}")
        
        return []
    
    async def get_recent_cves(self, days: int = 7) -> List[Dict]:
        """Get recent CVEs from last N days"""
        try:
            start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'pubStartDate': start_date,
                'resultsPerPage': 100
            }
            
            if self.nvd_api_key:
                params['apiKey'] = self.nvd_api_key
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_nvd_response_bulk(data)
        except Exception as e:
            print(f"Error getting recent CVEs: {str(e)}")
        
        return []
    
    def _parse_nvd_response(self, data: Dict) -> Dict:
        """Parse NVD API response for single CVE"""
        try:
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                return None
            
            cve_item = vulnerabilities[0]['cve']
            
            # Extract metrics
            metrics = cve_item.get('metrics', {})
            cvss_data = None
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
            
            # Extract descriptions
            descriptions = cve_item.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extract references
            references = []
            for ref in cve_item.get('references', []):
                references.append({
                    'url': ref.get('url'),
                    'source': ref.get('source')
                })
            
            return {
                'id': cve_item.get('id'),
                'published': cve_item.get('published'),
                'last_modified': cve_item.get('lastModified'),
                'description': description,
                'cvss_score': cvss_data.get('baseScore') if cvss_data else None,
                'cvss_vector': cvss_data.get('vectorString') if cvss_data else None,
                'severity': cvss_data.get('baseSeverity') if cvss_data else None,
                'references': references,
                'cwe_ids': self._extract_cwes(cve_item)
            }
            
        except Exception as e:
            print(f"Error parsing NVD response: {str(e)}")
            return None
    
    def _parse_nvd_response_bulk(self, data: Dict) -> List[Dict]:
        """Parse NVD API response for multiple CVEs"""
        results = []
        vulnerabilities = data.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            parsed = self._parse_nvd_response({'vulnerabilities': [vuln]})
            if parsed:
                results.append(parsed)
        
        return results
    
    def _extract_cwes(self, cve_item: Dict) -> List[str]:
        """Extract CWE IDs from CVE data"""
        cwes = []
        
        for problem in cve_item.get('problemTypes', []):
            for desc in problem.get('descriptions', []):
                cwe_id = desc.get('cweId')
                if cwe_id:
                    cwes.append(cwe_id)
        
        return cwes