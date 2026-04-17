# base/scanners/orchestrator.py (updated)
import asyncio
from ..ai.vulnerability_hunter import AIVulnerabilityHunter
from ..ai.groq_client import groq_client
from ..ai.test_generator import ai_test_generator

class AIDrivenScanner:
    """AI-augmented vulnerability scanner"""
    
    def __init__(self, target_url: str, scan_type: str = 'quick'):
        self.target_url = target_url
        self.scan_type = scan_type
        self.findings = []
        
    async def scan(self) -> List[Dict]:
        """Run AI-augmented scan"""
        
        # Update CVE tests if needed
        if self.scan_type == 'deep':
            await ai_test_generator.update_from_cve_feed()
        
        # Phase 1: AI-powered vulnerability hunting
        hunter = AIVulnerabilityHunter(self.target_url)
        ai_findings = await hunter.scan()
        self.findings.extend(ai_findings)
        
        # Phase 2: Let AI triage findings
        if self.findings:
            triage_result = await groq_client.triage_findings(
                findings=self.findings,
                asset_criticality='high'
            )
            
            # Mark false positives
            for fp_id in triage_result.get('false_positives', []):
                for finding in self.findings:
                    if finding.get('id') == fp_id:
                        finding['is_false_positive'] = True
            
            # Add prioritization
            for idx, finding_id in enumerate(triage_result.get('prioritized_findings', [])):
                for finding in self.findings:
                    if finding.get('id') == finding_id:
                        finding['priority'] = idx + 1
        
        # Phase 3: Generate remediation for each finding
        for finding in self.findings:
            if finding.get('is_vulnerable'):
                remediation = await groq_client.generate_remediation(
                    vulnerability=finding,
                    tech_stack=hunter.tech_stack
                )
                finding['remediation'] = remediation
        
        return self.findings