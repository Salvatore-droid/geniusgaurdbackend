# base/ai/groq_client.py
import json
import asyncio
import sys
from typing import Dict, List, Any, Optional
import logging

# Configure logging to print immediately
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
logger = logging.getLogger(__name__)

class GroqAIClient:
    """Groq-powered AI client for security analysis with hardcoded API key"""
    
    def __init__(self):
        print("\n=== GROQ CLIENT INITIALIZATION ===")  # Direct print for immediate output
        print(f"Python version: {sys.version}")
        print(f"Current working directory: {__file__}")
        
        # Hardcoded API key - replace with your actual key
        self.api_key = "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"
        self.model = "llama-3.3-70b-versatile"
        self.max_tokens = 8000
        self.temperature = 0.1
        self.client = None
        self.initialized = False
        
        print(f"API Key present: {'Yes' if self.api_key else 'No'}")
        print(f"API Key length: {len(self.api_key) if self.api_key else 0}")
        
        if self.api_key:
            try:
                print("Attempting to import AsyncGroq...")
                from groq import AsyncGroq
                print("✓ AsyncGroq imported successfully")
                
                print("Creating AsyncGroq client...")
                self.client = AsyncGroq(api_key=self.api_key)
                print("✓ AsyncGroq client created")
                
                self.initialized = True
                print("✓ Groq client initialized successfully!")
                
                # Test the connection
                print("Testing connection with a simple request...")
                # We'll test this in a separate method
                
            except ImportError as e:
                print(f"✗ ImportError: {e}")
                print("Make sure groq is installed: pip install groq")
                logger.error(f"Groq package not installed: {e}")
            except Exception as e:
                print(f"✗ Error: {type(e).__name__}: {e}")
                logger.error(f"Failed to initialize Groq client: {e}")
        else:
            print("✗ API key is empty")
            logger.warning("API key is empty. AI features will be disabled.")
        
        print(f"Final initialization status: {self.initialized}")
        print("===================================\n")
    
    async def test_connection(self):
        """Test the Groq API connection"""
        print("Testing Groq API connection...")
        if not self.initialized:
            print("Cannot test: client not initialized")
            return False
        
        try:
            completion = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": "Say 'OK' if you can hear me."}
                ],
                temperature=0.1,
                max_tokens=10
            )
            result = completion.choices[0].message.content
            print(f"✓ Test successful: {result}")
            return True
        except Exception as e:
            print(f"✗ Test failed: {type(e).__name__}: {e}")
            return False
    
    
    async def analyze_vulnerability(self, context: Dict) -> Dict:
        """Analyze a potential vulnerability using AI"""
        
        if not self.initialized:
            return {"is_vulnerable": False, "error": "AI not initialized", "confidence": 0}
        
        prompt = f"""You are a senior security researcher. Analyze this potential vulnerability and provide:
        1. Confirmation if it's a real vulnerability
        2. CVE mapping if applicable
        3. CVSS score (0-10)
        4. Remediation steps
        5. Proof of concept

        Context from scan:
        - Target URL: {context.get('url', 'unknown')}
        - Suspicious behavior: {context.get('finding', '')}
        - HTTP Response: {context.get('response', '')[:500]}
        - Technology stack: {context.get('tech_stack', [])}
        
        Respond in JSON format only:
        {{
            "is_vulnerable": boolean,
            "confidence": float (0-1),
            "vulnerability_name": string,
            "cve_id": string or null,
            "cvss_score": float,
            "severity": "critical|high|medium|low|info",
            "description": string,
            "remediation": string,
            "proof_of_concept": string,
            "false_positive_indicators": string or null
        }}"""
        
        try:
            completion = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a precise security analyst. Always respond with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(completion.choices[0].message.content)
            return result
            
        except Exception as e:
            logger.error(f"Groq API error: {e}")
            return {"is_vulnerable": False, "error": str(e), "confidence": 0}
    
    async def generate_test_payloads(self, cve_id: str, technology: str) -> List[str]:
        """Generate test payloads for a specific CVE"""
        
        if not self.initialized:
            return []
        
        prompt = f"""Generate 5 test payloads for {cve_id} affecting {technology}.
        Each payload should be a valid HTTP request or parameter.
        Consider:
        - Different bypass techniques
        - URL encoding variants
        - WAF evasion methods
        
        Return as JSON array of strings only."""
        
        try:
            completion = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Generate only valid attack payloads in JSON array."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            
            # Extract JSON array from response
            content = completion.choices[0].message.content
            # Find JSON array in response
            import re
            json_match = re.search(r'\[.*\]', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return []
            
        except Exception as e:
            logger.error(f"Payload generation error: {e}")
            return []
    
    async def triage_findings(self, findings: List[Dict], asset_criticality: str = "medium") -> Dict:
        """Triage and prioritize findings"""
        
        if not self.initialized or not findings:
            return {"prioritized_findings": [], "false_positives": []}
        
        prompt = f"""You are a security triage expert. Analyze these {len(findings)} findings and:
        1. Prioritize by actual business risk (not just CVSS)
        2. Identify false positives
        3. Group related issues
        4. Suggest immediate actions
        
        Asset criticality: {asset_criticality}
        
        Findings: {json.dumps(findings, indent=2)}
        
        Return JSON with:
        {{
            "prioritized_findings": [finding_ids in order],
            "false_positives": [finding_ids],
            "grouped_issues": {{"group_name": [finding_ids]}},
            "immediate_actions": [string]
        }}"""
        
        try:
            completion = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security triage expert. Respond with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=4000,
                response_format={"type": "json_object"}
            )
            
            return json.loads(completion.choices[0].message.content)
            
        except Exception as e:
            logger.error(f"Triage error: {e}")
            return {"prioritized_findings": [], "false_positives": []}

    async def analyze_technology(self, context: Dict) -> Dict:
        """Analyze technology stack using AI"""
        
        if not self.initialized:
            return {'technologies': []}
        
        prompt = f"""Analyze this web technology context and identify the technology stack:
        
        URL: {context.get('url')}
        Server: {context.get('server')}
        X-Powered-By: {context.get('x_powered_by')}
        Cookies: {context.get('cookies')}
        Forms count: {context.get('forms_count')}
        
        Return a JSON object with:
        {{
            "technologies": [
                {{
                    "name": "technology name",
                    "version": "version if detected",
                    "confidence": 0.0-1.0
                }}
            ]
        }}
        
        Only include technologies you're confident about."""
        
        try:
            completion = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a web technology expert. Respond with valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1000,
                response_format={"type": "json_object"}
            )
            
            return json.loads(completion.choices[0].message.content)
        except Exception as e:
            logger.error(f"Technology analysis failed: {e}")
            return {'technologies': []}
    
    async def generate_remediation(self, vulnerability: Dict, tech_stack: List[str]) -> str:
        """Generate specific remediation steps"""
        
        if not self.initialized:
            return "AI remediation not available (AI not initialized)"
        
        prompt = f"""Write detailed remediation steps for this vulnerability:
        
        Vulnerability: {vulnerability.get('name')}
        Description: {vulnerability.get('description')}
        Technology Stack: {', '.join(tech_stack)}
        
        Provide:
        1. Immediate fix
        2. Long-term solution
        3. Code examples if applicable
        4. Configuration changes
        5. Testing verification steps"""
        
        try:
            completion = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security engineer providing actionable remediation advice."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=3000
            )
            
            return completion.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Remediation generation error: {e}")
            return f"Remediation generation failed: {e}"
    
    async def discover_attack_surfaces(self, url: str, tech_stack: List[str]) -> List[str]:
        """Use AI to discover potential attack surfaces"""
        
        if not self.initialized:
            return []
        
        prompt = f"""Based on this technology stack: {', '.join(tech_stack)}
        For the target: {url}
        
        List 10 potential attack surfaces or misconfigurations to check.
        Be specific about endpoints, parameters, or configurations.
        
        Return as JSON array of strings."""
        
        try:
            completion = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a penetration tester identifying attack surfaces."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
                max_tokens=2000
            )
            
            content = completion.choices[0].message.content
            # Extract JSON array
            import re
            json_match = re.search(r'\[.*\]', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return []
            
        except Exception as e:
            logger.error(f"Attack surface discovery error: {e}")
            return []

# Singleton instance
groq_client = GroqAIClient()