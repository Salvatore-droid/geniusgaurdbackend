# base/scanners/base.py
import abc
import logging
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    """Vulnerability data structure"""
    name: str
    description: str
    severity: str  # critical, high, medium, low, info
    cvss_score: float
    cvss_vector: str = ""
    cve_id: str = ""
    cwe_id: str = ""
    affected_component: str = ""
    affected_version: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    evidence: str = ""
    proof_of_concept: str = ""
    exploit_available: bool = False
    metasploit_module: str = ""
    discovered_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'affected_component': self.affected_component,
            'affected_version': self.affected_version,
            'remediation': self.remediation,
            'references': self.references,
            'evidence': self.evidence,
            'proof_of_concept': self.proof_of_concept,
            'exploit_available': self.exploit_available,
            'metasploit_module': self.metasploit_module,
            'discovered_at': self.discovered_at.isoformat(),
            'tags': self.tags
        }

@dataclass
class ScanResult:
    """Scan result data structure"""
    target: str
    scan_type: str
    start_time: datetime
    end_time: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    info_gathering: Dict[str, Any] = field(default_factory=dict)
    technologies: List[Dict] = field(default_factory=list)
    open_ports: List[Dict] = field(default_factory=list)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    directories: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    scan_duration: float = 0.0
    scan_id: str = ""
    
    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on findings"""
        severity_weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 0.5
        }
        
        total_weight = sum(severity_weights.get(v.severity, 0) for v in self.vulnerabilities)
        
        # Normalize to 0-100 scale
        max_possible = len(self.vulnerabilities) * 10
        if max_possible > 0:
            self.risk_score = min(100, (total_weight / max_possible) * 100)
        else:
            self.risk_score = 0
        
        return self.risk_score
    
    def to_dict(self) -> Dict:
        return {
            'scan_id': self.scan_id,
            'target': self.target,
            'scan_type': self.scan_type,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.scan_duration,
            'risk_score': self.risk_score,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'info_gathering': self.info_gathering,
            'technologies': self.technologies,
            'open_ports': self.open_ports,
            'ssl_info': self.ssl_info,
            'headers': self.headers,
            'cookies': self.cookies,
            'forms': self.forms,
            'directories': self.directories,
            'subdomains': self.subdomains
        }

class BaseScanner(abc.ABC):
    """Abstract base class for all scanners"""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.result = ScanResult(
            target=target,
            scan_type=self.__class__.__name__,
            start_time=datetime.now()
        )
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    @abc.abstractmethod
    async def scan(self) -> ScanResult:
        """Main scan method to be implemented by subclasses"""
        pass
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add vulnerability to results"""
        self.result.vulnerabilities.append(vuln)
        self.logger.info(f"Found vulnerability: {vuln.name} ({vuln.severity})")
    
    def add_info(self, key: str, value: Any):
        """Add info gathering data"""
        self.result.info_gathering[key] = value
    
    def get_scan_id(self) -> str:
        """Generate unique scan ID"""
        data = f"{self.target}{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    async def run(self) -> ScanResult:
        """Run the scan with timing"""
        self.result.scan_id = self.get_scan_id()
        self.logger.info(f"Starting scan {self.result.scan_id} on {self.target}")
        
        try:
            result = await self.scan()
            result.end_time = datetime.now()
            result.scan_duration = (result.end_time - result.start_time).total_seconds()
            result.calculate_risk_score()
            
            self.logger.info(f"Scan completed. Found {len(result.vulnerabilities)} vulnerabilities")
            return result
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            raise