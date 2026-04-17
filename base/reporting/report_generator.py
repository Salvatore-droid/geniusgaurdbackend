# base/reporting/report_generator.py
import json
from datetime import datetime
from typing import Dict, List
from jinja2 import Template
import pdfkit
import os

class ReportGenerator:
    """Professional security report generator"""
    
    def __init__(self, scan_result):
        self.scan = scan_result
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        
        # Report templates
        self.templates = {
            'executive': self._load_template('executive_summary.html'),
            'technical': self._load_template('technical_report.html'),
            'compliance': self._load_template('compliance_report.html')
        }
    
    def generate_pdf(self, report_type: str = 'technical') -> bytes:
        """Generate PDF report"""
        html = self.generate_html(report_type)
        
        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'no-outline': None
        }
        
        return pdfkit.from_string(html, False, options=options)
    
    def generate_html(self, report_type: str = 'technical') -> str:
        """Generate HTML report"""
        template = self.templates.get(report_type, self.templates['technical'])
        
        # Prepare data
        data = {
            'scan': self.scan.to_dict(),
            'generated_at': datetime.now().isoformat(),
            'summary': self._generate_summary(),
            'statistics': self._generate_statistics(),
            'recommendations': self._generate_recommendations()
        }
        
        return template.render(**data)
    
    def generate_json(self) -> str:
        """Generate JSON report"""
        return json.dumps(self.scan.to_dict(), indent=2, default=str)
    
    def generate_csv(self) -> str:
        """Generate CSV report"""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(['Severity', 'Name', 'Description', 'CVSS', 'CVE', 'Component'])
        
        # Write vulnerabilities
        for vuln in self.scan.vulnerabilities:
            writer.writerow([
                vuln.severity,
                vuln.name,
                vuln.description[:100] + '...' if len(vuln.description) > 100 else vuln.description,
                vuln.cvss_score,
                vuln.cve_id,
                vuln.affected_component
            ])
        
        return output.getvalue()
    
    def _generate_summary(self) -> Dict:
        """Generate executive summary"""
        return {
            'total_vulnerabilities': len(self.scan.vulnerabilities),
            'critical_count': len([v for v in self.scan.vulnerabilities if v.severity == 'critical']),
            'high_count': len([v for v in self.scan.vulnerabilities if v.severity == 'high']),
            'medium_count': len([v for v in self.scan.vulnerabilities if v.severity == 'medium']),
            'low_count': len([v for v in self.scan.vulnerabilities if v.severity == 'low']),
            'info_count': len([v for v in self.scan.vulnerabilities if v.severity == 'info']),
            'risk_score': self.scan.risk_score,
            'scan_duration': self.scan.scan_duration,
            'target': self.scan.target
        }
    
    def _generate_statistics(self) -> Dict:
        """Generate detailed statistics"""
        return {
            'by_severity': {
                'critical': len([v for v in self.scan.vulnerabilities if v.severity == 'critical']),
                'high': len([v for v in self.scan.vulnerabilities if v.severity == 'high']),
                'medium': len([v for v in self.scan.vulnerabilities if v.severity == 'medium']),
                'low': len([v for v in self.scan.vulnerabilities if v.severity == 'low']),
                'info': len([v for v in self.scan.vulnerabilities if v.severity == 'info'])
            },
            'by_type': self._group_by_type(),
            'top_vulnerabilities': sorted(
                self.scan.vulnerabilities,
                key=lambda v: v.cvss_score,
                reverse=True
            )[:10]
        }
    
    def _group_by_type(self) -> Dict:
        """Group vulnerabilities by type"""
        groups = {}
        for vuln in self.scan.vulnerabilities:
            if vuln.cwe_id:
                groups.setdefault(vuln.cwe_id, []).append(vuln)
        return {k: len(v) for k, v in groups.items()}
    
    def _generate_recommendations(self) -> List[Dict]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Group by severity
        critical = [v for v in self.scan.vulnerabilities if v.severity == 'critical']
        high = [v for v in self.scan.vulnerabilities if v.severity == 'high']
        medium = [v for v in self.scan.vulnerabilities if v.severity == 'medium']
        
        if critical:
            recommendations.append({
                'priority': 'Immediate',
                'title': f'Address {len(critical)} critical vulnerabilities',
                'actions': [v.remediation for v in critical[:3]]
            })
        
        if high:
            recommendations.append({
                'priority': 'High',
                'title': f'Address {len(high)} high-risk vulnerabilities',
                'actions': [v.remediation for v in high[:3]]
            })
        
        if medium:
            recommendations.append({
                'priority': 'Medium',
                'title': f'Address {len(medium)} medium-risk vulnerabilities',
                'actions': [v.remediation for v in medium[:3]]
            })
        
        return recommendations
    
    def _load_template(self, template_name: str) -> Template:
        """Load HTML template"""
        template_path = os.path.join(self.template_dir, template_name)
        if os.path.exists(template_path):
            with open(template_path, 'r') as f:
                return Template(f.read())
        return Template(self._default_template())
    
    def _default_template(self) -> str:
        """Default HTML template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {{ scan.target }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1 { color: #333; }
                .summary { background: #f5f5f5; padding: 20px; border-radius: 5px; }
                .critical { color: #ff0000; }
                .high { color: #ff6600; }
                .medium { color: #ffaa00; }
                .low { color: #00cc00; }
                .vuln-item { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
            </style>
        </head>
        <body>
            <h1>Security Scan Report</h1>
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>Target: {{ scan.target }}</p>
                <p>Scan Date: {{ generated_at }}</p>
                <p>Risk Score: {{ summary.risk_score }}</p>
                <p>Total Vulnerabilities: {{ summary.total_vulnerabilities }}</p>
            </div>
            
            <h2>Findings by Severity</h2>
            <ul>
                <li class="critical">Critical: {{ summary.critical_count }}</li>
                <li class="high">High: {{ summary.high_count }}</li>
                <li class="medium">Medium: {{ summary.medium_count }}</li>
                <li class="low">Low: {{ summary.low_count }}</li>
            </ul>
            
            <h2>Detailed Findings</h2>
            {% for vuln in scan.vulnerabilities %}
            <div class="vuln-item">
                <h3 class="{{ vuln.severity }}">{{ vuln.name }}</h3>
                <p><strong>Severity:</strong> {{ vuln.severity }}</p>
                <p><strong>CVSS:</strong> {{ vuln.cvss_score }}</p>
                <p><strong>Description:</strong> {{ vuln.description }}</p>
                <p><strong>Remediation:</strong> {{ vuln.remediation }}</p>
                {% if vuln.cve_id %}<p><strong>CVE:</strong> {{ vuln.cve_id }}</p>{% endif %}
            </div>
            {% endfor %}
            
            <h2>Recommendations</h2>
            {% for rec in recommendations %}
            <div class="recommendation">
                <h3>{{ rec.priority }} Priority: {{ rec.title }}</h3>
                <ul>
                {% for action in rec.actions %}
                    <li>{{ action }}</li>
                {% endfor %}
                </ul>
            </div>
            {% endfor %}
        </body>
        </html>
        """