# base/reporting/pdf_generator.py
import os
from datetime import datetime
from typing import Dict, List, Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
import io
import base64

class PDFReportGenerator:
    """Professional PDF report generator for security scans"""
    
    def __init__(self, report_data: Dict[str, Any]):
        self.data = report_data
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.elements = []
        
    def _setup_custom_styles(self):
        """Set up custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1E40AF'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#1E293B'),
            spaceBefore=20,
            spaceAfter=10,
            borderWidth=1,
            borderColor=colors.HexColor('#E2E8F0'),
            borderPadding=5,
            borderRadius=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskCritical',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#DC2626'),
            fontSize=12,
            spaceAfter=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#F97316'),
            fontSize=12,
            spaceAfter=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#EAB308'),
            fontSize=12,
            spaceAfter=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='Footer',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.gray,
            alignment=TA_CENTER
        ))
        
    def _create_header(self):
        """Create report header with logo and title"""
        # Add title
        self.elements.append(Paragraph(
            f"<b>GeniusGuard Security Report</b>",
            self.styles['CustomTitle']
        ))
        
        # Add date
        self.elements.append(Paragraph(
            f"Generated: {self.data['generated_at']}",
            self.styles['Normal']
        ))
        self.elements.append(Spacer(1, 20))
        
    def _create_executive_summary(self):
        """Create executive summary section"""
        self.elements.append(Paragraph(
            "<b>Executive Summary</b>",
            self.styles['SectionHeader']
        ))
        
        summary = self.data.get('summary', {})
        
        # Create summary table
        summary_data = [
            ['Metric', 'Value'],
            ['Total Scans', str(summary.get('total_scans', 0))],
            ['Completed Scans', str(summary.get('completed_scans', 0))],
            ['Total Vulnerabilities', str(summary.get('total_vulnerabilities', 0))],
            ['Security Score', f"{summary.get('security_score', 0)}/100"],
            ['Average Duration', summary.get('avg_duration', 'N/A')]
        ]
        
        summary_table = Table(summary_data, colWidths=[200, 200])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#1E40AF')),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F8FAFC')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0'))
        ]))
        
        self.elements.append(summary_table)
        self.elements.append(Spacer(1, 20))
        
    def _create_severity_chart(self):
        """Create severity breakdown chart"""
        self.elements.append(Paragraph(
            "<b>Severity Breakdown</b>",
            self.styles['SectionHeader']
        ))
        
        severity = self.data.get('severity_breakdown', {})
        
        # Create bar chart
        drawing = Drawing(400, 200)
        chart = VerticalBarChart()
        chart.x = 50
        chart.y = 50
        chart.width = 300
        chart.height = 100
        chart.data = [[
            severity.get('critical', 0),
            severity.get('high', 0),
            severity.get('medium', 0),
            severity.get('low', 0),
            severity.get('info', 0)
        ]]
        chart.strokeColor = colors.black
        chart.valueAxis.valueMin = 0
        chart.valueAxis.valueMax = max(chart.data[0]) * 1.2 or 10
        chart.categoryAxis.categoryNames = ['Critical', 'High', 'Medium', 'Low', 'Info']
        chart.bars[0].fillColor = colors.HexColor('#DC2626')  # Critical
        chart.bars[1].fillColor = colors.HexColor('#F97316')  # High
        chart.bars[2].fillColor = colors.HexColor('#EAB308')  # Medium
        chart.bars[3].fillColor = colors.HexColor('#3B82F6')  # Low
        chart.bars[4].fillColor = colors.HexColor('#8B5CF6')  # Info
        
        drawing.add(chart)
        self.elements.append(drawing)
        self.elements.append(Spacer(1, 30))
        
        # Create severity table
        severity_data = [
            ['Severity', 'Count', 'Risk Level'],
            ['Critical', str(severity.get('critical', 0)), 'Immediate Action Required'],
            ['High', str(severity.get('high', 0)), 'Priority Fix Required'],
            ['Medium', str(severity.get('medium', 0)), 'Schedule Fix'],
            ['Low', str(severity.get('low', 0)), 'Monitor'],
            ['Info', str(severity.get('info', 0)), 'Informational']
        ]
        
        severity_table = Table(severity_data, colWidths=[100, 100, 200])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (2, 0), colors.HexColor('#1E40AF')),
            ('TEXTCOLOR', (0, 0), (2, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#FEE2E2')),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#FFEDD5')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#FEF9C3')),
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#DBEAFE')),
            ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#F3E8FF'))
        ]))
        
        self.elements.append(severity_table)
        self.elements.append(Spacer(1, 20))
        
    def _create_scan_details(self):
        """Create detailed scan information"""
        self.elements.append(Paragraph(
            "<b>Scan Details</b>",
            self.styles['SectionHeader']
        ))
        
        scans = self.data.get('scans', [])
        
        for scan in scans:
            # Scan header
            self.elements.append(Paragraph(
                f"<b>Target:</b> {scan['target']} | <b>Date:</b> {scan['date']} | <b>Type:</b> {scan['type'].upper()}",
                self.styles['Normal']
            ))
            self.elements.append(Spacer(1, 10))
            
            if scan.get('vulnerabilities'):
                # Vulnerabilities table
                vuln_data = [['Name', 'Severity', 'CVSS', 'CVE']]
                for vuln in scan['vulnerabilities'][:10]:  # Limit to 10 per scan
                    vuln_data.append([
                        vuln['name'][:50] + '...' if len(vuln['name']) > 50 else vuln['name'],
                        vuln['severity'].upper(),
                        str(vuln.get('cvss', 'N/A')),
                        vuln.get('cve', 'N/A')
                    ])
                
                if len(scan['vulnerabilities']) > 10:
                    vuln_data.append(['...', '', '', f"+{len(scan['vulnerabilities']) - 10} more"])
                
                vuln_table = Table(vuln_data, colWidths=[200, 80, 60, 100])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E40AF')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0'))
                ]))
                
                self.elements.append(vuln_table)
            else:
                self.elements.append(Paragraph(
                    "No vulnerabilities found in this scan.",
                    self.styles['Italic']
                ))
            
            self.elements.append(Spacer(1, 15))
        
    def _create_recommendations(self):
        """Create remediation recommendations"""
        self.elements.append(Paragraph(
            "<b>Remediation Recommendations</b>",
            self.styles['SectionHeader']
        ))
        
        # Collect unique recommendations
        recommendations = set()
        for scan in self.data.get('scans', []):
            for vuln in scan.get('vulnerabilities', []):
                if vuln.get('remediation'):
                    recommendations.add(vuln['remediation'])
        
        if recommendations:
            for i, rec in enumerate(list(recommendations)[:10], 1):
                self.elements.append(Paragraph(
                    f"{i}. {rec}",
                    self.styles['Normal']
                ))
                self.elements.append(Spacer(1, 5))
        else:
            self.elements.append(Paragraph(
                "No specific remediation recommendations available.",
                self.styles['Italic']
            ))
        
    def _create_footer(self):
        """Create footer with page numbers"""
        self.elements.append(Spacer(1, 30))
        self.elements.append(Paragraph(
            "© 2026 GeniusGuard - Enterprise Security Vulnerability Scanner",
            self.styles['Footer']
        ))
        
    def generate(self) -> bytes:
        """Generate the PDF report"""
        buffer = io.BytesIO()
        
        # Create PDF document
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        # Build document
        self._create_header()
        self._create_executive_summary()
        self._create_severity_chart()
        self._create_scan_details()
        self._create_recommendations()
        self._create_footer()
        
        # Build PDF
        doc.build(self.elements)
        
        # Get PDF content
        pdf_content = buffer.getvalue()
        buffer.close()
        
        return pdf_content