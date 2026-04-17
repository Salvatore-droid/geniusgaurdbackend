# base/tasks.py
from celery import shared_task
from celery.result import AsyncResult
from django.utils import timezone
from asgiref.sync import sync_to_async
import asyncio
import logging
import traceback
from typing import Dict, Any, List, Optional
from .models import Scan, Vulnerability, Notification, DeepScanSession, DeepFinding
from django.contrib.auth.models import User
from django.core.files.base import ContentFile

logger = logging.getLogger(__name__)


# ==================== TRADITIONAL SCAN TASKS (FALLBACK) ====================

@shared_task(bind=True)
def run_traditional_quick_scan(self, scan_id):
    """Traditional quick scan - uses actual scanning logic"""
    logger.info(f"Starting traditional quick scan for scan_id: {scan_id}")
    
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'running'
        scan.progress = 10
        scan.save()
        
        from .ai.vulnerability_hunter import AIVulnerabilityHunter
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        hunter = AIVulnerabilityHunter(scan.target)
        
        self.update_state(state='PROGRESS', meta={'progress': 20, 'status': 'Scanning target...'})
        findings = loop.run_until_complete(hunter.scan())
        loop.close()
        
        self.update_state(state='PROGRESS', meta={'progress': 80, 'status': 'Saving findings...'})
        
        vuln_count = 0
        for finding in findings:
            if finding.get('is_false_positive'):
                continue
                
            Vulnerability.objects.create(
                scan=scan,
                name=finding.get('name', 'Discovered Vulnerability'),
                description=finding.get('description', ''),
                severity=finding.get('severity', 'medium'),
                cvss_score=finding.get('cvss_score', 5.0),
                cve_id=finding.get('cve_id', ''),
                cwe_id=finding.get('cwe_id', ''),
                remediation=finding.get('remediation', ''),
                evidence=finding.get('evidence', ''),
                metadata={'scanner': 'traditional', 'confidence': finding.get('confidence', 0.5)},
                discovered_at=timezone.now()
            )
            vuln_count += 1
        
        scan.status = 'completed'
        scan.progress = 100
        scan.end_time = timezone.now()
        scan.metadata = {'ai_enhanced': False, 'fallback': True, 'vulnerabilities_found': vuln_count}
        scan.save()
        
        from .views import create_notification
        create_notification(
            user=scan.created_by,
            type='scan_complete',
            title='Quick Scan Completed',
            message=f'Found {vuln_count} vulnerabilities',
            scan=scan
        )
        
        logger.info(f"Traditional scan completed for {scan.target}. Found {vuln_count} vulnerabilities.")
        
        return {
            'status': 'completed',
            'scan_id': scan_id,
            'vulnerabilities': vuln_count,
            'type': 'traditional'
        }
        
    except Exception as e:
        logger.error(f"Traditional scan failed: {str(e)}", exc_info=True)
        
        if 'scan' in locals():
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.save()
        
        return {
            'status': 'failed',
            'scan_id': scan_id,
            'error': str(e)
        }


@shared_task(bind=True)
def run_traditional_deep_scan(self, scan_id):
    """Traditional deep scan - uses actual scanning logic"""
    logger.info(f"Starting traditional deep scan for scan_id: {scan_id}")
    
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'running'
        scan.progress = 5
        scan.save()
        
        from .ai.vulnerability_hunter import AIVulnerabilityHunter
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        hunter = AIVulnerabilityHunter(scan.target)
        
        self.update_state(state='PROGRESS', meta={'progress': 20, 'status': 'Deep scanning target...'})
        findings = loop.run_until_complete(hunter.scan())
        loop.close()
        
        self.update_state(state='PROGRESS', meta={'progress': 80, 'status': 'Saving findings...'})
        
        vuln_count = 0
        for finding in findings:
            if finding.get('is_false_positive'):
                continue
                
            Vulnerability.objects.create(
                scan=scan,
                name=finding.get('name', 'Discovered Vulnerability'),
                description=finding.get('description', ''),
                severity=finding.get('severity', 'medium'),
                cvss_score=finding.get('cvss_score', 5.0),
                cve_id=finding.get('cve_id', ''),
                cwe_id=finding.get('cwe_id', ''),
                remediation=finding.get('remediation', ''),
                evidence=finding.get('evidence', ''),
                metadata={'scanner': 'traditional', 'deep_scan': True, 'confidence': finding.get('confidence', 0.5)},
                discovered_at=timezone.now()
            )
            vuln_count += 1
        
        scan.status = 'completed'
        scan.progress = 100
        scan.end_time = timezone.now()
        scan.metadata = {'ai_enhanced': False, 'fallback': True, 'deep_scan': True, 'vulnerabilities_found': vuln_count}
        scan.save()
        
        from .views import create_notification
        create_notification(
            user=scan.created_by,
            type='scan_complete',
            title='Deep Scan Completed',
            message=f'Found {vuln_count} vulnerabilities',
            scan=scan
        )
        
        return {
            'status': 'completed',
            'scan_id': scan_id,
            'vulnerabilities': vuln_count,
            'type': 'traditional'
        }
        
    except Exception as e:
        logger.error(f"Traditional deep scan failed: {str(e)}", exc_info=True)
        
        if 'scan' in locals():
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.save()
        
        return {
            'status': 'failed',
            'scan_id': scan_id,
            'error': str(e)
        }


# ==================== ASYNC HELPER FUNCTIONS ====================

@sync_to_async
def get_scan(scan_id):
    """Async-safe function to get scan"""
    return Scan.objects.select_related('created_by').get(id=scan_id)


@sync_to_async
def update_scan(scan):
    """Async-safe function to update scan"""
    scan.save()
    return scan


@sync_to_async
def create_vulnerability(vuln_data):
    """Async-safe function to create vulnerability"""
    return Vulnerability.objects.create(**vuln_data)


@sync_to_async
def create_deep_finding_sync(finding_data):
    """Sync function to create deep finding"""
    return DeepFinding.objects.create(**finding_data)


@sync_to_async
def get_deep_session(session_id):
    """Async-safe function to get deep scan session"""
    return DeepScanSession.objects.select_related('user').get(id=session_id)


@sync_to_async
def update_deep_session(session):
    """Async-safe function to update deep session"""
    session.save()
    return session


@sync_to_async
def get_user(user_id):
    """Async-safe function to get user"""
    return User.objects.get(id=user_id)


@sync_to_async
def create_notification_async(user_id, type, title, message, scan=None, report=None):
    """Async-safe function to create notification"""
    from .views import create_notification
    user = User.objects.get(id=user_id)
    return create_notification(user, type, title, message, scan, report)


# ==================== AI-POWERED SCAN TASKS (PRODUCTION) ====================

async def run_ai_scan_async(scan_id: int, self, scan_type: str = 'quick') -> Dict[str, Any]:
    """Async function to run AI vulnerability scan with retry logic"""
    from .ai.vulnerability_hunter import AIVulnerabilityHunter
    
    logger.info(f"Starting REAL AI {scan_type} scan for scan_id: {scan_id}")
    
    scan = None
    user_id = None
    try:
        scan = await get_scan(scan_id)
        user_id = scan.created_by.id
        
        scan.status = 'running'
        scan.progress = 5
        scan.metadata = {
            'ai_enhanced': True,
            'ai_model': 'llama-3.3-70b-versatile',
            'scan_type': scan_type,
            'start_time': timezone.now().isoformat()
        }
        await update_scan(scan)
        
        self.update_state(state='PROGRESS', meta={'progress': 10, 'status': 'Initializing AI vulnerability hunter...'})
        scan.progress = 10
        await update_scan(scan)
        
        hunter = AIVulnerabilityHunter(scan.target)
        
        self.update_state(state='PROGRESS', meta={'progress': 15, 'status': 'Gathering information...'})
        scan.progress = 15
        await update_scan(scan)
        
        max_retries = 3
        retry_count = 0
        findings = []
        
        while retry_count < max_retries:
            try:
                findings = await hunter.scan()
                break
            except Exception as e:
                retry_count += 1
                logger.warning(f"Scan attempt {retry_count} failed: {str(e)}")
                if retry_count >= max_retries:
                    raise
                await asyncio.sleep(2)
        
        self.update_state(state='PROGRESS', meta={'progress': 80, 'status': 'Saving findings...'})
        
        vuln_count = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            if finding.get('is_false_positive'):
                continue
            
            severity = finding.get('severity', 'info').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            await create_vulnerability({
                'scan': scan,
                'name': finding.get('name', 'AI-Discovered Vulnerability'),
                'description': finding.get('description', ''),
                'severity': severity,
                'cvss_score': finding.get('cvss_score', 5.0),
                'cve_id': finding.get('cve_id', ''),
                'cwe_id': finding.get('cwe_id', ''),
                'remediation': finding.get('remediation', ''),
                'evidence': finding.get('evidence', ''),
                'metadata': {
                    'ai_confidence': finding.get('confidence', 0.5),
                    'ai_analyzed': True,
                    'attack_surface': finding.get('attack_surface', 'unknown')
                },
                'discovered_at': timezone.now()
            })
            vuln_count += 1
        
        scan.metadata.update({
            'vulnerabilities_found': vuln_count,
            'severity_breakdown': severity_counts,
            'requests_made': hunter.stats.get('requests_made', 0),
            'urls_crawled': hunter.stats.get('urls_crawled', 0),
            'forms_processed': hunter.stats.get('forms_processed', 0),
            'ai_calls': hunter.stats.get('ai_calls', 0),
            'duration_seconds': hunter.stats.get('duration', 0),
            'completion_time': timezone.now().isoformat()
        })
        
        scan.status = 'completed'
        scan.progress = 100
        scan.end_time = timezone.now()
        await update_scan(scan)
        
        message = f'AI found {vuln_count} vulnerabilities'
        if severity_counts['critical'] > 0:
            message += f' including {severity_counts["critical"]} critical'
        
        if user_id:
            await create_notification_async(
                user_id,
                'scan_complete',
                f'AI {scan_type.title()} Scan Completed',
                message,
                scan=scan
            )
        
        logger.info(f"AI {scan_type} scan completed for {scan.target}")
        
        return {
            'status': 'completed',
            'scan_id': scan_id,
            'vulnerabilities': vuln_count,
            'severity_breakdown': severity_counts,
            'type': 'ai',
            'ai_model': 'llama-3.3-70b-versatile',
            'stats': hunter.stats
        }
        
    except Exception as e:
        logger.error(f"AI {scan_type} scan failed: {str(e)}", exc_info=True)
        
        if scan:
            scan.status = 'failed'
            scan.error_message = str(e)
            if scan.metadata:
                scan.metadata['error'] = str(e)
                scan.metadata['error_traceback'] = traceback.format_exc()
            await update_scan(scan)
            
            if user_id:
                await create_notification_async(
                    user_id,
                    'scan_failed',
                    f'AI {scan_type.title()} Scan Failed',
                    f'Scan failed: {str(e)[:200]}',
                    scan=scan
                )
        
        return {
            'status': 'failed',
            'scan_id': scan_id,
            'error': str(e)
        }


@shared_task(bind=True)
def run_ai_quick_scan(self, scan_id):
    """Run REAL AI-augmented quick vulnerability scan"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(run_ai_scan_async(scan_id, self, 'quick'))
    finally:
        loop.close()


# ==================== REPLACE run_ai_deep_scan task in base/tasks.py ====================

@shared_task(bind=True)
def run_playwright_deep_scan(self, scan_id: int, credentials: dict = None):
    """
    Deep scan using headless Playwright browser.
    Replaces the browser extension approach.
    credentials (optional): {
        'login_url': 'https://target.com/login/',
        'username_field': 'email',
        'username': 'tester@example.com',
        'password': 'testpassword'
    }
    """
    logger.info(f"Starting Playwright deep scan for scan_id: {scan_id}")

    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status   = 'running'
        scan.progress = 5
        scan.metadata = {
            'scan_type':    'playwright_deep',
            'authenticated': credentials is not None,
            'start_time':   timezone.now().isoformat(),
        }
        scan.save()

        self.update_state(state='PROGRESS', meta={'progress': 10, 'status': 'Launching headless browser...'})

        from .ai.deep_scanner import DeepVulnerabilityScanner

        scanner = DeepVulnerabilityScanner(
            target_url=scan.target,
            credentials=credentials,
            scan_id=scan_id,
        )

        self.update_state(state='PROGRESS', meta={'progress': 20, 'status': 'Crawling and testing...'})

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        findings = loop.run_until_complete(scanner.scan())
        loop.close()

        self.update_state(state='PROGRESS', meta={'progress': 85, 'status': 'Saving findings...'})

        vuln_count      = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            Vulnerability.objects.create(
                scan=scan,
                name=finding.get('name', 'Deep Scan Finding'),
                description=finding.get('description', ''),
                severity=severity,
                cvss_score=finding.get('cvss_score', 5.0),
                cve_id=finding.get('cve_id', ''),
                cwe_id=finding.get('cwe_id', ''),
                remediation=finding.get('remediation', ''),
                evidence=finding.get('evidence', ''),
                metadata={
                    'ai_confidence':  finding.get('confidence', 0),
                    'ai_reviewed':    finding.get('ai_reviewed', False),
                    'scanner':        'playwright',
                    'authenticated':  credentials is not None,
                },
                discovered_at=timezone.now()
            )
            vuln_count += 1

        scan.status   = 'completed'
        scan.progress = 100
        scan.end_time = timezone.now()
        scan.metadata.update({
            'vulnerabilities_found':      vuln_count,
            'severity_breakdown':         severity_counts,
            'pages_crawled':              scanner.stats.get('pages_crawled', 0),
            'requests_intercepted':       scanner.stats.get('requests_intercepted', 0),
            'forms_tested':               scanner.stats.get('forms_tested', 0),
            'api_endpoints_found':        scanner.stats.get('api_endpoints_found', 0),
            'false_positives_filtered':   scanner.stats.get('false_positives_filtered', 0),
            'duration_seconds':           scanner.stats.get('duration', 0),
            'completion_time':            timezone.now().isoformat(),
        })
        scan.save()

        from .views import create_notification
        msg = f'Deep scan found {vuln_count} vulnerabilities'
        if severity_counts['critical'] > 0:
            msg += f" — {severity_counts['critical']} critical"
        create_notification(
            user=scan.created_by,
            type='scan_complete',
            title='Deep Scan Completed',
            message=msg,
            scan=scan
        )

        return {
            'status':             'completed',
            'scan_id':            scan_id,
            'vulnerabilities':    vuln_count,
            'severity_breakdown': severity_counts,
            'stats':              scanner.stats,
        }

    except Exception as e:
        logger.error(f"Playwright deep scan failed: {e}", exc_info=True)
        if 'scan' in locals():
            scan.status        = 'failed'
            scan.error_message = str(e)
            scan.save()
        return {'status': 'failed', 'scan_id': scan_id, 'error': str(e)}





# ==================== DEEP SCAN ANALYSIS TASKS ====================

@shared_task(bind=True)
def analyze_deep_session(self, session_id):
    """Analyze a deep scan session using real AI analysis"""
    from .ai.deep_analyzer import DeepSessionAnalyzer
    
    logger.info(f"Starting deep analysis for session {session_id}")
    
    try:
        # Sync call to get session (not async)
        session = DeepScanSession.objects.get(id=session_id)
        session.status = 'analyzing'
        session.progress = 10
        session.save()
        
        self.update_state(state='PROGRESS', meta={'progress': 20, 'status': 'Analyzing requests...'})
        
        # Run analysis in async loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        analyzer = DeepSessionAnalyzer(session.data, session.id)
        findings = loop.run_until_complete(analyzer.analyze())
        
        loop.close()
        
        self.update_state(state='PROGRESS', meta={'progress': 80, 'status': 'Saving findings...'})
        
        vuln_count = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Sync create - not async
            DeepFinding.objects.create(
                session=session,
                finding_type=finding.get('finding_type', 'other'),
                name=finding.get('name'),
                description=finding.get('description'),
                severity=severity,
                cvss_score=finding.get('cvss_score', 5.0),
                url=finding.get('url', ''),
                method=finding.get('method', ''),
                parameter=finding.get('parameter', ''),
                evidence=finding.get('evidence', ''),
                remediation=finding.get('remediation', ''),
                ai_confidence=finding.get('ai_confidence', 0.5),
                discovered_at=timezone.now()
            )
            vuln_count += 1
        
        session.status = 'completed'
        session.progress = 100
        session.end_time = timezone.now()
        session.findings_count = vuln_count
        session.critical_count = severity_counts['critical']
        session.high_count = severity_counts['high']
        session.medium_count = severity_counts['medium']
        session.low_count = severity_counts['low']
        session.info_count = severity_counts['info']
        session.save()
        
        from .views import create_notification
        create_notification(
            user=session.user,
            type='scan_complete',
            title='Deep Scan Analysis Complete',
            message=f'Found {vuln_count} vulnerabilities in your recorded session',
            scan=None
        )
        
        logger.info(f"Deep analysis completed for session {session_id}. Found {vuln_count} findings.")
        
        return {
            'status': 'completed',
            'session_id': session_id,
            'findings': vuln_count,
            'severity_breakdown': severity_counts
        }
        
    except Exception as e:
        logger.error(f"Deep analysis failed: {str(e)}", exc_info=True)
        
        if 'session' in locals():
            session.status = 'failed'
            session.error_message = str(e)
            session.save()
        
        return {
            'status': 'failed',
            'session_id': session_id,
            'error': str(e)
        }


@shared_task(bind=True)
def generate_deep_report(self, session_id, report_format='pdf'):
    """Generate PDF/HTML/JSON report for deep scan"""
    from .reporting.deep_report_generator import DeepReportGenerator
    
    logger.info(f"Generating {report_format} report for session {session_id}")
    
    try:
        session = DeepScanSession.objects.get(id=session_id)
        
        generator = DeepReportGenerator(session)
        
        if report_format == 'pdf':
            output_path = generator.generate_pdf()
        elif report_format == 'html':
            output_path = generator.generate_html()
        elif report_format == 'json':
            output_path = generator.generate_json()
        else:
            output_path = generator.generate_pdf()
        
        return {
            'status': 'completed',
            'session_id': session_id,
            'report_path': output_path,
            'format': report_format
        }
        
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}", exc_info=True)
        return {
            'status': 'failed',
            'session_id': session_id,
            'error': str(e)
        }


@shared_task(bind=True)
def generate_ai_report(self, report_id):
    """Generate AI-enhanced security report"""
    from .models import Report
    from .reporting.report_generator import ReportGenerator
    
    try:
        report = Report.objects.get(id=report_id)
        scan = report.scan
        
        generator = ReportGenerator(scan)
        
        if report.report_type == 'pdf':
            pdf_content = generator.generate_pdf()
            report.file.save(f'report_{scan.id}.pdf', ContentFile(pdf_content))
        elif report.report_type == 'html':
            html_content = generator.generate_html()
            report.file.save(f'report_{scan.id}.html', ContentFile(html_content.encode()))
        
        report.metadata = {'ai_enhanced': True, 'generated_at': timezone.now().isoformat()}
        report.save()
        
        from .views import create_notification
        create_notification(
            user=report.created_by,
            type='report_generated',
            title='AI Report Ready',
            message=f'AI-enhanced report for {scan.target} is ready',
            report=report
        )
        
        return {'status': 'completed', 'report_id': report_id}
        
    except Exception as e:
        logger.error(f"AI report generation failed: {str(e)}")
        return {'status': 'failed', 'report_id': report_id, 'error': str(e)}


# ==================== HELPER FUNCTIONS ====================

def get_scan_status(task_id):
    """Get scan status by task ID"""
    result = AsyncResult(task_id)
    return {
        'task_id': task_id,
        'status': result.status,
        'result': result.result if result.ready() else None
    }