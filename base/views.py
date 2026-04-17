# base/views.py
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.db.models import Count, Q, Avg, Sum
from django.db.models.functions import TruncMonth, TruncWeek
from datetime import timedelta
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authentication import BaseAuthentication
from django.middleware.csrf import get_token
from celery import shared_task
from celery.result import AsyncResult
import logging
import asyncio
import json
import hashlib
import os
from django.conf import settings
from django.http import FileResponse
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import secrets

from .models import *
from .serializers import *
from .ai.groq_client import groq_client
from .ai.test_generator import ai_test_generator
from .tasks import *
from .reporting.pdf_generator import PDFReportGenerator

logger = logging.getLogger(__name__)


# ==================== AUTHENTICATION VIEWS ====================

class ExtensionAuthentication(BaseAuthentication):
    """Authentication class specifically for browser extensions"""
    
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Bearer '):
            return None
        
        key = auth_header.replace('Bearer ', '')
        
        try:
            hashed = hashlib.sha256(key.encode()).hexdigest()
            api_key = ApiKey.objects.select_related('user').get(key=hashed)
            
            if api_key.expires_at and api_key.expires_at < timezone.now():
                raise AuthenticationFailed('API key expired')
            
            api_key.last_used = timezone.now()
            api_key.use_count += 1
            api_key.last_used_ip = request.META.get('REMOTE_ADDR')
            api_key.save()
            
            return (api_key.user, api_key)
            
        except ApiKey.DoesNotExist:
            raise AuthenticationFailed('Invalid API key')


@api_view(['GET'])
@permission_classes([AllowAny])
def get_csrf_token(request):
    return Response({'csrfToken': get_token(request)})



@api_view(['POST'])
@permission_classes([AllowAny])
def signup_view(request):
    serializer = SignupSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            'user': UserSerializer(user).data,
            'token': token.key
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        try:
            user = User.objects.get(email=email)
            user = authenticate(username=user.username, password=password)
            if user:
                login(request, user)
                token, _ = Token.objects.get_or_create(user=user)
                return Response({
                    'user': UserSerializer(user).data,
                    'token': token.key
                })
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    request.user.auth_token.delete()
    logout(request)
    return Response({'message': 'Logged out successfully'})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_view(request):
    return Response(UserSerializer(request.user).data)


# ==================== SOCIAL AUTH VIEWS ====================

@api_view(['GET'])
@permission_classes([AllowAny])
def google_login(request):
    return Response({'url': '/accounts/google/login/'})


@api_view(['GET'])
@permission_classes([AllowAny])
def google_callback(request):
    return Response({'message': 'Google callback'})


@api_view(['GET'])
@permission_classes([AllowAny])
def github_login(request):
    return Response({'url': '/accounts/github/login/'})


@api_view(['GET'])
@permission_classes([AllowAny])
def github_callback(request):
    return Response({'message': 'GitHub callback'})


# ==================== DASHBOARD VIEWS ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_stats(request):
    user = request.user
    scans = Scan.objects.filter(created_by=user)
    vulnerabilities = Vulnerability.objects.filter(scan__created_by=user)
    
    stats = {
        'total_scans': scans.count(),
        'active_scans': scans.filter(status='running').count(),
        'completed_scans': scans.filter(status='completed').count(),
        'failed_scans': scans.filter(status='failed').count(),
        'total_vulnerabilities': vulnerabilities.count(),
        'critical_vulnerabilities': vulnerabilities.filter(severity='critical').count(),
        'high_vulnerabilities': vulnerabilities.filter(severity='high').count(),
        'medium_vulnerabilities': vulnerabilities.filter(severity='medium').count(),
        'low_vulnerabilities': vulnerabilities.filter(severity='low').count(),
        'info_vulnerabilities': vulnerabilities.filter(severity='info').count(),
        'secure_targets': scans.filter(status='completed', vulnerabilities__isnull=True).values('target').distinct().count(),
        'scanned_targets': scans.values('target').distinct().count(),
        'ai_enhanced_scans': scans.filter(metadata__has_key='ai_enhanced').count()
    }
    return Response(stats)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def recent_scans(request):
    scans = Scan.objects.filter(created_by=request.user).order_by('-start_time')[:10]
    serializer = ScanSerializer(scans, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def vulnerability_trends(request):
    user = request.user
    end_date = timezone.now()
    start_date = end_date - timedelta(days=180)
    
    trends = []
    current_date = start_date
    
    while current_date <= end_date:
        month_name = current_date.strftime('%b')
        month_end = current_date + timedelta(days=30)
        
        month_scans = Scan.objects.filter(
            created_by=user,
            start_time__gte=current_date,
            start_time__lt=month_end,
            status='completed'
        )
        
        vulns = Vulnerability.objects.filter(scan__in=month_scans)
        
        trends.append({
            'month': month_name,
            'critical': vulns.filter(severity='critical').count(),
            'high': vulns.filter(severity='high').count(),
            'medium': vulns.filter(severity='medium').count(),
            'low': vulns.filter(severity='low').count(),
            'info': vulns.filter(severity='info').count(),
            'ai_discovered': vulns.filter(metadata__has_key='ai_confidence').count()
        })
        
        current_date = month_end
    
    return Response(trends)


# ==================== SCAN VIEWS ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_list(request):
    scans = Scan.objects.filter(created_by=request.user).order_by('-start_time')
    serializer = ScanSerializer(scans, many=True)
    return Response(serializer.data)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def scan_detail(request, pk):
    """Get, update, or delete a scan"""
    scan = get_object_or_404(Scan, pk=pk, created_by=request.user)
    
    if request.method == 'GET':
        serializer = ScanSerializer(scan)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = ScanSerializer(scan, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        scan.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_vulnerabilities(request, pk):
    scan = get_object_or_404(Scan, pk=pk, created_by=request.user)
    vulnerabilities = scan.vulnerabilities.all().order_by('-severity', '-cvss_score')
    serializer = VulnerabilitySerializer(vulnerabilities, many=True)
    return Response(serializer.data)


# ==================== REPLACE quick_scan and deep_scan in base/views.py ====================
# These are drop-in replacements for the existing quick_scan and deep_scan functions.
# They add authorization checking before any scan is allowed to start.

from .authorization import is_scan_authorized, extract_domain
from .models import ScanAuthorization


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def quick_scan(request):
    """
    Start a quick AI-powered scan.
    REQUIRES the target domain to be verified in AuthorizedTarget first.
    """
    url = request.data.get('target', '').strip()

    if not url:
        return Response(
            {'error': 'target URL is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # ----------------------------------------------------------------
    # AUTHORIZATION GATE — must pass before anything else happens
    # ----------------------------------------------------------------
    authorized, auth_target = is_scan_authorized(request.user, url)

    if not authorized:
        domain = extract_domain(url)
        return Response(
            {
                'error': 'Target not authorized',
                'detail': (
                    f'You must verify ownership of {domain} before scanning it. '
                    f'Register the domain at /api/authorized-targets/ and complete '
                    f'the verification process first.'
                ),
                'action_required': 'verify_domain',
                'domain': domain,
            },
            status=status.HTTP_403_FORBIDDEN
        )
    # ----------------------------------------------------------------

    scan = Scan.objects.create(
        target=url,
        type='quick',
        status='pending',
        created_by=request.user,
        metadata={
            'ai_enhanced': True,
            'authorized_domain': auth_target.domain,
            'authorized_at': auth_target.verified_at.isoformat() if auth_target.verified_at else None,
        }
    )

    # Record the authorization link
    ScanAuthorization.objects.create(
        scan=scan,
        authorized_target=auth_target,
        scope_confirmed=True
    )

    try:
        from .ai.groq_client import groq_client

        if groq_client.initialized:
            task    = run_ai_quick_scan.delay(scan.id)
            message = 'AI-powered scan started successfully'
            scan.metadata.update({'type': 'ai'})
        else:
            task    = run_traditional_quick_scan.delay(scan.id)
            message = 'Traditional scan started (AI unavailable)'
            scan.metadata.update({'ai_enhanced': False, 'type': 'traditional', 'fallback': True})

        scan.task_id = task.id
        scan.save()

        return Response(
            {
                'scan': ScanSerializer(scan).data,
                'task_id': task.id,
                'message': message,
                'ai_enabled': groq_client.initialized,
                'authorized_domain': auth_target.domain,
            },
            status=status.HTTP_202_ACCEPTED
        )

    except Exception as e:
        scan.status        = 'failed'
        scan.error_message = str(e)
        scan.save()
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ==================== REPLACE deep_scan view in base/views.py ====================
# This adds optional credential support to the deep scan endpoint

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deep_scan(request):
    """
    Start a Playwright-based deep scan.
    Requires domain authorization.
    Optionally accepts credentials for authenticated scanning.

    Body:
    {
        "target": "https://example.com",
        "credentials": {                      <- optional
            "login_url": "https://example.com/login/",
            "username_field": "email",
            "username": "tester@example.com",
            "password": "testpassword"
        }
    }
    """
    from .authorization import is_scan_authorized, extract_domain
    from .models import ScanAuthorization

    url         = request.data.get('target', '').strip()
    credentials = request.data.get('credentials', None)

    if not url:
        return Response({'error': 'target URL is required'}, status=status.HTTP_400_BAD_REQUEST)
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Authorization gate
    authorized, auth_target = is_scan_authorized(request.user, url)
    if not authorized:
        domain = extract_domain(url)
        return Response(
            {
                'error':            'Target not authorized',
                'detail':           f'Verify ownership of {domain} first at /api/authorized-targets/',
                'action_required':  'verify_domain',
                'domain':           domain,
            },
            status=status.HTTP_403_FORBIDDEN
        )

    scan = Scan.objects.create(
        target=url,
        type='deep',
        status='pending',
        created_by=request.user,
        metadata={
            'scan_type':     'playwright_deep',
            'authenticated': credentials is not None,
            'authorized_domain': auth_target.domain,
        }
    )

    ScanAuthorization.objects.create(
        scan=scan,
        authorized_target=auth_target,
        scope_confirmed=True
    )

    # Never store raw passwords in the model — pass only to Celery task memory
    task = run_playwright_deep_scan.delay(scan.id, credentials)

    scan.task_id = task.id
    scan.save()

    return Response(
        {
            'scan':              ScanSerializer(scan).data,
            'task_id':           task.id,
            'message':           'Playwright deep scan started' + (' (authenticated)' if credentials else ''),
            'authenticated':     credentials is not None,
            'authorized_domain': auth_target.domain,
        },
        status=status.HTTP_202_ACCEPTED
    )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_status(request, pk):
    scan = get_object_or_404(Scan, pk=pk, created_by=request.user)
    
    task_status = None
    if scan.status == 'running' and scan.task_id:
        try:
            task_result = AsyncResult(scan.task_id)
            task_status = {
                'task_id': scan.task_id,
                'state': task_result.state,
                'info': task_result.info if task_result.ready() else None
            }
            
            if task_result.state == 'PROGRESS' and task_result.info:
                scan.progress = task_result.info.get('progress', scan.progress)
                scan.save()
                
        except Exception as e:
            logger.error(f"Error getting task status: {str(e)}")
    
    return Response({
        'id': scan.id,
        'status': scan.status,
        'progress': scan.progress,
        'target': scan.target,
        'type': scan.type,
        'start_time': scan.start_time,
        'end_time': scan.end_time,
        'vulnerabilities': VulnerabilitySerializer(scan.vulnerabilities.all(), many=True).data,
        'task_status': task_status,
        'metadata': scan.metadata,
        'ai_enhanced': scan.metadata.get('ai_enhanced', False) if scan.metadata else False
    })


# ==================== VULNERABILITY VIEWS ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def vulnerability_list(request):
    vulnerabilities = Vulnerability.objects.filter(scan__created_by=request.user)
    
    severity = request.query_params.get('severity')
    if severity:
        vulnerabilities = vulnerabilities.filter(severity=severity)
    
    scan_id = request.query_params.get('scan_id')
    if scan_id:
        vulnerabilities = vulnerabilities.filter(scan_id=scan_id)
    
    serializer = VulnerabilitySerializer(vulnerabilities, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def vulnerability_detail(request, pk):
    vulnerability = get_object_or_404(Vulnerability, pk=pk, scan__created_by=request.user)
    serializer = VulnerabilitySerializer(vulnerability)
    return Response(serializer.data)


# ==================== SCHEDULED SCAN VIEWS ====================

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def scheduled_scan_list(request):
    if request.method == 'GET':
        scans = ScheduledScan.objects.filter(created_by=request.user)
        serializer = ScheduledScanSerializer(scans, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = ScheduledScanSerializer(data=request.data)
        if serializer.is_valid():
            scan = serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def scheduled_scan_detail(request, pk):
    scan = get_object_or_404(ScheduledScan, pk=pk, created_by=request.user)
    
    if request.method == 'GET':
        serializer = ScheduledScanSerializer(scan)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = ScheduledScanSerializer(scan, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        scan.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ==================== REPORT VIEWS ====================

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def report_list(request):
    if request.method == 'GET':
        reports = Report.objects.filter(created_by=request.user)
        serializer = ReportSerializer(reports, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = ReportSerializer(data=request.data)
        if serializer.is_valid():
            report = serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'DELETE'])
@permission_classes([IsAuthenticated])
def report_detail(request, pk):
    report = get_object_or_404(Report, pk=pk, created_by=request.user)
    
    if request.method == 'GET':
        serializer = ReportSerializer(report)
        return Response(serializer.data)
    
    elif request.method == 'DELETE':
        report.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_report(request):
    scan_id = request.data.get('scan_id')
    report_type = request.data.get('report_type', 'pdf')
    
    scan = get_object_or_404(Scan, pk=scan_id, created_by=request.user)
    
    report = Report.objects.create(
        name=f"Security Report - {scan.target}",
        scan=scan,
        report_type=report_type,
        created_by=request.user
    )
    
    serializer = ReportSerializer(report)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_pdf_report(request):
    try:
        report_data = request.data
        
        if not report_data:
            return Response({'error': 'No report data provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        generator = PDFReportGenerator(report_data)
        pdf_content = generator.generate()
        
        response = HttpResponse(pdf_content, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="geniusguard-report-{timezone.now().strftime("%Y%m%d")}.pdf"'
        
        return response
        
    except Exception as e:
        logger.error(f"PDF generation failed: {str(e)}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ==================== THREAT INTELLIGENCE VIEWS ====================

def categorize_vulnerability(name):
    name_lower = name.lower()
    if 'sql' in name_lower or 'injection' in name_lower:
        return 'SQL Injection'
    elif 'xss' in name_lower or 'cross-site' in name_lower:
        return 'Cross-Site Scripting'
    elif 'csrf' in name_lower or 'cross-site request' in name_lower:
        return 'CSRF'
    elif 'ssl' in name_lower or 'tls' in name_lower or 'certificate' in name_lower:
        return 'SSL/TLS'
    elif 'header' in name_lower or 'security headers' in name_lower:
        return 'Security Headers'
    elif 'cors' in name_lower:
        return 'CORS'
    elif 'information disclosure' in name_lower:
        return 'Information Disclosure'
    else:
        return 'Other'


def get_cve_for_vulnerability(name):
    # In production, this would query a CVE database
    return None


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def threat_intelligence_stats(request):
    user = request.user
    vulnerabilities = Vulnerability.objects.filter(scan__created_by=user).select_related('scan')
    
    total_threats = vulnerabilities.count()
    
    severity_counts = {
        'critical': vulnerabilities.filter(severity='critical').count(),
        'high': vulnerabilities.filter(severity='high').count(),
        'medium': vulnerabilities.filter(severity='medium').count(),
        'low': vulnerabilities.filter(severity='low').count(),
        'info': vulnerabilities.filter(severity='info').count(),
    }
    
    assets_scanned = Scan.objects.filter(created_by=user, status='completed').values('target').distinct().count()
    unique_issues = vulnerabilities.values('name').distinct().count()
    
    end_date = timezone.now()
    start_date = end_date - timedelta(days=30)
    
    timeline = []
    current_date = start_date
    while current_date <= end_date:
        next_date = current_date + timedelta(days=1)
        day_vulns = vulnerabilities.filter(discovered_at__gte=current_date, discovered_at__lt=next_date)
        
        top_target = day_vulns.values('scan__target').annotate(count=Count('id')).order_by('-count').first()
        
        timeline.append({
            'date': current_date.isoformat(),
            'count': day_vulns.count(),
            'target': top_target['scan__target'] if top_target else None
        })
        current_date = next_date
    
    active_threats = []
    vuln_types = vulnerabilities.values('name', 'severity').annotate(count=Count('id')).order_by('-count')[:20]
    
    for vuln in vuln_types:
        active_threats.append({
            'name': vuln['name'],
            'severity': vuln['severity'],
            'count': vuln['count'],
            'category': categorize_vulnerability(vuln['name']),
            'cve_id': get_cve_for_vulnerability(vuln['name'])
        })
    
    category_counts = {}
    for vuln in vulnerabilities:
        category = categorize_vulnerability(vuln.name)
        category_counts[category] = category_counts.get(category, 0) + 1
    
    recent_threats = vulnerabilities.order_by('-discovered_at')[:10].values('id', 'name', 'severity', 'discovered_at', 'scan__target')
    
    return Response({
        'total_threats': total_threats,
        'severity_breakdown': severity_counts,
        'assets_scanned': assets_scanned,
        'unique_issues': unique_issues,
        'timeline': timeline,
        'active_threats': active_threats,
        'category_counts': category_counts,
        'recent_threats': list(recent_threats)
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def threat_intelligence_list(request):
    threats = ThreatIntelligence.objects.all()
    
    threat_type = request.query_params.get('type')
    if threat_type:
        threats = threats.filter(threat_type=threat_type)
    
    severity = request.query_params.get('severity')
    if severity:
        threats = threats.filter(severity=severity)
    
    serializer = ThreatIntelligenceSerializer(threats, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def threat_intelligence_detail(request, pk):
    threat = get_object_or_404(ThreatIntelligence, pk=pk)
    serializer = ThreatIntelligenceSerializer(threat)
    return Response(serializer.data)


# ==================== NOTIFICATION VIEWS ====================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def notification_list(request):
    notifications = Notification.objects.filter(user=request.user)
    
    is_read = request.query_params.get('is_read')
    if is_read is not None:
        is_read = is_read.lower() == 'true'
        notifications = notifications.filter(is_read=is_read)
    
    limit = int(request.query_params.get('limit', 50))
    notifications = notifications[:limit]
    
    serializer = NotificationSerializer(notifications, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def unread_notifications(request):
    notifications = Notification.objects.filter(user=request.user, is_read=False)[:20]
    count = Notification.objects.filter(user=request.user, is_read=False).count()
    
    serializer = NotificationSerializer(notifications, many=True)
    return Response({'count': count, 'notifications': serializer.data})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_notification_read(request, pk):
    notification = get_object_or_404(Notification, pk=pk, user=request.user)
    notification.mark_as_read()
    return Response({'message': 'Notification marked as read'})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_all_notifications_read(request):
    notifications = Notification.objects.filter(user=request.user, is_read=False)
    count = notifications.count()
    
    for notification in notifications:
        notification.mark_as_read()
    
    return Response({'message': f'{count} notifications marked as read', 'count': count})


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_notification(request, pk):
    notification = get_object_or_404(Notification, pk=pk, user=request.user)
    notification.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_all_notifications(request):
    count = Notification.objects.filter(user=request.user).count()
    Notification.objects.filter(user=request.user).delete()
    return Response({'message': f'{count} notifications deleted'}, status=status.HTTP_204_NO_CONTENT)


def create_notification(user, type, title, message, scan=None, report=None):
    notification = Notification.objects.create(
        user=user,
        type=type,
        title=title,
        message=message,
        scan=scan,
        report=report
    )
    return notification


# ==================== SETTINGS VIEWS ====================

@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    user = request.user
    
    if request.method == 'GET':
        return Response(UserSerializer(user).data)
    
    elif request.method == 'PUT':
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    user = request.user
    current_password = request.data.get('current_password')
    new_password = request.data.get('new_password')
    
    if not user.check_password(current_password):
        return Response({'error': 'Current password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)
    
    user.set_password(new_password)
    user.save()
    return Response({'message': 'Password updated successfully'})


# ==================== SETTINGS VIEWS (ADD THESE) ====================

@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def notification_settings(request):
    """Get or update user notification settings"""
    try:
        settings, created = NotificationSetting.objects.get_or_create(user=request.user)
        
        if request.method == 'GET':
            return Response({
                'id': settings.id,
                'type': settings.type,
                'enabled': settings.enabled,
                'events': settings.events
            })
        
        elif request.method == 'PUT':
            data = request.data
            if 'type' in data:
                settings.type = data['type']
            if 'enabled' in data:
                settings.enabled = data['enabled']
            if 'events' in data:
                settings.events = data['events']
            settings.save()
            return Response({
                'id': settings.id,
                'type': settings.type,
                'enabled': settings.enabled,
                'events': settings.events
            })
            
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def scan_defaults(request):
    """Get or update user scan default settings"""
    try:
        defaults, created = ScanDefault.objects.get_or_create(user=request.user)
        
        if request.method == 'GET':
            return Response({
                'id': defaults.id,
                'scan_type': defaults.scan_type,
                'timeout': defaults.timeout,
                'max_retries': defaults.max_retries,
                'concurrent_scans': defaults.concurrent_scans,
                'auto_report': defaults.auto_report,
                'report_format': defaults.report_format,
                'notification_on_complete': defaults.notification_on_complete,
                'notification_on_failure': defaults.notification_on_failure,
                'excluded_paths': defaults.excluded_paths,
                'custom_headers': defaults.custom_headers,
                'cookies': defaults.cookies
            })
        
        elif request.method == 'PUT':
            data = request.data
            for field in ['scan_type', 'timeout', 'max_retries', 'concurrent_scans', 
                         'auto_report', 'report_format', 'notification_on_complete', 
                         'notification_on_failure', 'excluded_paths', 'custom_headers', 'cookies']:
                if field in data:
                    setattr(defaults, field, data[field])
            defaults.save()
            
            return Response({
                'id': defaults.id,
                'scan_type': defaults.scan_type,
                'timeout': defaults.timeout,
                'max_retries': defaults.max_retries,
                'concurrent_scans': defaults.concurrent_scans,
                'auto_report': defaults.auto_report,
                'report_format': defaults.report_format,
                'notification_on_complete': defaults.notification_on_complete,
                'notification_on_failure': defaults.notification_on_failure,
                'excluded_paths': defaults.excluded_paths,
                'custom_headers': defaults.custom_headers,
                'cookies': defaults.cookies
            })
            
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def team_members(request):
    """List and invite team members"""
    if request.method == 'GET':
        # Return empty list for now (implement when organization system is ready)
        return Response([])
    
    elif request.method == 'POST':
        # Return success for now
        return Response({'message': 'Invitation sent'}, status=status.HTTP_201_CREATED)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def remove_team_member(request, pk):
    """Remove team member"""
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def security_settings(request):
    """Get or update security settings"""
    try:
        settings, created = SecuritySetting.objects.get_or_create(user=request.user)
        
        if request.method == 'GET':
            return Response({
                'two_factor_enabled': settings.two_factor_enabled,
                'session_timeout': settings.session_timeout,
                'ip_whitelist': settings.ip_whitelist,
                'allowed_origins': settings.allowed_origins,
                'password_expiry_days': settings.password_expiry_days,
                'login_notifications': settings.login_notifications
            })
        
        elif request.method == 'PUT':
            data = request.data
            if 'two_factor_enabled' in data:
                settings.two_factor_enabled = data['two_factor_enabled']
            if 'session_timeout' in data:
                settings.session_timeout = data['session_timeout']
            if 'ip_whitelist' in data:
                settings.ip_whitelist = data['ip_whitelist']
            if 'allowed_origins' in data:
                settings.allowed_origins = data['allowed_origins']
            if 'password_expiry_days' in data:
                settings.password_expiry_days = data['password_expiry_days']
            if 'login_notifications' in data:
                settings.login_notifications = data['login_notifications']
            settings.save()
            
            return Response({
                'two_factor_enabled': settings.two_factor_enabled,
                'session_timeout': settings.session_timeout,
                'ip_whitelist': settings.ip_whitelist,
                'allowed_origins': settings.allowed_origins,
                'password_expiry_days': settings.password_expiry_days,
                'login_notifications': settings.login_notifications
            })
            
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ==================== API KEY VIEWS ====================

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def api_keys(request):
    if request.method == 'GET':
        keys = ApiKey.objects.filter(user=request.user)
        serializer = ApiKeySerializer(keys, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        name = request.data.get('name')
        permissions = request.data.get('permissions', 'read')
        
        if not name:
            return Response({'error': 'Name is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Handle permissions as string or array
        if isinstance(permissions, list):
            permissions = permissions[0] if permissions else 'read'
        
        raw_key = f"gsk_{secrets.token_urlsafe(32)}"
        prefix = raw_key[:8]
        hashed = hashlib.sha256(raw_key.encode()).hexdigest()
        
        api_key = ApiKey.objects.create(
            user=request.user,
            name=name,
            key=hashed,
            prefix=prefix,
            permissions=permissions
        )
        
        response_data = ApiKeySerializer(api_key).data
        response_data['key'] = raw_key
        
        create_notification(
            user=request.user,
            type='info',
            title='API Key Created',
            message=f'New API key "{name}" was created'
        )
        
        return Response(response_data, status=status.HTTP_201_CREATED)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def api_key_detail(request, pk):
    api_key = get_object_or_404(ApiKey, pk=pk, user=request.user)
    
    if request.method == 'GET':
        serializer = ApiKeySerializer(api_key)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        data = {
            'name': request.data.get('name', api_key.name),
            'permissions': request.data.get('permissions', api_key.permissions),
        }
        if isinstance(data['permissions'], list):
            data['permissions'] = data['permissions'][0] if data['permissions'] else 'read'
        
        serializer = ApiKeySerializer(api_key, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        api_key.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def regenerate_api_key(request, pk):
    old_key = get_object_or_404(ApiKey, pk=pk, user=request.user)
    
    raw_key = f"gsk_{secrets.token_urlsafe(32)}"
    prefix = raw_key[:8]
    hashed = hashlib.sha256(raw_key.encode()).hexdigest()
    
    new_key = ApiKey.objects.create(
        user=request.user,
        name=old_key.name,
        key=hashed,
        prefix=prefix,
        permissions=old_key.permissions
    )
    
    old_key.delete()
    
    response_data = ApiKeySerializer(new_key).data
    response_data['key'] = raw_key
    
    return Response(response_data, status=status.HTTP_201_CREATED)


# ==================== WEBHOOK VIEWS ====================

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def webhooks(request):
    if request.method == 'GET':
        webhooks = Webhook.objects.filter(user=request.user)
        serializer = WebhookSerializer(webhooks, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = WebhookSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def webhook_detail(request, pk):
    webhook = get_object_or_404(Webhook, pk=pk, user=request.user)
    
    if request.method == 'GET':
        serializer = WebhookSerializer(webhook)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = WebhookSerializer(webhook, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        webhook.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def test_webhook(request, pk):
    webhook = get_object_or_404(Webhook, pk=pk, user=request.user)
    
    test_payload = {
        'event': 'test',
        'timestamp': timezone.now().isoformat(),
        'data': {
            'message': 'This is a test webhook from GeniusGuard',
            'webhook_id': webhook.id,
            'url': webhook.url
        }
    }
    
    try:
        import requests
        response = requests.post(
            webhook.url,
            json=test_payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        return Response({'success': True, 'status_code': response.status_code})
    except Exception as e:
        return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def billing_info(request):
    billing = {
        'plan': 'free',
        'scans_used': Scan.objects.filter(created_by=request.user).count(),
        'scans_limit': 100,
        'next_billing': None,
        'payment_method': None,
        'invoices': []
    }
    return Response(billing)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def export_data(request):
    data = {
        'profile': UserSerializer(request.user).data,
        'scans': ScanSerializer(Scan.objects.filter(created_by=request.user), many=True).data,
        'vulnerabilities': VulnerabilitySerializer(Vulnerability.objects.filter(scan__created_by=request.user), many=True).data,
        'api_keys': ApiKeySerializer(ApiKey.objects.filter(user=request.user), many=True).data
    }
    
    response = Response(data, content_type='application/json')
    response['Content-Disposition'] = 'attachment; filename="geniusguard-export.json"'
    return response


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_account(request):
    user = request.user
    user.delete()
    return Response({'message': 'Account deleted'}, status=status.HTTP_204_NO_CONTENT)

# ==================== ADD THESE MISSING VIEW FUNCTIONS ====================

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def toggle_two_factor(request):
    """Toggle two-factor authentication for the user"""
    try:
        settings, created = SecuritySetting.objects.get_or_create(user=request.user)
        settings.two_factor_enabled = not settings.two_factor_enabled
        settings.save()
        
        return Response({
            'two_factor_enabled': settings.two_factor_enabled,
            'message': f'Two-factor authentication {"enabled" if settings.two_factor_enabled else "disabled"}'
        })
    except Exception as e:
        logger.error(f"Failed to toggle two-factor: {str(e)}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def regenerate_api_key(request, pk):
    """Regenerate an API key (create new, delete old)"""
    try:
        old_key = get_object_or_404(ApiKey, pk=pk, user=request.user)
        
        # Generate new key
        import secrets
        import hashlib
        
        raw_key = f"gsk_{secrets.token_urlsafe(32)}"
        prefix = raw_key[:8]
        hashed = hashlib.sha256(raw_key.encode()).hexdigest()
        
        new_key = ApiKey.objects.create(
            user=request.user,
            name=old_key.name,
            key=hashed,
            prefix=prefix,
            permissions=old_key.permissions
        )
        
        # Delete old key
        old_key.delete()
        
        response_data = ApiKeySerializer(new_key).data
        response_data['key'] = raw_key
        
        return Response(response_data, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def regenerate_api_key(request, pk):
    """Regenerate an API key (create new, delete old)"""
    try:
        old_key = get_object_or_404(ApiKey, pk=pk, user=request.user)
        
        # Generate new key
        import secrets
        import hashlib
        
        raw_key = f"gsk_{secrets.token_urlsafe(32)}"
        prefix = raw_key[:8]
        hashed = hashlib.sha256(raw_key.encode()).hexdigest()
        
        new_key = ApiKey.objects.create(
            user=request.user,
            name=old_key.name,
            key=hashed,
            prefix=prefix,
            permissions=old_key.permissions
        )
        
        # Delete old key
        old_key.delete()
        
        response_data = ApiKeySerializer(new_key).data
        response_data['key'] = raw_key
        
        return Response(response_data, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def test_webhook(request, pk):
    """Test a webhook by sending a test payload"""
    try:
        webhook = get_object_or_404(Webhook, pk=pk, user=request.user)
        
        test_payload = {
            'event': 'test',
            'timestamp': timezone.now().isoformat(),
            'data': {
                'message': 'This is a test webhook from GeniusGuard',
                'webhook_id': webhook.id,
                'url': webhook.url
            }
        }
        
        import requests
        response = requests.post(
            webhook.url,
            json=test_payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        webhook.last_triggered = timezone.now()
        webhook.last_response = response.status_code
        webhook.save()
        
        return Response({
            'success': True,
            'status_code': response.status_code,
            'message': 'Test webhook sent successfully'
        })
        
    except Exception as e:
        logger.error(f"Webhook test failed: {str(e)}")
        return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def purchase_deep_credits(request):
    """Purchase deep scan credits"""
    try:
        amount = request.data.get('amount', 1)
        credit, _ = DeepScanCredit.objects.get_or_create(user=request.user)
        credit.add_credits(amount)
        
        return Response({
            'message': f'Added {amount} credits',
            'credits_remaining': credit.credits_remaining
        })
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def subscribe_deep_scan(request):
    """Subscribe to deep scan plan"""
    try:
        plan = request.data.get('plan', 'pro')
        credit, _ = DeepScanCredit.objects.get_or_create(user=request.user)
        credit.subscription_tier = plan
        credit.subscription_expires = timezone.now() + timezone.timedelta(days=30)
        credit.save()
        
        return Response({
            'message': f'Subscribed to {plan} plan',
            'subscription_tier': credit.subscription_tier,
            'subscription_expires': credit.subscription_expires
        })
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_deep_scan_credits(request):
    """Get user's deep scan credits"""
    try:
        credit, _ = DeepScanCredit.objects.get_or_create(user=request.user)
        return Response({
            'credits_remaining': credit.credits_remaining,
            'total_credits_purchased': credit.total_credits_purchased,
            'subscription_tier': credit.subscription_tier,
            'subscription_expires': credit.subscription_expires
        })
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




# ==================== DEEP SCAN VIEWS ====================

@api_view(['POST'])
@authentication_classes([ExtensionAuthentication])
@permission_classes([IsAuthenticated])
def upload_deep_scan_session(request):
    user = request.user
    
    try:
        session_data = request.data
        session_id = session_data.get('sessionId', f"session_{secrets.token_urlsafe(16)}")
        
        session = DeepScanSession.objects.create(
            user=user,
            session_id=session_id,
            name=session_data.get('name', f"Deep Scan - {timezone.now().strftime('%Y-%m-%d %H:%M')}"),
            target=session_data.get('targetUrl', ''),
            data=session_data,
            start_time=timezone.now(),
            request_count=len(session_data.get('requests', [])),
            status='analyzing'
        )
        
        from .tasks import analyze_deep_session
        task = analyze_deep_session.delay(session.id)
        session.ai_task_id = task.id
        session.save()
        
        return Response({
            'session': DeepScanSessionSerializer(session).data,
            'message': 'Session uploaded successfully, analysis started',
            'task_id': task.id
        }, status=status.HTTP_202_ACCEPTED)
        
    except Exception as e:
        logger.error(f"Deep scan upload failed: {str(e)}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_deep_sessions(request):
    sessions = DeepScanSession.objects.filter(user=request.user)
    
    status_filter = request.query_params.get('status')
    if status_filter:
        sessions = sessions.filter(status=status_filter)
    
    limit = int(request.query_params.get('limit', 50))
    sessions = sessions[:limit]
    
    serializer = DeepScanSessionSerializer(sessions, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_deep_session(request, session_id):
    session = get_object_or_404(DeepScanSession, id=session_id, user=request.user)
    serializer = DeepScanSessionSerializer(session)
    return Response(serializer.data)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_deep_session(request, session_id):
    session = get_object_or_404(DeepScanSession, id=session_id, user=request.user)
    session.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_deep_findings(request, session_id):
    session = get_object_or_404(DeepScanSession, id=session_id, user=request.user)
    findings = session.findings.all()
    
    severity = request.query_params.get('severity')
    if severity:
        findings = findings.filter(severity=severity)
    
    finding_type = request.query_params.get('type')
    if finding_type:
        findings = findings.filter(finding_type=finding_type)
    
    serializer = DeepFindingSerializer(findings, many=True)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_deep_finding(request, finding_id):
    finding = get_object_or_404(DeepFinding, id=finding_id, session__user=request.user)
    
    status_val = request.data.get('status')
    if status_val:
        finding.status = status_val
    
    is_false_positive = request.data.get('is_false_positive')
    if is_false_positive is not None:
        finding.is_false_positive = is_false_positive
    
    finding.save()
    
    serializer = DeepFindingSerializer(finding)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_deep_scan_report(request, session_id):
    session = get_object_or_404(DeepScanSession, id=session_id, user=request.user)
    
    report_format = request.data.get('format', 'pdf')
    from .tasks import generate_deep_report
    task = generate_deep_report.delay(session.id, report_format)
    
    return Response({
        'task_id': task.id,
        'message': f'Report generation started as {report_format.upper()}'
    }, status=status.HTTP_202_ACCEPTED)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_deep_report(request, session_id):
    session = get_object_or_404(DeepScanSession, id=session_id, user=request.user)
    
    report_path = f'/tmp/deep_report_{session_id}.pdf'
    
    if os.path.exists(report_path):
        return FileResponse(
            open(report_path, 'rb'),
            as_attachment=True,
            filename=f'deep_scan_{session_id}.pdf'
        )
    
    return Response({'error': 'Report not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_deep_scan_credits(request):
    credit, _ = DeepScanCredit.objects.get_or_create(user=request.user)
    serializer = DeepScanCreditSerializer(credit)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def purchase_deep_credits(request):
    amount = request.data.get('amount', 1)
    
    credit, _ = DeepScanCredit.objects.get_or_create(user=request.user)
    credit.add_credits(amount)
    
    return Response({
        'message': f'Added {amount} credits',
        'credits_remaining': credit.credits_remaining
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def subscribe_deep_scan(request):
    plan = request.data.get('plan', 'pro')
    
    credit, _ = DeepScanCredit.objects.get_or_create(user=request.user)
    credit.subscription_tier = plan
    credit.subscription_expires = timezone.now() + timezone.timedelta(days=30)
    credit.save()
    
    return Response({
        'message': f'Subscribed to {plan} plan',
        'subscription_tier': credit.subscription_tier,
        'subscription_expires': credit.subscription_expires
    })


# ==================== EXTENSION VIEWS ====================

@api_view(['GET'])
@permission_classes([AllowAny])
def get_extension_id(request):
    return Response({
        'chrome_id': 'geniusguard-deepscan',
        'firefox_id': 'deepscan@geniusguard.com'
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def download_extension(request, browser):
    extension_files = {
        'chrome': os.path.join(settings.BASE_DIR, 'extensions', 'geniusguard-chrome.zip'),
        'firefox': os.path.join(settings.BASE_DIR, 'extensions', 'geniusguard-firefox.xpi')
    }
    
    file_path = extension_files.get(browser.lower())
    
    if not file_path or not os.path.exists(file_path):
        return Response({'error': f'Extension file not found for {browser}'}, status=status.HTTP_404_NOT_FOUND)
    
    filename = f'geniusguard-deepscan-{browser}.{"zip" if browser == "chrome" else "xpi"}'
    
    return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=filename)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def extension_status(request):
    return Response({'installed': False, 'connected': False, 'version': None})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def extension_connected(request):
    logger.info(f"Extension connected for user {request.user.email}")
    return Response({'status': 'connected', 'message': 'Extension successfully connected'})