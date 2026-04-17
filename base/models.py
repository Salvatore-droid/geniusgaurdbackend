from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Scan(models.Model):
    SCAN_TYPES = [
        ('quick', 'Quick Scan'),
        ('deep', 'Deep Scan'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    target = models.URLField(max_length=500)
    type = models.CharField(max_length=10, choices=SCAN_TYPES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    progress = models.IntegerField(default=0)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans')
    
    # Fix: Separate fields for duration and task ID
    scan_duration = models.DurationField(null=True, blank=True)  # For actual duration
    task_id = models.CharField(max_length=255, null=True, blank=True)  # For Celery task ID
    error_message = models.TextField(blank=True)
    metadata = models.JSONField(null=True, blank=True)  # Store tool results and scan metadata
    
    class Meta:
        ordering = ['-start_time']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['created_by', '-start_time']),
        ]
    
    def __str__(self):
        return f"{self.target} - {self.type} - {self.status}"
    
    def save(self, *args, **kwargs):
        # Calculate duration when scan completes
        if self.status == 'completed' and self.end_time and self.start_time:
            self.scan_duration = self.end_time - self.start_time
        super().save(*args, **kwargs)

class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('fixed', 'Fixed'),
        ('false_positive', 'False Positive'),
        ('accepted', 'Accepted Risk'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    name = models.CharField(max_length=255)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    description = models.TextField()
    remediation = models.TextField(blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    cve_id = models.CharField(max_length=20, blank=True)  # This exists
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='open')
    affected_component = models.CharField(max_length=255, blank=True)
    proof_of_concept = models.TextField(blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    due_date = models.DateField(null=True, blank=True)
    
    # Add these missing fields
    cwe_id = models.CharField(max_length=20, blank=True, default='')  # Add this
    metadata = models.JSONField(null=True, blank=True)  # Add this
    evidence = models.TextField(blank=True, default='')  # Add this if missing
    
    class Meta:
        ordering = ['-severity', '-cvss_score']
        indexes = [
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
            models.Index(fields=['scan', 'severity']),
        ]
    
    def __str__(self):
        return f"{self.name} - {self.severity}"

class ScheduledScan(models.Model):
    FREQUENCY_CHOICES = [
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('custom', 'Custom'),  # Add this
    ]
    
    name = models.CharField(max_length=255)
    target = models.URLField(max_length=500)
    scan_type = models.CharField(max_length=10, choices=Scan.SCAN_TYPES)
    frequency = models.CharField(max_length=10, choices=FREQUENCY_CHOICES)
    next_run = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    
    # Add these fields
    last_run = models.DateTimeField(null=True, blank=True)
    last_run_status = models.CharField(max_length=10, choices=Scan.STATUS_CHOICES, null=True, blank=True)
    cron_expression = models.CharField(max_length=100, blank=True)  # For custom schedules
    notification_email = models.EmailField(blank=True)  # Send results to email
    
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scheduled_scans')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['next_run']
    
    def __str__(self):
        return f"{self.name} - {self.frequency}"

class Report(models.Model):
    REPORT_TYPES = [
        ('pdf', 'PDF'),
        ('csv', 'CSV'),
        ('json', 'JSON'),
        ('html', 'HTML'),  # Add this
    ]
    
    REPORT_FORMATS = [  # Add this
        ('executive', 'Executive Summary'),
        ('detailed', 'Detailed Report'),
        ('technical', 'Technical Report'),
        ('compliance', 'Compliance Report'),
    ]
    
    name = models.CharField(max_length=255)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='reports', null=True, blank=True)
    report_type = models.CharField(max_length=10, choices=REPORT_TYPES)
    file = models.FileField(upload_to='reports/')
    
    # Add these fields
    format = models.CharField(max_length=20, choices=REPORT_FORMATS, default='detailed')
    date_range_start = models.DateTimeField(null=True, blank=True)
    date_range_end = models.DateTimeField(null=True, blank=True)
    include_remediation = models.BooleanField(default=True)
    include_evidence = models.BooleanField(default=False)
    generated_at = models.DateTimeField(auto_now_add=True, null=True)
    
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    
    def __str__(self):
        return f"{self.name} - {self.created_at}"

class ThreatIntelligence(models.Model):
    THREAT_TYPES = [
        ('cve', 'CVE'),
        ('exploit', 'Exploit'),
        ('malware', 'Malware'),
        ('phishing', 'Phishing'),
        ('ransomware', 'Ransomware'),  # Add this
        ('zero_day', 'Zero Day'),       # Add this
        ('apt', 'APT'),                  # Add this
    ]
    
    CONFIDENCE_LEVELS = [  # Add this
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('confirmed', 'Confirmed'),
    ]
    
    title = models.CharField(max_length=255)
    threat_type = models.CharField(max_length=20, choices=THREAT_TYPES)  # Increased max_length
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=Vulnerability.SEVERITY_CHOICES)
    affected_software = models.CharField(max_length=255, blank=True)
    published_date = models.DateField()
    reference_urls = models.JSONField(default=list)
    
    # Add these fields
    confidence = models.CharField(max_length=20, choices=CONFIDENCE_LEVELS, default='medium')
    cve_id = models.CharField(max_length=20, blank=True)  # For CVE mapping
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=100, blank=True)
    affected_versions = models.JSONField(default=list)  # List of affected versions
    patches_available = models.BooleanField(default=False)
    patch_urls = models.JSONField(default=list)
    exploit_available = models.BooleanField(default=False)
    exploit_urls = models.JSONField(default=list)
    mitigation_steps = models.TextField(blank=True)
    tags = models.JSONField(default=list)  # For categorization
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-published_date']
        indexes = [
            models.Index(fields=['threat_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['-published_date']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.threat_type}"



class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('scan_complete', 'Scan Complete'),
        ('scan_failed', 'Scan Failed'),
        ('critical_finding', 'Critical Finding'),
        ('high_finding', 'High Finding'),
        ('schedule_run', 'Scheduled Scan Run'),
        ('report_generated', 'Report Generated'),
        ('info', 'Information'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=255)
    message = models.TextField()
    scan = models.ForeignKey('Scan', on_delete=models.SET_NULL, null=True, blank=True, related_name='notifications')
    report = models.ForeignKey('Report', on_delete=models.SET_NULL, null=True, blank=True, related_name='notifications')
    
    # Status fields
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['user', 'is_read']),
        ]
    
    def __str__(self):
        return f"{self.user.email} - {self.title}"
    
    def mark_as_read(self):
        self.is_read = True
        self.read_at = timezone.now()
        self.save()




# ==================== DEEP SCAN MODELS ====================

class DeepScanSession(models.Model):
    """Recorded browser session for deep analysis"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('analyzing', 'Analyzing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='deep_sessions')
    session_id = models.CharField(max_length=100, unique=True)  # Generated by extension
    name = models.CharField(max_length=255, blank=True)
    target = models.URLField(max_length=500, blank=True)  # Main target URL
    
    # Session data
    data = models.JSONField()  # Full session data (requests, responses, actions)
    har_file = models.FileField(upload_to='deep_sessions/har/', null=True, blank=True)
    dom_snapshots = models.JSONField(default=list, blank=True)  # DOM snapshots at key points
    
    # Metadata
    start_time = models.DateTimeField()
    end_time = models.DateTimeField(null=True, blank=True)
    duration = models.IntegerField(null=True, blank=True)  # In seconds
    request_count = models.IntegerField(default=0)
    unique_urls = models.JSONField(default=list, blank=True)
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    progress = models.IntegerField(default=0)  # Analysis progress 0-100
    error_message = models.TextField(blank=True)
    
    # Analysis results
    findings_count = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    
    # AI processing
    ai_task_id = models.CharField(max_length=255, null=True, blank=True)
    ai_analysis_time = models.FloatField(null=True, blank=True)  # In seconds
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['session_id']),
        ]
    
    def __str__(self):
        return f"{self.name or self.session_id} - {self.user.email}"
    
    def calculate_duration(self):
        if self.end_time and self.start_time:
            self.duration = int((self.end_time - self.start_time).total_seconds())
            self.save()
    
    def update_severity_counts(self):
        """Update severity counts from findings"""
        findings = self.findings.all()
        self.findings_count = findings.count()
        self.critical_count = findings.filter(severity='critical').count()
        self.high_count = findings.filter(severity='high').count()
        self.medium_count = findings.filter(severity='medium').count()
        self.low_count = findings.filter(severity='low').count()
        self.info_count = findings.filter(severity='info').count()
        self.save()


class DeepFinding(models.Model):
    """Findings from deep scan analysis"""
    
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    FINDING_TYPES = [
        ('business_logic', 'Business Logic Flaw'),
        ('authentication', 'Authentication Issue'),
        ('authorization', 'Authorization Flaw'),
        ('xss', 'Cross-Site Scripting'),
        ('sqli', 'SQL Injection'),
        ('idor', 'Insecure Direct Object Reference'),
        ('session', 'Session Management'),
        ('api', 'API Security'),
        ('race_condition', 'Race Condition'),
        ('other', 'Other'),
    ]
    
    session = models.ForeignKey(DeepScanSession, on_delete=models.CASCADE, related_name='findings')
    finding_type = models.CharField(max_length=30, choices=FINDING_TYPES)
    name = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    cvss_score = models.FloatField(null=True, blank=True)
    
    # Location in the session
    url = models.URLField(max_length=2000, blank=True)
    method = models.CharField(max_length=10, blank=True)  # HTTP method
    parameter = models.CharField(max_length=255, blank=True)  # Affected parameter
    request_id = models.IntegerField(null=True, blank=True)  # Index in session requests
    
    # Evidence
    evidence = models.TextField(blank=True)
    screenshot = models.ImageField(upload_to='deep_screenshots/', null=True, blank=True)
    har_snippet = models.JSONField(null=True, blank=True)  # Relevant request/response
    
    # Remediation
    remediation = models.TextField(blank=True)
    references = models.JSONField(default=list, blank=True)
    
    # AI analysis
    ai_confidence = models.FloatField(default=0.0)  # 0-1 confidence score
    ai_reasoning = models.TextField(blank=True)  # Why AI flagged this
    
    # Status
    status = models.CharField(max_length=20, choices=Vulnerability.STATUS_CHOICES, default='open')
    is_false_positive = models.BooleanField(default=False)
    
    # Timestamps
    discovered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-severity', '-cvss_score']
        indexes = [
            models.Index(fields=['session', 'severity']),
            models.Index(fields=['finding_type']),
        ]
    
    def __str__(self):
        return f"{self.name} - {self.severity}"


class DeepScanCredit(models.Model):
    """Credit system for deep scans"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='deep_credits')
    credits_remaining = models.IntegerField(default=0)
    total_credits_purchased = models.IntegerField(default=0)
    
    # Stripe integration
    stripe_customer_id = models.CharField(max_length=255, blank=True)
    stripe_subscription_id = models.CharField(max_length=255, blank=True)
    
    # Subscription info
    subscription_tier = models.CharField(max_length=50, default='free')  # free, pro, enterprise
    subscription_expires = models.DateTimeField(null=True, blank=True)
    
    # Tracking
    last_purchase_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def has_credits(self, required=1):
        return self.credits_remaining >= required
    
    def use_credit(self):
        if self.credits_remaining > 0:
            self.credits_remaining -= 1
            self.save()
            return True
        return False
    
    def add_credits(self, amount):
        self.credits_remaining += amount
        self.total_credits_purchased += amount
        self.last_purchase_date = timezone.now()
        self.save()



# Add to base/models.py after your existing models

class ApiKey(models.Model):
    """API keys for programmatic access and extensions"""
    
    PERMISSION_CHOICES = [
        ('read', 'Read Only'),
        ('read_write', 'Read & Write'),
        ('admin', 'Admin'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    name = models.CharField(max_length=100)
    key = models.CharField(max_length=64, unique=True)  # Hashed key
    prefix = models.CharField(max_length=8)  # First 8 chars for identification
    
    permissions = models.CharField(max_length=20, choices=PERMISSION_CHOICES, default='read')
    
    # Tracking
    last_used = models.DateTimeField(null=True, blank=True)
    last_used_ip = models.GenericIPAddressField(null=True, blank=True)
    use_count = models.IntegerField(default=0)
    
    # Expiration
    expires_at = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['key']),
            models.Index(fields=['prefix']),
        ]
    
    def __str__(self):
        return f"{self.name} - {self.user.email}"
    
    def is_valid(self):
        """Check if key is valid and not expired"""
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return True
    
    def record_usage(self, ip=None):
        """Record API key usage"""
        self.last_used = timezone.now()
        self.use_count += 1
        if ip:
            self.last_used_ip = ip
        self.save()


# Add to base/models.py after your existing models

class Webhook(models.Model):
    """Webhook configuration for sending notifications"""
    
    WEBHOOK_EVENTS = [
        ('scan_complete', 'Scan Complete'),
        ('scan_failed', 'Scan Failed'),
        ('critical_finding', 'Critical Finding'),
        ('high_finding', 'High Finding'),
        ('report_generated', 'Report Generated'),
        ('schedule_run', 'Scheduled Scan Run'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webhooks')
    url = models.URLField(max_length=500)
    events = models.JSONField(default=list)  # List of events to trigger webhook
    secret = models.CharField(max_length=255, blank=True)  # Optional secret for signing
    
    # Status
    enabled = models.BooleanField(default=True)
    
    # Tracking
    last_triggered = models.DateTimeField(null=True, blank=True)
    last_response = models.IntegerField(null=True, blank=True)  # HTTP status code
    failure_count = models.IntegerField(default=0)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['enabled']),
        ]
    
    def __str__(self):
        return f"{self.url} - {self.user.email}"
    
    def trigger(self, event_type, payload):
        """Trigger the webhook with a payload"""
        import requests
        import json
        import hmac
        import hashlib
        from django.utils import timezone
        
        headers = {
            'Content-Type': 'application/json',
            'X-Webhook-Event': event_type,
            'X-Webhook-ID': str(self.id),
        }
        
        # Add signature if secret exists
        if self.secret:
            signature = hmac.new(
                self.secret.encode(),
                json.dumps(payload).encode(),
                hashlib.sha256
            ).hexdigest()
            headers['X-Webhook-Signature'] = signature
        
        try:
            response = requests.post(
                self.url,
                json=payload,
                headers=headers,
                timeout=10
            )
            
            self.last_triggered = timezone.now()
            self.last_response = response.status_code
            if response.status_code >= 400:
                self.failure_count += 1
            else:
                self.failure_count = 0
            self.save()
            
            return response
            
        except Exception as e:
            self.last_triggered = timezone.now()
            self.last_response = None
            self.failure_count += 1
            self.save()
            raise e



# Add to base/models.py after existing models

class Organization(models.Model):
    """Team organization model"""
    name = models.CharField(max_length=255)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_organizations')
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name


class TeamMember(models.Model):
    """Team member model"""
    ROLE_CHOICES = [
        ('owner', 'Owner'),
        ('admin', 'Admin'),
        ('member', 'Member'),
        ('viewer', 'Viewer'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('pending', 'Pending'),
        ('inactive', 'Inactive'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='team_memberships')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='members')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='member')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    invited_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='invited_members')
    joined_at = models.DateTimeField(auto_now_add=True)
    last_active = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ['user', 'organization']
    
    def __str__(self):
        return f"{self.user.email} - {self.organization.name}"


class TeamInvitation(models.Model):
    """Team invitation model"""
    email = models.EmailField()
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='invitations')
    role = models.CharField(max_length=20, choices=TeamMember.ROLE_CHOICES, default='member')
    invited_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_invitations')
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"Invitation for {self.email} to {self.organization.name}"


class SecuritySetting(models.Model):
    """User security settings"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='security_settings')
    two_factor_enabled = models.BooleanField(default=False)
    session_timeout = models.IntegerField(default=30)  # minutes
    password_expiry_days = models.IntegerField(default=90)
    login_notifications = models.BooleanField(default=True)
    ip_whitelist = models.JSONField(default=list)
    allowed_origins = models.JSONField(default=list)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Security settings for {self.user.email}"


class NotificationSetting(models.Model):
    """User notification settings"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='notification_settings')
    type = models.CharField(max_length=20, default='email')
    enabled = models.BooleanField(default=True)
    events = models.JSONField(default=dict)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Notification settings for {self.user.email}"


class ScanDefault(models.Model):
    """User scan default settings"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='scan_defaults')
    scan_type = models.CharField(max_length=10, default='quick')
    timeout = models.IntegerField(default=300)
    max_retries = models.IntegerField(default=3)
    concurrent_scans = models.IntegerField(default=1)
    auto_report = models.BooleanField(default=False)
    report_format = models.CharField(max_length=10, default='pdf')
    notification_on_complete = models.BooleanField(default=True)
    notification_on_failure = models.BooleanField(default=True)
    excluded_paths = models.JSONField(default=list)
    custom_headers = models.JSONField(default=dict)
    cookies = models.JSONField(default=dict)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Scan defaults for {self.user.email}"



# ==================== ADD TO base/models.py ====================
# Add these models to your existing models.py

import secrets
import hashlib
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class AuthorizedTarget(models.Model):
    """
    Represents a domain/IP that a user has proven they own or have
    written authorization to test. No scan can run without this record
    existing and being in 'verified' status.
    """
    VERIFICATION_METHODS = [
        ('dns_txt',   'DNS TXT Record'),
        ('file',      'Verification File'),
        ('meta_tag',  'HTML Meta Tag'),
    ]
    STATUS_CHOICES = [
        ('pending',    'Pending Verification'),
        ('verified',   'Verified'),
        ('failed',     'Verification Failed'),
        ('revoked',    'Revoked'),
        ('expired',    'Expired'),
    ]

    user                 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='authorized_targets')
    domain               = models.CharField(max_length=255)                        # e.g. "zoeestate.com"
    full_target          = models.URLField(max_length=500)                         # full URL scope
    verification_method  = models.CharField(max_length=20, choices=VERIFICATION_METHODS, default='dns_txt')
    verification_token   = models.CharField(max_length=128, unique=True)           # the token they must place
    status               = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    # Authorization document upload (optional but recommended)
    authorization_document = models.FileField(upload_to='auth_docs/', null=True, blank=True)
    authorization_notes    = models.TextField(blank=True)                          # e.g. "I am the owner"

    # Timestamps
    created_at      = models.DateTimeField(auto_now_add=True)
    verified_at     = models.DateTimeField(null=True, blank=True)
    expires_at      = models.DateTimeField(null=True, blank=True)                  # optional expiry
    last_checked_at = models.DateTimeField(null=True, blank=True)

    # Verification attempt tracking
    verification_attempts = models.IntegerField(default=0)
    last_verification_error = models.TextField(blank=True)

    class Meta:
        unique_together = ('user', 'domain')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} → {self.domain} ({self.status})"

    def save(self, *args, **kwargs):
        # Auto-generate a unique verification token on first save
        if not self.verification_token:
            self.verification_token = f"geniusguard-verify-{secrets.token_urlsafe(32)}"
        super().save(*args, **kwargs)

    @property
    def is_valid(self):
        """Returns True only if verified and not expired"""
        if self.status != 'verified':
            return False
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return True

    def get_dns_txt_record(self):
        """The exact TXT record value the user must add to their DNS"""
        return f"geniusguard-site-verification={self.verification_token}"

    def get_file_path(self):
        """The path where the verification file must be served"""
        return f"/.well-known/geniusguard-verification.txt"

    def get_file_content(self):
        """The content of the verification file"""
        return self.verification_token

    def get_meta_tag(self):
        """The meta tag the user must add to their HTML <head>"""
        return f'<meta name="geniusguard-site-verification" content="{self.verification_token}">'


class ScanAuthorization(models.Model):
    """
    Links a Scan to the AuthorizedTarget that permitted it.
    Every scan must have one of these — enforced at scan creation.
    """
    scan              = models.OneToOneField('Scan', on_delete=models.CASCADE, related_name='authorization')
    authorized_target = models.ForeignKey(AuthorizedTarget, on_delete=models.PROTECT, related_name='scans')
    authorized_at     = models.DateTimeField(auto_now_add=True)
    scope_confirmed   = models.BooleanField(default=True)

    def __str__(self):
        return f"Auth for scan {self.scan.id} on {self.authorized_target.domain}"