# base/urls.py
from django.urls import path
from . import views
from . import views_authorization

urlpatterns = [
    # Authentication URLs
    path('auth/csrf/', views.get_csrf_token, name='csrf'),
    path('auth/signup/', views.signup_view, name='signup'),
    path('auth/login/', views.login_view, name='login'),
    path('auth/logout/', views.logout_view, name='logout'),
    path('auth/user/', views.user_view, name='user'),
    
    # Social Auth URLs
    path('auth/google/', views.google_login, name='google-login'),
    path('auth/google/callback/', views.google_callback, name='google-callback'),
    path('auth/github/', views.github_login, name='github-login'),
    path('auth/github/callback/', views.github_callback, name='github-callback'),
    
    # Dashboard URLs
    path('dashboard/stats/', views.dashboard_stats, name='dashboard-stats'),
    path('dashboard/recent-scans/', views.recent_scans, name='recent-scans'),
    path('dashboard/vulnerability-trends/', views.vulnerability_trends, name='vulnerability-trends'),
    
    # Scan URLs
    path('scans/', views.scan_list, name='scan-list'),
    path('scans/<int:pk>/', views.scan_detail, name='scan-detail'),
    path('scans/<int:pk>/vulnerabilities/', views.scan_vulnerabilities, name='scan-vulnerabilities'),
    path('scans/quick/', views.quick_scan, name='quick-scan'),
    path('scans/deep/', views.deep_scan, name='deep-scan'),
    path('scans/<int:pk>/status/', views.scan_status, name='scan-status'),
    
    # Vulnerability URLs
    path('vulnerabilities/', views.vulnerability_list, name='vulnerability-list'),
    path('vulnerabilities/<int:pk>/', views.vulnerability_detail, name='vulnerability-detail'),
    
    # Scheduled Scans
    path('scheduled-scans/', views.scheduled_scan_list, name='scheduled-scan-list'),
    path('scheduled-scans/<int:pk>/', views.scheduled_scan_detail, name='scheduled-scan-detail'),
    
    # Reports
    path('reports/', views.report_list, name='report-list'),
    path('reports/<int:pk>/', views.report_detail, name='report-detail'),
    path('reports/generate/', views.generate_report, name='generate-report'),
    path('reports/generate-pdf/', views.generate_pdf_report, name='generate-pdf'),
    
    # Threat Intelligence
    path('threat-intelligence/', views.threat_intelligence_list, name='threat-intelligence-list'),
    path('threat-intelligence/stats/', views.threat_intelligence_stats, name='threat-intelligence-stats'),
    path('threat-intelligence/<int:pk>/', views.threat_intelligence_detail, name='threat-intelligence-detail'),
    
    # Notification URLs
    path('notifications/', views.notification_list, name='notification-list'),
    path('notifications/unread/', views.unread_notifications, name='unread-notifications'),
    path('notifications/<int:pk>/read/', views.mark_notification_read, name='mark-notification-read'),
    path('notifications/read-all/', views.mark_all_notifications_read, name='mark-all-read'),
    path('notifications/<int:pk>/delete/', views.delete_notification, name='delete-notification'),
    path('notifications/delete-all/', views.delete_all_notifications, name='delete-all-notifications'),

    # Settings endpoints
    path('settings/profile/', views.user_profile, name='user-profile'),
    path('settings/change-password/', views.change_password, name='change-password'),
    path('settings/api-keys/', views.api_keys, name='api-keys'),
    path('settings/api-keys/<int:pk>/', views.api_key_detail, name='api-key-detail'),
    path('settings/api-keys/<int:pk>/regenerate/', views.regenerate_api_key, name='regenerate-api-key'),
    path('settings/notifications/', views.notification_settings, name='notification-settings'),
    path('settings/scan-defaults/', views.scan_defaults, name='scan-defaults'),
    path('settings/team/', views.team_members, name='team-members'),
    path('settings/team/<int:pk>/', views.remove_team_member, name='remove-team-member'),
    path('settings/security/', views.security_settings, name='security-settings'),
    path('settings/security/two-factor/toggle/', views.toggle_two_factor, name='toggle-two-factor'),
    path('settings/billing/', views.billing_info, name='billing-info'),
    path('settings/webhooks/', views.webhooks, name='webhooks'),
    path('settings/webhooks/<int:pk>/', views.webhook_detail, name='webhook-detail'),
    path('settings/webhooks/<int:pk>/test/', views.test_webhook, name='test-webhook'),
    path('settings/export-data/', views.export_data, name='export-data'),
    path('auth/delete-account/', views.delete_account, name='delete-account'),

    # Deep Scan URLs
    path('deep-scan/upload/', views.upload_deep_scan_session, name='deep-scan-upload'),
    path('deep-scan/sessions/', views.list_deep_sessions, name='deep-scan-sessions'),
    path('deep-scan/sessions/<int:session_id>/', views.get_deep_session, name='deep-scan-detail'),
    path('deep-scan/sessions/<int:session_id>/delete/', views.delete_deep_session, name='deep-scan-delete'),
    path('deep-scan/sessions/<int:session_id>/findings/', views.get_deep_findings, name='deep-scan-findings'),
    path('deep-scan/findings/<int:finding_id>/', views.update_deep_finding, name='deep-finding-update'),
    path('deep-scan/sessions/<int:session_id>/report/', views.generate_deep_scan_report, name='deep-scan-report'),
    path('deep-scan/sessions/<int:session_id>/download/', views.download_deep_report, name='deep-scan-download'),

    # Credit/Subscription URLs
    path('deep-scan/credits/', views.get_deep_scan_credits, name='deep-scan-credits'),
    path('deep-scan/credits/purchase/', views.purchase_deep_credits, name='deep-scan-purchase'),
    path('deep-scan/subscribe/', views.subscribe_deep_scan, name='deep-scan-subscribe'),

    # Extension URLs
    path('extensions/extension-id/', views.get_extension_id, name='extension-id'),
    path('extensions/<str:browser>/download/', views.download_extension, name='download-extension'),
    path('deep-scan/extension-status/', views.extension_status, name='extension-status'),
    path('deep-scan/extension-connect/', views.extension_connected, name='extension-connect'),



    path('authorized-targets/',
         views_authorization.authorized_targets,
         name='authorized-targets'),
 
    # Trigger verification check for a registered target
    path('authorized-targets/<int:pk>/verify/',
         views_authorization.verify_target,
         name='verify-target'),
 
    # Get authorization status
    path('authorized-targets/<int:pk>/status/',
         views_authorization.authorization_status,
         name='authorization-status'),
 
    # Revoke an authorization
    path('authorized-targets/<int:pk>/revoke/',
         views_authorization.revoke_authorization,
         name='revoke-authorization'),
 
    # Quick check: is this URL authorized?
    path('authorized-targets/check/',
         views_authorization.check_target_authorized,
         name='check-target-authorized'),
]