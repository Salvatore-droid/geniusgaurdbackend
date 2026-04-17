# base/serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from .models import *
import secrets
import hashlib


class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'full_name', 'date_joined', 'last_login']
        read_only_fields = ['date_joined', 'last_login']
    
    def get_full_name(self, obj):
        if obj.first_name and obj.last_name:
            return f"{obj.first_name} {obj.last_name}"
        elif obj.first_name:
            return obj.first_name
        return obj.email


class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['email', 'password', 'confirm_password', 'first_name', 'last_name']
    
    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        if User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError({"email": "User with this email already exists."})
        
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('confirm_password')
        validated_data['username'] = validated_data['email']
        
        user = User.objects.create_user(
            username=validated_data['email'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)


class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = '__all__'


class ScanSerializer(serializers.ModelSerializer):
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    created_by_email = serializers.CharField(source='created_by.email', read_only=True)
    
    class Meta:
        model = Scan
        fields = ['id', 'target', 'type', 'status', 'progress', 'start_time', 'end_time', 
                 'created_by', 'created_by_email', 'vulnerabilities', 'metadata', 'task_id']
        read_only_fields = ['created_by', 'start_time']


class ScheduledScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScheduledScan
        fields = '__all__'
        read_only_fields = ['created_by', 'created_at', 'updated_at']


class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = '__all__'
        read_only_fields = ['created_by', 'created_at', 'generated_at']


class ThreatIntelligenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatIntelligence
        fields = '__all__'


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = '__all__'


class ApiKeySerializer(serializers.ModelSerializer):
    key_preview = serializers.SerializerMethodField()
    
    class Meta:
        model = ApiKey
        fields = ['id', 'name', 'key', 'prefix', 'permissions', 'last_used', 
                  'expires_at', 'created_at', 'key_preview']
        read_only_fields = ['key', 'prefix', 'created_at', 'last_used']
    
    def get_key_preview(self, obj):
        if obj.prefix:
            return f"{obj.prefix}...{obj.key[-4:]}" if len(obj.key) > 12 else obj.prefix
        return None
    
    def to_representation(self, instance):
        data = super().to_representation(instance)
        if 'key' in data and data['key'] and len(data['key']) > 12:
            data['key'] = f"{data['key'][:8]}...{data['key'][-4:]}"
        return data


class WebhookSerializer(serializers.ModelSerializer):
    class Meta:
        model = Webhook
        fields = ['id', 'url', 'events', 'secret', 'enabled', 'last_triggered', 
                  'last_response', 'failure_count', 'created_at', 'updated_at']
        read_only_fields = ['last_triggered', 'last_response', 'failure_count', 'created_at', 'updated_at']


class DeepScanSessionSerializer(serializers.ModelSerializer):
    findings = serializers.SerializerMethodField()
    
    class Meta:
        model = DeepScanSession
        fields = ['id', 'session_id', 'name', 'target', 'start_time', 'end_time', 
                  'duration', 'request_count', 'status', 'progress', 'error_message',
                  'findings_count', 'critical_count', 'high_count', 'medium_count',
                  'low_count', 'info_count', 'findings', 'created_at']
        read_only_fields = ['user', 'created_at']
    
    def get_findings(self, obj):
        from .serializers import DeepFindingSerializer
        return DeepFindingSerializer(obj.findings.all(), many=True).data


class DeepFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeepFinding
        fields = '__all__'
        read_only_fields = ['discovered_at', 'updated_at']


class DeepScanCreditSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeepScanCredit
        fields = ['credits_remaining', 'total_credits_purchased', 'subscription_tier', 'subscription_expires']


# ==================== ADD TO base/serializers.py ====================

from rest_framework import serializers
from .models import AuthorizedTarget, ScanAuthorization


class AuthorizedTargetSerializer(serializers.ModelSerializer):
    dns_txt_record  = serializers.SerializerMethodField()
    file_path       = serializers.SerializerMethodField()
    file_content    = serializers.SerializerMethodField()
    meta_tag        = serializers.SerializerMethodField()
    is_valid        = serializers.SerializerMethodField()

    class Meta:
        model  = AuthorizedTarget
        fields = [
            'id', 'domain', 'full_target', 'verification_method',
            'verification_token', 'status', 'authorization_notes',
            'created_at', 'verified_at', 'expires_at', 'last_checked_at',
            'verification_attempts', 'last_verification_error',
            'dns_txt_record', 'file_path', 'file_content', 'meta_tag',
            'is_valid',
        ]
        read_only_fields = [
            'verification_token', 'status', 'verified_at',
            'last_checked_at', 'verification_attempts', 'last_verification_error',
        ]

    def get_dns_txt_record(self, obj):
        return obj.get_dns_txt_record()

    def get_file_path(self, obj):
        return obj.get_file_path()

    def get_file_content(self, obj):
        return obj.get_file_content()

    def get_meta_tag(self, obj):
        return obj.get_meta_tag()

    def get_is_valid(self, obj):
        return obj.is_valid


class ScanAuthorizationSerializer(serializers.ModelSerializer):
    authorized_target = AuthorizedTargetSerializer(read_only=True)

    class Meta:
        model  = ScanAuthorization
        fields = ['id', 'authorized_target', 'authorized_at', 'scope_confirmed']