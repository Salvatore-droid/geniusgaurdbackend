# base/authentication.py
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.utils import timezone
import hashlib
from .models import ApiKey

class ExtensionAuthentication(BaseAuthentication):
    """Authentication class specifically for browser extensions"""
    
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Bearer '):
            return None
        
        key = auth_header.replace('Bearer ', '')
        
        try:
            # Hash the key
            hashed = hashlib.sha256(key.encode()).hexdigest()
            
            # Find the key
            api_key = ApiKey.objects.select_related('user').get(key=hashed)
            
            # Check expiration
            if api_key.expires_at and api_key.expires_at < timezone.now():
                raise exceptions.AuthenticationFailed('API key expired')
            
            # Record usage
            api_key.last_used = timezone.now()
            api_key.use_count += 1
            api_key.last_used_ip = request.META.get('REMOTE_ADDR')
            api_key.save()
            
            return (api_key.user, api_key)
            
        except ApiKey.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid API key')