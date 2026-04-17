# base/views_authorization.py
"""
API views for target authorization management.
These endpoints let users register domains, get verification instructions,
trigger verification checks, and see their authorized targets.
"""

import asyncio
import logging
from urllib.parse import urlparse

from django.utils import timezone
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import AuthorizedTarget
from .serializers import *
from .authorization import AuthorizationVerifier, extract_domain

logger = logging.getLogger(__name__)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def authorized_targets(request):
    """
    GET  — list all authorization records for the current user
    POST — register a new domain for authorization
    """
    if request.method == 'GET':
        targets = AuthorizedTarget.objects.filter(user=request.user).order_by('-created_at')
        serializer = AuthorizedTargetSerializer(targets, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        target_url = request.data.get('target_url', '').strip()
        method     = request.data.get('verification_method', 'dns_txt')
        notes      = request.data.get('authorization_notes', '')

        if not target_url:
            return Response(
                {'error': 'target_url is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        domain = extract_domain(target_url)

        if not domain:
            return Response(
                {'error': 'Could not extract a valid domain from the URL'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if method not in ['dns_txt', 'file', 'meta_tag']:
            return Response(
                {'error': 'verification_method must be one of: dns_txt, file, meta_tag'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if already exists for this user+domain
        existing = AuthorizedTarget.objects.filter(user=request.user, domain=domain).first()
        if existing:
            if existing.status == 'verified' and existing.is_valid:
                serializer = AuthorizedTargetSerializer(existing)
                return Response(
                    {
                        'message': 'Domain is already verified',
                        'target': serializer.data
                    },
                    status=status.HTTP_200_OK
                )
            # Allow re-attempt — update method and notes
            existing.verification_method  = method
            existing.authorization_notes  = notes
            existing.full_target          = target_url
            existing.status               = 'pending'
            existing.save()
            serializer = AuthorizedTargetSerializer(existing)
            return Response(
                {
                    'message': 'Authorization record updated. Follow the verification instructions.',
                    'target': serializer.data
                },
                status=status.HTTP_200_OK
            )

        # Create new authorization record
        auth_target = AuthorizedTarget.objects.create(
            user=request.user,
            domain=domain,
            full_target=target_url,
            verification_method=method,
            authorization_notes=notes,
        )

        serializer = AuthorizedTargetSerializer(auth_target)
        return Response(
            {
                'message': (
                    'Domain registered. Complete verification using the instructions provided, '
                    'then call the /verify/ endpoint.'
                ),
                'target': serializer.data
            },
            status=status.HTTP_201_CREATED
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_target(request, pk):
    """
    Trigger ownership verification for a registered target.
    The user must have already placed the DNS record / file / meta tag
    before calling this endpoint.
    """
    auth_target = get_object_or_404(AuthorizedTarget, pk=pk, user=request.user)

    if auth_target.status == 'verified' and auth_target.is_valid:
        return Response(
            {
                'verified': True,
                'message': 'Domain is already verified',
                'target': AuthorizedTargetSerializer(auth_target).data
            }
        )

    # Run the async verifier synchronously
    verifier = AuthorizationVerifier(auth_target)
    from asgiref.sync import async_to_sync
    success, message = async_to_sync(verifier.verify)()

    if success:
        auth_target.status      = 'verified'
        auth_target.verified_at = timezone.now()
        auth_target.expires_at  = timezone.now() + timezone.timedelta(days=365)
        auth_target.last_verification_error = ''
        auth_target.save()

        logger.info(f"Target {auth_target.domain} verified for user {request.user.username}")

        return Response(
            {
                'verified': True,
                'message': message,
                'target': AuthorizedTargetSerializer(auth_target).data
            }
        )
    else:
        auth_target.status = 'failed'
        auth_target.last_verification_error = message
        auth_target.save()

        return Response(
            {
                'verified': False,
                'message': message,
                'instructions': _get_instructions(auth_target),
                'target': AuthorizedTargetSerializer(auth_target).data
            },
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def authorization_status(request, pk):
    """Get the current authorization status for a target"""
    auth_target = get_object_or_404(AuthorizedTarget, pk=pk, user=request.user)
    return Response(
        {
            'is_valid': auth_target.is_valid,
            'status': auth_target.status,
            'domain': auth_target.domain,
            'verified_at': auth_target.verified_at,
            'expires_at': auth_target.expires_at,
            'instructions': _get_instructions(auth_target) if not auth_target.is_valid else None,
            'target': AuthorizedTargetSerializer(auth_target).data
        }
    )


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def revoke_authorization(request, pk):
    """Revoke an authorized target — prevents any further scans against it"""
    auth_target = get_object_or_404(AuthorizedTarget, pk=pk, user=request.user)
    auth_target.status = 'revoked'
    auth_target.save()
    logger.info(f"Target {auth_target.domain} revoked by user {request.user.username}")
    return Response({'message': f'Authorization for {auth_target.domain} has been revoked'})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_target_authorized(request):
    """
    Quick check: is a given URL authorized for the current user?
    Used by the frontend before showing scan options.
    Query param: ?url=https://example.com
    """
    from .authorization import is_scan_authorized
    target_url = request.query_params.get('url', '').strip()

    if not target_url:
        return Response(
            {'error': 'url query parameter is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    authorized, auth_target = is_scan_authorized(request.user, target_url)

    return Response(
        {
            'authorized': authorized,
            'domain': extract_domain(target_url),
            'target': AuthorizedTargetSerializer(auth_target).data if auth_target else None,
            'message': (
                'Target is authorized for scanning'
                if authorized
                else 'Target not authorized. Register and verify domain ownership first.'
            )
        }
    )


def _get_instructions(auth_target) -> dict:
    """Return human-readable setup instructions based on verification method"""
    method = auth_target.verification_method

    if method == 'dns_txt':
        return {
            'method': 'DNS TXT Record',
            'steps': [
                f"Log into your DNS provider (GoDaddy, Cloudflare, Namecheap, etc.)",
                f"Add a new TXT record to your domain: {auth_target.domain}",
                f"Set the Name/Host to: @ (or leave blank for root domain)",
                f"Set the Value/Content to exactly: {auth_target.get_dns_txt_record()}",
                f"Save the record and wait 1–5 minutes for DNS propagation",
                f"Then call the verify endpoint again",
            ]
        }
    elif method == 'file':
        return {
            'method': 'Verification File',
            'steps': [
                f"Create a file at: {auth_target.get_file_path()} on your web server",
                f"The file must contain exactly this text: {auth_target.get_file_content()}",
                f"Ensure it is publicly accessible at: https://{auth_target.domain}{auth_target.get_file_path()}",
                f"Then call the verify endpoint",
            ]
        }
    elif method == 'meta_tag':
        return {
            'method': 'HTML Meta Tag',
            'steps': [
                f"Add this meta tag inside the <head> section of your homepage:",
                auth_target.get_meta_tag(),
                f"Deploy the change so it is live at: https://{auth_target.domain}/",
                f"Then call the verify endpoint",
            ]
        }
    return {}