# base/authorization.py
"""
Domain ownership / authorization verification engine.
Supports three methods: DNS TXT record, hosted file, HTML meta tag.
Called before ANY scan is allowed to start.
"""

import asyncio
import aiohttp
import dns.resolver
import logging
import re
from urllib.parse import urlparse
from django.utils import timezone
from typing import Tuple
from asgiref.sync import sync_to_async

logger = logging.getLogger(__name__)


class AuthorizationVerifier:
    """
    Verifies that a user actually controls the target domain before
    allowing any scan to proceed.
    """

    TIMEOUT = aiohttp.ClientTimeout(total=15)

    def __init__(self, authorized_target):
        self.target = authorized_target
        self.domain = authorized_target.domain
        self.token  = authorized_target.verification_token

    async def verify(self) -> Tuple[bool, str]:
        self.target.verification_attempts += 1
        self.target.last_checked_at = timezone.now()

        # Save attempt fields async-safely
        await sync_to_async(
            lambda: self.target.__class__.objects.filter(pk=self.target.pk).update(
                verification_attempts=self.target.verification_attempts,
                last_checked_at=self.target.last_checked_at,
            )
        )()

        method = self.target.verification_method

        if method == 'dns_txt':
            success, message = await self._verify_dns_txt()
        elif method == 'file':
            success, message = await self._verify_file()
        elif method == 'meta_tag':
            success, message = await self._verify_meta_tag()
        else:
            return False, f"Unknown verification method: {method}"

        return success, message

    async def _verify_dns_txt(self) -> Tuple[bool, str]:
        """
        Check for a TXT record on the domain containing the verification token.
        Expected record value: geniusguard-site-verification=<token>
        """
        expected = self.target.get_dns_txt_record()
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: dns.resolver.resolve(self.domain, 'TXT')
            )

            for rdata in answers:
                for txt_string in rdata.strings:
                    record_value = txt_string.decode('utf-8', errors='ignore').strip()
                    if record_value == expected:
                        return True, "DNS TXT record verified successfully"

            return False, (
                f"DNS TXT record not found. Add this exact TXT record to your domain:\n"
                f"Name: @ (or {self.domain})\n"
                f"Value: {expected}"
            )

        except dns.resolver.NXDOMAIN:
            return False, f"Domain {self.domain} does not exist in DNS"
        except dns.resolver.NoAnswer:
            return False, f"No TXT records found for {self.domain}. Add the verification record."
        except Exception as e:
            logger.error(f"DNS verification error for {self.domain}: {e}")
            return False, f"DNS lookup failed: {str(e)}"

    async def _verify_file(self) -> Tuple[bool, str]:
        """
        Check that a verification file exists at:
        https://<domain>/.well-known/geniusguard-verification.txt
        containing the exact token value.
        """
        url = f"https://{self.domain}/.well-known/geniusguard-verification.txt"
        expected_content = self.target.get_file_content()

        try:
            async with aiohttp.ClientSession(timeout=self.TIMEOUT) as session:
                async with session.get(url, allow_redirects=True) as response:
                    if response.status != 200:
                        return False, (
                            f"Verification file not found (HTTP {response.status}).\n"
                            f"Please create the file at: {self.target.get_file_path()}\n"
                            f"With exactly this content: {expected_content}"
                        )
                    content = (await response.text()).strip()
                    if content == expected_content:
                        return True, "Verification file confirmed successfully"
                    return False, (
                        f"File found but content doesn't match.\n"
                        f"Expected: {expected_content}\n"
                        f"Got: {content[:100]}"
                    )
        except aiohttp.ClientConnectorError:
            return False, f"Could not connect to {self.domain}. Is the server reachable over HTTPS?"
        except Exception as e:
            logger.error(f"File verification error for {self.domain}: {e}")
            return False, f"File verification failed: {str(e)}"

    async def _verify_meta_tag(self) -> Tuple[bool, str]:
        """
        Check that the homepage contains the verification meta tag in <head>.
        """
        url = f"https://{self.domain}/"
        expected_token = self.token

        try:
            async with aiohttp.ClientSession(timeout=self.TIMEOUT) as session:
                async with session.get(url, allow_redirects=True) as response:
                    if response.status != 200:
                        return False, f"Homepage returned HTTP {response.status}"

                    html = await response.text()

                    # Look for the meta tag in a case-insensitive way
                    pattern = re.compile(
                        r'<meta[^>]+name=["\']geniusguard-site-verification["\'][^>]+content=["\']([^"\']+)["\']',
                        re.IGNORECASE
                    )
                    match = pattern.search(html)

                    # Also check reversed attribute order
                    if not match:
                        pattern2 = re.compile(
                            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']geniusguard-site-verification["\']',
                            re.IGNORECASE
                        )
                        match = pattern2.search(html)

                    if match and match.group(1).strip() == expected_token:
                        return True, "Meta tag verified successfully"

                    return False, (
                        f"Meta tag not found in page <head>.\n"
                        f"Add this tag inside your <head>:\n"
                        f"{self.target.get_meta_tag()}"
                    )

        except Exception as e:
            logger.error(f"Meta tag verification error for {self.domain}: {e}")
            return False, f"Meta tag verification failed: {str(e)}"


def extract_domain(url: str) -> str:
    """Extract clean domain from a full URL"""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    # Strip port if present
    domain = domain.split(':')[0]
    # Strip www. prefix for consistency
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain.lower().strip()


def get_or_create_authorized_target(user, target_url: str):
    """
    Check if the user already has a verified authorization for this domain.
    Returns (authorized_target, created: bool)
    """
    from .models import AuthorizedTarget
    domain = extract_domain(target_url)

    target, created = AuthorizedTarget.objects.get_or_create(
        user=user,
        domain=domain,
        defaults={
            'full_target': target_url,
            'verification_method': 'dns_txt',
        }
    )
    return target, created


def is_scan_authorized(user, target_url: str) -> Tuple[bool, object]:
    """
    Quick synchronous check: does this user have a valid, verified
    authorization for this target URL?
    Returns (is_authorized: bool, authorized_target_or_None)
    """
    from .models import AuthorizedTarget
    domain = extract_domain(target_url)

    try:
        auth = AuthorizedTarget.objects.get(user=user, domain=domain)
        return auth.is_valid, auth
    except AuthorizedTarget.DoesNotExist:
        return False, None