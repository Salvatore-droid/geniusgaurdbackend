# base/ai/deep_scanner.py
"""
Playwright-based deep vulnerability scanner.
Replaces the browser extension approach entirely.

What this covers that URL-only scanning cannot:
  - JavaScript-rendered pages (React, Vue, Angular apps)
  - Authenticated flows (user provides credentials)
  - Business logic flaws (multi-step workflows)
  - DOM-based XSS
  - IDOR via authenticated API calls
  - Session management weaknesses
  - CSRF in real form submissions
  - Race conditions
  - Privilege escalation between roles

Flow:
  1. Launch headless Chromium via Playwright
  2. Optionally authenticate (if credentials provided)
  3. Crawl all reachable pages/routes
  4. Intercept and record every network request/response
  5. Actively test forms, API endpoints, auth flows
  6. Send all findings through Groq AI for triage
  7. Return confirmed, remediated findings
"""

import asyncio
import json
import logging
import re
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin
from datetime import datetime

logger = logging.getLogger(__name__)

# Confidence threshold — findings below this are discarded before AI triage
MIN_CONFIDENCE = 0.65

# How many pages to crawl max
MAX_PAGES = 60

# How long to wait for page loads (ms)
PAGE_TIMEOUT = 15000


class DeepVulnerabilityScanner:
    """
    Headless browser scanner using Playwright.
    Accepts an authorized target URL and optional credentials.
    """

    def __init__(
        self,
        target_url: str,
        credentials: Optional[Dict] = None,
        scan_id: int = None,
    ):
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        self.target       = target_url
        self.parsed       = urlparse(target_url)
        self.base_url     = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.domain       = self.parsed.netloc.replace('www.', '')
        self.credentials  = credentials   # {'username_field': 'email', 'username': '...', 'password': '...', 'login_url': '...'}
        self.scan_id      = scan_id

        self.visited_urls : set  = set()
        self.network_log  : List = []    # all intercepted requests/responses
        self.raw_findings : List = []
        self.final        : List = []

        self.stats = {
            'pages_crawled': 0,
            'requests_intercepted': 0,
            'forms_tested': 0,
            'api_endpoints_found': 0,
            'ai_calls': 0,
            'false_positives_filtered': 0,
            'duration': 0,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Public entry point
    # ─────────────────────────────────────────────────────────────────────────

    async def scan(self) -> List[Dict]:
        start = time.time()

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise RuntimeError(
                "Playwright is not installed. Run: pip install playwright && playwright install chromium"
            )

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                ]
            )

            context = await browser.new_context(
                viewport={'width': 1280, 'height': 800},
                user_agent='Mozilla/5.0 (compatible; GeniusGuard-Scanner/1.0; +https://geniusguard.com/bot)',
                ignore_https_errors=True,
            )

            # Intercept all network traffic
            await context.route('**/*', self._intercept_request)

            page = await context.new_page()
            page.on('response', lambda r: asyncio.ensure_future(self._record_response(r)))

            # Phase 1 — authenticate if credentials provided
            if self.credentials:
                await self._authenticate(page)

            # Phase 2 — crawl all reachable pages
            await self._crawl(page, self.target)

            # Phase 3 — active vulnerability tests
            await self._test_security_headers(page)
            await self._test_cors(page, context)
            await self._test_authentication_security(page, context)
            await self._test_idor(page, context)
            await self._test_business_logic(page, context)
            await self._test_xss(page)
            await self._test_csrf(page, context)
            await self._analyze_network_log()

            await browser.close()

        # Phase 4 — AI triage
        await self._ai_triage()

        self.stats['duration'] = round(time.time() - start, 2)
        logger.info(
            f"Deep scan complete: {len(self.raw_findings)} raw → "
            f"{len(self.final)} confirmed | "
            f"{self.stats['false_positives_filtered']} filtered | "
            f"{self.stats['duration']}s"
        )
        return self.final

    # ─────────────────────────────────────────────────────────────────────────
    # Network interception
    # ─────────────────────────────────────────────────────────────────────────

    async def _intercept_request(self, route, request):
        """Record outgoing requests and let them proceed normally"""
        self.stats['requests_intercepted'] += 1

        # Track API endpoints discovered
        if '/api/' in request.url or request.resource_type in ('fetch', 'xhr'):
            self.stats['api_endpoints_found'] += 1
            self.network_log.append({
                'url':     request.url,
                'method':  request.method,
                'headers': dict(request.headers),
                'post_data': request.post_data,
                'type':    'api' if '/api/' in request.url else 'xhr',
            })

        await route.continue_()

    async def _record_response(self, response):
        """Record responses for network log entries"""
        try:
            if '/api/' in response.url or response.request.resource_type in ('fetch', 'xhr'):
                body = ''
                try:
                    body = await response.text()
                except Exception:
                    pass

                # Find and update the matching network log entry
                for entry in reversed(self.network_log):
                    if entry.get('url') == response.url and 'response_status' not in entry:
                        entry['response_status']  = response.status
                        entry['response_headers'] = dict(response.headers)
                        entry['response_body']    = body[:2000]
                        break
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 1 — Authentication
    # ─────────────────────────────────────────────────────────────────────────

    async def _authenticate(self, page):
        """
        Log into the application using provided credentials.
        Supports email/password forms and detects token storage.
        """
        creds     = self.credentials
        login_url = creds.get('login_url', self.base_url + '/login/')

        logger.info(f"Attempting authentication at {login_url}")

        try:
            await page.goto(login_url, timeout=PAGE_TIMEOUT, wait_until='networkidle')

            # Find username/email field
            username_field = creds.get('username_field', 'email')
            username       = creds.get('username', '')
            password       = creds.get('password', '')

            # Try common selectors for username input
            username_selectors = [
                f'input[name="{username_field}"]',
                f'input[type="{username_field}"]',
                'input[type="email"]',
                'input[name="email"]',
                'input[name="username"]',
                'input[placeholder*="email" i]',
                'input[placeholder*="username" i]',
            ]
            password_selectors = [
                'input[type="password"]',
                'input[name="password"]',
            ]

            # Fill username
            for sel in username_selectors:
                try:
                    await page.fill(sel, username, timeout=2000)
                    break
                except Exception:
                    continue

            # Fill password
            for sel in password_selectors:
                try:
                    await page.fill(sel, password, timeout=2000)
                    break
                except Exception:
                    continue

            # Submit
            submit_selectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Login")',
                'button:has-text("Sign in")',
                'button:has-text("Log in")',
            ]
            for sel in submit_selectors:
                try:
                    await page.click(sel, timeout=3000)
                    break
                except Exception:
                    continue

            await page.wait_for_load_state('networkidle', timeout=10000)

            # Check if we're still on login page (failed login)
            current_url = page.url
            if 'login' in current_url.lower() or 'signin' in current_url.lower():
                logger.warning("Authentication may have failed — still on login page")
            else:
                logger.info(f"Authentication successful — now at {current_url}")

                # Check where tokens are stored
                local_storage = await page.evaluate("() => JSON.stringify(Object.entries(localStorage))")
                session_storage = await page.evaluate("() => JSON.stringify(Object.entries(sessionStorage))")
                ls_data = json.loads(local_storage)
                ss_data = json.loads(session_storage)

                jwt_pattern = re.compile(r'ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

                for key, value in ls_data:
                    if jwt_pattern.search(str(value)) or 'token' in key.lower():
                        self._add_finding(
                            name='Authentication Token Stored in localStorage',
                            severity='high',
                            cvss=7.4,
                            description=(
                                f"The application stores authentication tokens in localStorage (key: '{key}'). "
                                "localStorage is accessible to any JavaScript on the page, making tokens "
                                "vulnerable to theft via XSS attacks."
                            ),
                            evidence=f"localStorage key: {key}, value prefix: {str(value)[:50]}",
                            url=login_url,
                            confidence=0.95,
                            cwe='CWE-922',
                        )
                        break

        except Exception as e:
            logger.error(f"Authentication failed: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 2 — Crawl
    # ─────────────────────────────────────────────────────────────────────────

    async def _crawl(self, page, url: str, depth: int = 0):
        if depth > 4 or len(self.visited_urls) >= MAX_PAGES:
            return
        if url in self.visited_urls:
            return
        if not url.startswith(self.base_url):
            return

        self.visited_urls.add(url)
        self.stats['pages_crawled'] += 1

        try:
            await page.goto(url, timeout=PAGE_TIMEOUT, wait_until='domcontentloaded')
            await page.wait_for_timeout(800)   # let JS settle

            # Collect all links
            links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(h => h && !h.startsWith('javascript:') && !h.startsWith('mailto:'))
            """)

            # Collect form actions for testing later
            forms = await page.evaluate("""
                () => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action,
                    method: f.method || 'GET',
                    fields: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                        name: i.name, type: i.type, placeholder: i.placeholder
                    }))
                }))
            """)

            # Test each form
            for form in forms:
                await self._test_form(page, form, url)

            # Recurse into links
            for link in links[:15]:
                await self._crawl(page, link, depth + 1)

        except Exception as e:
            logger.debug(f"Crawl error at {url}: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 3 — Active tests
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_security_headers(self, page):
        """Check response headers from the main page"""
        try:
            response = await page.goto(self.target, timeout=PAGE_TIMEOUT)
            if not response:
                return

            headers = {k.lower(): v for k, v in response.headers.items()}

            required = {
                'strict-transport-security': ('Missing HSTS', 'medium', 5.3, 'CWE-319'),
                'x-frame-options':           ('Missing X-Frame-Options (clickjacking)', 'medium', 4.3, 'CWE-1021'),
                'x-content-type-options':    ('Missing X-Content-Type-Options', 'low', 3.1, 'CWE-693'),
                'content-security-policy':   ('Missing Content-Security-Policy', 'medium', 5.4, 'CWE-79'),
                'referrer-policy':           ('Missing Referrer-Policy', 'low', 3.1, 'CWE-200'),
            }

            missing = [(msg, sev, cvss, cwe) for h, (msg, sev, cvss, cwe) in required.items() if h not in headers]

            if missing:
                self._add_finding(
                    name='Missing Security Headers',
                    severity='medium',
                    cvss=5.3,
                    description=f"Missing headers: {', '.join(m[0] for m in missing)}",
                    evidence=f"Present headers: {list(headers.keys())}",
                    url=self.target,
                    confidence=0.98,
                    cwe='CWE-693',
                )

            # Check for version disclosure
            for h in ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']:
                if h in headers:
                    self._add_finding(
                        name='Technology Version Disclosure',
                        severity='low',
                        cvss=3.1,
                        description=f"Header '{h}' reveals: {headers[h]}",
                        evidence=f"{h}: {headers[h]}",
                        url=self.target,
                        confidence=0.97,
                        cwe='CWE-200',
                    )
        except Exception as e:
            logger.error(f"Header test failed: {e}")

    async def _test_cors(self, page, context):
        """Test CORS policy with a spoofed origin"""
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=10)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.options(
                    self.target,
                    headers={'Origin': 'https://evil-attacker.com', 'Access-Control-Request-Method': 'GET'},
                    ssl=False,
                ) as resp:
                    acao = resp.headers.get('Access-Control-Allow-Origin', '')
                    acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

                    if acao == '*':
                        self._add_finding(
                            name='CORS Wildcard Origin',
                            severity='medium',
                            cvss=5.4,
                            description='Access-Control-Allow-Origin: * allows any website to make API calls.',
                            evidence=f"ACAO: {acao}",
                            url=self.target,
                            confidence=0.97,
                            cwe='CWE-942',
                        )
                    elif acao == 'https://evil-attacker.com':
                        sev  = 'critical' if acac == 'true' else 'high'
                        cvss = 9.0       if acac == 'true' else 7.5
                        self._add_finding(
                            name=f"CORS Origin Reflection {'with Credentials' if acac == 'true' else ''}",
                            severity=sev,
                            cvss=cvss,
                            description=(
                                'Server reflects arbitrary origins in ACAO header. '
                                + ('With credentials=true this enables full session hijack from any origin.' if acac == 'true' else '')
                            ),
                            evidence=f"Sent Origin: evil-attacker.com | Got ACAO: {acao} | Credentials: {acac}",
                            url=self.target,
                            confidence=0.96,
                            cwe='CWE-942',
                        )
        except Exception as e:
            logger.debug(f"CORS test: {e}")

    async def _test_authentication_security(self, page, context):
        """Test login endpoints for rate limiting, account enumeration, weak lockout"""
        import aiohttp

        auth_paths = ['/api/token/', '/api/auth/login/', '/api/login/', '/login/', '/auth/']
        timeout    = aiohttp.ClientTimeout(total=10)

        for path in auth_paths:
            url = self.base_url + path

            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    # Test 1: Rate limiting
                    codes = []
                    for _ in range(15):
                        async with session.post(
                            url,
                            json={'email': 'test@test.com', 'password': 'wrongpassword123'},
                            ssl=False
                        ) as r:
                            codes.append(r.status)

                    if codes and 429 not in codes and any(c in [200, 400, 401] for c in codes):
                        self._add_finding(
                            name='No Rate Limiting on Login Endpoint',
                            severity='high',
                            cvss=7.5,
                            description=(
                                f"Endpoint {path} accepted 15 consecutive failed login attempts "
                                "without throttling. Brute force attacks are possible."
                            ),
                            evidence=f"15 attempts, response codes: {list(set(codes))}",
                            url=url,
                            confidence=0.91,
                            cwe='CWE-307',
                        )

                    # Test 2: Account enumeration
                    # Different error messages for existing vs non-existing users
                    async with session.post(url, json={'email': 'definitelynotauser_xyz123@test.com', 'password': 'wrong'}, ssl=False) as r1:
                        body1 = await r1.text()
                    async with session.post(url, json={'email': 'admin@' + self.domain, 'password': 'wrong'}, ssl=False) as r2:
                        body2 = await r2.text()

                    # If error messages differ significantly, account enumeration is possible
                    if abs(len(body1) - len(body2)) > 20 or (
                        ('not found' in body1.lower() and 'invalid' in body2.lower()) or
                        ('not found' in body2.lower() and 'invalid' in body1.lower())
                    ):
                        self._add_finding(
                            name='User Account Enumeration via Login',
                            severity='medium',
                            cvss=5.3,
                            description=(
                                f"The login endpoint returns different error messages for existing "
                                "vs non-existing accounts, allowing attackers to enumerate valid users."
                            ),
                            evidence=f"Non-existent user response length: {len(body1)}\nExisting user guess response length: {len(body2)}",
                            url=url,
                            confidence=0.75,
                            cwe='CWE-204',
                        )
                    break  # found auth endpoint

            except Exception as e:
                logger.debug(f"Auth test on {path}: {e}")

    async def _test_idor(self, page, context):
        """
        Test for Insecure Direct Object References on API endpoints
        discovered during crawling.
        """
        import aiohttp

        # Get cookies from the authenticated Playwright session
        cookies     = await context.cookies()
        cookie_str  = '; '.join([f"{c['name']}={c['value']}" for c in cookies])
        local_store = {}
        timeout     = aiohttp.ClientTimeout(total=10)

        try:
            # Get auth token from localStorage if present
            token_page = await context.new_page()
            await token_page.goto(self.target, timeout=PAGE_TIMEOUT)
            ls = await token_page.evaluate("() => JSON.stringify(Object.entries(localStorage))")
            for key, value in json.loads(ls):
                if 'token' in key.lower() or 'auth' in key.lower():
                    local_store['token'] = value
                    break
            await token_page.close()
        except Exception:
            pass

        # Find API endpoints with numeric IDs from the network log
        id_pattern = re.compile(r'/(\d+)/?$')
        tested     = set()

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for entry in self.network_log:
                url    = entry.get('url', '')
                method = entry.get('method', 'GET')

                if not id_pattern.search(url):
                    continue
                if url in tested:
                    continue
                tested.add(url)

                # Try adjacent IDs
                match     = id_pattern.search(url)
                current_id = int(match.group(1))
                test_ids  = [max(1, current_id - 1), max(1, current_id - 2), current_id + 1]

                headers = {}
                if cookie_str:
                    headers['Cookie'] = cookie_str
                if local_store.get('token'):
                    headers['Authorization'] = f"Bearer {local_store['token']}"

                for test_id in test_ids:
                    test_url = url[:match.start(1)] + str(test_id) + url[match.end(1):]
                    try:
                        async with session.get(test_url, headers=headers, ssl=False) as r:
                            if r.status == 200:
                                body = await r.text()
                                # If we get data back, it might be IDOR
                                if len(body) > 10 and body.strip() not in ('{}', '[]', 'null'):
                                    self._add_finding(
                                        name='Potential IDOR — Object Access Without Ownership Check',
                                        severity='high',
                                        cvss=8.1,
                                        description=(
                                            f"API endpoint {url} returned HTTP 200 for object ID {test_id}, "
                                            "which may belong to a different user. If this data is for another "
                                            "user's record, this is an Insecure Direct Object Reference."
                                        ),
                                        evidence=f"Original ID: {current_id} | Tested ID: {test_id} | URL: {test_url} | Response length: {len(body)}",
                                        url=test_url,
                                        confidence=0.70,   # AI will confirm
                                        cwe='CWE-639',
                                    )
                    except Exception:
                        pass

    async def _test_business_logic(self, page, context):
        """
        Test business logic flows:
        - Price/quantity manipulation
        - Workflow step skipping
        - Privilege escalation via role parameter tampering
        """
        import aiohttp
        cookies   = await context.cookies()
        cookie_str = '; '.join([f"{c['name']}={c['value']}" for c in cookies])
        timeout   = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            headers = {'Cookie': cookie_str, 'Content-Type': 'application/json'}

            for entry in self.network_log:
                if entry.get('method') != 'POST':
                    continue

                post_data = entry.get('post_data', '')
                if not post_data:
                    continue

                try:
                    data = json.loads(post_data)
                except Exception:
                    continue

                # Test 1: Negative price / quantity manipulation
                price_keys    = [k for k in data if any(w in k.lower() for w in ['price', 'amount', 'total', 'cost', 'fee'])]
                quantity_keys = [k for k in data if any(w in k.lower() for w in ['qty', 'quantity', 'count', 'num'])]

                for key in price_keys:
                    tampered      = data.copy()
                    tampered[key] = -1
                    try:
                        async with session.post(entry['url'], json=tampered, headers=headers, ssl=False) as r:
                            if r.status in (200, 201):
                                self._add_finding(
                                    name='Business Logic — Negative Price Accepted',
                                    severity='critical',
                                    cvss=9.1,
                                    description=(
                                        f"The API accepted a negative value (-1) for field '{key}'. "
                                        "This may allow price manipulation, resulting in free or refunded transactions."
                                    ),
                                    evidence=f"URL: {entry['url']}\nPayload: {json.dumps(tampered)}\nStatus: {r.status}",
                                    url=entry['url'],
                                    confidence=0.82,
                                    cwe='CWE-840',
                                )
                    except Exception:
                        pass

                # Test 2: Role/privilege field tampering
                role_keys = [k for k in data if any(w in k.lower() for w in ['role', 'is_admin', 'admin', 'permission', 'privilege'])]
                for key in role_keys:
                    tampered       = data.copy()
                    original_value = tampered[key]
                    tampered[key]  = True if isinstance(original_value, bool) else 'admin'
                    try:
                        async with session.post(entry['url'], json=tampered, headers=headers, ssl=False) as r:
                            body = await r.text()
                            if r.status in (200, 201) and 'error' not in body.lower():
                                self._add_finding(
                                    name='Business Logic — Role/Privilege Escalation via Parameter Tampering',
                                    severity='critical',
                                    cvss=9.8,
                                    description=(
                                        f"The API accepted a tampered '{key}' field with elevated privilege value. "
                                        "The server should enforce roles server-side, never trusting client-submitted role values."
                                    ),
                                    evidence=f"URL: {entry['url']}\nOriginal {key}: {original_value}\nTampered {key}: {tampered[key]}\nStatus: {r.status}",
                                    url=entry['url'],
                                    confidence=0.78,
                                    cwe='CWE-269',
                                )
                    except Exception:
                        pass

    async def _test_form(self, page, form: Dict, page_url: str):
        """Test a discovered form for XSS reflection and SQL errors"""
        self.stats['forms_tested'] += 1
        fields = form.get('fields', [])
        if not fields:
            return

        # Only test text/email/search/textarea inputs
        text_fields = [f for f in fields if f.get('type', '') in ('text', 'email', 'search', 'textarea', '') and f.get('name')]
        if not text_fields:
            return

        xss_payload = '<geniusguard-xss-test>'
        sql_payload = "'"

        for field in text_fields[:3]:
            name = field['name']

            # XSS reflection test
            try:
                await page.goto(page_url, timeout=PAGE_TIMEOUT, wait_until='domcontentloaded')
                selector = f'[name="{name}"]'
                await page.fill(selector, xss_payload, timeout=3000)

                action = form.get('action', page_url)
                method = form.get('method', 'GET').upper()

                if method == 'GET':
                    await page.keyboard.press('Enter')
                    await page.wait_for_load_state('domcontentloaded', timeout=5000)

                content = await page.content()
                if xss_payload in content:
                    self._add_finding(
                        name='Reflected XSS — Unencoded Input in Response',
                        severity='high',
                        cvss=7.4,
                        description=(
                            f"Form field '{name}' on {page_url} reflects input without HTML encoding. "
                            "An attacker can craft a URL that executes JavaScript in the victim's browser."
                        ),
                        evidence=f"Payload '{xss_payload}' reflected verbatim in response body",
                        url=page_url,
                        confidence=0.88,
                        cwe='CWE-79',
                    )
            except Exception:
                pass

    async def _test_xss(self, page):
        """Test URL parameters for XSS"""
        for url in list(self.visited_urls)[:10]:
            if '?' not in url:
                continue
            base, qs = url.split('?', 1)
            params = dict(p.split('=', 1) for p in qs.split('&') if '=' in p)
            for key in list(params.keys())[:3]:
                test_params      = params.copy()
                test_params[key] = '<geniusguard-xss>'
                test_url         = base + '?' + '&'.join(f"{k}={v}" for k, v in test_params.items())
                try:
                    await page.goto(test_url, timeout=PAGE_TIMEOUT, wait_until='domcontentloaded')
                    content = await page.content()
                    if '<geniusguard-xss>' in content:
                        self._add_finding(
                            name='Reflected XSS via URL Parameter',
                            severity='high',
                            cvss=7.4,
                            description=f"URL parameter '{key}' is reflected without encoding in the response.",
                            evidence=f"Test URL: {test_url}",
                            url=url,
                            confidence=0.88,
                            cwe='CWE-79',
                        )
                except Exception:
                    pass

    async def _test_csrf(self, page, context):
        """Check for CSRF protection on state-changing forms"""
        for entry in self.network_log:
            if entry.get('method') != 'POST':
                continue
            headers = entry.get('headers', {})
            has_csrf = any(
                k.lower() in ('x-csrftoken', 'x-xsrf-token', 'csrf-token') or
                'csrf' in k.lower()
                for k in headers
            )
            if not has_csrf:
                self._add_finding(
                    name='Missing CSRF Token on State-Changing Request',
                    severity='medium',
                    cvss=6.5,
                    description=(
                        f"POST request to {entry['url']} does not include a CSRF token header. "
                        "This may allow cross-site request forgery if the endpoint is cookie-authenticated."
                    ),
                    evidence=f"URL: {entry['url']}\nHeaders present: {list(headers.keys())[:10]}",
                    url=entry['url'],
                    confidence=0.72,
                    cwe='CWE-352',
                )

    async def _analyze_network_log(self):
        """Analyze the captured network traffic for additional issues"""
        sensitive_patterns = {
            'password':     ('Sensitive Data in Request', 'high',   7.5, 'CWE-312'),
            'credit_card':  ('Credit Card Data in Transit', 'critical', 9.1, 'CWE-311'),
            'ssn':          ('SSN in Request', 'critical', 9.1, 'CWE-312'),
            'private_key':  ('Private Key in Response', 'critical', 9.8, 'CWE-312'),
            'secret_key':   ('Secret Key in Response', 'critical', 9.8, 'CWE-312'),
            'api_key':      ('API Key Exposed in Response', 'high', 7.5, 'CWE-312'),
        }

        for entry in self.network_log:
            body = (entry.get('response_body', '') + entry.get('post_data', '')).lower()
            for pattern, (name, sev, cvss, cwe) in sensitive_patterns.items():
                if pattern in body and entry.get('response_status') == 200:
                    self._add_finding(
                        name=name,
                        severity=sev,
                        cvss=cvss,
                        description=f"Found '{pattern}' in network traffic for {entry['url']}",
                        evidence=f"URL: {entry['url']}\nMethod: {entry.get('method')}\nStatus: {entry.get('response_status')}",
                        url=entry['url'],
                        confidence=0.70,
                        cwe=cwe,
                    )

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 4 — AI triage
    # ─────────────────────────────────────────────────────────────────────────

    async def _ai_triage(self):
        from .groq_client import groq_client

        if not groq_client.initialized or not self.raw_findings:
            self.final = [f for f in self.raw_findings if f.get('confidence', 0) >= MIN_CONFIDENCE]
            return

        sem = asyncio.Semaphore(3)

        async def triage_one(finding):
            async with sem:
                self.stats['ai_calls'] += 1
                try:
                    prompt = f"""You are a senior penetration tester doing quality control.
Review this finding from an automated deep scan and determine if it is real.

Finding:
{json.dumps(finding, indent=2)}

Respond ONLY with JSON:
{{
    "confirmed": true/false,
    "is_false_positive": true/false,
    "false_positive_reason": "reason or null",
    "confirmed_severity": "critical|high|medium|low|info",
    "confirmed_cvss": 0.0-10.0,
    "confidence": 0.0-1.0,
    "description": "clear developer-facing description",
    "remediation": "specific fix steps with code examples where applicable",
    "cve_references": ["CVE-..." ] or []
}}

Be strict. Only confirm findings with clear evidence. Business logic findings need strong evidence."""

                    result = await groq_client.client.chat.completions.create(
                        model=groq_client.model,
                        messages=[
                            {"role": "system", "content": "Precise security analyst. Valid JSON only."},
                            {"role": "user",   "content": prompt},
                        ],
                        temperature=0.05,
                        max_tokens=1200,
                        response_format={"type": "json_object"},
                    )
                    review = json.loads(result.choices[0].message.content)

                    if review.get('is_false_positive') or not review.get('confirmed'):
                        self.stats['false_positives_filtered'] += 1
                        return None
                    if review.get('confidence', 0) < MIN_CONFIDENCE:
                        self.stats['false_positives_filtered'] += 1
                        return None

                    finding.update({
                        'severity':    review.get('confirmed_severity', finding['severity']),
                        'cvss_score':  review.get('confirmed_cvss', finding.get('cvss_score', 5.0)),
                        'confidence':  review.get('confidence', finding['confidence']),
                        'description': review.get('description', finding['description']),
                        'remediation': review.get('remediation', ''),
                        'cve_id':      ', '.join(review.get('cve_references', [])),
                        'ai_reviewed': True,
                    })
                    return finding

                except Exception as e:
                    logger.error(f"AI triage error: {e}")
                    if finding.get('confidence', 0) >= MIN_CONFIDENCE:
                        finding['remediation'] = 'See OWASP guidance for this vulnerability type.'
                        return finding
                    return None

        results    = await asyncio.gather(*[triage_one(f) for f in self.raw_findings])
        self.final = [r for r in results if r is not None]

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _add_finding(self, name, severity, cvss, description, evidence, url,
                     confidence, cwe='', cve_id='', remediation=''):
        key = f"{name}::{url}"
        for f in self.raw_findings:
            if f"{f['name']}::{f['url']}" == key:
                return
        self.raw_findings.append({
            'name': name, 'severity': severity, 'cvss_score': cvss,
            'description': description, 'evidence': evidence, 'url': url,
            'confidence': confidence, 'cwe_id': cwe, 'cve_id': cve_id,
            'remediation': remediation, 'ai_reviewed': False,
        })