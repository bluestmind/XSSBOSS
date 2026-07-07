"""Filter profiling utilities."""
from typing import Dict, Any, List, Optional
import httpx
import re
from backend_api.utils.logger import logger
from backend_api.utils.request_builder import RequestBuilder


class FilterProfiler:
    """Profile WAF/sanitizer behavior."""
    
    # Probe payloads
    PROBE_PAYLOADS = [
        # Character probes (xss{c}xss pattern to prevent false-positives)
        {
            'name': 'char_lt',
            'payload': 'xss<xss',
            'purpose': 'Check if lower-than bracket is allowed, escaped, or stripped'
        },
        {
            'name': 'char_gt',
            'payload': 'xss>xss',
            'purpose': 'Check if greater-than bracket is allowed, escaped, or stripped'
        },
        {
            'name': 'char_single_quote',
            'payload': "xss'xss",
            'purpose': 'Check if single quote is allowed, escaped, or stripped'
        },
        {
            'name': 'char_double_quote',
            'payload': 'xss"xss',
            'purpose': 'Check if double quote is allowed, escaped, or stripped'
        },
        {
            'name': 'char_backtick',
            'payload': 'xss`xss',
            'purpose': 'Check if backtick is allowed, escaped, or stripped'
        },
        {
            'name': 'char_slash',
            'payload': 'xss/xss',
            'purpose': 'Check if forward slash is allowed, escaped, or stripped'
        },
        {
            'name': 'char_backslash',
            'payload': 'xss\\xss',
            'purpose': 'Check if backslash is allowed, escaped, or stripped'
        },
        {
            'name': 'char_semicolon',
            'payload': 'xss;xss',
            'purpose': 'Check if semicolon is allowed, escaped, or stripped'
        },
        {
            'name': 'char_lparen',
            'payload': 'xss(xss',
            'purpose': 'Check if left parenthesis is allowed, escaped, or stripped'
        },
        {
            'name': 'char_rparen',
            'payload': 'xss)xss',
            'purpose': 'Check if right parenthesis is allowed, escaped, or stripped'
        },
        # Word/structure probes
        {
            'name': 'html_tag',
            'payload': '<test>',
            'purpose': 'Test basic HTML tag handling'
        },
        {
            'name': 'closing_tag',
            'payload': '</div><b>x</b>',
            'purpose': 'Test tag breaking and closing'
        },
        {
            'name': 'script_tag',
            'payload': '<script>alert(1)</script>',
            'purpose': 'Test script tag blocking'
        },
        {
            'name': 'event_handler',
            'payload': '" onerror=alert(1)',
            'purpose': 'Test event handler blocking'
        },
        {
            'name': 'javascript_protocol',
            'payload': 'javascript:alert(1)',
            'purpose': 'Test javascript: protocol blocking'
        },
        {
            'name': 'svg_onload',
            'payload': '<svg/onload=alert(1)>',
            'purpose': 'Test SVG tag and onload handler'
        },
        {
            'name': 'img_src',
            'payload': '<img src=x onerror=alert(1)>',
            'purpose': 'Test img tag and onerror handler'
        },
        {
            'name': 'iframe_src',
            'payload': '<iframe src=javascript:alert(1)>',
            'purpose': 'Test iframe and javascript: protocol'
        },
        {
            'name': 'quotes_test',
            'payload': '\'"',
            'purpose': 'Test quote handling (escaping vs stripping)'
        },
        {
            'name': 'backslash_test',
            'payload': '\\',
            'purpose': 'Test backslash handling'
        },
        {
            'name': 'brackets_test',
            'payload': '()[]',
            'purpose': 'Test parenthesis/bracket execution block'
        },
        {
            'name': 'comments_test',
            'payload': '/*',
            'purpose': 'Test block comment strip'
        }
    ]
    
    # WAF detection patterns
    WAF_PATTERNS = [
        (r'403\s+forbidden', re.IGNORECASE),
        (r'access\s+denied', re.IGNORECASE),
        (r'blocked', re.IGNORECASE),
        (r'security', re.IGNORECASE),
        (r'waf', re.IGNORECASE),
        (r'cloudflare', re.IGNORECASE),
        (r'incapsula', re.IGNORECASE),
        (r'akamai', re.IGNORECASE),
        (r'barracuda', re.IGNORECASE),
        (r'fortinet', re.IGNORECASE),
        (r'mod_security', re.IGNORECASE),
        (r'403', re.IGNORECASE),
        (r'406\s+not\s+acceptable', re.IGNORECASE),
    ]
    
    # Sanitizer detection patterns
    SANITIZER_PATTERNS = [
        (r'dompurify', re.IGNORECASE),
        (r'sanitize-html', re.IGNORECASE),
        (r'xss\s+filter', re.IGNORECASE),
        (r'htmlpurifier', re.IGNORECASE),
    ]
    
    @staticmethod
    def send_probe(
        method: str,
        url: str,
        param_name: str,
        param_value: str,
        param_location: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        base_body: Optional[Dict[str, Any]] = None,
        base_json: Optional[Dict[str, Any]] = None,
        timeout: int = 10
    ) -> Dict[str, Any]:
        """Send a probe request and analyze response.
        
        Args:
            method: HTTP method
            url: Request URL
            param_name: Parameter name
            param_value: Probe payload value
            param_location: Parameter location
            headers: Base headers
            cookies: Base cookies
            base_body: Base body data
            base_json: Base JSON data
            timeout: Request timeout
            
        Returns:
            Dictionary with probe results
        """
        try:
            # Build request
            if param_location == "query":
                url = RequestBuilder.url_with_query_param(url, param_name, param_value)
                response = httpx.request(
                    method=method,
                    url=url,
                    headers=headers or {},
                    cookies=cookies or {},
                    timeout=timeout,
                    follow_redirects=True
                )
            elif param_location == "body":
                body = (base_body or {}).copy()
                body[param_name] = param_value
                response = httpx.request(
                    method=method,
                    url=url,
                    headers=headers or {},
                    cookies=cookies or {},
                    data=body,
                    timeout=timeout,
                    follow_redirects=True
                )
            elif param_location == "json":
                json_data = (base_json or {}).copy()
                # Handle nested keys
                keys = param_name.split('.')
                current = json_data
                for key in keys[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                current[keys[-1]] = param_value
                response = httpx.request(
                    method=method,
                    url=url,
                    headers=headers or {},
                    cookies=cookies or {},
                    json=json_data,
                    timeout=timeout,
                    follow_redirects=True
                )
            elif param_location == "header":
                headers_with_payload = (headers or {}).copy()
                headers_with_payload[param_name] = param_value
                response = httpx.request(
                    method=method,
                    url=url,
                    headers=headers_with_payload,
                    cookies=cookies or {},
                    timeout=timeout,
                    follow_redirects=True
                )
            elif param_location == "cookie":
                cookies_with_payload = (cookies or {}).copy()
                cookies_with_payload[param_name] = param_value
                response = httpx.request(
                    method=method,
                    url=url,
                    headers=headers or {},
                    cookies=cookies_with_payload,
                    timeout=timeout,
                    follow_redirects=True
                )
            else:
                raise ValueError(f"Unknown parameter location: {param_location}")
            
            # Analyze response
            return FilterProfiler._analyze_response(response, param_value)
            
        except Exception as e:
            logger.error(f"Error sending probe: {e}", exc_info=True)
            return {
                'status_code': None,
                'error': str(e),
                'reflected': False,
                'blocked': False,
                'escaped': False,
                'stripped': False
            }
    
    @staticmethod
    def _analyze_response(
        response: httpx.Response,
        payload: str
    ) -> Dict[str, Any]:
        """Analyze response for filter behavior.
        
        Args:
            response: HTTP response
            payload: Original payload
            
        Returns:
            Dictionary with analysis results
        """
        status_code = response.status_code
        response_text = response.text
        response_headers = dict(response.headers)
        
        # Check if blocked
        blocked = FilterProfiler._detect_blocking(status_code, response_text, response_headers)
        
        # Determine if character-level probe
        is_char_probe = len(payload) == 7 and payload.startswith('xss') and payload.endswith('xss')
        
        if is_char_probe and not blocked:
            char = payload[3]
            unmodified_reflected = payload in response_text
            
            escaped_variants = []
            if char == '<':
                escaped_variants = ['&lt;', '&#60;', '&#x3c;', '&#x3C;']
            elif char == '>':
                escaped_variants = ['&gt;', '&#62;', '&#x3e;', '&#x3E;']
            elif char == "'":
                escaped_variants = ['&#39;', '&#x27;', '&apos;']
            elif char == '"':
                escaped_variants = ['&quot;', '&#34;', '&#x22;']
                
            html_escaped = any(f"xss{v}xss" in response_text for v in escaped_variants)
            url_encoded = f"xss%{ord(char):02X}xss" in response_text or f"xss%{ord(char):02x}xss" in response_text
            backslash_escaped = f"xss\\{char}xss" in response_text
            stripped = f"xssxss" in response_text and not (unmodified_reflected or html_escaped or url_encoded or backslash_escaped)
            
            reflected = unmodified_reflected or html_escaped or url_encoded or backslash_escaped
            escaped = html_escaped or url_encoded or backslash_escaped
            
            normalized = escaped or stripped
            normalization_behaviors = []
            if html_escaped:
                normalization_behaviors.append('html_encoded')
            if url_encoded:
                normalization_behaviors.append('url_encoded')
            if backslash_escaped:
                normalization_behaviors.append('backslash_escaped')
            if stripped:
                normalization_behaviors.append('stripped')
        else:
            # Check if reflected
            reflected = payload in response_text
            
            # Check if escaped
            escaped = False
            if reflected:
                # Check for HTML entity encoding
                if '&lt;' in response_text or '&gt;' in response_text:
                    escaped = True
                # Check for URL encoding
                if '%3C' in response_text or '%3E' in response_text:
                    escaped = True
                # Check for JavaScript escaping
                if '\\x3C' in response_text or '\\u003C' in response_text:
                    escaped = True
            
            # Check if stripped
            stripped = False
            if not reflected and not blocked:
                # Payload was sent but not reflected - likely stripped
                stripped = True
            elif reflected:
                # Check if HTML tags were removed
                if '<' in payload and '<' not in response_text:
                    stripped = True
                # Check if specific tags were removed
                if '<script' in payload.lower() and '<script' not in response_text.lower():
                    stripped = True
            
            # Detect normalization
            normalized = False
            normalization_behaviors = []
            if reflected:
                # Check for case normalization
                if payload.lower() != payload and payload.lower() in response_text.lower():
                    normalized = True
                    normalization_behaviors.append('case_normalized')
                # Check for whitespace normalization
                if ' ' in payload and payload.replace(' ', '') in response_text:
                    normalized = True
                    normalization_behaviors.append('whitespace_removed')
                # Check for quotes escaping
                if any(q in payload for q in ["'", '"']):
                    has_escaped_quote = any(esc in response_text for esc in ["\\'", '\\"', '&#39;', '&#34;', '&quot;', '&#x27;', '&#x22;'])
                    if has_escaped_quote:
                        normalized = True
                        normalization_behaviors.append('quotes_escaped')
                    # Check for quotes stripping
                    cleaned_payload_no_quotes = payload.replace("'", "").replace('"', "")
                    if cleaned_payload_no_quotes in response_text and not any(q in response_text for q in ["'", '"', "\\'", '\\"', '&#39;', '&#34;', '&quot;', '&#x27;', '&#x22;']):
                        normalized = True
                        normalization_behaviors.append('quotes_stripped')
                # Check for backslash escaping
                if '\\' in payload:
                    if '\\\\' in response_text:
                        normalized = True
                        normalization_behaviors.append('backslashes_escaped')
                    elif '\\' not in response_text:
                        normalized = True
                        normalization_behaviors.append('backslashes_stripped')
                # Check for comments stripping
                if '/*' in payload and '/*' not in response_text:
                    normalized = True
                    normalization_behaviors.append('comments_stripped')
                # Check for brackets blocking/escaping
                if any(b in payload for b in ['(', ')']):
                    if not any(b in response_text for b in ['(', ')']):
                        normalized = True
                        normalization_behaviors.append('brackets_stripped')
        
        # Detect WAF
        waf_detected = FilterProfiler._detect_waf(status_code, response_text, response_headers)
        
        # Detect sanitizer
        sanitizer_detected = FilterProfiler._detect_sanitizer(response_text, response_headers)
        
        return {
            'status_code': status_code,
            'reflected': reflected,
            'blocked': blocked,
            'escaped': escaped,
            'stripped': stripped,
            'normalized': normalized,
            'normalization_behavior': normalization_behaviors,  # Save the list of behaviors
            'waf_detected': waf_detected,
            'sanitizer_detected': sanitizer_detected,
            'response_length': len(response_text),
            'response_preview': response_text[:500] if response_text else None
        }
    
    @staticmethod
    def _detect_blocking(
        status_code: int,
        response_text: str,
        response_headers: Dict[str, str]
    ) -> bool:
        """Detect if request was blocked.
        
        Args:
            status_code: HTTP status code
            response_text: Response body text
            response_headers: Response headers
            
        Returns:
            True if blocked
        """
        # Check status code
        if status_code in [403, 406, 429]:
            return True
        
        # Check response content for blocking patterns
        for pattern, flags in FilterProfiler.WAF_PATTERNS:
            if re.search(pattern, response_text, flags):
                return True
            if re.search(pattern, str(response_headers), flags):
                return True
        
        return False
    
    @staticmethod
    def _detect_waf(
        status_code: int,
        response_text: str,
        response_headers: Dict[str, str]
    ) -> Optional[str]:
        """Detect specific WAF.
        
        Args:
            status_code: HTTP status code
            response_text: Response body text
            response_headers: Response headers
            
        Returns:
            WAF name or None
        """
        waf_indicators = {
            'cloudflare': ['cloudflare', 'cf-ray'],
            'incapsula': ['incapsula', 'x-iinfo'],
            'akamai': ['akamai', 'x-akamai'],
            'barracuda': ['barracuda'],
            'fortinet': ['fortinet', 'fortigate'],
            'mod_security': ['mod_security', 'modsecurity'],
        }
        
        combined_text = (response_text + ' ' + str(response_headers)).lower()
        
        for waf_name, indicators in waf_indicators.items():
            for indicator in indicators:
                if indicator in combined_text:
                    return waf_name
        
        return None
    
    @staticmethod
    def _detect_sanitizer(
        response_text: str,
        response_headers: Dict[str, str]
    ) -> Optional[str]:
        """Detect specific sanitizer.
        
        Args:
            response_text: Response body text
            response_headers: Response headers
            
        Returns:
            Sanitizer name or None
        """
        combined_text = (response_text + ' ' + str(response_headers)).lower()
        
        for pattern, flags in FilterProfiler.SANITIZER_PATTERNS:
            if re.search(pattern, combined_text, flags):
                if 'dompurify' in pattern.lower():
                    return 'DOMPurify'
                elif 'sanitize-html' in pattern.lower():
                    return 'sanitize-html'
                elif 'htmlpurifier' in pattern.lower():
                    return 'HTMLPurifier'
        
        return None
    
    @staticmethod
    def profile_endpoint_param(
        method: str,
        url: str,
        param_name: str,
        param_location: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        base_body: Optional[Dict[str, Any]] = None,
        base_json: Optional[Dict[str, Any]] = None,
        timeout: int = 10
    ) -> Dict[str, Any]:
        """Profile filter behavior for an endpoint parameter.
        
        Args:
            method: HTTP method
            url: Request URL
            param_name: Parameter name
            param_location: Parameter location
            headers: Base headers
            cookies: Base cookies
            base_body: Base body data
            base_json: Base JSON data
            timeout: Request timeout
            
        Returns:
            Dictionary with filter profile
        """
        probe_results = []
        blocked_tokens = []
        allowed_tokens = []
        normalization_behaviors = []
        
        # Send all probe payloads
        for probe in FilterProfiler.PROBE_PAYLOADS:
            payload = probe['payload']
            result = FilterProfiler.send_probe(
                method=method,
                url=url,
                param_name=param_name,
                param_value=payload,
                param_location=param_location,
                headers=headers,
                cookies=cookies,
                base_body=base_body,
                base_json=base_json,
                timeout=timeout
            )
            
            result['probe_name'] = probe['name']
            result['payload'] = payload
            probe_results.append(result)
            
            # Analyze tokens
            if result['blocked']:
                # Extract blocked tokens
                tokens = FilterProfiler._extract_tokens(payload)
                blocked_tokens.extend(tokens)
            elif result['reflected'] and not result['escaped']:
                # Payload reflected without escaping - tokens allowed
                tokens = FilterProfiler._extract_tokens(payload)
                allowed_tokens.extend(tokens)
            
            # Track normalization
            if result['normalized'] and result.get('normalization_behavior'):
                behaviors = result['normalization_behavior']
                if isinstance(behaviors, list):
                    for b in behaviors:
                        if b not in normalization_behaviors:
                            normalization_behaviors.append(b)
                else:
                    if behaviors not in normalization_behaviors:
                        normalization_behaviors.append(behaviors)
        
        # Deduplicate tokens
        blocked_tokens = list(set(blocked_tokens))
        allowed_tokens = list(set(allowed_tokens))
        
        # Determine overall WAF/sanitizer detection
        waf_detected = any(r.get('waf_detected') for r in probe_results)
        sanitizer_detected = None
        for result in probe_results:
            if result.get('sanitizer_detected'):
                sanitizer_detected = result['sanitizer_detected']
                break
                
        # Extract and parse CSP headers
        from backend_api.utils.csp_parser import CSPParser
        csp_rules = {
            'allow_inline_scripts': True,
            'allow_event_handlers': True,
            'allow_eval': True,
            'allow_javascript_urls': True,
            'has_csp': False
        }
        
        # Find raw response headers in the results
        for probe in probe_results:
            # We can request a header directly from the response if available
            pass
            
        # As an improvement, we can perform a quick HEAD/GET request to collect the CSP header explicitly
        try:
            with httpx.Client(timeout=5) as client:
                res = client.request(method=method, url=url, headers=headers, cookies=cookies, follow_redirects=True)
                csp_header = res.headers.get('content-security-policy') or res.headers.get('content-security-policy-report-only')
                if csp_header:
                    directives = CSPParser.parse_header(csp_header)
                    csp_rules = CSPParser.evaluate_csp(directives)
        except Exception as csp_err:
            logger.warning(f"Failed to fetch CSP header explicitly: {csp_err}")
        
        # Generate summary
        summary = FilterProfiler._generate_summary(probe_results, blocked_tokens, allowed_tokens)
        if csp_rules.get('has_csp'):
            summary += f". CSP Detected: Inline scripts={csp_rules['allow_inline_scripts']}, Eval={csp_rules['allow_eval']}"
        
        return {
            'summary': summary,
            'blocked_tokens': blocked_tokens,
            'allowed_tokens': allowed_tokens,
            'normalization_behavior': normalization_behaviors,
            'waf_detected': bool(waf_detected),
            'sanitizer_detected': sanitizer_detected,
            'csp_rules': csp_rules,
            'probe_results': probe_results
        }
    
    @staticmethod
    def _extract_tokens(payload: str) -> List[str]:
        """Extract tokens from payload.
        
        Args:
            payload: Payload string
            
        Returns:
            List of tokens
        """
        tokens = []
        
        # Extract HTML tags
        tag_pattern = r'<(\w+)'
        tags = re.findall(tag_pattern, payload, re.IGNORECASE)
        tokens.extend(tags)
        
        # Extract event handlers
        handler_pattern = r'on\w+'
        handlers = re.findall(handler_pattern, payload, re.IGNORECASE)
        tokens.extend(handlers)
        
        # Extract protocols
        if 'javascript:' in payload.lower():
            tokens.append('javascript:')
        
        # Extract keywords
        keywords = ['script', 'alert', 'eval', 'function', 'onerror', 'onload']
        for keyword in keywords:
            if keyword in payload.lower():
                tokens.append(keyword)
        
        return tokens
    
    @staticmethod
    def _generate_summary(
        probe_results: List[Dict[str, Any]],
        blocked_tokens: List[str],
        allowed_tokens: List[str]
    ) -> str:
        """Generate human-readable summary.
        
        Args:
            probe_results: List of probe results
            blocked_tokens: List of blocked tokens
            allowed_tokens: List of allowed tokens
            
        Returns:
            Summary string
        """
        parts = []
        
        # Overall behavior
        blocked_count = sum(1 for r in probe_results if r.get('blocked'))
        escaped_count = sum(1 for r in probe_results if r.get('escaped'))
        stripped_count = sum(1 for r in probe_results if r.get('stripped'))
        
        # Subtract character probes from count to make summary representational of payloads
        blocked_count = sum(1 for r in probe_results if r.get('blocked') and not r.get('probe_name', '').startswith('char_'))
        escaped_count = sum(1 for r in probe_results if r.get('escaped') and not r.get('probe_name', '').startswith('char_'))
        stripped_count = sum(1 for r in probe_results if r.get('stripped') and not r.get('probe_name', '').startswith('char_'))
        
        if blocked_count > 0:
            parts.append(f"WAF blocking detected ({blocked_count} probes blocked)")
        if escaped_count > 0:
            parts.append(f"Output escaping detected ({escaped_count} probes escaped)")
        if stripped_count > 0:
            parts.append(f"Content stripping detected ({stripped_count} probes stripped)")
        
        if not parts:
            parts.append("No filtering detected - input reflected as-is")
        
        # Token analysis
        if blocked_tokens:
            parts.append(f"Blocked tokens: {', '.join(blocked_tokens[:5])}")
        if allowed_tokens:
            parts.append(f"Allowed tokens: {', '.join(allowed_tokens[:5])}")
        
        return ". ".join(parts)
