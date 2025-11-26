"""
Confidence Scorer for Security Findings

Calculates confidence scores (0.0 - 1.0) for security findings to reduce false positives.
Uses multiple indicators and contextual analysis to determine likelihood of true vulnerability.
"""

from __future__ import annotations

import re
import html
from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class ConfidenceResult:
    """Result of confidence scoring"""
    score: float  # 0.0 - 1.0
    factors: List[str]  # Evidence supporting the score
    recommendation: str  # Action recommendation


class ConfidenceScorer:
    """Calculate confidence scores for security findings"""
    
    # Confidence thresholds
    HIGH_CONFIDENCE = 0.7
    MEDIUM_CONFIDENCE = 0.4
    
    @staticmethod
    def score_sql_injection(indicators: Dict) -> ConfidenceResult:
        """
        Score SQL injection findings
        
        High confidence (0.7-1.0):
        - Multiple SQL error patterns
        - SQLSTATE codes
        - Database-specific errors (ora-, pg_)
        
        Medium confidence (0.4-0.6):
        - Single generic SQL keyword
        - 500 error with SQL-like response
        
        Low confidence (0.0-0.3):
        - Generic "mysql" or "sql" in response
        - No error codes
        """
        confidence = 0.5
        factors = []
        response_body = indicators.get("response_body", "").lower()
        status_code = indicators.get("status_code", 200)
        
        # HIGH CONFIDENCE INDICATORS
        
        # SQLSTATE error codes (very specific)
        if re.search(r'sqlstate\[\w+\]', response_body):
            confidence += 0.3
            factors.append("SQLSTATE error code detected (high confidence)")
        
        # Database-specific error functions
        db_specific_patterns = [
            (r'ora-\d{5}', "Oracle error code"),
            (r'pg_query\(\)', "PostgreSQL function"),
            (r'mysql_fetch_', "MySQL fetch function"),
            (r'sqlite3\.operationalerror', "SQLite error"),
        ]
        for pattern, desc in db_specific_patterns:
            if re.search(pattern, response_body):
                confidence += 0.25
                factors.append(f"{desc} detected")
                break
        
        # SQL syntax error messages (specific)
        if re.search(r'(sql syntax|syntax error).*near', response_body):
            confidence += 0.2
            factors.append("SQL syntax error message")
        
        # MEDIUM CONFIDENCE INDICATORS
        
        # Multiple generic SQL keywords
        sql_keywords = ["mysql", "postgresql", "sqlstate", "sql syntax", "database"]
        keyword_count = sum(1 for kw in sql_keywords if kw in response_body)
        if keyword_count >= 3:
            confidence += 0.15
            factors.append(f"{keyword_count} SQL-related keywords found")
        elif keyword_count == 2:
            confidence += 0.05
            factors.append(f"{keyword_count} SQL keywords (moderate confidence)")
        
        # LOW CONFIDENCE PENALTIES
        
        # Generic error page
        if "<title>error</title>" in response_body or "error page" in response_body:
            confidence -= 0.2
            factors.append("Generic error page (may be false positive)")
        
        # Single generic keyword only
        if keyword_count == 1 and confidence < 0.6:
            confidence -= 0.1
            factors.append("Only single generic SQL keyword (low confidence)")
        
        # Response contains "mysql.com" or similar (not an error)
        if "mysql.com" in response_body or "postgresql.org" in response_body:
            confidence -= 0.3
            factors.append("Contains database website URL (likely false positive)")
        
        # Very large response (often false positives)
        if len(response_body) > 100000:
            confidence -= 0.15
            factors.append("Very large response (may be legitimate content)")
        
        # Normalize score
        confidence = max(0.0, min(1.0, confidence))
        
        # Generate recommendation
        if confidence >= ConfidenceScorer.HIGH_CONFIDENCE:
            recommendation = "High confidence - Investigate immediately"
        elif confidence >= ConfidenceScorer.MEDIUM_CONFIDENCE:
            recommendation = "Medium confidence - Manual verification recommended"
        else:
            recommendation = "Low confidence - Likely false positive, verify carefully"
        
        return ConfidenceResult(confidence, factors, recommendation)
    
    @staticmethod
    def score_xss(indicators: Dict) -> ConfidenceResult:
        """Score XSS findings"""
        confidence = 0.5
        factors = []
        payload = indicators.get("payload", "")
        response_body = indicators.get("response_body", "")
        
        # Check if payload is HTML-encoded (SAFE)
        if html.escape(payload) in response_body:
            confidence = 0.1
            factors.append("Payload is HTML-encoded (safe, false positive)")
            return ConfidenceResult(confidence, factors, "Low confidence - Payload is properly encoded")
        
        # Check if payload is reflected at all
        if payload not in response_body:
            confidence = 0.0
            factors.append("Payload not reflected in response")
            return ConfidenceResult(confidence, factors, "No XSS - Payload not reflected")
        
        # HIGH CONFIDENCE - Payload in executable context
        
        # In <script> tag
        if f"<script>{payload}" in response_body or f"<script>{payload}</script>" in response_body:
            confidence = 0.95
            factors.append("Payload in <script> tag (high confidence XSS)")
        
        # In event handler
        event_handlers = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus']
        for handler in event_handlers:
            if re.search(f'{handler}\\s*=\\s*["\']?.*{re.escape(payload)}', response_body, re.IGNORECASE):
                confidence = 0.9
                factors.append(f"Payload in {handler} event handler (high confidence)")
                break
        
        # In href with javascript:
        if f'href="javascript:{payload}' in response_body or f"href='javascript:{payload}" in response_body:
            confidence = 0.85
            factors.append("Payload in javascript: href (high confidence)")
        
        # MEDIUM CONFIDENCE - Reflected but context unclear
        
        # In HTML attribute value
        if re.search(r'\w+\s*=\s*["\'].*' + re.escape(payload), response_body):
            if confidence < 0.7:  # Don't downgrade if already high
                confidence = 0.6
                factors.append("Payload in HTML attribute (medium confidence)")
        
        # In HTML body but not in dangerous context
        if f"<body>{payload}" in response_body or f"<div>{payload}</div>" in response_body:
            if confidence < 0.6:
                confidence = 0.4
                factors.append("Payload in HTML body (low-medium confidence)")
        
        # LOW CONFIDENCE PENALTIES
        
        # Payload in comment
        if f"<!--{payload}-->" in response_body:
            confidence = 0.2
            factors.append("Payload in HTML comment (not executable, false positive)")
        
        # Payload in <pre> or <code> tag (often safe)
        if f"<pre>{payload}</pre>" in response_body or f"<code>{payload}</code>" in response_body:
            confidence = 0.3
            factors.append("Payload in <pre> or <code> tag (likely safe)")
        
        # Normalize
        confidence = max(0.0, min(1.0, confidence))
        
        # Recommendation
        if confidence >= 0.8:
            recommendation = "High confidence XSS - Exploit immediately testable"
        elif confidence >= 0.5:
            recommendation = "Medium confidence - Test in browser to confirm"
        else:
            recommendation = "Low confidence - Likely false positive or non-exploitable"
        
        return ConfidenceResult(confidence, factors, recommendation)
    
    @staticmethod
    def score_schema_validation(indicators: Dict) -> ConfidenceResult:
        """Score schema validation findings"""
        confidence = 0.5
        factors = []
        
        invalid_payloads_accepted = indicators.get("invalid_payloads_accepted", 0)
        total_payloads = indicators.get("total_payloads", 1)
        response_indicates_error = indicators.get("response_indicates_error", False)
        
        # HIGH CONFIDENCE - Multiple invalid payloads accepted
        if invalid_payloads_accepted >= 3:
            confidence = 0.8
            factors.append(f"{invalid_payloads_accepted} invalid payloads accepted (high confidence)")
        elif invalid_payloads_accepted == 2:
            confidence = 0.6
            factors.append(f"{invalid_payloads_accepted} invalid payloads accepted (medium confidence)")
        elif invalid_payloads_accepted == 1:
            confidence = 0.3
            factors.append("Only 1 invalid payload accepted (low confidence)")
        
        # PENALTIES
        
        # API might accept extra fields for forward compatibility
        if response_indicates_error:
            confidence += 0.1
            factors.append("Response indicates validation occurred")
        else:
            confidence -= 0.1
            factors.append("No error indication (may be lenient validation)")
        
        # Normalize
        confidence = max(0.0, min(1.0, confidence))
        
        if confidence >= 0.7:
            recommendation = "High confidence - Schema validation is weak"
        elif confidence >= 0.4:
            recommendation = "Medium confidence - May accept some invalid data"
        else:
            recommendation = "Low confidence - Likely false positive (lenient validation)"
        
        return ConfidenceResult(confidence, factors, recommendation)
    
    @staticmethod
    def score_generic(finding_type: str, indicators: Dict) -> ConfidenceResult:
        """
        Generic confidence scoring for findings without specific scorers
        
        Uses heuristics based on:
        - Number of indicators
        - Response characteristics
        - Error patterns
        """
        confidence = 0.5
        factors = [f"Using generic scoring for {finding_type}"]
        
        # Boost confidence if multiple indicators
        indicator_count = len([v for v in indicators.values() if v])
        if indicator_count >= 3:
            confidence += 0.2
            factors.append(f"{indicator_count} indicators present")
        
        # Check for specific error patterns
        response_body = indicators.get("response_body", "").lower()
        if "error" in response_body and "stack trace" in response_body:
            confidence += 0.15
            factors.append("Stack trace in response")
        
        confidence = max(0.0, min(1.0, confidence))
        recommendation = "Medium confidence - Manual verification recommended"
        
        return ConfidenceResult(confidence, factors, recommendation)
    
    @classmethod
    def score_finding(cls, finding_type: str, indicators: Dict) -> ConfidenceResult:
        """
        Main entry point for confidence scoring
        
        Args:
            finding_type: Type of finding (e.g., "SQL_Injection", "XSS")
            indicators: Dictionary of indicators and evidence
        
        Returns:
            ConfidenceResult with score, factors, and recommendation
        """
        # Route to specific scorer
        scorers = {
            "SQL_Injection": cls.score_sql_injection,
            "XSS": cls.score_xss,
            "Schema_Validation": cls.score_schema_validation,
        }
        
        scorer = scorers.get(finding_type, cls.score_generic)
        
        if scorer == cls.score_generic:
            return scorer(finding_type, indicators)
        else:
            return scorer(indicators)


# Example usage
if __name__ == "__main__":
    # Test SQL Injection scoring
    print("=== SQL Injection Test ===")
    
    # High confidence case
    result = ConfidenceScorer.score_sql_injection({
        "response_body": "SQLSTATE[42000]: Syntax error or access violation near 'SELECT'",
        "status_code": 500
    })
    print(f"Score: {result.score:.2f}")
    print(f"Factors: {result.factors}")
    print(f"Recommendation: {result.recommendation}\n")
    
    # Low confidence case
    result = ConfidenceScorer.score_sql_injection({
        "response_body": "Visit mysql.com for more information about databases",
        "status_code": 200
    })
    print(f"Score: {result.score:.2f}")
    print(f"Factors: {result.factors}")
    print(f"Recommendation: {result.recommendation}\n")
    
    # Test XSS scoring
    print("=== XSS Test ===")
    
    # High confidence
    result = ConfidenceScorer.score_xss({
        "payload": "<script>alert(1)</script>",
        "response_body": "<div><script>alert(1)</script></div>"
    })
    print(f"Score: {result.score:.2f}")
    print(f"Factors: {result.factors}")
    print(f"Recommendation: {result.recommendation}")
