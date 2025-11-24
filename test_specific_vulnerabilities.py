#!/usr/bin/env python3
"""Test specific vulnerable endpoints"""
import sys
sys.path.insert(0, '.')

from module1_input_validation.fuzzer import InputFuzzer
from common import get_logger

logger = get_logger("vuln_test", debug_mode=True)

# Test known vulnerable pages
vulnerable_pages = [
    "http://testphp.vulnweb.com/artists.php",
    "http://testphp.vulnweb.com/listproducts.php",
    "http://testphp.vulnweb.com/showimage.php",
]

print("\n" + "="*60)
print("Testing Known Vulnerable Pages")
print("="*60 + "\n")

for page in vulnerable_pages:
    print(f"\nTesting: {page}")
    print("-" * 60)
    
    fuzzer = InputFuzzer(page, logger)
    
    # Test SQLi
    sql_results = fuzzer.test_sql_injection()
    if sql_results["vulnerable"]:
        print(f"✗ SQLi VULNERABLE - Found {len(sql_results['findings'])} issues")
        for finding in sql_results['findings']:
            print(f"  • Payload: {finding['payload']}")
            print(f"    Error: {finding['error']}")
    else:
        print(f"✓ SQLi - No issues detected (tested {sql_results['tested_payloads']} payloads)")
    
    # Test XSS
    xss_results = fuzzer.test_xss()
    if xss_results["vulnerable"]:
        print(f"✗ XSS VULNERABLE - Found {len(xss_results['findings'])} issues")
        for finding in xss_results['findings']:
            print(f"  • Payload: {finding['payload']}")
    else:
        print(f"✓ XSS - No issues detected (tested {xss_results['tested_payloads']} payloads)")

print("\n" + "="*60)
print("Testing Complete")
print("="*60)
