#!/usr/bin/env python3
"""
Test script for Module 1: Input & Data Validation Analyzer
Run basic tests to verify module functionality
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from common import get_logger, load_config
from module1_input_validation import Module1Analyzer, ZAPScanner, NiktoScanner, InputFuzzer


def test_zap_scanner():
    """Test ZAP scanner initialization"""
    print("\n" + "="*60)
    print("Testing ZAP Scanner")
    print("="*60)
    
    logger = get_logger("test_zap")
    config = load_config()
    
    zap_path = config.get_tool_path("zap")
    
    if not zap_path or not os.path.exists(zap_path):
        print("❌ ZAP not found at configured path")
        print(f"   Expected: {zap_path}")
        return False
    
    print(f"✓ ZAP found at: {zap_path}")
    
    scanner = ZAPScanner(zap_path, logger)
    print("✓ ZAP scanner initialized successfully")
    
    return True


def test_nikto_scanner():
    """Test Nikto scanner initialization"""
    print("\n" + "="*60)
    print("Testing Nikto Scanner")
    print("="*60)
    
    logger = get_logger("test_nikto")
    config = load_config()
    
    nikto_path = config.get_tool_path("nikto")
    
    if not nikto_path:
        print("❌ Nikto not found in configuration")
        return False
    
    print(f"✓ Nikto configured at: {nikto_path}")
    
    scanner = NiktoScanner(nikto_path, logger)
    print("✓ Nikto scanner initialized successfully")
    
    return True


def test_fuzzer():
    """Test custom fuzzer"""
    print("\n" + "="*60)
    print("Testing Custom Fuzzer")
    print("="*60)
    
    logger = get_logger("test_fuzzer")
    
    test_url = "http://example.com"
    fuzzer = InputFuzzer(test_url, logger)
    
    print(f"✓ Fuzzer initialized with target: {test_url}")
    print(f"✓ SQL payloads loaded: {len(fuzzer.SQL_PAYLOADS)}")
    print(f"✓ XSS payloads loaded: {len(fuzzer.XSS_PAYLOADS)}")
    print(f"✓ Dangerous extensions loaded: {len(fuzzer.DANGEROUS_EXTENSIONS)}")
    
    return True


def test_module1_initialization():
    """Test Module 1 initialization"""
    print("\n" + "="*60)
    print("Testing Module 1 Analyzer")
    print("="*60)
    
    logger = get_logger("test_module1")
    config = load_config()
    
    analyzer = Module1Analyzer(config, logger)
    
    print(f"✓ Module 1 initialized")
    print(f"✓ Target URL: {analyzer.target_url or 'Not configured'}")
    print(f"✓ Controls to test: {len(analyzer.controls)}")
    
    # Verify all controls are present
    expected_controls = [
        "SQL_Injection",
        "XSS",
        "HTTP_Request_Smuggling",
        "Client_Side_Validation",
        "File_Upload_Validation",
        "XML_Validation",
        "Schema_Validation",
        "Content_Type_Validation",
        "Buffer_Overflow_Basic",
        "DOS_Basic"
    ]
    
    for control in expected_controls:
        if control not in analyzer.controls:
            print(f"❌ Missing control: {control}")
            return False
        print(f"   ✓ {control}: {analyzer.controls[control]}")
    
    return True


def test_configuration():
    """Test configuration loading"""
    print("\n" + "="*60)
    print("Testing Configuration")
    print("="*60)
    
    config = load_config()
    
    print(f"✓ Configuration loaded")
    print(f"   Target URL: {config.get_target_url() or 'Not set'}")
    print(f"   API Base: {config.get_target_api() or 'Not set'}")
    print(f"   Output Dir: {config.get_output_dir()}")
    print(f"   Log Level: {config.get_log_level()}")
    print(f"   Timeout: {config.get_timeout()}s")
    
    # Check tool paths
    tools = ['zap', 'nikto']
    for tool in tools:
        path = config.get_tool_path(tool)
        if path:
            exists = os.path.exists(path)
            status = "✓" if exists else "❌"
            print(f"   {status} {tool}: {path}")
        else:
            print(f"   ⚠ {tool}: Not configured")
    
    return True


def test_directory_structure():
    """Test required directories exist"""
    print("\n" + "="*60)
    print("Testing Directory Structure")
    print("="*60)
    
    required_dirs = [
        'config',
        'common',
        'module1_input_validation',
        'outputs',
        'logs'
    ]
    
    all_exist = True
    for directory in required_dirs:
        exists = os.path.isdir(directory)
        status = "✓" if exists else "❌"
        print(f"{status} {directory}/")
        
        if not exists:
            all_exist = False
    
    return all_exist


def run_all_tests():
    """Run all tests"""
    print("\n" + "="*70)
    print(" MODULE 1 TEST SUITE".center(70))
    print("="*70)
    
    tests = [
        ("Directory Structure", test_directory_structure),
        ("Configuration", test_configuration),
        ("ZAP Scanner", test_zap_scanner),
        ("Nikto Scanner", test_nikto_scanner),
        ("Custom Fuzzer", test_fuzzer),
        ("Module 1 Initialization", test_module1_initialization)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ Test '{test_name}' failed with error:")
            print(f"   {str(e)}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*70)
    print(" TEST SUMMARY".center(70))
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:<10} {test_name}")
    
    print("\n" + "-"*70)
    print(f"Total: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print("="*70)
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
