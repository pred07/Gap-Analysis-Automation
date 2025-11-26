#!/usr/bin/env python3
"""
Verification script to test multi-target merging logic.
Runs Module 1 on 2 dummy URLs to ensure both are preserved in the output.
"""
import sys
import json
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.absolute()))

from common import load_config
from batch_analysis.orchestrator import BatchOrchestrator

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("VerifyFix")

def verify_fix():
    print("\n🔍 STARTING VERIFICATION TEST...")
    
    # 1. Setup
    config = load_config("config")
    orchestrator = BatchOrchestrator(config=config, debug=True)
    
    # 2. Define test targets
    test_targets = [
        "https://example.com",
        "https://google.com"
    ]
    
    print(f"🎯 Testing with {len(test_targets)} URLs: {test_targets}")
    
    # 3. Run ONLY Module 1 (Input Validation)
    # This is fast and safe
    print("🚀 Running Module 1...")
    results = orchestrator.execute_all_modules(
        targets=test_targets,
        modules=[1]  # Only Module 1
    )
    
    # 4. Verify Results
    print("\n📊 VERIFYING RESULTS...")
    
    # Check in-memory results
    mod1_result = results.module_results.get(1, {})
    if not mod1_result.get("success"):
        print("❌ Module 1 execution failed!")
        return False
        
    output_file = mod1_result.get("output_file")
    print(f"📄 Output file: {output_file}")
    
    # Read the file to check contents
    with open(output_file, 'r') as f:
        data = json.load(f)
        
    saved_targets = data.get("targets", [])
    saved_urls = [t.get("target") for t in saved_targets]
    
    print(f"📝 Found {len(saved_targets)} targets in output file:")
    for url in saved_urls:
        print(f"   - {url}")
        
    # 5. Final Verdict
    if len(saved_targets) == 2:
        print("\n✅ SUCCESS! Both targets were saved.")
        print("   The fix is working correctly. You can safely run the full batch.")
        return True
    else:
        print(f"\n❌ FAILURE! Expected 2 targets, found {len(saved_targets)}.")
        print("   The fix is NOT working.")
        return False

if __name__ == "__main__":
    success = verify_fix()
    sys.exit(0 if success else 1)
