import os
import json
import time
import sys
from pathlib import Path

# Fix python parsing path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from app.graph.workflow import app as workflow_app
from app.models.state import RemediationState
from app.core.vulnerability_config import VULNERABILITIES
from app.services.llm import llm_service

def run_batch():
    manifest_path = os.path.abspath("../sandbox/test_cases/manifest.json")
    if not os.path.exists(manifest_path):
        print(f"Error: Manifest not found at {manifest_path}")
        return

    with open(manifest_path, "r") as f:
        test_cases = json.load(f)

    all_vulns = list(VULNERABILITIES.keys())
    
    metrics = {
        "total_cases": len(test_cases),
        "total_known_vulns": len(test_cases),  # 1 confirmed known vulnerability per test case in our current setup
        "true_positives": 0,
        "false_positives": 0,
        "successful_patches": 0,
        "regressions_caused": 0,
        "total_mttr_seconds": 0.0,
        "total_tokens_used": 0,
        "adversarial_tests_passed": 0,
        "functional_tests_passed": 0,
        "total_adversarial_tests": 0,
        "total_functional_tests": 0
    }
    
    detailed_reports = []

    print(f"Starting batch execution on {len(test_cases)} cases...")
    batch_start_time = time.time()
    
    for case in test_cases:
        target_file = case["path"]
        ground_truth_target = case["target"] # e.g. 'SQL'
        print(f"\nEvaluating Case: {case['cve']} ({ground_truth_target})")
        
        initial_state = RemediationState(
            code_path=os.path.abspath(os.path.join("..", "sandbox", "test_cases", case["cve"][4:] + "_idx", "vulnerable_sample.py")), # We use absolute targeting but let's just pass absolute
            target_vulnerabilities=all_vulns,
            iteration_count=0,
            workflow_id=f"batch_{case['cve']}"
        )
        
        # Override with exact absolute Path
        initial_state.code_path = os.path.abspath(target_file)
        
        case_start = time.time()
        final_state_dict = workflow_app.invoke(initial_state)
        # LangGraph invoke returns a distinct State dict
        final_state = RemediationState(**final_state_dict) if isinstance(final_state_dict, dict) else final_state_dict
        case_end = time.time()
        
        mttr = case_end - case_start
        metrics["total_mttr_seconds"] += mttr
        
        # TPR / FPR logic
        # Red agent writes to vulnerability_checklist
        checklist = final_state.vulnerability_checklist
        detected_types = [v for v, detected in checklist.items() if detected]
        
        tp_found = ground_truth_target in detected_types
        if tp_found:
            metrics["true_positives"] += 1
            
        fp_detected = len([v for v in detected_types if v != ground_truth_target])
        metrics["false_positives"] += fp_detected
        
        # Patch Success Logic
        # It's a successful patch ONLY if the green agent passed verification (functional AND adversarial)
        is_patched = (final_state.verification_status == "PASS")
        if is_patched and tp_found:
            metrics["successful_patches"] += 1
            
        # Regression Logic
        # Regression rate: Red flag if it broke original logic while patching
        # Specifically, if regression_passed is False, it means normal functionalities broke!
        if final_state.regression_passed == False:
            metrics["regressions_caused"] += 1
            
        # Verification Rigor Logic
        # Adversarial Test mapping: 
        # green agent ran security test (to verify red agent payloads no longer work)
        metrics["total_functional_tests"] += 1
        if final_state.regression_passed:
            metrics["functional_tests_passed"] += 1
            
        metrics["total_adversarial_tests"] += len(detected_types) # security test runs once per detected vulnerability
        if final_state.security_passed:
             metrics["adversarial_tests_passed"] += len(detected_types)
             
        detailed_reports.append({
            "cve": case["cve"],
            "ground_truth": ground_truth_target,
            "detected": detected_types,
            "mttr_sec": round(mttr, 2),
            "verification_status": final_state.verification_status,
            "regression_passed": final_state.regression_passed,
            "security_passed": final_state.security_passed
        })
        
    metrics["total_tokens_used"] = llm_service.total_tokens_used
    
    # Calculate finals
    tpr = (metrics["true_positives"] / metrics["total_known_vulns"]) * 100 if metrics["total_known_vulns"] else 0
    psr = (metrics["successful_patches"] / metrics["true_positives"]) * 100 if metrics["true_positives"] else 0
    token_eff = metrics["total_tokens_used"] / len(test_cases)
    avg_mttr = metrics["total_mttr_seconds"] / len(test_cases)
    
    metrics_summary = f"""
Sentinel Batch Ingestion Metrics Showcase
=========================================
Total Cases Analyzed:   {metrics['total_cases']}
True Positive Rate:     {tpr:.2f}% ({metrics['true_positives']}/{metrics['total_known_vulns']})
False Positives (FPR):  {metrics['false_positives']} total incorrect classifications
Patch Success Rate:     {psr:.2f}% (Patched {metrics['successful_patches']} out of {metrics['true_positives']} detected)
Regression Rate:        {(metrics['regressions_caused'] / metrics['total_cases']) * 100:.2f}% ({metrics['regressions_caused']} cases ruined functional logic)
Mean Time To Remediate: {avg_mttr:.2f} seconds / vulnerability
API Token Efficiency:   {token_eff:.2f} tokens / fix
Verification Rigor:     {metrics['adversarial_tests_passed']}/{metrics['total_adversarial_tests']} Adversarial Tests Passed | {metrics['functional_tests_passed']}/{metrics['total_functional_tests']} Functional Tests Passed
"""
    
    print(metrics_summary)
    
    with open("metrics_showcase.txt", "w") as f:
        f.write(metrics_summary)
        
    with open("batch_report.json", "w") as f:
        json.dump({
            "summary_metrics": metrics,
            "detailed_reports": detailed_reports
        }, f, indent=4)
        
    print("Metrics rigorously exported to metrics_showcase.txt and batch_report.json.")

if __name__ == "__main__":
    run_batch()
