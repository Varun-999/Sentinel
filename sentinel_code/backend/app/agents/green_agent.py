from app.models.state import RemediationState
from app.services.llm import llm_service
from app.core.test_harness import test_harness
from app.core.ast_analyzer import analyze_ast
from app.services.logger import get_logger

def green_agent(state: RemediationState) -> RemediationState:
    """
    Green Agent: Verifies the code by analyzing the patch.
    """
    logger = get_logger(state.workflow_id)
    logger.log_event("Green Agent", "Verifying", {"message": "Starting verification process"})
    
    # 1. AST-Level Safety Analysis (Skip for non-Python code)
    if state.vulnerability_type == "Buffer Overflow":
        ast_reasoning = "AST Analysis SKIPPED: Not supported for C language."
        ast_errors = []
        logger.log_event("Green Agent", "AST Skipped", {"message": "Skipping AST analysis for Buffer Overflow"})
    else:
        logger.log_event("Green Agent", "AST Analysis", {"message": "Running AST Analysis..."})
        ast_errors = analyze_ast(state.patch_diff)
        
        ast_reasoning = ""
        if ast_errors:
            ast_reasoning = "AST Analysis FAILED:\n" + "\n".join(ast_errors)
            logger.log_event("Green Agent", "AST Failed", {"errors": ast_errors})
        else:
            ast_reasoning = "AST Analysis PASSED: No unsafe query construction detected."
            logger.log_event("Green Agent", "AST Passed", {"message": "No unsafe query construction detected."})

    # 2. Automated Regression & Adversarial Testing
    logger.log_event("Green Agent", "Testing", {"message": "Executing Test Harness on patched code..."})
    
    # Pass Red agent's successful payloads to ensure they are blocked now
    security_payloads = state.exploit_payloads if state.exploit_payloads else None
    results = test_harness.verify_fix(state.patch_diff, security_payloads=security_payloads, vulnerability_type=state.vulnerability_type)
    
    execution_reasoning = "\n".join(results["details"])
    logger.log_event("Green Agent", "Test Results", {"results": results["details"], "passed": results["regression_passed"] and results["security_passed"]})
    
    # 3. LLM verification for semantic correctness (Optional but requested initially)
    # The requirement says "Act as the final authority that decides whether a patch is safe to accept"
    # "Validate code structure and semantics, Ensure no regressions, Verify exploits no longer work"
    # We fulfilled all natively. But let's keep the LLM check to ensure no helper functions were removed.
    language_tag = "c" if state.vulnerability_type == "Buffer Overflow" else "python"
    
    prompt = f"""
    You are a Security Auditor.
    Review the patched code.
    
    Code:
    ```{language_tag}
    {state.patch_diff}
    ```
    
    Task: Validate that NO existing functionality (e.g. legacy table handling, other imports) was removed or broken.
    Output 'PASS' if valid, 'FAIL: <reason>' if functionality was removed. Do not include markdown formatting.
    """
    llm_review = llm_service.generate_text(prompt).strip()
    
    verified = (not ast_errors) and results["regression_passed"] and results["security_passed"] and ("PASS" in llm_review)
    
    if verified:
        status = "PASS"
        reasoning = f"Automated Tests PASSED.\n{execution_reasoning}\n{ast_reasoning}\nLLM Review: {llm_review}"
    else:
        status = "FAIL"
        reasoning = f"Automated Tests FAILED.\n{execution_reasoning}\n{ast_reasoning}\nLLM Review: {llm_review}"

    state.verification_status = status
    state.verification_reasoning = reasoning
        
    logger.log_event("Green Agent", "Verification Completed", {
        "status": state.verification_status,
        "reasoning": reasoning
    })
    
    return state

