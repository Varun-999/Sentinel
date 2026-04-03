from app.models.state import RemediationState
from app.services.llm import llm_service
from app.services.logger import get_logger
import difflib
import os


def _build_unified_diff(original_code: str, updated_code: str) -> str:
    diff_lines = difflib.unified_diff(
        original_code.splitlines(),
        updated_code.splitlines(),
        fromfile="original.py",
        tofile="patched.py",
        lineterm="",
    )
    diff_text = "\n".join(diff_lines)
    if diff_text.strip():
        return diff_text
    return updated_code

def blue_agent(state: RemediationState) -> RemediationState:
    """
    Blue Agent: Generates a consolidated fix for all discovered vulnerabilities.
    """
    logger = get_logger(state.workflow_id) if state.workflow_id else None
    if logger:
        logger.log_and_print("Blue Agent", "--- Blue Agent: Batch Patching ---")
    else:
        print("--- Blue Agent: Batch Patching ---")
    
    with open(state.code_path, "r") as f:
        code_content = f.read()

    # Dedicated deterministic test fixture for frontend/state-flow verification.
    # This avoids spending LLM calls when we intentionally want the workflow to
    # end in FAIL after the max iteration count.
    if os.path.basename(state.code_path) == "force_verification_fail.py":
        msg = "Deterministic test fixture detected. Reusing code to force verification failure flow."
        if logger:
            logger.log_and_print("Blue Agent", msg)
        else:
            print(msg)
        state.patched_code = code_content
        state.patch_diff = _build_unified_diff(code_content, code_content)
        state.patch_explanation = "Debug fixture: retained original code to exercise the repeated verification failure path."
        state.iteration_count += 1
        return state
    
    # Demonstrate agent cycling by intentionally failing the first iteration
    if state.iteration_count == 0:
        msg = "Iter 0: Simulating a flawed consolidated patch generation..."
        if logger:
            logger.log_and_print("Blue Agent", msg)
        else:
            print(msg)
        flawed_code = code_content.replace(
            "def ", "# INITIAL FLAWED BATCH PATCH ATTEMPT\ndef "
        )
        state.patched_code = flawed_code
        state.patch_diff = _build_unified_diff(code_content, flawed_code)
        state.patch_explanation = "Initial attempt: Tried to fix the issues by adding comments, but the core vulnerabilities remain unpatched."
    else:
        # Build prompt for all successful exploits
        vulns_to_fix = [vt for vt, success in state.vulnerability_checklist.items() if success]
        
        msg = f"Using LLM to fix multiple vulnerabilities: {', '.join(vulns_to_fix)}..."
        if logger:
            logger.log_and_print("Blue Agent", msg)
        else:
            print(msg)
            
        payloads_text = "\\n".join([f"- {vt}: {state.successful_payloads[vt]}" for vt in vulns_to_fix])
        
        prompt = f"""
        You are an expert Secure Code Developer.
        Your task is to fix MULTIPLE vulnerabilities in the provided code SIMULTANEOUSLY.
        
        The code is vulnerable to the following: {', '.join(vulns_to_fix)}
        
        Successful attack payloads that worked against the current code:
        {payloads_text}
        
        Vulnerable code:
        ```python
        {code_content}
        ```
        
        Provide ONLY the complete fixed Python file.
        IMPORTANT: Do NOT truncate the code! Do NOT write "rest of the code here". You must return the ENTIRE file from the first import to the last function.
        IMPORTANT: Your response must be a SINGLE continuous ```python block containing the full script. Do not split it across multiple blocks.

        Follow extremely secure coding practices to fix ALL listed vulnerabilities at once:
        - CRITICAL: Do NOT use ANY string formatting (f-strings, %, .format, or +) for SQL queries! You MUST rewrite the logic to use standard parameterized SQLite queries (e.g., `cursor.execute("SELECT * FROM table WHERE user=?", (user,))`). The AST analyzer will instantly reject any f-string SQL!
        - Escape/sanitize all user input (HTML escaping for XSS).
        - Validate file paths to prevent traversal securely (use `os.path.abspath` and `os.path.commonprefix`).
        - Enforce input size limits for buffer overflows.
        - NEVER use `pickle` for untrusted data. Use `json` instead.
        """
        
        fixed_code = llm_service.generate_text(prompt)
        
        # Strip markdown if present
        if "```python" in fixed_code:
            fixed_code = fixed_code.split("```python")[1].split("```")[0].strip()
        elif "```" in fixed_code:
            fixed_code = fixed_code.split("```")[1].split("```")[0].strip()
        
        fixed_code = fixed_code.strip()
        state.patched_code = fixed_code
        state.patch_diff = _build_unified_diff(code_content, fixed_code)
        state.patch_explanation = f"Applied unified secure coding patterns to remediate: {', '.join(vulns_to_fix)}."
    
    state.iteration_count += 1
    
    return state
