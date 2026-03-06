from app.models.state import RemediationState
from app.services.llm import llm_service
from app.services.logger import get_logger
import os

def blue_agent(state: RemediationState) -> RemediationState:
    """
    Blue Agent: Generates a fix for the vulnerability.
    """
    logger = get_logger(state.workflow_id)
    logger.log_event("Blue Agent", "Patching", {"message": f"Starting to patch {state.vulnerability_type} vulnerability"})
    
    with open(state.code_path, "r") as f:
        code_content = f.read()

    if state.vulnerability_type == "SQL Injection":
        constraints = "Use parameterized queries (e.g. `cursor.execute(query, params)`) instead of string formatting or concatenation."
    elif state.vulnerability_type == "RCE (Remote Code Execution)":
        constraints = "Use safe `subprocess` invocation (e.g. passing a list of arguments without `shell=True`) or sanitize inputs using `shlex.quote`."
    elif state.vulnerability_type == "Buffer Overflow":
        constraints = "Use safe string copying functions bounded by the buffer size, such as `strncpy` instead of `strcpy`, and ensure null termination."
    else:
        constraints = "Apply secure coding practices to fix the vulnerability."

    language_tag = "c" if state.vulnerability_type == "Buffer Overflow" else "python"
    
    prompt = f"""
    You are an expert Secure Code Developer.
    Fix the {state.vulnerability_type} vulnerability in the following code.
    An attacker found this exploit: {state.exploit_payloads[-1] if state.exploit_payloads else 'None'}
    
    Constraints:
    1. Modify ONLY the security-relevant code. Do not remove or change any other functionality (e.g. legacy table support).
    2. {constraints}
    3. Ensure minimal code changes. Do not over-engineer.
    
    Code:
    ```{language_tag}
    {code_content}
    ```
    
    Provide the fixed code. Return ONLY the {language_tag} code for the fixed file, without markdown formatting or conversational text.
    """

    logger.log_event("Blue Agent", "LLM Request", {"message": "Requesting patch from LLM"})
    fixed_code = llm_service.generate_text(prompt)
    
    # Strip markdown code blocks if present
    if f"```{language_tag}" in fixed_code:
        fixed_code = fixed_code.split(f"```{language_tag}")[1].split("```")[0].strip()
    elif "```" in fixed_code:
        fixed_code = fixed_code.split("```")[1].split("```")[0].strip()
    
    # Store full patched code in state
    state.patch_diff = fixed_code.strip()
    state.patch_explanation = "Applied secure coding practices (parameterized queries)."
    state.iteration_count += 1
    
    logger.log_event("Blue Agent", "Patch Generated", {"iteration": state.iteration_count})
    return state
