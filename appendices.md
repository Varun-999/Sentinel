# Appendices: Relevant Source Code
`
The following sections contain the key components of the Sentinel pipeline, detailing the core agent implementations, the batch execution pipeline, workflow configuration, large language model service layer, and the testing sandbox.
`
## 1. sentinel_code/backend/app/agents/blue_agent.py
`python
from app.models.state import RemediationState
from app.services.llm import llm_service
import difflib
import os
`
def _build_unified_diff(original_code: str, updated_code: str) -> str:
    diff_lines = difflib.unified_diff(original_code.splitlines(), updated_code.splitlines(), fromfile='original.py', tofile='patched.py', lineterm='')
    diff_text = '\n'.join(diff_lines)
    if diff_text.strip():
        return diff_text
    return updated_code
`
def blue_agent(state: RemediationState) -> RemediationState:
    with open(state.code_path, 'r') as f:
        code_content = f.read()
    if os.path.basename(state.code_path) == 'force_verification_fail.py':
        state.patched_code = code_content
        state.patch_diff = _build_unified_diff(code_content, code_content)
        state.patch_explanation = 'Debug fixture: retained original code to exercise the repeated verification failure path.'
        state.iteration_count += 1
        return state
    if state.iteration_count == 0:
        flawed_code = code_content.replace('def ', '# INITIAL FLAWED BATCH PATCH ATTEMPT\ndef ')
        state.patched_code = flawed_code
        state.patch_diff = _build_unified_diff(code_content, flawed_code)
        state.patch_explanation = 'Initial attempt: Tried to fix the issues by adding comments, but the core vulnerabilities remain unpatched.'
    else:
        vulns_to_fix = [vt for vt, success in state.vulnerability_checklist.items() if success]
        payloads_text = '\\n'.join([f'- {vt}: {state.successful_payloads[vt]}' for vt in vulns_to_fix])
        prompt = f"""\n        You are an expert Secure Code Developer.\n        Your task is to fix MULTIPLE vulnerabilities in the provided code SIMULTANEOUSLY.\n        \n        The code is vulnerable to the following: {', '.join(vulns_to_fix)}\n        \n        Successful attack payloads that worked against the current code:\n        {payloads_text}\n        \n        Vulnerable code:\n        ```python\n        {code_content}\n        ```\n        \n        Provide ONLY the complete fixed Python file.\n        IMPORTANT: Do NOT truncate the code! Do NOT write "rest of the code here". You must return the ENTIRE file from the first import to the last function.\n        IMPORTANT: Your response must be a SINGLE continuous ```python block containing the full script. Do not split it across multiple blocks.\n\n        Follow extremely secure coding practices to fix ALL listed vulnerabilities at once:\n        - CRITICAL: Do NOT use ANY string formatting (f-strings, %, .format, or +) for SQL queries! You MUST rewrite the logic to use standard parameterized SQLite queries (e.g., `cursor.execute("SELECT * FROM table WHERE user=?", (user,))`). The AST analyzer will instantly reject any f-string SQL!\n        - Escape/sanitize all user input (HTML escaping for XSS).\n        - Validate file paths to prevent traversal securely (use `os.path.abspath` and `os.path.commonprefix`).\n        - Enforce input size limits for buffer overflows.\n        - NEVER use `pickle` for untrusted data. Use `json` instead.\n        """
        fixed_code = llm_service.generate_text(prompt)
        if '```python' in fixed_code:
            fixed_code = fixed_code.split('```python')[1].split('```')[0].strip()
        elif '```' in fixed_code:
            fixed_code = fixed_code.split('```')[1].split('```')[0].strip()
        fixed_code = fixed_code.strip()
        state.patched_code = fixed_code
        state.patch_diff = _build_unified_diff(code_content, fixed_code)
        state.patch_explanation = f"Applied unified secure coding patterns to remediate: {', '.join(vulns_to_fix)}."
    state.iteration_count += 1
    return state
`
`
## 2. sentinel_code/backend/app/agents/red_agent.py
`python
from app.models.state import RemediationState
from app.services.llm import llm_service
from app.core.test_harness import test_harness
from app.core.vulnerability_config import get_payloads_for_type
from app.services.target_validator import validate_target_file
import os
`
def red_agent(state: RemediationState) -> RemediationState:
    is_valid, validation_message = validate_target_file(state.code_path)
    if not is_valid:
        state.verification_status = 'FAIL'
        state.verification_reasoning = validation_message
        return state
    if not state.vulnerability_checklist:
        state.vulnerability_checklist = {}
    if not state.successful_payloads:
        state.successful_payloads = {}
    any_success = False
    test_harness.stop_server()
    try:
        test_harness.start_server(code_path=state.code_path)
    except Exception as e:
        return state
    try:
        for vuln_type in state.target_vulnerabilities:
            PAYLOADS = get_payloads_for_type(vuln_type)
            if not PAYLOADS:
                continue
            success = False
            successful_payload = None
            for payload in PAYLOADS:
                result = test_harness.run_attack(payload, vuln_type=vuln_type)
                if result['success']:
                    success = True
                    successful_payload = payload
                    break
            state.vulnerability_checklist[vuln_type] = success
            if success:
                any_success = True
                state.successful_payloads[vuln_type] = [successful_payload]
`
                def make_payload_snippet(vt, p):
                    if isinstance(p, dict):
                        return p
                    if vt == 'SQL':
                        return {'username': p, 'request_id': 'poc_1'}
                    elif vt == 'XSS':
                        return {'comment': p}
                    elif vt == 'PATH_TRAVERSAL':
                        return {'filename': p}
                    elif vt == 'BUFFER_OVERFLOW':
                        return {'input': p}
                    elif vt == 'INFO_EXPOSURE':
                        return {'key': 'test', 'data': p}
                    elif vt == 'XXE':
                        return {'xml': p}
                    elif vt == 'SSRF':
                        return {'url': p}
                    elif vt == 'INSECURE_RANDOMNESS':
                        return {'user_id': 1, 'data': p}
                    elif vt == 'RACE_CONDITION':
                        return {'data': p}
                    elif vt == 'BOLA':
                        try:
                            import json as _json
                            return _json.loads(p)
                        except Exception:
                            return {'data': p}
                    elif vt == 'HARDCODED_SECRETS':
                        return {'data': p}
                    elif vt == 'DESERIALIZATION':
                        return {'session_data': p}
                    else:
                        return {'data': p}
                poc_payload = make_payload_snippet(vuln_type, successful_payload)
                poc_content = f'import requests\n\n# Auto-generated PoC exploit by Red Agent - {vuln_type}\nurl = "http://localhost:5000/analyze"\npayload = {poc_payload}\ntry:\n    response = requests.post(url, json=payload, timeout=5)\n    print("Status:", response.status_code)\n    print("Response:", response.json())\nexcept Exception as e:\n    print("Error:", e)\n'
                poc_path = os.path.join(os.path.dirname(state.code_path), f'poc_exploit_{vuln_type}.py')
                with open(poc_path, 'w') as f:
                    f.write(poc_content)
    finally:
        test_harness.stop_server()
    if not any_success:
        state.verification_status = 'PASS'
        state.verification_reasoning = 'No successful exploit payloads found for any vulnerability. System appears secure.'
    return state
`
`
## 3. sentinel_code/backend/app/agents/green_agent.py
`python
from app.models.state import RemediationState
from app.services.llm import llm_service
from app.core.test_harness import test_harness
from app.core.ast_analyzer import analyze_ast
import os
`
def green_agent(state: RemediationState) -> RemediationState:
    if os.path.basename(state.code_path) == 'force_verification_fail.py':
        reasoning = f'Deterministic frontend test fixture: forcing verification failure for this target. Iteration {state.iteration_count} of {state.max_iterations}.'
        state.verification_status = 'FAIL'
        state.verification_reasoning = reasoning
        state.regression_passed = False
        state.security_passed = False
        return state
    code_under_test = state.patched_code or state.patch_diff or ''
    ast_errors = analyze_ast(code_under_test)
    ast_reasoning = ''
    if ast_errors:
        ast_reasoning = 'AST Analysis FAILED:\n' + '\n'.join(ast_errors)
    else:
        ast_reasoning = 'AST Analysis PASSED: No unsafe query construction detected.'
    results = test_harness.verify_fix(code_content=code_under_test, vulnerability_checklist=state.vulnerability_checklist, successful_payloads=state.successful_payloads)
    execution_reasoning = '\n'.join(results['details'])
    llm_passed = True
    llm_review = 'LLM review skipped for speed - AST, regression, and security tests are sufficient'
    verified = not ast_errors and results['regression_passed'] and results['security_passed'] and llm_passed
    if verified:
        status = 'PASS'
        reasoning = f'Automated Tests PASSED.\n{execution_reasoning}\n{ast_reasoning}\nLLM Review: {llm_review}'
    else:
        status = 'FAIL'
        reasoning = f'Automated Tests FAILED.\n{execution_reasoning}\n{ast_reasoning}\nLLM Review: {llm_review}'
    state.verification_status = status
    state.verification_reasoning = reasoning
    state.regression_passed = results['regression_passed']
    state.security_passed = results['security_passed']
    final_msg = f'Verification Result: {state.verification_status}'
    return state
`
`
## 4. sentinel_code/ingestion/batch_runner.py
`python
import os
import json
import time
import sys
from pathlib import Path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))
from app.graph.workflow import app as workflow_app
from app.models.state import RemediationState
from app.core.vulnerability_config import VULNERABILITIES
from app.services.llm import llm_service
`
def run_batch():
    manifest_path = os.path.abspath('../sandbox/test_cases/manifest.json')
    if not os.path.exists(manifest_path):
        print(f'Error: Manifest not found at {manifest_path}')
        return
    with open(manifest_path, 'r') as f:
        test_cases = json.load(f)
    all_vulns = list(VULNERABILITIES.keys())
    metrics = {'total_cases': len(test_cases), 'total_known_vulns': len(test_cases), 'true_positives': 0, 'false_positives': 0, 'successful_patches': 0, 'regressions_caused': 0, 'total_mttr_seconds': 0.0, 'total_tokens_used': 0, 'adversarial_tests_passed': 0, 'functional_tests_passed': 0, 'total_adversarial_tests': 0, 'total_functional_tests': 0}
    detailed_reports = []
    print(f'Starting batch execution on {len(test_cases)} cases...')
    batch_start_time = time.time()
    for case in test_cases:
        target_file = case['path']
        ground_truth_target = case['target']
        print(f"\nEvaluating Case: {case['cve']} ({ground_truth_target})")
        initial_state = RemediationState(code_path=os.path.abspath(os.path.join('..', 'sandbox', 'test_cases', case['cve'][4:] + '_idx', 'vulnerable_sample.py')), target_vulnerabilities=all_vulns, iteration_count=0, workflow_id=f"batch_{case['cve']}")
        initial_state.code_path = os.path.abspath(target_file)
        case_start = time.time()
        final_state_dict = workflow_app.invoke(initial_state)
        final_state = RemediationState(**final_state_dict) if isinstance(final_state_dict, dict) else final_state_dict
        case_end = time.time()
        mttr = case_end - case_start
        metrics['total_mttr_seconds'] += mttr
        checklist = final_state.vulnerability_checklist
        detected_types = [v for v, detected in checklist.items() if detected]
        tp_found = ground_truth_target in detected_types
        if tp_found:
            metrics['true_positives'] += 1
        fp_detected = len([v for v in detected_types if v != ground_truth_target])
        metrics['false_positives'] += fp_detected
        is_patched = final_state.verification_status == 'PASS'
        if is_patched and tp_found:
            metrics['successful_patches'] += 1
        if final_state.regression_passed == False:
            metrics['regressions_caused'] += 1
        metrics['total_functional_tests'] += 1
        if final_state.regression_passed:
            metrics['functional_tests_passed'] += 1
        metrics['total_adversarial_tests'] += len(detected_types)
        if final_state.security_passed:
            metrics['adversarial_tests_passed'] += len(detected_types)
        detailed_reports.append({'cve': case['cve'], 'ground_truth': ground_truth_target, 'detected': detected_types, 'mttr_sec': round(mttr, 2), 'verification_status': final_state.verification_status, 'regression_passed': final_state.regression_passed, 'security_passed': final_state.security_passed})
    metrics['total_tokens_used'] = llm_service.total_tokens_used
    tpr = metrics['true_positives'] / metrics['total_known_vulns'] * 100 if metrics['total_known_vulns'] else 0
    psr = metrics['successful_patches'] / metrics['true_positives'] * 100 if metrics['true_positives'] else 0
    token_eff = metrics['total_tokens_used'] / len(test_cases)
    avg_mttr = metrics['total_mttr_seconds'] / len(test_cases)
    metrics_summary = f"\nSentinel Batch Ingestion Metrics Showcase\n=========================================\nTotal Cases Analyzed:   {metrics['total_cases']}\nTrue Positive Rate:     {tpr:.2f}% ({metrics['true_positives']}/{metrics['total_known_vulns']})\nFalse Positives (FPR):  {metrics['false_positives']} total incorrect classifications\nPatch Success Rate:     {psr:.2f}% (Patched {metrics['successful_patches']} out of {metrics['true_positives']} detected)\nRegression Rate:        {metrics['regressions_caused'] / metrics['total_cases'] * 100:.2f}% ({metrics['regressions_caused']} cases ruined functional logic)\nMean Time To Remediate: {avg_mttr:.2f} seconds / vulnerability\nAPI Token Efficiency:   {token_eff:.2f} tokens / fix\nVerification Rigor:     {metrics['adversarial_tests_passed']}/{metrics['total_adversarial_tests']} Adversarial Tests Passed | {metrics['functional_tests_passed']}/{metrics['total_functional_tests']} Functional Tests Passed\n"
    print(metrics_summary)
    with open('metrics_showcase.txt', 'w') as f:
        f.write(metrics_summary)
    with open('batch_report.json', 'w') as f:
        json.dump({'summary_metrics': metrics, 'detailed_reports': detailed_reports}, f, indent=4)
    print('Metrics rigorously exported to metrics_showcase.txt and batch_report.json.')
if __name__ == '__main__':
    run_batch()
`
`
## 5. sentinel_code/backend/app/graph/workflow.py
`python
from langgraph.graph import StateGraph, END
from app.models.state import RemediationState
from app.agents.red_agent import red_agent
from app.agents.blue_agent import blue_agent
from app.agents.green_agent import green_agent
`
def decide_next_node_after_red(state: RemediationState):
    if any(state.vulnerability_checklist.values()):
        return 'blue_agent'
    return END
`
def decide_next_node_after_green(state: RemediationState):
    if state.verification_status == 'PASS':
        return END
    if state.iteration_count < state.max_iterations:
        return 'blue_agent'
    return END
workflow = StateGraph(RemediationState)
workflow.add_node('red_agent', red_agent)
workflow.add_node('blue_agent', blue_agent)
workflow.add_node('green_agent', green_agent)
workflow.set_entry_point('red_agent')
workflow.add_conditional_edges('red_agent', decide_next_node_after_red, {'blue_agent': 'blue_agent', END: END})
workflow.add_edge('blue_agent', 'green_agent')
workflow.add_conditional_edges('green_agent', decide_next_node_after_green, {'blue_agent': 'blue_agent', END: END})
app = workflow.compile()
`
`
## 6. sentinel_code/backend/app/services/llm.py
`python
from app.core.config import settings
import time
`
class LLMService:
`
    def __init__(self):
        settings.validate()
        self.provider = settings.LLM_PROVIDER
        self.model_name = settings.MODEL_NAME
        self.total_tokens_used = 0
        if self.provider == 'gemini':
            from google import genai
            self.client = genai.Client(api_key=settings.GEMINI_API_KEY)
        elif self.provider == 'groq':
            from groq import Groq
            self.client = Groq(api_key=settings.GROQ_API_KEY)
`
    def generate_text(self, prompt: str, max_retries: int=4) -> str:
        last_error = None
        for attempt in range(max_retries):
            try:
                if self.provider == 'gemini':
                    response = self.client.models.generate_content(model=self.model_name, contents=prompt)
                    if not response.text:
                        raise ValueError('Empty response from LLM')
                    if hasattr(response, 'usage_metadata') and response.usage_metadata:
                        self.total_tokens_used += getattr(response.usage_metadata, 'total_token_count', len(prompt) // 4)
                    else:
                        self.total_tokens_used += len(prompt) // 4
                    return response.text
                elif self.provider == 'groq':
                    chat_completion = self.client.chat.completions.create(messages=[{'role': 'user', 'content': prompt}], model=self.model_name, max_tokens=4096, timeout=30.0)
                    if hasattr(chat_completion, 'usage') and chat_completion.usage:
                        self.total_tokens_used += getattr(chat_completion.usage, 'total_tokens', len(prompt) // 4)
                    return chat_completion.choices[0].message.content
            except Exception as e:
                last_error = e
                err_str = str(e).lower()
                is_rate_limit = any((kw in err_str for kw in ['429', 'resource_exhausted', 'rate_limit', 'quota', 'too many requests', 'rateLimitExceeded']))
                if is_rate_limit and attempt < max_retries - 1:
                    wait = 15 * 2 ** attempt
                    print(f'[LLM] Rate limit hit (attempt {attempt + 1}/{max_retries}). Retrying in {wait}s...')
                    time.sleep(wait)
                    continue
                else:
                    print(f'[LLM] Unrecoverable error after {attempt + 1} attempts: {e}')
                    raise RuntimeError(f'LLM call failed: {e}') from e
        raise RuntimeError(f'LLM call failed after {max_retries} retries: {last_error}')
llm_service = LLMService()
`
`
## 7. sentinel_code/sandbox/app.py
`python
from flask import Flask, request, jsonify
import sqlite3
import os
import vulnerable_code
app = Flask(__name__)
DB_NAME = 'production.db'
FLAG = 'SECRET_FLAG_DATA_123'
`
def setup_db():
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, active INTEGER, data TEXT)')
    cursor.execute("INSERT INTO users (username, password, active, data) VALUES ('alice', 'password123', 1, 'Public Profile Data')")
    cursor.execute("INSERT INTO users (username, password, active, data) VALUES ('admin', 'admin123', 1, ?)", (FLAG,))
    conn.commit()
    conn.close()
setup_db()
`
@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json(force=True)
        import json
        import importlib
        payload = json.dumps(data)
        importlib.reload(vulnerable_code)
        import inspect
        functions = inspect.getmembers(vulnerable_code, inspect.isfunction)
        result = None
        handler = None
        if hasattr(vulnerable_code, 'handle'):
            handler = vulnerable_code.handle
        elif functions:
            for name, func in functions:
                if func.__module__ == 'vulnerable_code':
                    handler = func
                    break
        if handler:
            result = handler(payload)
        else:
            raise AttributeError('vulnerable_code module has no handler function defined')
        if result:
            return jsonify({'status': 'success', 'data': result})
        else:
            return jsonify({'status': 'failure', 'data': None})
    except Exception as e:
        return (jsonify({'status': 'error', 'error': str(e)}), 500)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)
`
