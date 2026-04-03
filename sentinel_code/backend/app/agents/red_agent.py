from app.models.state import RemediationState
from app.services.llm import llm_service
from app.core.test_harness import test_harness
from app.core.vulnerability_config import get_payloads_for_type
from app.services.logger import get_logger
from app.services.target_validator import validate_target_file
import os

def red_agent(state: RemediationState) -> RemediationState:
    """
    Red Agent: Simulates an attack on the vulnerable code.
    Iterates through all target vulnerabilities, tests payloads, and builds a checklist.
    """
    logger = get_logger(state.workflow_id) if state.workflow_id else None
    if logger:
        logger.log_and_print("Red Agent", "--- Red Agent: Attacking ---")
    else:
        print("--- Red Agent: Attacking ---")
    
    is_valid, validation_message = validate_target_file(state.code_path)
    if not is_valid:
        msg = validation_message
        state.verification_status = "FAIL"
        state.verification_reasoning = validation_message
        if logger:
            logger.log_and_print("Red Agent", msg)
        else:
            print(msg)
        return state

    # Initialize checklists if not already
    if not state.vulnerability_checklist:
        state.vulnerability_checklist = {}
    if not state.successful_payloads:
        state.successful_payloads = {}

    any_success = False

    test_harness.stop_server()  # Ensure clean state
    try:
        test_harness.start_server(code_path=state.code_path)
    except Exception as e:
        msg = f"FATAL ERROR: Target file prevented server from starting. Check syntax or imports: {e}"
        if logger:
            logger.log_and_print("Red Agent", msg)
        else:
            print(msg)
        return state

    try:
        for vuln_type in state.target_vulnerabilities:
            PAYLOADS = get_payloads_for_type(vuln_type)
            if not PAYLOADS:
                continue

            msg = f"Executing payloads ({vuln_type}) against {state.code_path} via TestHarness..."
            if logger:
                logger.log_and_print("Red Agent", msg)
            else:
                print(msg)
                
            success = False
            successful_payload = None
            
            for payload in PAYLOADS:
                attempt_msg = f"Trying {vuln_type} payload: {payload}"
                if logger:
                    logger.log_and_print("Red Agent", attempt_msg)
                else:
                    print(attempt_msg)
                result = test_harness.run_attack(payload, vuln_type=vuln_type)
                
                if result["success"]:
                    exploit_msg = f"{vuln_type} Exploit VERIFIED! Flag leaked: {result['data']}"
                    if logger:
                        logger.log_and_print("Red Agent", exploit_msg)
                    else:
                        print(exploit_msg)
                    success = True
                    successful_payload = payload
                    break
                else:
                    failure_msg = f"Failed. Output: {result.get('data')} | Error: {result.get('error')}"
                    if logger:
                        logger.log_and_print("Red Agent", failure_msg)
                    else:
                        print(failure_msg)

            state.vulnerability_checklist[vuln_type] = success
            if logger:
                logger.update_checklist(state.vulnerability_checklist)
                
            if success:
                any_success = True
                state.successful_payloads[vuln_type] = [successful_payload]
                
                # PoC Generation
                def make_payload_snippet(vt, p):
                    if isinstance(p, dict): return p
                    if vt == "SQL": return {"username": p, "request_id": "poc_1"}
                    elif vt == "XSS": return {"comment": p}
                    elif vt == "PATH_TRAVERSAL": return {"filename": p}
                    elif vt == "BUFFER_OVERFLOW": return {"input": p}
                    elif vt == "INFO_EXPOSURE": return {"key": "test", "data": p}
                    elif vt == "XXE": return {"xml": p}
                    elif vt == "SSRF": return {"url": p}
                    elif vt == "INSECURE_RANDOMNESS": return {"user_id": 1, "data": p}
                    elif vt == "RACE_CONDITION": return {"data": p}
                    elif vt == "BOLA":
                        try:
                            import json as _json
                            return _json.loads(p)
                        except Exception: return {"data": p}
                    elif vt == "HARDCODED_SECRETS": return {"data": p}
                    elif vt == "DESERIALIZATION": return {"session_data": p}
                    else: return {"data": p}

                poc_payload = make_payload_snippet(vuln_type, successful_payload)
                poc_content = f"""import requests

# Auto-generated PoC exploit by Red Agent - {vuln_type}
url = "http://localhost:5000/analyze"
payload = {poc_payload}
try:
    response = requests.post(url, json=payload, timeout=5)
    print("Status:", response.status_code)
    print("Response:", response.json())
except Exception as e:
    print("Error:", e)
"""
                poc_path = os.path.join(os.path.dirname(state.code_path), f"poc_exploit_{vuln_type}.py")
                with open(poc_path, "w") as f:
                    f.write(poc_content)
    finally:
        test_harness.stop_server()

    if not any_success:
        msg = "Red Agent: All payloads failed across all vulnerability types. No exploits found."
        if logger:
            logger.log_and_print("Red Agent", msg)
        else:
            print(msg)
        state.verification_status = "PASS"
        state.verification_reasoning = "No successful exploit payloads found for any vulnerability. System appears secure."

    return state
