import sqlite3
import os
import importlib.util
import sys
import json

import os
import sys
import json
import time
import shutil
import subprocess

class TestHarness:
    def __init__(self):
        self.flag = "SECRET_FLAG_DATA_123"
        self.server_process = None
        self.sandbox_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../sandbox"))
        self.backup_path = os.path.join(self.sandbox_dir, "vulnerable_code.py.bak")
        self.target_code_path = os.path.join(self.sandbox_dir, "vulnerable_code.py")
        self.server_url = "http://localhost:5000/analyze"

    def start_server(self, code_path: str = None, code_content: str = None):
        """Starts the Flask app in a subprocess. Replaces vulnerable_code.py if code requested."""
        if not os.path.exists(self.backup_path):
            shutil.copyfile(self.target_code_path, self.backup_path)

        if code_path and os.path.exists(code_path) and os.path.abspath(code_path) != self.target_code_path:
            shutil.copyfile(code_path, self.target_code_path)
        elif code_content:
            with open(self.target_code_path, "w", encoding="utf-8") as f:
                f.write(code_content)
            # Ensure file is fully flushed to disk
            time.sleep(0.5)
        
        # Wait a bit longer for port to be released from previous server
        time.sleep(0.3)
        
        env = os.environ.copy()
        env['FLASK_ENV'] = 'production'
        env['PYTHONUNBUFFERED'] = '1'
        
        print("Starting Flask server...")
        self.server_process = subprocess.Popen(
            [sys.executable, "app.py"],
            cwd=self.sandbox_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait and retry for server startup
        max_retries = 20
        retry_count = 0
        server_ready = False
        
        while retry_count < max_retries and not server_ready:
            time.sleep(0.4)
            
            # Check if process has died
            if self.server_process.poll() is not None:
                print(f"ERROR: Flask process exited unexpectedly!")
                raise RuntimeError(f"Flask server failed to start.")
            
            try:
                import json
                import urllib.request
                import urllib.error
                data = json.dumps({"username": "alice", "request_id": "ping"}).encode('utf-8')
                req = urllib.request.Request(self.server_url, data=data, headers={'Content-Type': 'application/json'})
                try:
                    with urllib.request.urlopen(req, timeout=2) as response:
                        server_ready = True
                        print("Flask server is up and responding!")
                except urllib.error.HTTPError as e:
                    # An HTTPError (like 4xx or 500) means the server IS running and responding,
                    # even if the specific ping payload triggered an error.
                    server_ready = True
                    print(f"Flask server is up (responded with {e.code})!")
            except (urllib.error.URLError, OSError) as e:
                retry_count += 1
                print(f"Waiting for server... ({retry_count}/{max_retries})")
        
        if not server_ready:
            # Try to kill the process and read output
            if self.server_process:
                self.server_process.terminate()
                try:
                    stdout_output, stderr_output = self.server_process.communicate(timeout=2)
                    error_details = stderr_output or stdout_output or "No output available"
                    print(f"Server output:\n{error_details}")
                except Exception as e:
                    error_details = str(e)
                    print(f"Could not retrieve server output: {e}")
            raise RuntimeError(f"Flask server failed to start. Traceback:\n{error_details}")

    def stop_server(self):
        """Stops the Flask app and restores original vulnerable code."""
        if self.server_process:
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
                try:
                    self.server_process.wait(timeout=2)
                except:
                    pass
            self.server_process = None
            # Wait for port to be released
            time.sleep(0.8)
            
        if os.path.exists(self.backup_path):
            try:
                shutil.move(self.backup_path, self.target_code_path)
            except Exception as e:
                print(f"Warning: Could not restore backup: {e}")
                # If move fails, try to remove and copy instead
                try:
                    os.remove(self.target_code_path)
                    shutil.copy(self.backup_path, self.target_code_path)
                    os.remove(self.backup_path)
                except:
                    pass

    def run_attack(self, payload, code_path: str = None, vuln_type: str = "SQL") -> dict:
        """
        Runs the attack using the given payload with retry logic.
        Payload may be a string or dictionary depending on vulnerability type.
        If the server isn't running, it starts it briefly for this attack.
        """
        manage_server = False
        if not self.server_process:
            manage_server = True
            self.start_server(code_path=code_path)
            
        result = {"success": False, "data": None, "error": None}
        
        def build_input(p):
            # if we've already been given a dict, just use it
            if isinstance(p, dict):
                return p
            # build input payloads according to the vulnerability type
            if vuln_type == "SQL":
                return {"username": p, "request_id": "test_run_1"}
            elif vuln_type == "XSS":
                return {"comment": p}
            elif vuln_type == "PATH_TRAVERSAL":
                return {"filename": p}
            elif vuln_type == "BUFFER_OVERFLOW":
                return {"input": p}
            elif vuln_type == "INFO_EXPOSURE":
                # some vulnerabilities expect both a key and data field
                return {"key": "test", "data": p}
            elif vuln_type == "XXE":
                # pass xml string inside a JSON object so the server will dump it to a string
                return {"xml": p}
            elif vuln_type == "SSRF":
                return {"url": p}
            elif vuln_type == "INSECURE_RANDOMNESS":
                # include a dummy user_id for token generation
                return {"user_id": 1, "data": p}
            elif vuln_type == "RACE_CONDITION":
                # additional fields are accepted by the vulnerable function
                return {"data": p}
            elif vuln_type == "BOLA":
                # the payloads in config are already JSON strings
                try:
                    return json.loads(p)
                except Exception:
                    return {"data": p}
            elif vuln_type == "HARDCODED_SECRETS":
                return {"data": p}
            elif vuln_type == "DESERIALIZATION":
                return {"session_data": p}
            else:
                return {"data": p}
        
        try:
            # Retry logic for sending the attack
            max_attack_retries = 3
            for attempt in range(max_attack_retries):
                try:
                    input_data = build_input(payload)
                    import json
                    import urllib.request
                    import urllib.error
                    data = json.dumps(input_data).encode('utf-8')
                    req = urllib.request.Request(self.server_url, data=data, headers={'Content-Type': 'application/json'})
                    with urllib.request.urlopen(req, timeout=5) as response:
                        res_text = response.read().decode('utf-8')
                        res_json = json.loads(res_text)
                        
                    data = res_json.get("data")
                    status = res_json.get("status")
                    
                    if status == "success" and data:
                        result["data"] = str(data)
                        if vuln_type == "XSS":
                            # Natural check for unescaped HTML reflection
                            if "<script>" in str(data) or "onerror" in str(data) or "javascript:" in str(data):
                                result["success"] = True
                        elif vuln_type == "PATH_TRAVERSAL":
                            # Natural string leak representing system files
                            if "root:x" in str(data) or "etc/passwd" in str(data) or "boot.ini" in str(data):
                                result["success"] = True
                        elif vuln_type == "DESERIALIZATION":
                            if "Command executed" in str(data) or "uid=0" in str(data):
                                result["success"] = True
                        else:
                            # Flag checks for SQL, Info Exposures
                            if self.flag and self.flag in str(data):
                                result["success"] = True
                                
                    elif status == "error":
                        result["error"] = res_json.get("error", "Unknown server error")
                        if vuln_type == "BUFFER_OVERFLOW" and ("Segmentation fault" in result["error"] or "Memory Error" in result["error"]):
                            result["success"] = True
                        elif vuln_type == "COMMAND_INJECTION" and "Timeout" in result["error"]:
                            result["success"] = True
                    
                    return result
                    
                except urllib.error.HTTPError as e:
                    # Server is definitely running, but the payload caused an error (e.g. 500)
                    try:
                        res_text = e.read().decode('utf-8')
                        res_json = json.loads(res_text)
                        result["error"] = res_json.get("error", f"HTTP {e.code}")
                    except Exception:
                        result["error"] = f"HTTP {e.code}"
                        
                    # Evaluate success for vulnerabilities that naturally cause HTTP errors (like crashes)
                    if vuln_type == "BUFFER_OVERFLOW" and ("Segmentation fault" in result["error"] or "Memory Error" in result["error"] or "MemoryError" in result["error"]):
                        result["success"] = True
                    elif vuln_type == "COMMAND_INJECTION" and "Timeout" in result["error"]:
                        result["success"] = True
                        
                    return result
                except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
                    if attempt < max_attack_retries - 1:
                        print(f"Attack attempt {attempt + 1} failed, retrying... ({str(e)[:50]})")
                        time.sleep(1)
                    else:
                        result["error"] = f"Failed to execute attack after {max_attack_retries} attempts: {str(e)}"
                except Exception as e:
                    result["error"] = str(e)
                    break
        finally:
            if manage_server:
                self.stop_server()
                
        return result

    def verify_fix(self, code_content: str, vulnerability_checklist: dict, successful_payloads: dict) -> dict:
        """
        Verifies the consolidated fix by running:
        1. Regression test for all vulnerabilities (valid user/normal input)
        2. Security test (ensure Red Agent's payloads fail for all found vulnerabilities)
        """
        results = {
            "regression_passed": True, # Assume true until one fails
            "security_passed": True,   # Assume true until one fails
            "details": []
        }
        
        # choose a normal payload based on vulnerability type
        normal_inputs = {
            "SQL": "alice",
            "XSS": "Hello world",
            "PATH_TRAVERSAL": "data.txt",
            "BUFFER_OVERFLOW": "safe"
        }
        
        try:
            self.start_server(code_content=code_content)
        except Exception as e:
            results["details"].append(f"FATAL: Server failed to start with patched code: {e}")
            results["regression_passed"] = False
            results["security_passed"] = False
            return results
        
        try:
            
            # Identify which vulnerabilities we need to check (the ones that were found)
            vulns_to_check = [vt for vt, success in vulnerability_checklist.items() if success]
            if not vulns_to_check:
                results["details"].append("No vulnerabilities were previously found to verify against.")
                return results

            # 1. Regression Test: Normal input for each
            for vuln_type in vulns_to_check:
                normal_payload = normal_inputs.get(vuln_type, "test")
                res_normal = self.run_attack(normal_payload, vuln_type=vuln_type)
                
                if res_normal.get("data"):
                    results["details"].append(f"Regression Test ({vuln_type}): PASS (Normal input returned data)")
                else:
                    results["details"].append(f"Regression Test ({vuln_type}): FAIL (No normal data | Error: {res_normal.get('error')})")
                    results["regression_passed"] = False

            # 2. Security Test: Re-run attacks for each
            for vuln_type in vulns_to_check:
                payloads = successful_payloads.get(vuln_type, [])
                if not payloads:
                    continue
                    
                for payload in payloads:
                    res_attack = self.run_attack(payload, vuln_type=vuln_type)
                    if res_attack.get("success"):
                        results["details"].append(f"Security Test ({vuln_type}): FAIL (payload {payload} succeeded with data {res_attack.get('data')})")
                        results["security_passed"] = False
                    else:
                        results["details"].append(f"Security Test ({vuln_type}): PASS (payload failed, effectively patched)")
                        
        finally:
            self.stop_server()
                
        return results

test_harness = TestHarness()

