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
import requests
import subprocess

class TestHarness:
    def __init__(self):
        self.flag = "SECRET_FLAG_DATA_123"
        self.server_process = None
        self.sandbox_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../sandbox"))
        self.backup_path = os.path.join(self.sandbox_dir, "vulnerable_code.py.bak")
        self.target_code_path = os.path.join(self.sandbox_dir, "vulnerable_code.py")
        self.server_url = "http://localhost:5000/analyze"

    def start_server(self, code_path: str = None, code_content: str = None, vulnerability_type: str = "SQL Injection"):
        """Starts the Flask app in a subprocess. Replaces target file if code requested."""
        if vulnerability_type == "RCE (Remote Code Execution)":
            target_name = "vulnerable_rce.py"
        elif vulnerability_type == "Buffer Overflow":
            target_name = "vulnerable_bof.c"
        else:
            target_name = "vulnerable_code.py"
            
        self.target_code_path = os.path.join(self.sandbox_dir, target_name)
        self.backup_path = self.target_code_path + ".bak"
        
        if not os.path.exists(self.backup_path) and os.path.exists(self.target_code_path):
            shutil.copyfile(self.target_code_path, self.backup_path)

        if code_path and os.path.exists(code_path) and os.path.abspath(code_path) != self.target_code_path:
            shutil.copyfile(code_path, self.target_code_path)
        elif code_content:
            with open(self.target_code_path, "w", encoding="utf-8") as f:
                f.write(code_content)
        
        env = os.environ.copy()
        
        print(f"Starting Flask server for {vulnerability_type}...")
        self.server_process = subprocess.Popen(
            [sys.executable, "app.py"],
            cwd=self.sandbox_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for server to start
        time.sleep(2)
        
        # Verify server is up
        try:
            requests.post(self.server_url, json={"username": "alice", "request_id": "ping"}, timeout=2)
        except Exception as e:
            print(f"Warning: Server might not be fully up: {e}")

    def stop_server(self):
        """Stops the Flask app and restores original vulnerable code."""
        if self.server_process:
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
            self.server_process = None
            
        if os.path.exists(self.backup_path):
            shutil.move(self.backup_path, self.target_code_path)

    def run_attack(self, payload: str, code_path: str = None, vulnerability_type: str = "SQL Injection") -> dict:
        """
        Runs the attack using the given payload.
        If the server isn't running, it starts it briefly for this attack.
        """
        manage_server = False
        if not self.server_process:
            manage_server = True
            self.start_server(code_path=code_path, vulnerability_type=vulnerability_type)
            
        result = {"success": False, "data": None, "error": None}
        
        endpoint = self.server_url
        if vulnerability_type == "RCE (Remote Code Execution)":
            endpoint = "http://localhost:5000/analyze_rce"
        elif vulnerability_type == "Buffer Overflow":
            endpoint = "http://localhost:5000/analyze_bof"
            
        try:
            input_data = {"username": payload, "request_id": "test_run_1"}
            response = requests.post(endpoint, json=input_data, timeout=5)
            # Flask may return 500 if the code raises an exception or syntax error
            
            try:
                res_json = response.json()
            except ValueError:
                result["error"] = f"Invalid JSON response. Status: {response.status_code}, Text: {response.text}"
                return result
                
            data = res_json.get("data")
            status = res_json.get("status")
            
            if status == "success" and data is not None:
                result["data"] = str(data)
                
                if vulnerability_type == "Buffer Overflow":
                    if res_json.get("returncode", 0) != 0:
                        result["success"] = True
                elif vulnerability_type == "RCE (Remote Code Execution)":
                    if "ATTACK_SUCCESS" in str(data) or "root:x:0:0" in str(data):
                        result["success"] = True
                else:
                    if self.flag in str(data):
                        result["success"] = True
            elif status == "error":
                result["error"] = res_json.get("error", "Unknown server error")
        except Exception as e:
            result["error"] = str(e)
            
        finally:
            if manage_server:
                self.stop_server()
                
        return result

    def verify_fix(self, code_content: str, security_payloads: list = None, vulnerability_type: str = "SQL Injection") -> dict:
        """
        Verifies the fix by running regression and security tests.
        """
        results = {
            "regression_passed": False,
            "security_passed": False,
            "details": []
        }
        
        try:
            self.start_server(code_content=code_content, vulnerability_type=vulnerability_type)
            
            # 1. Regression Test: Normal user
            res_normal = self.run_attack("alice", vulnerability_type=vulnerability_type)
            
            regression_pass = False
            if vulnerability_type == "SQL Injection":
                regression_pass = res_normal.get("data") and "Public Profile Data" in res_normal.get("data")
            elif vulnerability_type == "RCE (Remote Code Execution)":
                regression_pass = res_normal.get("data") and ("ping statistics" in res_normal.get("data").lower() or "reply from" in res_normal.get("data").lower() or "timed out" in res_normal.get("data").lower() or "not find host" in res_normal.get("data").lower())
            elif vulnerability_type == "Buffer Overflow":
                regression_pass = res_normal.get("data") and "Input copied successfully" in res_normal.get("data")
                
            if regression_pass:
                results["regression_passed"] = True
                results["details"].append("Regression Test: PASS")
            else:
                results["details"].append(f"Regression Test: FAIL ({res_normal.get('data')} | {res_normal.get('error')})")

            # 2. Security Test: Re-run attacks
            if not security_payloads:
                if vulnerability_type == "Buffer Overflow":
                    security_payloads = ["A" * 70]
                elif vulnerability_type == "RCE (Remote Code Execution)":
                    security_payloads = ["127.0.0.1 & echo ATTACK_SUCCESS"]
                else:
                    security_payloads = ["' OR '1'='1"]
                
            all_attacks_blocked = True
            for payload in security_payloads:
                res_attack = self.run_attack(payload, vulnerability_type=vulnerability_type)
                if res_attack["success"]: # Success means we prevented the leak? No, it means attack succeeded!
                    all_attacks_blocked = False
                    results["details"].append(f"Security Test: FAIL (Flag leaked with payload: {payload}!)")
                    break
                else:
                    results["details"].append(f"Security Test: blocked attack with payload: {payload}")
                    
            if all_attacks_blocked:
                results["security_passed"] = True
                results["details"].append("Security Test: PASS (No flags leaked)")
                
        finally:
            self.stop_server()
                
        return results

test_harness = TestHarness()

