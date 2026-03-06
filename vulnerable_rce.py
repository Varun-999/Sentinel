import json
import subprocess

def get_system_info(request_payload):
    """
    Vulnerable function that pings a target host.
    The payload is directly interpolated into the command string without sanitization.
    """
    try:
        data = json.loads(request_payload)
        target_ip = data.get("username", "127.0.0.1")  # Using 'username' field for payload backward compatibility in test harness
        
        # VULNERABLE: Direct concatenation of user input into shell command
        command = f"ping -n 1 {target_ip}"
        
        print(f"Executing: {command}")
        # Using shell=True makes it vulnerable to command injection
        output = subprocess.check_output(command, shell=True, text=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Command execution failed: {e.output}"
    except Exception as e:
        return f"Error executing ping: {str(e)}"
