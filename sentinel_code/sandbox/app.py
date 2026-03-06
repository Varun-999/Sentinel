from flask import Flask, request, jsonify
import sqlite3
import os
import subprocess

app = Flask(__name__)

DB_NAME = "production.db"
FLAG = "SECRET_FLAG_DATA_123"

def setup_db():
    """Initialize the database with sample data."""
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
        
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, active INTEGER, data TEXT)")
    
    # Insert normal user
    cursor.execute("INSERT INTO users (username, password, active, data) VALUES ('alice', 'password123', 1, 'Public Profile Data')")
    
    # Insert admin user with FLAG
    cursor.execute("INSERT INTO users (username, password, active, data) VALUES ('admin', 'admin123', 1, ?)", (FLAG,))
    
    conn.commit()
    conn.close()

# Initialize DB on startup
setup_db()

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json(force=True)
        # Pass the raw JSON string to the vulnerable function as it expects
        # In a real app, this might be request.data or similar
        import json
        payload = json.dumps(data)
        
        import vulnerable_code
        result = vulnerable_code.get_secure_user_data(payload)
        
        if result:
            return jsonify({"status": "success", "data": result})
        else:
            return jsonify({"status": "failure", "data": None})
            
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/analyze_rce', methods=['POST'])
def analyze_rce():
    try:
        data = request.get_json(force=True)
        import json
        payload = json.dumps(data)
        
        import vulnerable_rce
        result = vulnerable_rce.get_system_info(payload)
        return jsonify({"status": "success", "data": result})
            
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/analyze_bof', methods=['POST'])
def analyze_bof():
    try:
        data = request.get_json(force=True)
        payload = data.get("username", "")
        
        # Compile vulnerable_bof.c if not already compiled, or force recompile to catch patched versions
        bof_exe = os.path.abspath(os.path.join(os.path.dirname(__file__), "vulnerable_bof.exe"))
        bof_src = os.path.abspath(os.path.join(os.path.dirname(__file__), "vulnerable_bof.c"))
        
        # Always recompile to ensure we are testing the latest code from the test_harness
        if os.path.exists(bof_exe):
            os.remove(bof_exe)
        subprocess.run(["gcc", bof_src, "-o", bof_exe], check=True)
            
        print(f"Running BOF with payload: {payload[:20]}...")
        try:
            # Run the compiled C program with the payload, shorter timeout to beat requests timeout
            proc = subprocess.run([bof_exe, payload], capture_output=True, text=True, timeout=2)
            return jsonify({"status": "success", "data": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode})
        except subprocess.TimeoutExpired:
            return jsonify({"status": "success", "data": "Process timed out (likely crashed)", "returncode": -1})
            
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
