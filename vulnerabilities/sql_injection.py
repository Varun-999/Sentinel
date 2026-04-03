# Vulnerable SQL Injection example (CVE-2023-1000)

def handle(payload):
    import sqlite3, json
    data = json.loads(payload)
    username = data.get('username','')
    conn = sqlite3.connect('production.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return str(cursor.fetchall())
