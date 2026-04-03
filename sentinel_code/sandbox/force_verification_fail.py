def handle(payload):
    import json
    import sqlite3

    data = json.loads(payload)
    username = data.get("username", "")

    conn = sqlite3.connect("production.db")
    cursor = conn.cursor()

    # Intentionally vulnerable SQL query so Red Agent confirms a real issue and
    # the workflow enters the Blue/Green loop before the deterministic fail hook.
    query = f"SELECT * FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        return str(cursor.fetchall())
    finally:
        conn.close()
