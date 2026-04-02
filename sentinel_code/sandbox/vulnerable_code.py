def handle(payload):
    import sqlite3, json
    data = json.loads(payload)
    username = data.get('username','')
    conn = sqlite3.connect("production.db")
    cursor = conn.cursor()
    # Flaw: Naked string interpolation
    query = f"SELECT * FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        return str(cursor.fetchall())
    except Exception as e:
        return str(e)