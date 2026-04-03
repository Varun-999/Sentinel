import json
import os
import sqlite3


UPLOAD_ROOT = "/var/www/uploads"


def _db():
    conn = sqlite3.connect("production.db")
    return conn, conn.cursor()


def list_users(payload):
    data = json.loads(payload)
    username = data.get("username", "")
    conn, cursor = _db()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        return str(cursor.fetchall())
    except Exception as exc:
        return str(exc)
    finally:
        conn.close()


def search_accounts(payload):
    data = json.loads(payload)
    username = data.get("username", "")
    conn, cursor = _db()
    query = f"SELECT * FROM users WHERE username = '{username}' AND active = 1"
    try:
        cursor.execute(query)
        return str(cursor.fetchall())
    except Exception as exc:
        return str(exc)
    finally:
        conn.close()


def read_profile_file(payload):
    data = json.loads(payload)
    filename = data.get("filename", "")
    path = os.path.join(UPLOAD_ROOT, filename)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except Exception as exc:
        return str(exc)


def read_template_file(payload):
    data = json.loads(payload)
    filename = data.get("filename", "")
    path = os.path.join(UPLOAD_ROOT, filename)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except Exception as exc:
        return str(exc)


def render_comment(payload):
    data = json.loads(payload)
    comment = data.get("comment", "")
    return f"""
    <div class="comment-shell">
        <h3>Public Comment</h3>
        <div class="comment-body">{comment}</div>
    </div>
    """


def render_bio(payload):
    data = json.loads(payload)
    bio = data.get("comment", "")
    return f"<article class='bio-card'><p>{bio}</p></article>"


def render_status(payload):
    data = json.loads(payload)
    message = data.get("comment", "")
    return f"<span class='status-pill'>{message}</span>"


def helper_one():
    return "helper-one"


def helper_two():
    return "helper-two"


def helper_three():
    return "helper-three"


def helper_four():
    return "helper-four"


def helper_five():
    return "helper-five"


def helper_six():
    return "helper-six"


def helper_seven():
    return "helper-seven"


def helper_eight():
    return "helper-eight"


def helper_nine():
    return "helper-nine"


def helper_ten():
    return "helper-ten"


def handle(payload):
    data = json.loads(payload)

    if "filename" in data and data.get("template_mode"):
        return read_template_file(payload)
    if "filename" in data:
        return read_profile_file(payload)
    if "comment" in data and data.get("status_mode"):
        return render_status(payload)
    if "comment" in data and data.get("bio_mode"):
        return render_bio(payload)
    if "comment" in data:
        return render_comment(payload)
    if data.get("admin_mode"):
        return search_accounts(payload)
    if "username" in data:
        return list_users(payload)

    return {
        "helpers": [
            helper_one(),
            helper_two(),
            helper_three(),
            helper_four(),
            helper_five(),
            helper_six(),
            helper_seven(),
            helper_eight(),
            helper_nine(),
            helper_ten(),
        ]
    }
