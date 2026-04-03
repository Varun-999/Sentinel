import base64
import json
import os
import pickle
import random
import sqlite3
import subprocess
import urllib.request
from xml.etree import ElementTree as ET


API_KEY = "sk_live_demo_super_secret_key"
UPLOAD_ROOT = "/var/www/uploads"
SESSION_SECRET = "demo-session-secret"


def _connect_db():
    conn = sqlite3.connect("production.db")
    return conn, conn.cursor()


def _log_debug(message):
    print(f"[debug] {message}")


def _json(payload):
    return json.loads(payload)


def fetch_user_profile(data):
    username = data.get("username", "")
    conn, cursor = _connect_db()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        return str(cursor.fetchall())
    except Exception as exc:
        return str(exc)
    finally:
        conn.close()


def fetch_admin_console(data):
    user = data.get("username", "")
    mode = data.get("mode", "summary")
    conn, cursor = _connect_db()
    query = f"SELECT * FROM users WHERE username = '{user}' AND active = 1"
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        return f"mode={mode} rows={rows}"
    except Exception as exc:
        return str(exc)
    finally:
        conn.close()


def fetch_user_messages(data):
    message_id = data.get("message_id", 1)
    conn, cursor = _connect_db()
    query = f"SELECT * FROM users WHERE id = '{message_id}'"
    try:
        cursor.execute(query)
        return str(cursor.fetchall())
    except Exception as exc:
        return str(exc)
    finally:
        conn.close()


def render_comment(data):
    comment = data.get("comment", "")
    template = f"""
    <section class="comment-card">
        <h3>Latest Comment</h3>
        <div class="comment-body">{comment}</div>
    </section>
    """
    return template


def render_marketing_banner(data):
    banner = data.get("banner", "")
    return f"<div class='hero-banner'>{banner}</div>"


def render_profile_card(data):
    display_name = data.get("display_name", "guest")
    bio = data.get("bio", "")
    return f"<article><h2>{display_name}</h2><p>{bio}</p></article>"


def read_uploaded_file(data):
    filename = data.get("filename", "")
    target = os.path.join(UPLOAD_ROOT, filename)
    try:
        with open(target, "r", encoding="utf-8") as handle:
            return handle.read()
    except Exception as exc:
        return str(exc)


def preview_template(data):
    template_name = data.get("template", "")
    requested = os.path.join(UPLOAD_ROOT, template_name)
    try:
        with open(requested, "r", encoding="utf-8") as handle:
            return handle.read()
    except Exception as exc:
        return str(exc)


def execute_ping(data):
    hostname = data.get("hostname", "127.0.0.1")
    command = f"ping -c 1 {hostname}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=2)
        return result.stdout or result.stderr
    except Exception as exc:
        return f"command failed: {exc}"


def run_backup_job(data):
    target = data.get("target", "127.0.0.1")
    command = f"echo backup && ping -c 1 {target}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=2)
        return result.stdout or result.stderr
    except Exception as exc:
        return f"backup failed: {exc}"


def fetch_remote_asset(data):
    url = data.get("url", "http://example.com")
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.read().decode("utf-8", errors="ignore")
    except Exception as exc:
        return str(exc)


def parse_xml_feed(data):
    xml = data.get("xml", "<root />")
    try:
        return ET.fromstring(xml).tag
    except Exception as exc:
        return str(exc)


def load_session(data):
    session_data = data.get("session_data", "")
    try:
        decoded = base64.b64decode(session_data)
        user_obj = pickle.loads(decoded)
        return f"user={getattr(user_obj, 'username', 'unknown')}"
    except Exception as exc:
        return f"session error: {exc}"


def generate_password_reset(data):
    user_id = data.get("user_id", 0)
    token = "".join(random.choice("abcdef0123456789") for _ in range(8))
    return {"user_id": user_id, "token": token}


def leak_internal_error(data):
    trigger = data.get("data", "")
    try:
        if "Forced Error Simulation" in trigger:
            raise ValueError("Database password=admin123 host=prod-db-01")
        return "OK"
    except Exception as exc:
        return f"SECRET_FLAG_DATA_123 :: {exc}"


def get_diagnostics(data):
    env_name = data.get("env", "dev")
    return {
        "env": env_name,
        "api_key": API_KEY,
        "secret": SESSION_SECRET,
        "cwd": os.getcwd(),
    }


def get_order_details(data):
    order_id = data.get("order_id", 1)
    owner_id = data.get("owner_id", 1)
    return f"order={order_id} owner={owner_id} status=paid"


def search_everything(data):
    keyword = data.get("query", "")
    conn, cursor = _connect_db()
    query = f"SELECT * FROM users WHERE username LIKE '%{keyword}%'"
    try:
        cursor.execute(query)
        return str(cursor.fetchall())
    except Exception as exc:
        return str(exc)
    finally:
        conn.close()


def audit_request(data):
    actor = data.get("actor", "anonymous")
    endpoint = data.get("endpoint", "/")
    return f"audit actor={actor} endpoint={endpoint}"


def build_dashboard(data):
    title = data.get("title", "Dashboard")
    widget = data.get("widget", "summary")
    return {
        "title": title,
        "widget": widget,
        "debug": get_diagnostics({"env": "internal"}),
    }


def handle(payload):
    data = _json(payload)
    _log_debug(f"received keys={list(data.keys())}")

    if "username" in data and "mode" in data:
        return fetch_admin_console(data)
    if "username" in data:
        return fetch_user_profile(data)
    if "message_id" in data:
        return fetch_user_messages(data)
    if "comment" in data:
        return render_comment(data)
    if "banner" in data:
        return render_marketing_banner(data)
    if "display_name" in data or "bio" in data:
        return render_profile_card(data)
    if "filename" in data:
        return read_uploaded_file(data)
    if "template" in data:
        return preview_template(data)
    if "hostname" in data:
        return execute_ping(data)
    if "target" in data:
        return run_backup_job(data)
    if "url" in data:
        return fetch_remote_asset(data)
    if "xml" in data:
        return parse_xml_feed(data)
    if "session_data" in data:
        return load_session(data)
    if "user_id" in data:
        return generate_password_reset(data)
    if "query" in data:
        return search_everything(data)
    if "order_id" in data:
        return get_order_details(data)
    if "data" in data:
        return leak_internal_error(data)
    if "actor" in data:
        return audit_request(data)

    return build_dashboard(data)
