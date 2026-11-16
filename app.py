from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import date
from functools import wraps
from pathlib import Path
from urllib.parse import quote

from flask import Flask, g, jsonify, request, send_from_directory
from flask_cors import CORS
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash


ROOT = Path(__file__).resolve().parent
SUPABASE_PROJECT_REF = os.environ.get("SUPABASE_PROJECT_REF", "cddfrdcjenmmtwyluiaf")
SUPABASE_DB_HOST = os.environ.get("SUPABASE_DB_HOST", "aws-1-eu-central-1.pooler.supabase.com")
SUPABASE_DB_USER = os.environ.get("SUPABASE_DB_USER", f"postgres.{SUPABASE_PROJECT_REF}")
SUPABASE_DB_PORT = os.environ.get("SUPABASE_DB_PORT", "5432")
SUPABASE_DB_PASSWORD = os.environ.get("SUPABASE_DB_PASSWORD")
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL and SUPABASE_DB_PASSWORD:
    user = quote(SUPABASE_DB_USER, safe="")
    password = quote(SUPABASE_DB_PASSWORD, safe="")
    DATABASE_URL = (
        f"postgresql://{user}:{password}@{SUPABASE_DB_HOST}:{SUPABASE_DB_PORT}/postgres?sslmode=require"
    )
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///research_grants.db"
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
DATABASE_URL = DATABASE_URL.replace("postgresql+psycopg://", "postgresql://", 1)
IS_SQLITE = DATABASE_URL.startswith("sqlite:///")

app = Flask(__name__, static_folder=None)
app.config.update(
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)
allowed_origins = [
    origin.strip()
    for origin in os.environ.get(
        "ALLOWED_ORIGINS",
        "https://amirmarat27-cmyk.github.io,http://127.0.0.1:8000,http://localhost:8000",
    ).split(",")
    if origin.strip()
]
CORS(
    app,
    resources={r"/api/*": {"origins": allowed_origins}},
    allow_headers=["Authorization", "Content-Type", "X-App-Role"],
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)


def open_connection():
    if IS_SQLITE:
        database_path = DATABASE_URL.removeprefix("sqlite:///")
        if not Path(database_path).is_absolute():
            database_path = str(ROOT / database_path)
        conn = sqlite3.connect(database_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10)


@contextmanager
def connection():
    conn = open_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def adapt_sql(sql):
    return sql if IS_SQLITE else sql.replace("?", "%s")


def db_one(sql, params=()):
    with connection() as conn:
        row = conn.execute(adapt_sql(sql), params).fetchone()
    return dict(row) if row is not None else None


def db_all(sql, params=()):
    with connection() as conn:
        rows = conn.execute(adapt_sql(sql), params).fetchall()
    return [dict(row) for row in rows]


def db_execute(sql, params=()):
    with connection() as conn:
        conn.execute(adapt_sql(sql), params)


def initialize_database():
    statements = (
        """CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT FALSE,
            is_reviewer BOOLEAN NOT NULL DEFAULT FALSE,
            saved TEXT NOT NULL DEFAULT '[]',
            created BIGINT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS collection_documents (
            collection TEXT NOT NULL,
            id TEXT NOT NULL,
            data TEXT NOT NULL,
            updated BIGINT NOT NULL,
            PRIMARY KEY (collection, id)
        )""",
        """CREATE TABLE IF NOT EXISTS access_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires BIGINT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS proposal_events (
            id TEXT PRIMARY KEY,
            proposal_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            created BIGINT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS approval_roles (
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            PRIMARY KEY (user_id, role)
        )""",
        """CREATE TABLE IF NOT EXISTS applicant_profiles (
            user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            applicant_type TEXT NOT NULL
        )""",
    )
    with connection() as conn:
        for statement in statements:
            conn.execute(statement)


_database_ready = False
_database_lock = threading.Lock()


def ensure_database():
    global _database_ready
    if _database_ready:
        return
    with _database_lock:
        if not _database_ready:
            initialize_database()
            _database_ready = True


@app.before_request
def initialize_database_on_demand():
    if request.path.startswith("/api/") and request.path != "/api/health":
        try:
            ensure_database()
        except Exception:
            app.logger.exception("Database initialization failed")
            return api_error("База данных недоступна. Проверьте конфигурацию подключения.", 503)


def now_ms():
    return int(time.time() * 1000)


def api_error(message, status):
    return jsonify({"error": message}), status


def user_record(row):
    if row is None:
        return None
    return {
        **row,
        "is_admin": bool(row["is_admin"]),
        "is_reviewer": bool(row["is_reviewer"]),
        "saved": json.loads(row["saved"] or "[]"),
    }


def user_data(user, viewer):
    profile = db_one("SELECT applicant_type FROM applicant_profiles WHERE user_id = ?", (user["id"],))
    result = {
        "id": user["id"],
        "name": user["name"],
        "isAdmin": user["is_admin"],
        "isReviewer": user["is_reviewer"],
        "applicantType": profile["applicant_type"] if profile else "student",
        "created": user["created"],
    }
    if user["id"] == viewer["id"] or viewer["is_admin"]:
        result["email"] = user["email"]
        result["saved"] = user["saved"]
        result["approvalRoles"] = approval_roles(user["id"])
    return result


APPROVAL_STAGES = ("department_head", "ethics_committee", "grant_board")
REVIEW_CRITERIA = ("Оригинальность", "Методология", "Осуществимость", "Значимость")
REVIEW_RECOMMENDATIONS = ("Финансировать", "Финансировать с доработками", "Не финансировать")


def approval_roles(user_id):
    return [row["role"] for row in db_all("SELECT role FROM approval_roles WHERE user_id = ?", (user_id,))]


def current_user():
    if getattr(g, "user_loaded", False):
        return getattr(g, "user", None)
    g.user_loaded = True
    g.user = None
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    raw_token = header[7:].strip()
    if not raw_token:
        return None
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    access = db_one("SELECT user_id, expires FROM access_tokens WHERE token_hash = ?", (token_hash,))
    if access is None:
        return None
    if access["expires"] < now_ms():
        db_execute("DELETE FROM access_tokens WHERE token_hash = ?", (token_hash,))
        return None
    g.user = user_record(db_one("SELECT * FROM users WHERE id = ?", (access["user_id"],)))
    return g.user


def app_role(user):
    role = request.headers.get("X-App-Role", "student")
    if role == "admin" and user["is_admin"]:
        return "admin"
    if role == "reviewer" and (user["is_reviewer"] or user["is_admin"]):
        return "reviewer"
    if role == "faculty":
        profile = db_one("SELECT applicant_type FROM applicant_profiles WHERE user_id = ?", (user["id"],))
        if profile and profile["applicant_type"] == "faculty":
            return "faculty"
    if role in APPROVAL_STAGES and role in approval_roles(user["id"]):
        return role
    profile = db_one("SELECT applicant_type FROM applicant_profiles WHERE user_id = ?", (user["id"],))
    if profile and profile["applicant_type"] == "external_reviewer":
        return "none"
    return "student"


def authenticated(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return api_error("Требуется войти в аккаунт.", 401)
        g.user = user
        return handler(*args, **kwargs)

    return wrapped


def issue_token(user):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    db_execute(
        "INSERT INTO access_tokens (token_hash, user_id, expires) VALUES (?, ?, ?)",
        (token_hash, user["id"], now_ms() + 30 * 24 * 60 * 60 * 1000),
    )
    return token


def auth_result(user):
    return jsonify({"token": issue_token(user), "user": user_data(user, user)})


def get_document(collection, document_id):
    document = db_one(
        "SELECT collection, id, data, updated FROM collection_documents WHERE collection = ? AND id = ?",
        (collection, document_id),
    )
    if document is not None:
        document["data"] = decode_sensitive_json(document["data"]) if collection == "proposals" else json.loads(document["data"])
    return document


def put_document(collection, document_id, data, event=None):
    with connection() as conn:
        conn.execute(adapt_sql(
            """INSERT INTO collection_documents (collection, id, data, updated) VALUES (?, ?, ?, ?)
            ON CONFLICT(collection, id) DO UPDATE SET data = excluded.data, updated = excluded.updated"""
        ), (collection, document_id, encode_sensitive_json(data) if collection == "proposals" else json.dumps(data, ensure_ascii=False), now_ms()))
        if event:
            conn.execute(adapt_sql(
                "INSERT INTO proposal_events (id, proposal_id, actor_id, action, details, created) VALUES (?, ?, ?, ?, ?, ?)"
            ), (secrets.token_urlsafe(16), document_id, event["actor_id"], event["action"],
                encode_sensitive_json(event["details"]), now_ms()))
    return get_document(collection, document_id)


def visible_proposal(user, role, data):
    if user["is_admin"] and role == "admin":
        return data.get("sid") != user["id"]
    if role in ("student", "faculty"):
        return data.get("sid") == user["id"]
    if role in APPROVAL_STAGES:
        approvals = data.get("approvals", [])
        return (data.get("sid") != user["id"] and data.get("status") in ("submitted", "review")
                and len(approvals) < len(APPROVAL_STAGES) and APPROVAL_STAGES[len(approvals)] == role)
    if role != "reviewer":
        return False
    return data.get("sid") != user["id"] and data.get("status") != "draft" and (
        data.get("status") == "submitted" or user["id"] in data.get("reviewers", [])
    )


def proposal_for_viewer(data, user, role):
    if role == "admin" or role in APPROVAL_STAGES:
        return data
    result = {key: value for key, value in data.items() if key != "reviewers"}
    reviews = data.get("reviews") or {}
    if role == "reviewer":
        result.pop("versions", None)
        result["reviewers"] = [user["id"]] if user["id"] in data.get("reviewers", []) else []
        result["reviews"] = {user["id"]: reviews[user["id"]]} if user["id"] in reviews else {}
    else:
        result["reviews"] = {
            str(index): {"scores": review.get("scores", {})}
            for index, review in enumerate(reviews.values(), 1)
        } if data.get("decision") else {}
        if isinstance(result.get("decision"), dict):
            result["decision"] = {key: value for key, value in result["decision"].items() if key != "by"}
        if isinstance(result.get("approvals"), list):
            result["approvals"] = [{key: value for key, value in entry.items() if key != "by"} for entry in result["approvals"]]
    return result


def list_documents(collection):
    rows = db_all(
        "SELECT collection, id, data, updated FROM collection_documents WHERE collection = ?",
        (collection,),
    )
    return [{**row, "data": decode_sensitive_json(row["data"]) if collection == "proposals" else json.loads(row["data"])} for row in rows]


def record_proposal_version(data, author_id):
    fields = ("gid", "title", "abstract", "method", "budget", "months", "outcomes", "status")
    previous_versions = data.get("versions", [])
    version = {
        "number": len(previous_versions) + 1,
        "author_id": author_id,
        "at": now_ms(),
        "data": {field: data.get(field) for field in fields},
    }
    return {**data, "versions": [*previous_versions, version]}


def valid_milestones(milestones, budget):
    if not isinstance(milestones, list) or len(milestones) > 100:
        return False
    total = 0
    for milestone in milestones:
        if not isinstance(milestone, dict):
            return False
        amount = milestone.get("amount")
        if type(amount) not in (int, float) or not 0 < amount <= 1e15:
            return False
        if not isinstance(milestone.get("title"), str) or not 1 <= len(milestone["title"].strip()) <= 160:
            return False
        if milestone.get("status") not in ("planned", "paid"):
            return False
        try:
            date.fromisoformat(milestone["due_date"])
            date.fromisoformat(milestone["report_due"])
        except (KeyError, TypeError, ValueError):
            return False
        total += amount
    return type(budget) in (int, float) and total <= budget


class EncryptionConfigurationError(Exception):
    pass


def document_cipher():
    key = os.environ.get("DOCUMENT_ENCRYPTION_KEY")
    if not key and IS_SQLITE:
        key_path = ROOT / "instance" / "document.key"
        key_path.parent.mkdir(exist_ok=True)
        try:
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as key_file:
                key_file.write(Fernet.generate_key())
        key = key_path.read_text(encoding="ascii").strip()
    if not key:
        raise EncryptionConfigurationError("Encryption key is not configured")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeError) as error:
        raise EncryptionConfigurationError("Invalid encryption key") from error


def encode_sensitive_json(data):
    payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return json.dumps({"encrypted_v1": document_cipher().encrypt(payload).decode("ascii")})


def decode_sensitive_json(data):
    parsed = json.loads(data)
    if isinstance(parsed, dict) and set(parsed) == {"encrypted_v1"}:
        payload = document_cipher().decrypt(parsed["encrypted_v1"].encode("ascii"))
        return json.loads(payload)
    return parsed


def encrypt_document(data):
    content = data.get("data")
    name = data.get("name")
    if not isinstance(name, str) or not 1 <= len(name) <= 255 or not isinstance(content, str):
        raise ValueError("Invalid file")
    match = re.fullmatch(r"data:[a-zA-Z0-9.+/\-]*;base64,([A-Za-z0-9+/=]*)", content)
    if not match:
        raise ValueError("Invalid file data")
    raw = base64.b64decode(match.group(1), validate=True)
    if len(raw) != data["size"] or len(raw) > 122880:
        raise ValueError("Invalid file size")
    payload = {"name": name, "data": "data:application/octet-stream;base64," + match.group(1)}
    encrypted = document_cipher().encrypt(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    return {"pid": data["pid"], "size": data["size"], "encrypted_payload": encrypted.decode("ascii")}


def decrypt_document(data):
    if "encrypted_payload" not in data:
        return data
    payload = document_cipher().decrypt(data["encrypted_payload"].encode("ascii"))
    return {"pid": data["pid"], "size": data["size"], **json.loads(payload)}


@app.get("/")
@app.get("/index.html")
def index():
    return send_from_directory(ROOT, "index.html")


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "storage": "sqlite" if IS_SQLITE else "postgres"})


@app.get("/api/proposals/<document_id>/events")
@authenticated
def proposal_events(document_id):
    if app_role(g.user) != "admin":
        return api_error("Журнал доступен только администратору.", 403)
    proposal = get_document("proposals", document_id)
    if proposal is None or proposal["data"].get("sid") == g.user["id"]:
        return api_error("Журнал заявки недоступен.", 403)
    events = db_all(
        "SELECT actor_id, action, details, created FROM proposal_events WHERE proposal_id = ? ORDER BY created, id",
        (document_id,),
    )
    return jsonify({"events": [{**event, "details": decode_sensitive_json(event["details"])} for event in events]})


@app.post("/api/proposals/<document_id>/approval")
@authenticated
def approve_proposal_stage(document_id):
    role = app_role(g.user)
    if role not in APPROVAL_STAGES and role != "admin":
        return api_error("Для согласования необходима соответствующая роль.", 403)
    body = request.get_json(silent=True) or {}
    decision = body.get("decision")
    note = body.get("note", "")
    if decision not in ("approve", "reject") or not isinstance(note, str) or len(note) > 4000:
        return api_error("Некорректное решение или комментарий.", 400)
    with connection() as conn:
        if IS_SQLITE:
            conn.execute("BEGIN IMMEDIATE")
        query = "SELECT data FROM collection_documents WHERE collection = ? AND id = ?"
        if not IS_SQLITE:
            query += " FOR UPDATE"
        row = conn.execute(adapt_sql(query), ("proposals", document_id)).fetchone()
        if row is None:
            return api_error("Заявка не найдена.", 404)
        data = decode_sensitive_json(row["data"])
        if data.get("sid") == g.user["id"]:
            return api_error("Нельзя согласовывать собственную заявку.", 403)
        if g.user["id"] in (data.get("reviews") or {}):
            return api_error("Эксперт не может согласовывать заявку, которую он оценивал.", 403)
        approvals = data.get("approvals", [])
        if data.get("status") not in ("submitted", "review") or len(approvals) >= len(APPROVAL_STAGES):
            return api_error("Заявка не находится на согласовании.", 409)
        stage = APPROVAL_STAGES[len(approvals)]
        if role != "admin" and role != stage:
            return api_error("Сначала необходимо завершить предыдущий этап.", 409)
        if not data.get("reviews"):
            return api_error("До согласования необходима хотя бы одна рецензия эксперта.", 409)
        if role != "admin" and any(item.get("by") == g.user["id"] for item in approvals):
            return api_error("Один пользователь не может согласовать несколько этапов одной заявки.", 403)
        approved_budget = body.get("approved_budget")
        if stage == "grant_board" and decision == "approve":
            requested_budget = data.get("budget")
            if (type(approved_budget) not in (int, float) or type(requested_budget) not in (int, float)
                    or not 0 <= approved_budget <= requested_budget):
                return api_error("Утверждённая сумма должна быть не больше запрошенного бюджета.", 400)
            data["approved_budget"] = approved_budget
        timestamp = now_ms()
        entry = {
            "stage": stage,
            "decision": decision,
            "note": note.strip(),
            "by": g.user["id"],
            "at": timestamp,
            "status_before": data.get("status"),
        }
        if stage == "grant_board" and decision == "approve":
            entry["approved_budget"] = approved_budget
        data["approvals"] = [*approvals, entry]
        data["updated"] = timestamp
        data["status"] = "rejected" if decision == "reject" else ("approved" if stage == "grant_board" else "review")
        entry["status_after"] = data["status"]
        if data["status"] in ("approved", "rejected"):
            data["decision"] = {"note": note.strip(), "by": g.user["id"], "at": timestamp}
        conn.execute(adapt_sql("UPDATE collection_documents SET data = ?, updated = ? WHERE collection = ? AND id = ?"),
                     (encode_sensitive_json(data), timestamp, "proposals", document_id))
        conn.execute(adapt_sql("INSERT INTO proposal_events (id, proposal_id, actor_id, action, details, created) VALUES (?, ?, ?, ?, ?, ?)"),
                     (secrets.token_urlsafe(16), document_id, g.user["id"], "approval", encode_sensitive_json(entry), timestamp))
    return jsonify({"ok": True, "status": data["status"]})


@app.post("/api/proposals/<document_id>/reports")
@authenticated
def submit_progress_report(document_id):
    if app_role(g.user) not in ("student", "faculty"):
        return api_error("Отчёт может отправить только автор заявки.", 403)
    body = request.get_json(silent=True) or {}
    milestone_index = body.get("milestone")
    text = body.get("text")
    if type(milestone_index) is not int or not isinstance(text, str) or not text.strip() or len(text) > 10000:
        return api_error("Укажите этап и текст отчёта.", 400)
    with connection() as conn:
        if IS_SQLITE:
            conn.execute("BEGIN IMMEDIATE")
        query = "SELECT data FROM collection_documents WHERE collection = ? AND id = ?"
        if not IS_SQLITE:
            query += " FOR UPDATE"
        row = conn.execute(adapt_sql(query), ("proposals", document_id)).fetchone()
        if row is None:
            return api_error("Заявка не найдена.", 404)
        data = decode_sensitive_json(row["data"])
        if data.get("sid") != g.user["id"]:
            return api_error("Отчёт может отправить только автор заявки.", 403)
        milestones = data.get("milestones", [])
        if data.get("status") != "approved" or not 0 <= milestone_index < len(milestones):
            return api_error("Отчёт можно отправить для этапа одобренной заявки.", 400)
        reports = data.get("progressReports", [])
        if len(reports) >= 100:
            return api_error("Достигнут лимит отчётов.", 400)
        timestamp = now_ms()
        report = {"milestone": milestone_index, "milestone_title": milestones[milestone_index]["title"],
                  "text": text.strip(), "by": g.user["id"], "at": timestamp}
        data["progressReports"] = [*reports, report]
        data["updated"] = timestamp
        conn.execute(adapt_sql("UPDATE collection_documents SET data = ?, updated = ? WHERE collection = ? AND id = ?"),
                     (encode_sensitive_json(data), timestamp, "proposals", document_id))
        conn.execute(adapt_sql("INSERT INTO proposal_events (id, proposal_id, actor_id, action, details, created) VALUES (?, ?, ?, ?, ?, ?)"),
                     (secrets.token_urlsafe(16), document_id, g.user["id"], "report", encode_sensitive_json(report), timestamp))
    return jsonify({"ok": True}), 201


@app.post("/api/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name", "")).strip()
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    applicant_type = body.get("applicantType", "student")
    if applicant_type not in ("student", "faculty", "external_reviewer"):
        return api_error("Выберите тип заявителя.", 400)
    if not name or len(name) > 120:
        return api_error("Укажите имя длиной до 120 символов.", 400)
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return api_error("Укажите корректную электронную почту.", 400)
    if len(password) < 6:
        return api_error("Пароль должен содержать не менее 6 символов.", 400)
    if db_one("SELECT id FROM users WHERE email = ?", (email,)) is not None:
        return api_error("Эта почта уже зарегистрирована.", 409)
    user_id = secrets.token_urlsafe(12)
    is_first_user = db_one("SELECT COUNT(*) AS count FROM users")["count"] == 0
    with connection() as conn:
        conn.execute(adapt_sql(
            """INSERT INTO users (id, email, name, password_hash, is_admin, is_reviewer, saved, created)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""
        ), (user_id, email, name, generate_password_hash(password), is_first_user, False, "[]", now_ms()))
        conn.execute(adapt_sql("INSERT INTO applicant_profiles (user_id, applicant_type) VALUES (?, ?)"),
                     (user_id, applicant_type))
    user = user_record(db_one("SELECT * FROM users WHERE id = ?", (user_id,)))
    return auth_result(user), 201


@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    user = user_record(db_one("SELECT * FROM users WHERE email = ?", (email,)))
    if user is None or not check_password_hash(user["password_hash"], password):
        return api_error("Неверная почта или пароль.", 401)
    return auth_result(user)


@app.post("/api/auth/logout")
@authenticated
def logout():
    header = request.headers.get("Authorization", "")
    token_hash = hashlib.sha256(header[7:].strip().encode("utf-8")).hexdigest()
    db_execute("DELETE FROM access_tokens WHERE token_hash = ?", (token_hash,))
    return jsonify({"ok": True})


@app.get("/api/collections/<collection>")
def list_collection(collection):
    if collection not in {"users", "proposals", "files", "grants"}:
        return api_error("Неизвестный раздел данных.", 404)
    user = current_user()
    role = app_role(user) if user else ""
    if collection == "grants":
        documents = list_documents(collection)
    elif user is None:
        documents = []
    elif collection == "users":
        users = [user_record(row) for row in db_all("SELECT * FROM users ORDER BY created")]
        return jsonify({"docs": [{"id": item["id"], "data": user_data(item, user)} for item in users]})
    else:
        documents = list_documents(collection)
        if collection == "proposals":
            documents = [item for item in documents if visible_proposal(user, role, item["data"])]
            documents = [{**item, "data": proposal_for_viewer(item["data"], user, role)} for item in documents]
        elif collection == "files":
            proposals = list_documents("proposals")
            visible_ids = {
                proposal["id"]
                for proposal in proposals
                if visible_proposal(user, role, proposal["data"])
            }
            documents = [item for item in documents if item["data"].get("pid") in visible_ids]
            try:
                documents = [{**item, "data": decrypt_document(item["data"])} for item in documents]
            except (ValueError, InvalidToken):
                app.logger.error("Unable to decrypt documents: check DOCUMENT_ENCRYPTION_KEY")
                return api_error("Не удалось расшифровать документы. Проверьте ключ сервера.", 503)
    return jsonify({"docs": [{"id": item["id"], "data": item["data"]} for item in documents]})


@app.put("/api/collections/<collection>/<document_id>")
@authenticated
def set_collection_document(collection, document_id):
    body = request.get_json(silent=True) or {}
    data = body.get("data")
    if not isinstance(data, dict):
        return api_error("Ожидался объект данных.", 400)
    user = g.user
    role = app_role(user)

    if collection == "proposals":
        if role in ("student", "faculty"):
            if get_document(collection, document_id) is not None:
                return api_error("Заявка с таким идентификатором уже существует.", 409)
            if data.get("status") not in {"draft", "submitted"}:
                return api_error("Недопустимый статус заявки.", 400)
            data = {
                key: data.get(key)
                for key in ("gid", "title", "abstract", "method", "budget", "months", "outcomes", "status", "updated")
            }
            data.update(id=document_id, sid=user["id"], created=now_ms(), reviewers=[], reviews={})
            if data["status"] == "submitted" and any(not data.get(key) for key in ("title", "abstract", "method", "outcomes")):
                return api_error("Заполните все обязательные поля заявки.", 400)
            data = record_proposal_version(data, user["id"])
        else:
            return api_error("Эксперт не может создавать заявки.", 403)
    elif collection == "files":
        proposal = get_document("proposals", str(data.get("pid", "")))
        if role not in ("student", "faculty") or proposal is None or proposal["data"].get("sid") != user["id"] or proposal["data"].get("status") != "draft":
            return api_error("Нет доступа к вложению этой заявки.", 403)
        if not isinstance(data.get("size"), int) or data["size"] < 0 or data["size"] > 122880:
            return api_error("Размер файла превышает 120 КБ.", 400)
        if get_document(collection, document_id) is not None:
            return api_error("Файл с таким идентификатором уже существует.", 409)
        try:
            data = encrypt_document(data)
        except (ValueError, binascii.Error, UnicodeError):
            return api_error("Не удалось сохранить файл: проверьте содержимое и ключ шифрования сервера.", 400)
    elif collection == "grants":
        if role != "admin":
            return api_error("Управлять грантами может только администратор.", 403)
        data = {**data, "id": document_id}
    else:
        return api_error("Создание этого типа записи запрещено.", 403)

    event = {"actor_id": user["id"], "action": "created", "details": {"status": data.get("status")}} if collection == "proposals" else None
    put_document(collection, document_id, data, event)
    return jsonify({"ok": True})


@app.patch("/api/collections/<collection>/<document_id>")
@authenticated
def update_collection_document(collection, document_id):
    body = request.get_json(silent=True) or {}
    changes = body.get("data")
    if not isinstance(changes, dict):
        return api_error("Ожидался объект изменений.", 400)
    user = g.user
    role = app_role(user)

    if collection == "users":
        target = user_record(db_one("SELECT * FROM users WHERE id = ?", (document_id,)))
        if target is None:
            return api_error("Пользователь не найден.", 404)
        if document_id == user["id"] and set(changes) == {"saved"}:
            if not isinstance(changes["saved"], list) or len(changes["saved"]) > 100:
                return api_error("Некорректный список сохранённых грантов.", 400)
            db_execute("UPDATE users SET saved = ? WHERE id = ?", (json.dumps(changes["saved"]), document_id))
        elif role == "admin" and document_id != user["id"] and set(changes) == {"approvalRoles"}:
            roles = changes["approvalRoles"]
            if not isinstance(roles, list) or any(not isinstance(item, str) or item not in APPROVAL_STAGES for item in roles) or len(roles) != len(set(roles)):
                return api_error("Некорректные роли согласования.", 400)
            with connection() as conn:
                conn.execute(adapt_sql("DELETE FROM approval_roles WHERE user_id = ?"), (document_id,))
                for approval_role in roles:
                    conn.execute(adapt_sql("INSERT INTO approval_roles (user_id, role) VALUES (?, ?)"), (document_id, approval_role))
        elif role == "admin" and document_id != user["id"] and set(changes).issubset({"isAdmin", "isReviewer", "role"}):
            if any(key in changes and type(changes[key]) is not bool for key in ("isAdmin", "isReviewer")):
                return api_error("Права пользователя должны быть указаны как да или нет.", 400)
            db_execute(
                "UPDATE users SET is_admin = ?, is_reviewer = ? WHERE id = ?",
                (bool(changes.get("isAdmin", target["is_admin"])), bool(changes.get("isReviewer", target["is_reviewer"])), document_id),
            )
        else:
            return api_error("Нет прав изменять этого пользователя.", 403)
        return jsonify({"ok": True})

    document = get_document(collection, document_id)
    if document is None:
        return api_error("Запись не найдена.", 404)

    if collection == "proposals":
        existing = document["data"]
        if role == "admin":
            if existing.get("sid") == user["id"]:
                return api_error("Нельзя администрировать собственную заявку.", 403)
            if set(changes) - {"reviewers", "status", "updated", "milestones"}:
                return api_error("Эти поля нельзя менять через управление заявкой.", 403)
            if "status" in changes and (changes["status"] != "review" or existing.get("status") not in ("submitted", "review")):
                return api_error("Итоговое решение принимается через этапы согласования.", 403)
            if "reviewers" in changes:
                reviewers = changes["reviewers"]
                if (existing.get("status") not in ("submitted", "review") or existing.get("approvals")
                        or not isinstance(reviewers, list)
                        or any(not isinstance(reviewer, str) for reviewer in reviewers)
                        or len(reviewers) != len(set(reviewers)) or existing.get("sid") in reviewers):
                    return api_error("Некорректное назначение экспертов.", 400)
                for reviewer in reviewers:
                    account = user_record(db_one("SELECT * FROM users WHERE id = ?", (reviewer,)))
                    if not account or not (account["is_reviewer"] or account["is_admin"]):
                        return api_error("Назначить можно только пользователя с правом эксперта.", 400)
            if "milestones" in changes and (existing.get("status") != "approved" or not valid_milestones(changes["milestones"], existing.get("approved_budget", existing.get("budget")))):
                return api_error("Проверьте этапы финансирования: заявка должна быть одобрена, а суммы не должны превышать бюджет.", 400)
            updated = {**existing, **changes, "id": document_id}
        elif role in ("student", "faculty") and existing.get("sid") == user["id"] and existing.get("status") == "draft":
            allowed = {"gid", "title", "abstract", "method", "budget", "months", "outcomes", "status", "updated"}
            if not set(changes).issubset(allowed) or changes.get("status", "draft") not in {"draft", "submitted"}:
                return api_error("Нельзя изменить эти поля заявки.", 403)
            updated = {**existing, **changes}
            if updated.get("status") == "submitted" and any(not updated.get(key) for key in ("title", "abstract", "method", "outcomes")):
                return api_error("Заполните все обязательные поля заявки.", 400)
            updated = record_proposal_version(updated, user["id"])
        elif role == "reviewer" and visible_proposal(user, role, existing):
            if existing.get("status") not in ("submitted", "review") or existing.get("approvals"):
                return api_error("Рецензирование завершено: согласование уже началось.", 409)
            review = (changes.get("reviews") or {}).get(user["id"])
            scores = review.get("scores") if isinstance(review, dict) else None
            if (not isinstance(scores, dict) or set(scores) != set(REVIEW_CRITERIA)
                    or any(type(value) not in (int, float) or not 1 <= value <= 10 for value in scores.values())
                    or not isinstance(review.get("comment"), str) or not review["comment"].strip()
                    or len(review["comment"]) > 4000 or review.get("rec") not in REVIEW_RECOMMENDATIONS):
                return api_error("Некорректная оценка рецензии.", 400)
            merged_reviews = {**(existing.get("reviews") or {}), user["id"]: review}
            updated = {**existing, "reviews": merged_reviews, "updated": changes.get("updated", now_ms())}
        else:
            return api_error("Нет доступа изменять эту заявку.", 403)
        details = {}
        for field in ("status", "reviewers", "decision", "milestones"):
            if existing.get(field) != updated.get(field):
                details[field] = {"before": existing.get(field), "after": updated.get(field)}
        if role == "reviewer":
            details["review"] = updated["reviews"][user["id"]]
        action = "review" if role == "reviewer" else "updated"
        put_document(collection, document_id, updated, {"actor_id": user["id"], "action": action, "details": details})
        return jsonify({"ok": True})

    if collection == "grants" and role == "admin":
        put_document(collection, document_id, {**document["data"], **changes, "id": document_id})
        return jsonify({"ok": True})
    return api_error("Нет прав изменять эту запись.", 403)


@app.delete("/api/collections/<collection>/<document_id>")
@authenticated
def delete_collection_document(collection, document_id):
    user = g.user
    role = app_role(user)
    document = get_document(collection, document_id)
    if collection == "users":
        target = db_one("SELECT id FROM users WHERE id = ?", (document_id,))
        if role != "admin" or target is None or target["id"] == user["id"]:
            return api_error("Нет прав удалить этого пользователя.", 403)
        db_execute("DELETE FROM users WHERE id = ?", (document_id,))
        return jsonify({"ok": True})
    if document is None:
        return api_error("Запись не найдена.", 404)
    if collection == "proposals":
        if role == "admin" and document["data"].get("sid") == user["id"]:
            return api_error("Нельзя администрировать собственную заявку.", 403)
        if role != "admin" and not (role in ("student", "faculty") and document["data"].get("sid") == user["id"] and document["data"].get("status") == "draft"):
            return api_error("Удалять можно только свой черновик.", 403)
        files = list_documents("files")
        for item in files:
            if item["data"].get("pid") == document_id:
                db_execute("DELETE FROM collection_documents WHERE collection = ? AND id = ?", ("files", item["id"]))
    elif collection == "files":
        proposal = get_document("proposals", str(document["data"].get("pid", "")))
        if role == "admin" and proposal and proposal["data"].get("sid") == user["id"]:
            return api_error("Нельзя администрировать собственную заявку.", 403)
        if role != "admin" and not (
            role in ("student", "faculty")
            and proposal is not None
            and proposal["data"].get("sid") == user["id"]
            and proposal["data"].get("status") == "draft"
        ):
            return api_error("Нет прав удалить это вложение.", 403)
    elif collection == "grants" and role != "admin":
        return api_error("Управлять грантами может только администратор.", 403)
    elif collection not in {"proposals", "files", "grants"}:
        return api_error("Удаление этого типа записи запрещено.", 403)
    db_execute("DELETE FROM collection_documents WHERE collection = ? AND id = ?", (collection, document_id))
    return jsonify({"ok": True})


@app.errorhandler(413)
def request_too_large(_error):
    return api_error("Размер запроса слишком велик.", 413)


@app.errorhandler(EncryptionConfigurationError)
@app.errorhandler(InvalidToken)
def encryption_error(_error):
    app.logger.error("Encryption key is missing, invalid or does not match the stored data")
    return api_error("Данные недоступны: проверьте ключ шифрования сервера.", 503)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)