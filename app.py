from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from urllib.parse import quote

from flask import Flask, g, jsonify, request, send_from_directory
from flask_cors import CORS
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

    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


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
    )
    with connection() as conn:
        for statement in statements:
            conn.execute(statement)


initialize_database()


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
    result = {
        "id": user["id"],
        "name": user["name"],
        "isAdmin": user["is_admin"],
        "isReviewer": user["is_reviewer"],
        "created": user["created"],
    }
    if user["id"] == viewer["id"] or viewer["is_admin"]:
        result["email"] = user["email"]
        result["saved"] = user["saved"]
    return result


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
        document["data"] = json.loads(document["data"])
    return document


def put_document(collection, document_id, data):
    db_execute(
        """INSERT INTO collection_documents (collection, id, data, updated) VALUES (?, ?, ?, ?)
        ON CONFLICT(collection, id) DO UPDATE SET data = excluded.data, updated = excluded.updated""",
        (collection, document_id, json.dumps(data, ensure_ascii=False), now_ms()),
    )
    return get_document(collection, document_id)


def visible_proposal(user, role, data):
    if user["is_admin"] and role == "admin":
        return True
    if role == "student":
        return data.get("sid") == user["id"]
    return data.get("status") == "submitted" or user["id"] in data.get("reviewers", [])


def list_documents(collection):
    rows = db_all(
        "SELECT collection, id, data, updated FROM collection_documents WHERE collection = ?",
        (collection,),
    )
    return [{**row, "data": json.loads(row["data"])} for row in rows]


@app.get("/")
@app.get("/index.html")
def index():
    return send_from_directory(ROOT, "index.html")


@app.get("/api/health")
def health():
    return jsonify({"ok": True})


@app.post("/api/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name", "")).strip()
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
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
    db_execute(
        """INSERT INTO users (id, email, name, password_hash, is_admin, is_reviewer, saved, created)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, email, name, generate_password_hash(password), is_first_user, False, "[]", now_ms()),
    )
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
        elif collection == "files":
            proposals = list_documents("proposals")
            visible_ids = {
                proposal["id"]
                for proposal in proposals
                if visible_proposal(user, role, proposal["data"])
            }
            documents = [item for item in documents if item["data"].get("pid") in visible_ids]
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
        if role == "admin":
            data = {**data, "id": document_id}
        elif role == "student":
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
        else:
            return api_error("Эксперт не может создавать заявки.", 403)
    elif collection == "files":
        proposal = get_document("proposals", str(data.get("pid", "")))
        if role != "student" or proposal is None or proposal["data"].get("sid") != user["id"]:
            return api_error("Нет доступа к вложению этой заявки.", 403)
        if not isinstance(data.get("size"), int) or data["size"] < 0 or data["size"] > 122880:
            return api_error("Размер файла превышает 120 КБ.", 400)
    elif collection == "grants":
        if role != "admin":
            return api_error("Управлять грантами может только администратор.", 403)
        data = {**data, "id": document_id}
    else:
        return api_error("Создание этого типа записи запрещено.", 403)

    put_document(collection, document_id, data)
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
        elif user["is_admin"] and document_id != user["id"] and set(changes).issubset({"isAdmin", "isReviewer", "role"}):
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
            updated = {**existing, **changes, "id": document_id}
        elif role == "student" and existing.get("sid") == user["id"] and existing.get("status") == "draft":
            allowed = {"gid", "title", "abstract", "method", "budget", "months", "outcomes", "status", "updated"}
            if not set(changes).issubset(allowed) or changes.get("status", "draft") not in {"draft", "submitted"}:
                return api_error("Нельзя изменить эти поля заявки.", 403)
            updated = {**existing, **changes}
            if updated.get("status") == "submitted" and any(not updated.get(key) for key in ("title", "abstract", "method", "outcomes")):
                return api_error("Заполните все обязательные поля заявки.", 400)
        elif role == "reviewer" and visible_proposal(user, role, existing):
            review = (changes.get("reviews") or {}).get(user["id"])
            scores = review.get("scores") if isinstance(review, dict) else None
            if not isinstance(scores, dict) or any(not isinstance(value, (int, float)) or not 1 <= value <= 10 for value in scores.values()):
                return api_error("Некорректная оценка рецензии.", 400)
            merged_reviews = {**(existing.get("reviews") or {}), user["id"]: review}
            updated = {**existing, "reviews": merged_reviews, "updated": changes.get("updated", now_ms())}
        else:
            return api_error("Нет доступа изменять эту заявку.", 403)
        put_document(collection, document_id, updated)
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
        if not user["is_admin"] or target is None or target["id"] == user["id"]:
            return api_error("Нет прав удалить этого пользователя.", 403)
        db_execute("DELETE FROM users WHERE id = ?", (document_id,))
        return jsonify({"ok": True})
    if document is None:
        return api_error("Запись не найдена.", 404)
    if collection == "proposals":
        if role != "admin" and not (role == "student" and document["data"].get("sid") == user["id"] and document["data"].get("status") == "draft"):
            return api_error("Удалять можно только свой черновик.", 403)
        files = list_documents("files")
        for item in files:
            if item["data"].get("pid") == document_id:
                db_execute("DELETE FROM collection_documents WHERE collection = ? AND id = ?", ("files", item["id"]))
    elif collection == "files":
        proposal = get_document("proposals", str(document["data"].get("pid", "")))
        if role != "admin" and not (
            role == "student"
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)