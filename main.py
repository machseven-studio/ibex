# main.py — I.B.E.X. backend (hardened build)
import csv
import hashlib
import hmac
import io
import json
import logging
import os
import random
import re
import secrets
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
import psycopg2
from psycopg2.extras import DictCursor

from fastapi import (
    Cookie, Depends, FastAPI, File, Form, Header, HTTPException,
    Request, Response, UploadFile,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr

# ---------------------------------------------------------------------------
# Logging (server-side; never surfaced to users)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("ibex")

app = FastAPI(title="I.B.E.X.", version="5.1.0")

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
# IBEX-SEC: upload dir must be a persistent mount on Render (disk) — set via env.
UPLOAD_DIR = os.path.abspath(os.getenv("IBEX_UPLOAD_DIR") or os.path.join(os.path.dirname(__file__), "..", "private_uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

SESSION_LIFETIME_DAYS = 30
SESSION_COOKIE_NAME = "alg_session"
IS_PRODUCTION = os.getenv("ENV", "production").lower() != "development"
PBKDF2_ITERATIONS = 200_000

ALLOWED_UPLOAD_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx"}
ALLOWED_UPLOAD_MIME_TYPES = {
    "application/pdf", "image/jpeg", "image/png",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

LOGIN_MAX_ATTEMPTS = int(os.getenv("IBEX_LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SECONDS = int(os.getenv("IBEX_LOGIN_WINDOW_SECONDS", str(15 * 60)))
_login_attempts: dict[str, list[float]] = defaultdict(list)
_login_attempts_lock = threading.Lock()

VALID_MODULES = ['students', 'teachers', 'classrooms', 'syllabus', 'attendance', 'invigilation', 'fees']
SEATING_MODULE = 'seating'

ACCESS_HEADS = ['homepage', 'administrations', 'examination', 'front_office']
MODULE_HEAD = {
    'analytics': 'homepage', 'assistant': 'homepage', 'students': 'homepage',
    'teachers': 'homepage', 'classrooms': 'homepage',
    'attendance': 'administrations', 'syllabus': 'administrations',
    'timetables': 'administrations', 'whatsapp': 'administrations',
    'seating': 'examination', 'invigilation': 'examination',
    'results': 'examination', 'history': 'examination', 'performance': 'examination',
    'inquiry': 'front_office', 'fees': 'front_office', 'users': 'front_office',
    'journal': 'front_office', 'audit_history': 'front_office',
}
OWNER_ONLY_MODULES = {'users', 'journal', 'audit_history'}
STAFF_GRANTABLE_MODULES = [
    m for m, h in MODULE_HEAD.items()
    if h in ('administrations', 'examination', 'front_office') and m not in OWNER_ONLY_MODULES
]
ALL_ACCESS_MODULES = list(MODULE_HEAD.keys())

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
DESIGNATION_PRESETS = ['Admin', 'Accountant', 'Teacher', 'Head', 'Clerk', 'Custom']
WHATSAPP_API_URL = os.getenv("WHATSAPP_API_URL")
WHATSAPP_API_TOKEN = os.getenv("WHATSAPP_API_TOKEN")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID")

GATED_MODULES = {"fees", "users", "journal", "audit_history"}
GATE_TTL_SECONDS = 15 * 60

IST_OFFSET = timedelta(hours=5, minutes=30)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is required.")
    kwargs = {"cursor_factory": DictCursor}
    if "sslmode=" not in DATABASE_URL and "localhost" not in DATABASE_URL and "127.0.0.1" not in DATABASE_URL:
        kwargs["sslmode"] = "require"
    return psycopg2.connect(DATABASE_URL, **kwargs)


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    statements = [
        "CREATE TABLE IF NOT EXISTS institutes (id SERIAL PRIMARY KEY, institute_name TEXT NOT NULL, full_name TEXT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL)",
        "CREATE TABLE IF NOT EXISTS branches (id SERIAL PRIMARY KEY, institute_id INTEGER NOT NULL REFERENCES institutes(id) ON DELETE CASCADE, tenant_id INTEGER NOT NULL, name TEXT NOT NULL, UNIQUE(institute_id, name))",
        "CREATE TABLE IF NOT EXISTS staff_users (id SERIAL PRIMARY KEY, institute_id INTEGER NOT NULL REFERENCES institutes(id) ON DELETE CASCADE, full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, permission TEXT NOT NULL DEFAULT 'read_only', designation TEXT, module_access TEXT, created_at TIMESTAMPTZ NOT NULL)",
        "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, institute_id INTEGER NOT NULL REFERENCES institutes(id) ON DELETE CASCADE, staff_user_id INTEGER REFERENCES staff_users(id) ON DELETE CASCADE, expires_at TIMESTAMPTZ NOT NULL)",
        "CREATE TABLE IF NOT EXISTS module_gate_tokens (token TEXT PRIMARY KEY, institute_id INTEGER NOT NULL REFERENCES institutes(id) ON DELETE CASCADE, staff_user_id INTEGER, module TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS students (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, name TEXT, email TEXT, batch TEXT, status TEXT, document TEXT, roll_number TEXT, parent_contact TEXT)",
        "CREATE TABLE IF NOT EXISTS teachers (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, name TEXT, subject TEXT, department TEXT, document TEXT, contact_number TEXT)",
        "CREATE TABLE IF NOT EXISTS classrooms (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, room_no TEXT, capacity INTEGER, building TEXT, document TEXT)",
        "CREATE TABLE IF NOT EXISTS syllabus (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, subject TEXT, semester TEXT, units INTEGER, document TEXT, topic TEXT, teacher_name TEXT, num_lectures INTEGER, lecture_date TEXT)",
        # IBEX-SEC: attendance now has student_id (FK); student_name retained for display compat
        "CREATE TABLE IF NOT EXISTS attendance (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, student_id INTEGER REFERENCES students(id) ON DELETE CASCADE, student_name TEXT, date TEXT, status TEXT, document TEXT)",
        "CREATE TABLE IF NOT EXISTS timetables_slots (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, batch_name TEXT, day TEXT, time_slot TEXT, lecture_number INTEGER, subject TEXT, teacher TEXT, room TEXT)",
        "CREATE TABLE IF NOT EXISTS timetable_configs (id SERIAL PRIMARY KEY, branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE, batch_name TEXT NOT NULL, timings_json TEXT NOT NULL, teachers_config_json TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL, UNIQUE(branch_id, batch_name))",
        "CREATE TABLE IF NOT EXISTS exam_seatings (id SERIAL PRIMARY KEY, branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE, exam_date TEXT NOT NULL, room_number TEXT NOT NULL, rows INTEGER NOT NULL, columns INTEGER NOT NULL, assignments_json TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL)",
        "CREATE TABLE IF NOT EXISTS invigilation (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, teacher_name TEXT, exam_date TEXT, room TEXT, document TEXT)",
        "CREATE TABLE IF NOT EXISTS fees (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, student_name TEXT, amount_inr NUMERIC(12,2), status TEXT, due_date TEXT, document TEXT, utr_reference TEXT, paid_at TIMESTAMPTZ, paid_by INTEGER)",
        # IBEX-SEC: audit_log gains institute_id, actor_type, actor_id
        """CREATE TABLE IF NOT EXISTS audit_log (
            id BIGSERIAL PRIMARY KEY,
            timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            institute_id INTEGER,
            branch_id INTEGER,
            actor_type TEXT NOT NULL DEFAULT 'unknown',
            actor_id TEXT,
            user_id INTEGER,
            action_type TEXT NOT NULL,
            before_after_payload JSONB NOT NULL DEFAULT '{}'::jsonb
        )""",
        """CREATE TABLE IF NOT EXISTS journal_entries (
            id SERIAL PRIMARY KEY,
            institute_id INTEGER NOT NULL REFERENCES institutes(id) ON DELETE CASCADE,
            branch_id INTEGER REFERENCES branches(id) ON DELETE SET NULL,
            author_user_id INTEGER,
            author_name TEXT,
            content TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS inquiries (
            id SERIAL PRIMARY KEY,
            branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
            name TEXT NOT NULL, phone TEXT, email TEXT, source TEXT,
            interested_in TEXT, status TEXT NOT NULL DEFAULT 'New',
            notes TEXT, follow_up_date TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS exam_results (
            id SERIAL PRIMARY KEY,
            branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
            batch_name TEXT NOT NULL, subjects TEXT NOT NULL, topics TEXT NOT NULL,
            exam_date TEXT NOT NULL, overall_marks NUMERIC(12,2) NOT NULL,
            student_id INTEGER REFERENCES students(id) ON DELETE SET NULL,
            student_name TEXT NOT NULL, roll_number TEXT, marks NUMERIC(12,2),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS exam_history (
            id SERIAL PRIMARY KEY,
            branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
            subject TEXT NOT NULL, topic TEXT NOT NULL, batch_name TEXT NOT NULL,
            exam_date TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
    ]
    for stmt in statements:
        cur.execute(stmt)

    # Column additions (idempotent)
    for stmt in [
        "ALTER TABLE branches ADD COLUMN IF NOT EXISTS tenant_id INTEGER",
        "UPDATE branches SET tenant_id = institute_id WHERE tenant_id IS NULL",
        "ALTER TABLE staff_users ADD COLUMN IF NOT EXISTS permission TEXT NOT NULL DEFAULT 'read_only'",
        "ALTER TABLE staff_users ADD COLUMN IF NOT EXISTS designation TEXT",
        "ALTER TABLE staff_users ADD COLUMN IF NOT EXISTS module_access TEXT",
        "ALTER TABLE students ADD COLUMN IF NOT EXISTS email TEXT",
        "ALTER TABLE students ADD COLUMN IF NOT EXISTS batch TEXT",
        "ALTER TABLE students ADD COLUMN IF NOT EXISTS status TEXT",
        "ALTER TABLE students ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE students ADD COLUMN IF NOT EXISTS roll_number TEXT",
        "ALTER TABLE students ADD COLUMN IF NOT EXISTS parent_contact TEXT",
        "ALTER TABLE teachers ADD COLUMN IF NOT EXISTS name TEXT",
        "ALTER TABLE teachers ADD COLUMN IF NOT EXISTS subject TEXT",
        "ALTER TABLE teachers ADD COLUMN IF NOT EXISTS department TEXT",
        "ALTER TABLE teachers ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE teachers ADD COLUMN IF NOT EXISTS contact_number TEXT",
        "ALTER TABLE classrooms ADD COLUMN IF NOT EXISTS room_no TEXT",
        "ALTER TABLE classrooms ADD COLUMN IF NOT EXISTS capacity INTEGER",
        "ALTER TABLE classrooms ADD COLUMN IF NOT EXISTS building TEXT",
        "ALTER TABLE classrooms ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS subject TEXT",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS semester TEXT",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS units INTEGER",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS topic TEXT",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS teacher_name TEXT",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS num_lectures INTEGER",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS lecture_date TEXT",
        # Attendance: student_id + name compat
        "ALTER TABLE attendance ADD COLUMN IF NOT EXISTS student_id INTEGER",
        "ALTER TABLE attendance ADD COLUMN IF NOT EXISTS student_name TEXT",
        "ALTER TABLE attendance ADD COLUMN IF NOT EXISTS date TEXT",
        "ALTER TABLE attendance ADD COLUMN IF NOT EXISTS status TEXT",
        "ALTER TABLE attendance ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS batch_name TEXT",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS day TEXT",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS time_slot TEXT",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS lecture_number INTEGER",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS subject TEXT",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS teacher TEXT",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS room TEXT",
        "ALTER TABLE timetable_configs ADD COLUMN IF NOT EXISTS timings_json TEXT",
        "ALTER TABLE timetable_configs ADD COLUMN IF NOT EXISTS teachers_config_json TEXT",
        "ALTER TABLE timetable_configs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ",
        "ALTER TABLE exam_seatings ADD COLUMN IF NOT EXISTS exam_date TEXT",
        "ALTER TABLE exam_seatings ADD COLUMN IF NOT EXISTS room_number TEXT",
        "ALTER TABLE exam_seatings ADD COLUMN IF NOT EXISTS rows INTEGER",
        "ALTER TABLE exam_seatings ADD COLUMN IF NOT EXISTS columns INTEGER",
        "ALTER TABLE exam_seatings ADD COLUMN IF NOT EXISTS assignments_json TEXT",
        "ALTER TABLE exam_seatings ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ",
        "ALTER TABLE invigilation ADD COLUMN IF NOT EXISTS teacher_name TEXT",
        "ALTER TABLE invigilation ADD COLUMN IF NOT EXISTS exam_date TEXT",
        "ALTER TABLE invigilation ADD COLUMN IF NOT EXISTS room TEXT",
        "ALTER TABLE invigilation ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS student_name TEXT",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS amount_inr NUMERIC(12,2)",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS status TEXT",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS due_date TEXT",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS utr_reference TEXT",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS paid_by INTEGER",
        # audit_log additions
        "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS institute_id INTEGER",
        "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS actor_type TEXT NOT NULL DEFAULT 'unknown'",
        "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS actor_id TEXT",
    ]:
        cur.execute(stmt)

    # Backfill audit_log.institute_id — safe, non-destructive.
    # 1) rows with branch_id -> branch's tenant
    cur.execute("""
        UPDATE audit_log a
        SET institute_id = b.tenant_id
        FROM branches b
        WHERE a.institute_id IS NULL AND a.branch_id = b.id
    """)
    # 2) rows whose user_id matches a staff_user
    cur.execute("""
        UPDATE audit_log a
        SET institute_id = s.institute_id,
            actor_type = COALESCE(NULLIF(a.actor_type,'unknown'),'staff'),
            actor_id   = COALESCE(a.actor_id, 'staff:' || s.id::text)
        FROM staff_users s
        WHERE a.institute_id IS NULL AND a.user_id = s.id
    """)
    # 3) rows whose user_id matches an institute owner
    cur.execute("""
        UPDATE audit_log a
        SET institute_id = i.id,
            actor_type = COALESCE(NULLIF(a.actor_type,'unknown'),'owner'),
            actor_id   = COALESCE(a.actor_id, 'owner:' || i.id::text)
        FROM institutes i
        WHERE a.institute_id IS NULL AND a.user_id = i.id
    """)
    # Rows still NULL are orphaned legacy entries — never exposed by any query.
    # Backfill attendance.student_id where names match uniquely within a branch.
    cur.execute("""
        UPDATE attendance a
        SET student_id = s.id
        FROM students s
        WHERE a.student_id IS NULL
          AND a.branch_id = s.branch_id
          AND a.student_name = s.name
          AND (
            SELECT COUNT(*) FROM students s2
            WHERE s2.branch_id = s.branch_id AND s2.name = s.name
          ) = 1
    """)

    # Unique indexes / FKs where safe
    for stmt in [
        "CREATE INDEX IF NOT EXISTS idx_branches_institute ON branches(institute_id)",
        "CREATE INDEX IF NOT EXISTS idx_branches_tenant ON branches(tenant_id)",
        "CREATE INDEX IF NOT EXISTS idx_students_branch ON students(branch_id)",
        "CREATE INDEX IF NOT EXISTS idx_students_branch_name ON students(branch_id, name)",
        "CREATE INDEX IF NOT EXISTS idx_teachers_branch ON teachers(branch_id)",
        "CREATE INDEX IF NOT EXISTS idx_classrooms_branch ON classrooms(branch_id)",
        "CREATE INDEX IF NOT EXISTS idx_syllabus_branch ON syllabus(branch_id)",
        "CREATE INDEX IF NOT EXISTS idx_attendance_branch_date ON attendance(branch_id, date)",
        "CREATE INDEX IF NOT EXISTS idx_attendance_student_date ON attendance(branch_id, student_id, date)",
        "CREATE INDEX IF NOT EXISTS idx_timetable_branch_day_slot ON timetables_slots(branch_id, day, time_slot)",
        "CREATE INDEX IF NOT EXISTS idx_fees_branch_status ON fees(branch_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_audit_institute_timestamp ON audit_log(institute_id, timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_audit_branch_timestamp ON audit_log(branch_id, timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_journal_institute_created ON journal_entries(institute_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_inquiries_branch_created ON inquiries(branch_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_gate_tokens_expires ON module_gate_tokens(expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_exam_results_branch_batch ON exam_results(branch_id, batch_name)",
        "CREATE INDEX IF NOT EXISTS idx_exam_history_branch_date ON exam_history(branch_id, exam_date)",
    ]:
        cur.execute(stmt)
    conn.commit()
    cur.close()
    conn.close()


init_db()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _legacy_pbkdf2_hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str, legacy_salt: str | None) -> tuple[bool, str | None]:
    if password_hash.startswith("$2"):
        try:
            return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")), None
        except ValueError:
            return False, None
    if not legacy_salt:
        return False, None
    computed = _legacy_pbkdf2_hash(password, legacy_salt)
    if secrets.compare_digest(computed, password_hash):
        return True, hash_password(password)
    return False, None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ist_now() -> datetime:
    return _utcnow() + IST_OFFSET


def _ist_today_iso() -> str:
    return _ist_now().date().isoformat()


def _safe_error(context: str, exc: Exception) -> str:
    """Log full detail server-side; return a generic client message."""
    log.exception("[%s] %s", context, exc)
    return "We couldn't complete that request. Please try again."


def _rate_limit_key(request: Request, email: str) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{ip}:{email.strip().lower()}"


def check_login_rate_limit(request: Request, email: str):
    key = _rate_limit_key(request, email)
    now = time.time()
    with _login_attempts_lock:
        attempts = [t for t in _login_attempts[key] if now - t < LOGIN_WINDOW_SECONDS]
        _login_attempts[key] = attempts
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            raise HTTPException(status_code=429, detail="Too many login attempts. Please wait and try again.")


def record_failed_login(request: Request, email: str):
    with _login_attempts_lock:
        _login_attempts[_rate_limit_key(request, email)].append(time.time())


def clear_login_attempts(request: Request, email: str):
    with _login_attempts_lock:
        _login_attempts.pop(_rate_limit_key(request, email), None)


def set_session_cookie(response: Response, token: str):
    response.set_cookie(
        key=SESSION_COOKIE_NAME, value=token,
        httponly=True, secure=IS_PRODUCTION, samesite="lax",
        max_age=SESSION_LIFETIME_DAYS * 86400, path="/",
    )


def clear_session_cookie(response: Response):
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")


def create_session(institute_id: int, staff_user_id: int | None = None) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (_utcnow() + timedelta(days=SESSION_LIFETIME_DAYS)).isoformat()
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO sessions (token, institute_id, staff_user_id, expires_at) VALUES (%s, %s, %s, %s)",
            (token, institute_id, staff_user_id, expires_at),
        )
        conn.commit()
    finally:
        conn.close()
    audit_system(institute_id, None, "CREATE_SESSION", None, {"staff_user_id": staff_user_id})
    return token


def touch_session(token: str):
    conn = get_conn()
    try:
        cur = conn.cursor()
        new_expiry = (_utcnow() + timedelta(days=SESSION_LIFETIME_DAYS)).isoformat()
        cur.execute("UPDATE sessions SET expires_at = %s WHERE token = %s", (new_expiry, token))
        conn.commit()
    finally:
        conn.close()


class CurrentInstitute(BaseModel):
    user_id: int | None = None
    id: int
    institute_name: str
    full_name: str
    email: str
    is_owner: bool
    permission: str
    designation: str = "Owner"
    allowed_modules: list = ALL_ACCESS_MODULES


# ---------------------------------------------------------------------------
# Gate tokens — bound to (institute_id, staff_user_id_or_owner)
# ---------------------------------------------------------------------------

def _actor_key(institute: "CurrentInstitute") -> str:
    """Unambiguous actor key: 'owner:<institute>' or 'staff:<id>'."""
    if institute.is_owner:
        return f"owner:{institute.id}"
    return f"staff:{institute.user_id}"


def create_gate_token(institute: "CurrentInstitute", module: str) -> str:
    token = secrets.token_urlsafe(24)
    expires_at = (_utcnow() + timedelta(seconds=GATE_TTL_SECONDS)).isoformat()
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO module_gate_tokens (token, institute_id, staff_user_id, module, expires_at) VALUES (%s, %s, %s, %s, %s)",
            (token, institute.id, institute.user_id if not institute.is_owner else None, module, expires_at),
        )
        conn.commit()
    finally:
        conn.close()
    return token


def consume_gate_token(institute: "CurrentInstitute", module: str, token: str | None) -> None:
    """Raise 403 unless a valid, unexpired gate token exists for THIS actor+module.
    Token is also bound to the actor — one user's token cannot be reused by another."""
    if not token:
        raise HTTPException(status_code=403, detail=f"Password re-verification required for {module.replace('_', ' ')}.")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT expires_at, staff_user_id FROM module_gate_tokens WHERE token = %s AND institute_id = %s AND module = %s",
            (token, institute.id, module),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=403, detail="Invalid or expired gate token. Please re-verify.")
        # IBEX-SEC: bind token to the actor
        stored_staff = row["staff_user_id"]
        if institute.is_owner:
            if stored_staff is not None:
                raise HTTPException(status_code=403, detail="Gate token does not belong to this user.")
        else:
            if stored_staff != institute.user_id:
                raise HTTPException(status_code=403, detail="Gate token does not belong to this user.")
        expires_at = row["expires_at"]
        if not isinstance(expires_at, datetime):
            expires_at = datetime.fromisoformat(expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < _utcnow():
            raise HTTPException(status_code=403, detail="Gate token expired. Please re-verify.")
        new_expiry = (_utcnow() + timedelta(seconds=GATE_TTL_SECONDS)).isoformat()
        cur.execute("UPDATE module_gate_tokens SET expires_at = %s WHERE token = %s", (new_expiry, token))
        conn.commit()
    finally:
        conn.close()


def check_module_access(institute: "CurrentInstitute", module: str):
    if institute.is_owner:
        return
    if module in OWNER_ONLY_MODULES:
        raise HTTPException(status_code=403, detail=f"Only the institute owner can access {module.replace('_', ' ').title()}")
    if module not in (institute.allowed_modules or []):
        raise HTTPException(status_code=403, detail=f"Your account does not have access to the {module.title()} module")


def get_current_institute(alg_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME)) -> CurrentInstitute:
    if not alg_session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = alg_session
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE token = %s", (token,))
        session = cursor.fetchone()
        if not session:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        expires_at = session["expires_at"]
        if not isinstance(expires_at, datetime):
            expires_at = datetime.fromisoformat(expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < _utcnow():
            cursor.execute("DELETE FROM sessions WHERE token = %s", (token,))
            conn.commit()
            audit_system(session["institute_id"], None, "EXPIRE_SESSION", {"token": "redacted"}, None)
            raise HTTPException(status_code=401, detail="Session expired, please log in again")

        cursor.execute("SELECT * FROM institutes WHERE id = %s", (session["institute_id"],))
        institute = cursor.fetchone()
        if not institute:
            raise HTTPException(status_code=401, detail="Invalid session")

        if session["staff_user_id"] is not None:
            cursor.execute("SELECT * FROM staff_users WHERE id = %s", (session["staff_user_id"],))
            staff = cursor.fetchone()
            if not staff:
                raise HTTPException(status_code=401, detail="Invalid session")
            raw_access = staff["module_access"] if "module_access" in staff.keys() else None
            try:
                allowed = json.loads(raw_access) if raw_access else []
            except (TypeError, ValueError):
                allowed = []
            touch_session(token)
            return CurrentInstitute(
                user_id=staff["id"], id=institute["id"],
                institute_name=institute["institute_name"], full_name=staff["full_name"],
                email=staff["email"], is_owner=False, permission=staff["permission"],
                designation=(staff["designation"] if "designation" in staff.keys() and staff["designation"] else "Staff"),
                allowed_modules=allowed,
            )

        touch_session(token)
        return CurrentInstitute(
            user_id=institute["id"], id=institute["id"],
            institute_name=institute["institute_name"], full_name=institute["full_name"] or "",
            email=institute["email"], is_owner=True, permission="owner",
        )
    finally:
        conn.close()


def require_write_access(institute: CurrentInstitute = Depends(get_current_institute)) -> CurrentInstitute:
    if institute.permission == "read_only":
        raise HTTPException(status_code=403, detail="Your account has read-only access")
    return institute


def require_owner(institute: CurrentInstitute = Depends(get_current_institute)) -> CurrentInstitute:
    if not institute.is_owner:
        raise HTTPException(status_code=403, detail="Only the institute owner can do this")
    return institute


def require_institute_admin(institute: CurrentInstitute = Depends(get_current_institute)) -> CurrentInstitute:
    """Owner OR staff with 'edit' permission and a designation resembling admin/head.
    Used for institute-level config that shouldn't be open to any editor."""
    if institute.is_owner:
        return institute
    if institute.permission != "edit":
        raise HTTPException(status_code=403, detail="Administrative access required")
    desig = (institute.designation or "").strip().lower()
    if desig in ("admin", "head", "principal", "director", "owner"):
        return institute
    raise HTTPException(status_code=403, detail="Administrative access required")


def verify_branch_ownership(branch_id: int, institute_id: int) -> int:
    """Confirm branch belongs to institute. Returns branch_id. Raises 404 if not."""
    if branch_id is None:
        raise HTTPException(status_code=400, detail="Branch is required")
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM branches WHERE id = %s AND tenant_id = %s", (branch_id, institute_id))
        row = cursor.fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Branch not found")
    return row["id"]


def verify_branch_read_access(branch_id: int, institute_id: int):
    if branch_id == 0:
        return  # HQ aggregate — scoped by tenant in queries
    verify_branch_ownership(branch_id, institute_id)


# ---------------------------------------------------------------------------
# Audit writers — always include institute_id and unambiguous actor
# ---------------------------------------------------------------------------

def _redact(payload):
    """Strip secrets before persisting to audit."""
    if payload is None:
        return None
    if isinstance(payload, dict):
        out = {}
        for k, v in payload.items():
            kl = str(k).lower()
            if kl in {"password", "password_hash", "password_salt", "token", "session", "gate_token", "secret"}:
                out[k] = "[redacted]"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(payload, list):
        return [_redact(x) for x in payload]
    return payload


def _insert_audit(institute_id: int | None, branch_id: int | None, actor_type: str,
                  actor_id: str | None, user_id: int | None,
                  action_type: str, before, after):
    payload = json.dumps({"before": _redact(before), "after": _redact(after)}, default=str)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO audit_log
               (timestamp, institute_id, branch_id, actor_type, actor_id, user_id, action_type, before_after_payload)
               VALUES (NOW(), %s, %s, %s, %s, %s, %s, %s::jsonb)""",
            (institute_id, branch_id, actor_type, actor_id, user_id, action_type, payload),
        )
        conn.commit()
    except Exception as exc:
        log.exception("audit insert failed: %s", exc)
    finally:
        conn.close()


def audit_write(institute: CurrentInstitute, branch_id: int | None, action_type: str, before=None, after=None):
    _insert_audit(
        institute_id=institute.id,
        branch_id=branch_id,
        actor_type="owner" if institute.is_owner else "staff",
        actor_id=_actor_key(institute),
        user_id=institute.user_id,
        action_type=action_type,
        before=before, after=after,
    )


def audit_system(institute_id: int | None, branch_id: int | None, action_type: str, before=None, after=None, actor_id: str | None = None):
    _insert_audit(
        institute_id=institute_id, branch_id=branch_id,
        actor_type="system" if actor_id is None else "system",
        actor_id=actor_id or "system",
        user_id=None, action_type=action_type, before=before, after=after,
    )


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # CSP: allow CDN scripts we actually use, inline styles/scripts already in index.html
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com "
        "https://cdn.jsdelivr.net https://generativelanguage.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' https://generativelanguage.googleapis.com https://graph.facebook.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Frame-Options"] = "DENY"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, private"
    return response


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

class SignupRequest(BaseModel):
    institute_name: str
    full_name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.post("/api/auth/signup")
def signup(req: SignupRequest, response: Response):
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    password_hash = hash_password(req.password)
    conn = get_conn()
    try:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO institutes (institute_name, full_name, email, password_hash, password_salt, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                (req.institute_name, req.full_name, req.email.lower(), password_hash, "", _utcnow().isoformat()),
            )
            institute_id = cursor.fetchone()["id"]
            cursor.execute(
                "INSERT INTO branches (institute_id, tenant_id, name) VALUES (%s, %s, %s)",
                (institute_id, institute_id, "Main Campus"),
            )
            conn.commit()
        except psycopg2.IntegrityError:
            conn.rollback()
            raise HTTPException(status_code=400, detail="An account with this email already exists")
    finally:
        conn.close()
    audit_system(institute_id, None, "CREATE_INSTITUTE", None, {"institute_id": institute_id, "starter_branch": "Main Campus"})
    token = create_session(institute_id)
    set_session_cookie(response, token)
    return {
        "institute_name": req.institute_name, "full_name": req.full_name,
        "is_owner": True, "permission": "owner", "designation": "Owner",
        "allowed_modules": ALL_ACCESS_MODULES,
    }


@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response):
    check_login_rate_limit(request, req.email)
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM institutes WHERE email = %s", (req.email.lower(),))
        institute = cursor.fetchone()

        if institute:
            valid, upgraded = verify_password(req.password, institute["password_hash"], institute["password_salt"])
            if valid:
                if upgraded:
                    cursor.execute("UPDATE institutes SET password_hash=%s, password_salt='' WHERE id=%s", (upgraded, institute["id"]))
                    conn.commit()
                clear_login_attempts(request, req.email)
                token = create_session(institute["id"])
                set_session_cookie(response, token)
                return {
                    "institute_name": institute["institute_name"],
                    "full_name": institute["full_name"] or "",
                    "is_owner": True, "permission": "owner", "designation": "Owner",
                    "allowed_modules": ALL_ACCESS_MODULES,
                }

        cursor.execute("SELECT * FROM staff_users WHERE email = %s", (req.email.lower(),))
        staff = cursor.fetchone()
        if staff:
            valid, upgraded = verify_password(req.password, staff["password_hash"], staff["password_salt"])
            if valid:
                if upgraded:
                    cursor.execute("UPDATE staff_users SET password_hash=%s, password_salt='' WHERE id=%s", (upgraded, staff["id"]))
                    conn.commit()
                cursor.execute("SELECT * FROM institutes WHERE id = %s", (staff["institute_id"],))
                parent_institute = cursor.fetchone()
                clear_login_attempts(request, req.email)
                token = create_session(staff["institute_id"], staff_user_id=staff["id"])
                set_session_cookie(response, token)
                try:
                    staff_modules = json.loads(staff["module_access"]) if staff["module_access"] else []
                except (TypeError, ValueError):
                    staff_modules = []
                return {
                    "institute_name": parent_institute["institute_name"] if parent_institute else "",
                    "full_name": staff["full_name"],
                    "is_owner": False, "permission": staff["permission"],
                    "designation": staff["designation"] or "Staff",
                    "allowed_modules": staff_modules,
                }

        record_failed_login(request, req.email)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    finally:
        conn.close()


@app.get("/api/auth/me")
def whoami(institute: CurrentInstitute = Depends(get_current_institute)):
    return {
        "user_id": institute.user_id, "institute_id": institute.id,
        "institute_name": institute.institute_name, "full_name": institute.full_name,
        "is_owner": institute.is_owner, "permission": institute.permission,
        "designation": institute.designation, "allowed_modules": institute.allowed_modules,
    }


@app.post("/api/auth/refresh")
def refresh_session(response: Response, institute: CurrentInstitute = Depends(get_current_institute),
                    alg_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME)):
    if alg_session:
        touch_session(alg_session)
        set_session_cookie(response, alg_session)
    return {"status": "refreshed", "expires_in_days": SESSION_LIFETIME_DAYS}


@app.post("/api/auth/logout")
def logout(response: Response, alg_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME)):
    if alg_session:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT institute_id FROM sessions WHERE token=%s", (alg_session,))
            row = cur.fetchone()
            cur.execute("DELETE FROM sessions WHERE token = %s", (alg_session,))
            conn.commit()
        finally:
            conn.close()
        if row:
            audit_system(row["institute_id"], None, "LOGOUT_SESSION", None, {"token": "redacted"})
    clear_session_cookie(response)
    return {"status": "logged out"}


class PasswordVerifyPayload(BaseModel):
    password: str
    target_module: str | None = None
    target_label: str | None = None


@app.post("/api/auth/verify-password")
def verify_password_gate(payload: PasswordVerifyPayload, institute: CurrentInstitute = Depends(get_current_institute)):
    conn = get_conn()
    try:
        cur = conn.cursor()
        if institute.is_owner:
            cur.execute("SELECT password_hash, password_salt FROM institutes WHERE id=%s", (institute.id,))
        else:
            cur.execute("SELECT password_hash, password_salt FROM staff_users WHERE id=%s", (institute.user_id,))
        row = cur.fetchone()
    finally:
        conn.close()

    ok = False
    if row:
        ok, upgraded_hash = verify_password(payload.password, row["password_hash"], row["password_salt"] or None)
        if ok and upgraded_hash:
            conn2 = get_conn()
            try:
                cur2 = conn2.cursor()
                table = "institutes" if institute.is_owner else "staff_users"
                target_id = institute.id if institute.is_owner else institute.user_id
                cur2.execute(f"UPDATE {table} SET password_hash=%s WHERE id=%s", (upgraded_hash, target_id))
                conn2.commit()
            finally:
                conn2.close()

    status = "Access Allowed" if ok else "Access Denied"
    audit_write(institute, None, "PASSWORD_CHECK", None, {
        "user_name": institute.full_name,
        "target_module": payload.target_module,
        "target_label": payload.target_label,
        "status": status,
    })
    gate_token = None
    if ok and payload.target_module and payload.target_module in GATED_MODULES:
        gate_token = create_gate_token(institute, payload.target_module)
    return {"verified": ok, "gate_token": gate_token, "expires_in_seconds": GATE_TTL_SECONDS}


# ---------------------------------------------------------------------------
# Institute profile — OWNER ONLY
# ---------------------------------------------------------------------------

class InstituteNameUpdate(BaseModel):
    institute_name: str


@app.patch("/api/institute/name")
def update_institute_name(req: InstituteNameUpdate, institute: CurrentInstitute = Depends(require_owner)):
    name = req.institute_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Institute name cannot be empty")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT institute_name FROM institutes WHERE id = %s", (institute.id,))
        row = cur.fetchone()
        before_name = (row["institute_name"] if row else None)
        cur.execute("UPDATE institutes SET institute_name = %s WHERE id = %s", (name, institute.id))
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, None, "UPDATE_INSTITUTE", {"institute_name": before_name}, {"institute_name": name})
    return {"institute_name": name}


# ---------------------------------------------------------------------------
# Staff users
# ---------------------------------------------------------------------------

class StaffUserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    permission: str
    designation: str
    modules: list = []


class StaffPermissionUpdate(BaseModel):
    permission: str | None = None
    designation: str | None = None
    modules: list | None = None


def _validate_modules(modules: list):
    if not isinstance(modules, list):
        raise HTTPException(status_code=400, detail="Module privileges must be a list")
    bad = [m for m in modules if m not in STAFF_GRANTABLE_MODULES]
    if bad:
        raise HTTPException(status_code=400, detail=f"Unknown module privilege(s): {', '.join(bad)}")


@app.get("/api/users")
def list_staff_users(institute: CurrentInstitute = Depends(require_owner),
                     x_gate_token: str | None = Header(default=None)):
    consume_gate_token(institute, "users", x_gate_token)
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, full_name, email, permission, designation, module_access, created_at FROM staff_users WHERE institute_id = %s",
            (institute.id,),
        )
        users = []
        for row in cursor.fetchall():
            u = dict(row)
            raw = u.pop("module_access", None)
            try:
                u["modules"] = json.loads(raw) if raw else []
            except (TypeError, ValueError):
                u["modules"] = []
            u["designation"] = u.get("designation") or "Staff"
            users.append(u)
        return users
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=_safe_error("list_users", exc))
    finally:
        conn.close()


@app.post("/api/users")
def add_staff_user(req: StaffUserCreate, institute: CurrentInstitute = Depends(require_owner),
                   x_gate_token: str | None = Header(default=None)):
    consume_gate_token(institute, "users", x_gate_token)
    if req.permission not in ("edit", "read_only"):
        raise HTTPException(status_code=400, detail="Permission must be 'edit' or 'read_only'")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not req.designation.strip():
        raise HTTPException(status_code=400, detail="Designation is required")
    _validate_modules(req.modules)
    password_hash = hash_password(req.password)
    conn = get_conn()
    try:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO staff_users (institute_id, full_name, email, password_hash, password_salt, permission, designation, module_access, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                (institute.id, req.full_name, req.email.lower(), password_hash, "", req.permission,
                 req.designation.strip(), json.dumps(req.modules), _utcnow().isoformat()),
            )
            user_id = cursor.fetchone()["id"]
            conn.commit()
        except psycopg2.IntegrityError:
            conn.rollback()
            raise HTTPException(status_code=400, detail="A user with this email already exists")
    finally:
        conn.close()
    audit_write(institute, None, "CREATE_USER", None, {
        "id": user_id, "full_name": req.full_name, "email": req.email.lower(),
        "permission": req.permission, "designation": req.designation.strip(), "modules": req.modules,
    })
    return {"id": user_id, "full_name": req.full_name, "email": req.email.lower(),
            "permission": req.permission, "designation": req.designation.strip(), "modules": req.modules}


def verify_staff_ownership(user_id: int, institute_id: int):
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM staff_users WHERE id = %s AND institute_id = %s", (user_id, institute_id))
        row = cursor.fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")


@app.patch("/api/users/{user_id}")
def update_staff_permission(user_id: int, req: StaffPermissionUpdate,
                            institute: CurrentInstitute = Depends(require_owner),
                            x_gate_token: str | None = Header(default=None)):
    consume_gate_token(institute, "users", x_gate_token)
    verify_staff_ownership(user_id, institute.id)
    conn = get_conn()
    try:
        pre_cur = conn.cursor()
        pre_cur.execute("SELECT permission, designation, module_access FROM staff_users WHERE id = %s", (user_id,))
        before_user = pre_cur.fetchone()

        updates, params = [], []
        if req.permission is not None:
            if req.permission not in ("edit", "read_only"):
                raise HTTPException(status_code=400, detail="Permission must be 'edit' or 'read_only'")
            updates.append("permission = %s"); params.append(req.permission)
        if req.designation is not None:
            if not req.designation.strip():
                raise HTTPException(status_code=400, detail="Designation cannot be empty")
            updates.append("designation = %s"); params.append(req.designation.strip())
        if req.modules is not None:
            _validate_modules(req.modules)
            updates.append("module_access = %s"); params.append(json.dumps(req.modules))
        if not updates:
            raise HTTPException(status_code=400, detail="Nothing to update")
        cur = conn.cursor()
        cur.execute(f"UPDATE staff_users SET {', '.join(updates)} WHERE id = %s", (*params, user_id))
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, None, "UPDATE_USER", dict(before_user) if before_user else None,
                {"permission": req.permission, "designation": req.designation, "modules": req.modules})
    return {"id": user_id, "status": "updated"}


@app.delete("/api/users/{user_id}")
def remove_staff_user(user_id: int, institute: CurrentInstitute = Depends(require_owner),
                      x_gate_token: str | None = Header(default=None)):
    consume_gate_token(institute, "users", x_gate_token)
    verify_staff_ownership(user_id, institute.id)
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, full_name, email, permission, designation, module_access FROM staff_users WHERE id = %s", (user_id,))
        before_user = cursor.fetchone()
        cursor.execute("DELETE FROM staff_users WHERE id = %s", (user_id,))
        cursor.execute("DELETE FROM sessions WHERE staff_user_id = %s", (user_id,))
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, None, "DELETE_USER", dict(before_user) if before_user else None, None)
    return {"status": "removed"}


# ---------------------------------------------------------------------------
# Branches — OWNER ONLY for create/update/delete
# ---------------------------------------------------------------------------

class BranchCreate(BaseModel):
    name: str


@app.get("/api/branches")
def get_branches(institute: CurrentInstitute = Depends(get_current_institute)):
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM branches WHERE tenant_id = %s ORDER BY id", (institute.id,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


@app.post("/api/branches")
def add_branch(branch: BranchCreate, institute: CurrentInstitute = Depends(require_owner)):
    name = (branch.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Branch name is required")
    conn = get_conn()
    try:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO branches (institute_id, tenant_id, name) VALUES (%s, %s, %s) RETURNING id",
                (institute.id, institute.id, name),
            )
            conn.commit()
            branch_id = cursor.fetchone()["id"]
        except psycopg2.IntegrityError:
            conn.rollback()
            raise HTTPException(status_code=400, detail="Branch already exists")
    finally:
        conn.close()
    audit_write(institute, branch_id, "CREATE_BRANCH", None, {"id": branch_id, "name": name})
    return {"id": branch_id, "name": name}


@app.patch("/api/branches/{branch_id}")
def edit_branch(branch_id: int, branch: BranchCreate, institute: CurrentInstitute = Depends(require_owner)):
    verify_branch_ownership(branch_id, institute.id)
    name = (branch.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Branch name cannot be empty")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM branches WHERE id=%s AND tenant_id=%s", (branch_id, institute.id))
        before = cur.fetchone()
        if not before:
            raise HTTPException(status_code=404, detail="Branch not found")
        try:
            cur.execute("UPDATE branches SET name=%s WHERE id=%s AND tenant_id=%s RETURNING id, name",
                        (name, branch_id, institute.id))
            row = cur.fetchone()
            conn.commit()
        except psycopg2.IntegrityError:
            conn.rollback()
            raise HTTPException(status_code=400, detail="A branch with that name already exists")
    finally:
        conn.close()
    audit_write(institute, branch_id, "UPDATE_BRANCH", dict(before), {"id": row["id"], "name": row["name"]})
    return {"id": row["id"], "name": row["name"]}


@app.delete("/api/branches/{branch_id}")
def delete_branch(branch_id: int, institute: CurrentInstitute = Depends(require_owner)):
    verify_branch_ownership(branch_id, institute.id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM branches WHERE id=%s AND tenant_id=%s", (branch_id, institute.id))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Branch not found")
        name = row["name"]
        cur.execute("DELETE FROM branches WHERE id=%s AND tenant_id=%s", (branch_id, institute.id))
        if cur.rowcount != 1:
            raise HTTPException(status_code=404, detail="Branch not found")
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, None, "DELETE_BRANCH", {"id": branch_id, "name": name}, None)
    return {"status": "deleted", "id": branch_id, "name": name, "data_wiped": True}


# ---------------------------------------------------------------------------
# Generic records
# ---------------------------------------------------------------------------

RECORD_FIELDS = {
    "students": ["name", "batch", "roll_number", "parent_contact"],
    "teachers": ["name", "subject", "contact_number"],
    "classrooms": ["room_no", "capacity", "building"],
    "syllabus": ["subject", "topic", "teacher_name", "num_lectures", "lecture_date"],
    # IBEX-SEC: attendance now keyed on student_id; student_name retained for display
    "attendance": ["student_id", "student_name", "date", "status"],
    "invigilation": ["teacher_name", "exam_date", "room"],
    "fees": ["student_name", "amount_inr", "status", "due_date", "utr_reference"],
}
RECORD_HAS_DOCUMENT = {"classrooms", "attendance", "invigilation", "fees"}

BULK_IMPORT_COLUMNS = {
    "students": ["name", "batch", "roll_number", "parent_contact"],
    "teachers": ["name", "subject", "contact_number"],
    "classrooms": ["room_no", "capacity"],
    "syllabus": ["subject", "topic", "teacher_name", "num_lectures", "lecture_date"],
    "attendance": ["student_name", "date", "status"],
    "invigilation": ["teacher_name", "exam_date", "room"],
    "fees": ["student_name", "amount_inr", "status", "due_date"],
}


def _coerce_record_value(module: str, key: str, value):
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if value == "":
            return None
    if key in ("capacity", "num_lectures", "student_id"):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    if key == "amount_inr":
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
    return value


def _sniff_mime(contents: bytes, ext: str) -> str:
    if contents[:4] == b"%PDF": return "application/pdf"
    if contents[:3] == b"\xff\xd8\xff": return "image/jpeg"
    if contents[:8] == b"\x89PNG\r\n\x1a\n": return "image/png"
    if contents[:4] == b"PK\x03\x04": return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    if contents[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": return "application/msword"
    return "application/octet-stream"


def save_upload(file: UploadFile) -> str:
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_UPLOAD_EXTENSIONS))}")
    contents = file.file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="File too large (max 5 MB)")
    if not contents:
        raise HTTPException(status_code=400, detail="File is empty")
    sniffed = _sniff_mime(contents, ext)
    if sniffed not in ALLOWED_UPLOAD_MIME_TYPES:
        raise HTTPException(status_code=400, detail="File content does not match an allowed file type")
    filename = f"{secrets.token_hex(16)}{ext}"
    dest = os.path.join(UPLOAD_DIR, filename)
    if os.path.commonpath([UPLOAD_DIR, os.path.abspath(dest)]) != UPLOAD_DIR:
        raise HTTPException(status_code=400, detail="Invalid upload path")
    with open(dest, "wb") as buffer:
        buffer.write(contents)
    return filename


@app.get("/api/records/{module}/{branch_id}")
def get_records(module: str, branch_id: int, search: str = "", sort: str = "id", direction: str = "desc",
                page: int = 1, page_size: int = 200, institute: CurrentInstitute = Depends(get_current_institute)):
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    check_module_access(institute, module)
    verify_branch_read_access(branch_id, institute.id)
    page = max(1, min(page, 10000))
    page_size = max(1, min(page_size, 500))
    allowed_sort = {"id", *RECORD_FIELDS[module]}
    if sort not in allowed_sort:
        sort = "id"
    direction = "ASC" if direction.lower() == "asc" else "DESC"
    conn = get_conn()
    try:
        cursor = conn.cursor()
        params = [institute.id if branch_id == 0 else branch_id]
        where = "branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)" if branch_id == 0 else "branch_id = %s"
        search_fields = RECORD_FIELDS[module]
        if search.strip():
            clauses = [f"CAST({f} AS TEXT) ILIKE %s" for f in search_fields]
            where += " AND (" + " OR ".join(clauses) + ")"
            params.extend([f"%{search.strip()}%"] * len(clauses))
        offset = (page - 1) * page_size
        cursor.execute(
            f"SELECT * FROM {module} WHERE {where} ORDER BY {sort} {direction}, id DESC LIMIT %s OFFSET %s",
            (*params, page_size, offset),
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


@app.post("/api/records/{module}/bulk")
async def bulk_import_records(module: str, branch_id: int = Form(...), file: UploadFile = File(...),
                              institute: CurrentInstitute = Depends(require_write_access)):
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    check_module_access(institute, module)
    verify_branch_ownership(branch_id, institute.id)
    if module not in BULK_IMPORT_COLUMNS:
        raise HTTPException(status_code=400, detail=f"Bulk import isn't supported for {module}.")

    expected = BULK_IMPORT_COLUMNS[module]
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="CSV must be UTF-8 encoded.")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise HTTPException(status_code=400, detail="CSV has no header row.")
    normalized = {}
    for h in reader.fieldnames:
        if h is None:
            continue
        normalized[h.strip().lower()] = h
    missing = [c for c in expected if c not in normalized]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"CSV is missing required column(s): {', '.join(missing)}. Expected header: {', '.join(expected)}",
        )

    conn = get_conn()
    cur = conn.cursor()
    inserted = 0
    try:
        for row in reader:
            data = {col: _coerce_record_value(module, col, row.get(normalized[col])) for col in expected}

            # IBEX-SEC: attendance import — resolve student_id from name within this branch
            if module == "attendance":
                name = data.get("student_name")
                sid = None
                if name:
                    cur.execute(
                        "SELECT id FROM students WHERE branch_id=%s AND name=%s LIMIT 2",
                        (branch_id, name),
                    )
                    matches = cur.fetchall()
                    if len(matches) == 1:
                        sid = matches[0]["id"]
                cols = ["branch_id", "student_id", "student_name", "date", "status"]
                values = [branch_id, sid, name, data.get("date"), data.get("status")]
                cur.execute(
                    f"INSERT INTO attendance ({', '.join(cols)}) VALUES ({', '.join(['%s']*len(cols))})",
                    values,
                )
            else:
                cols = ["branch_id"] + expected
                values = [branch_id] + [data[c] for c in expected]
                placeholders = ", ".join(["%s"] * len(cols))
                cur.execute(f"INSERT INTO {module} ({', '.join(cols)}) VALUES ({placeholders})", values)
            inserted += 1
        conn.commit()
    except Exception as exc:
        conn.rollback()
        log.exception("bulk import failed")
        raise HTTPException(status_code=500, detail=_safe_error("bulk_import", exc))
    finally:
        conn.close()

    audit_write(institute, branch_id, "BULK_IMPORT", None, {"module": module, "inserted": inserted})
    return {"inserted": inserted}


@app.post("/api/records/{module}")
async def create_record(module: str, branch_id: int = Form(...), data_json: str = Form(...),
                        document: UploadFile | None = File(None),
                        institute: CurrentInstitute = Depends(require_write_access)):
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    check_module_access(institute, module)
    verify_branch_ownership(branch_id, institute.id)

    try:
        data = json.loads(data_json)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="data_json is not valid JSON")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="data_json must be a JSON object")

    allowed = set(RECORD_FIELDS[module])
    clean = {k: _coerce_record_value(module, k, v) for k, v in data.items() if k in allowed}

    # IBEX-SEC: attendance must reference a real student in this branch
    if module == "attendance" and clean.get("student_id") is not None:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, name FROM students WHERE id=%s AND branch_id=%s", (clean["student_id"], branch_id))
            st = cur.fetchone()
        finally:
            conn.close()
        if not st:
            raise HTTPException(status_code=400, detail="Student not found in this branch")
        clean["student_name"] = st["name"]

    if document is not None and getattr(document, "filename", None):
        if module in RECORD_HAS_DOCUMENT:
            clean["document"] = save_upload(document)

    if not clean:
        raise HTTPException(status_code=400, detail="No valid fields to insert.")

    cols = ["branch_id"] + list(clean.keys())
    placeholders = ", ".join(["%s"] * len(cols))
    values = [branch_id] + list(clean.values())

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(f"INSERT INTO {module} ({', '.join(cols)}) VALUES ({placeholders}) RETURNING *", values)
        created = dict(cur.fetchone())
        conn.commit()
    except Exception as exc:
        conn.rollback()
        log.exception("create_record failed")
        raise HTTPException(status_code=500, detail=_safe_error("create_record", exc))
    finally:
        conn.close()

    audit_write(institute, branch_id, "CREATE_RECORD", None, {"module": module, "record": created})
    return {"id": created["id"], "status": "created"}


@app.patch("/api/records/{module}/{record_id}")
async def update_record(module: str, record_id: int, data_json: str = Form(...),
                        document: UploadFile | None = File(None),
                        institute: CurrentInstitute = Depends(require_write_access)):
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    check_module_access(institute, module)

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            f"SELECT * FROM {module} WHERE id = %s AND branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)",
            (record_id, institute.id),
        )
        existing = cur.fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Record not found")

        try:
            data = json.loads(data_json)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="data_json is not valid JSON")
        if not isinstance(data, dict):
            raise HTTPException(status_code=400, detail="data_json must be a JSON object")

        allowed = set(RECORD_FIELDS[module])
        clean = {k: _coerce_record_value(module, k, v) for k, v in data.items() if k in allowed}

        if module == "attendance" and "student_id" in clean and clean["student_id"] is not None:
            cur.execute("SELECT id, name FROM students WHERE id=%s AND branch_id=%s",
                        (clean["student_id"], existing["branch_id"]))
            st = cur.fetchone()
            if not st:
                raise HTTPException(status_code=400, detail="Student not found in this branch")
            clean["student_name"] = st["name"]

        if document is not None and getattr(document, "filename", None):
            if module in RECORD_HAS_DOCUMENT:
                clean["document"] = save_upload(document)

        if not clean:
            raise HTTPException(status_code=400, detail="Nothing to update.")

        set_clause = ", ".join(f"{k} = %s" for k in clean.keys())
        values = list(clean.values()) + [record_id]
        cur.execute(f"UPDATE {module} SET {set_clause} WHERE id = %s RETURNING *", values)
        updated = dict(cur.fetchone())
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        log.exception("update_record failed")
        raise HTTPException(status_code=500, detail=_safe_error("update_record", exc))
    finally:
        conn.close()

    audit_write(institute, existing["branch_id"], "UPDATE_RECORD", dict(existing), {"module": module, "record": updated})
    return {"id": record_id, "status": "updated"}


@app.delete("/api/records/{module}/{record_id}")
def delete_record(module: str, record_id: int, institute: CurrentInstitute = Depends(require_write_access)):
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    check_module_access(institute, module)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            f"SELECT * FROM {module} WHERE id = %s AND branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)",
            (record_id, institute.id),
        )
        existing = cur.fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Record not found")
        cur.execute(f"DELETE FROM {module} WHERE id = %s", (record_id,))
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        log.exception("delete_record failed")
        raise HTTPException(status_code=500, detail=_safe_error("delete_record", exc))
    finally:
        conn.close()
    audit_write(institute, existing["branch_id"], "DELETE_RECORD", dict(existing), {"module": module, "id": record_id})
    return {"status": "deleted"}


# ---------------------------------------------------------------------------
# File serving
# ---------------------------------------------------------------------------

DOCUMENT_TABLES = ["classrooms", "attendance", "invigilation", "fees", "students", "teachers", "syllabus"]


@app.get("/api/uploads/{filename}")
def get_uploaded_file(filename: str, institute: CurrentInstitute = Depends(get_current_institute)):
    safe_name = os.path.basename(filename)
    if safe_name != filename or not safe_name:
        raise HTTPException(status_code=404, detail="File not found")
    path = os.path.join(UPLOAD_DIR, safe_name)
    if os.path.commonpath([UPLOAD_DIR, os.path.abspath(path)]) != UPLOAD_DIR or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="File not found")
    conn = get_conn()
    try:
        cur = conn.cursor()
        owned = False
        for table in DOCUMENT_TABLES:
            cur.execute(
                f"""SELECT 1 FROM {table} t JOIN branches b ON b.id = t.branch_id
                    WHERE t.document = %s AND b.tenant_id = %s LIMIT 1""",
                (safe_name, institute.id),
            )
            if cur.fetchone():
                owned = True
                break
    finally:
        conn.close()
    if not owned:
        raise HTTPException(status_code=404, detail="File not found")
    # Non-inline download protects against HTML/SVG execution
    return FileResponse(path, headers={"Content-Disposition": f'attachment; filename="{safe_name}"'})


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

@app.get("/api/search/{branch_id}")
def search_institute(branch_id: int, q: str = "", institute: CurrentInstitute = Depends(get_current_institute)):
    verify_branch_read_access(branch_id, institute.id)
    term = (q or "").strip()
    if not term:
        return {"results": []}
    labels = {
        "students": "Student Department", "teachers": "Teacher Department",
        "classrooms": "Classroom Department", "syllabus": "Syllabus",
        "attendance": "Attendance", "fees": "Fees", "invigilation": "Invigilation",
    }
    results = []
    conn = get_conn()
    try:
        cur = conn.cursor()
        for module in ("students", "teachers", "classrooms", "syllabus", "attendance", "fees", "invigilation"):
            if not institute.is_owner and module not in (institute.allowed_modules or []):
                continue
            fields = RECORD_FIELDS[module]
            clauses = " OR ".join(f"CAST({f} AS TEXT) ILIKE %s" for f in fields)
            branch_where = "branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)" if branch_id == 0 else "branch_id = %s"
            first_param = institute.id if branch_id == 0 else branch_id
            params = [first_param] + [f"%{term}%"] * len(fields)
            cur.execute(f"SELECT * FROM {module} WHERE {branch_where} AND ({clauses}) ORDER BY id DESC LIMIT 4", params)
            for row in cur.fetchall():
                item = dict(row)
                primary = item.get("name") or item.get("student_name") or item.get("subject") or item.get("room_no") or item.get("teacher_name") or "Record"
                parts = []
                for key in fields:
                    value = item.get(key)
                    if value not in (None, "") and str(value) != str(primary):
                        parts.append(f"{key.replace('_', ' ')}: {value}")
                    if len(parts) >= 4:
                        break
                results.append({"module": module, "label": labels[module],
                                "primary": str(primary), "details": " · ".join(parts)})
        return {"results": results[:24]}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# WhatsApp — hardened branch/module scoping
# ---------------------------------------------------------------------------

def send_whatsapp(to_number: str, message: str) -> bool:
    if not all([WHATSAPP_API_URL, WHATSAPP_API_TOKEN, WHATSAPP_PHONE_NUMBER_ID]):
        return False
    import requests
    url = f"{WHATSAPP_API_URL.rstrip('/')}/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {"Authorization": f"Bearer {WHATSAPP_API_TOKEN}", "Content-Type": "application/json"}
    payload = {"messaging_product": "whatsapp", "to": to_number, "type": "text", "text": {"body": message}}
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        return resp.status_code == 201
    except Exception:
        log.exception("whatsapp send failed")
        return False


class WhatsAppAbsenceRequest(BaseModel):
    branch_id: int
    student_id: int
    date: str


@app.post("/api/whatsapp/send-absence")
def send_absence_notification(req: WhatsAppAbsenceRequest, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "whatsapp")
    verify_branch_ownership(req.branch_id, institute.id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT s.id, s.name, s.parent_contact
               FROM students s JOIN branches b ON b.id = s.branch_id
               WHERE s.id=%s AND s.branch_id=%s AND b.tenant_id=%s""",
            (req.student_id, req.branch_id, institute.id),
        )
        row = cur.fetchone()
        if not row or not row["parent_contact"]:
            return {"status": "skipped", "reason": "No parent contact found."}
        parent_contact = row["parent_contact"]
        if not parent_contact.startswith('+'):
            parent_contact = '+91' + parent_contact
        msg = f"Attendance Alert: Your ward {row['name']} was marked ABSENT on {req.date}. Please contact the institute for further details."
        sent = send_whatsapp(parent_contact, msg)
        audit_write(institute, req.branch_id, "WHATSAPP_ABSENCE", None,
                    {"student_id": row["id"], "date": req.date, "sent": sent})
        return {"status": "sent" if sent else "failed"}
    finally:
        conn.close()


class WhatsAppFeeRemindersRequest(BaseModel):
    branch_id: int | None = None  # None => institute-wide (owner/admin only)


@app.post("/api/whatsapp/send-fee-reminders")
def send_fee_reminders(req: WhatsAppFeeRemindersRequest, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "whatsapp")
    if req.branch_id is None:
        if not (institute.is_owner or institute.permission == "edit"):
            raise HTTPException(status_code=403, detail="Institute-wide reminders require administrative access")
    else:
        verify_branch_ownership(req.branch_id, institute.id)

    conn = get_conn()
    try:
        cur = conn.cursor()
        # IBEX-SEC: branch filter is enforced in SQL, never trusted from frontend alone
        if req.branch_id is None:
            branch_clause = "f.branch_id IN (SELECT id FROM branches WHERE tenant_id=%s)"
            params = (institute.id,)
        else:
            branch_clause = "f.branch_id = %s AND f.branch_id IN (SELECT id FROM branches WHERE tenant_id=%s)"
            params = (req.branch_id, institute.id)

        cur.execute(f"""
            SELECT f.student_name, s.parent_contact, f.due_date, f.amount_inr
            FROM fees f
            LEFT JOIN students s ON s.name = f.student_name AND s.branch_id = f.branch_id
            WHERE {branch_clause}
              AND LOWER(COALESCE(f.status,'')) != 'paid'
              AND f.due_date ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}$'
              AND f.due_date::date - CURRENT_DATE <= 7
              AND f.due_date::date >= CURRENT_DATE
        """, params)
        rows = cur.fetchall()
        sent_count = 0
        for row in rows:
            name, contact = row["student_name"], row["parent_contact"]
            if not contact:
                continue
            if not contact.startswith('+'):
                contact = '+91' + contact
            msg = f"Fee Reminder: Your ward {name} has a pending fee of ₹{row['amount_inr']} due on {row['due_date']}. Please clear the dues at the earliest."
            if send_whatsapp(contact, msg):
                sent_count += 1
        audit_write(institute, req.branch_id, "WHATSAPP_FEE_REMINDERS", None, {"sent": sent_count, "branch_id": req.branch_id})
        return {"sent": sent_count}
    finally:
        conn.close()


class BroadcastNoticeboardRequest(BaseModel):
    branch_id: int | None = None  # None => institute-wide, owner/admin only
    message: str
    batch: str | None = None


@app.post("/api/whatsapp/broadcast")
def broadcast_notice(req: BroadcastNoticeboardRequest, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "whatsapp")
    msg = (req.message or "").strip()
    if not msg:
        raise HTTPException(status_code=400, detail="Message body cannot be empty.")

    # IBEX-SEC: institute-wide broadcast requires administrative rights, and
    # any branch_id provided must belong to this institute.
    if req.branch_id is None:
        if not (institute.is_owner or institute.permission == "edit"):
            raise HTTPException(status_code=403, detail="Institute-wide broadcasts require administrative access")
    else:
        verify_branch_ownership(req.branch_id, institute.id)

    conn = get_conn()
    try:
        cur = conn.cursor()
        # Build SQL so the scope is enforced server-side.
        if req.branch_id is not None:
            branch_clause = "branch_id = %s AND branch_id IN (SELECT id FROM branches WHERE tenant_id=%s)"
            base_params = [req.branch_id, institute.id]
        else:
            branch_clause = "branch_id IN (SELECT id FROM branches WHERE tenant_id=%s)"
            base_params = [institute.id]

        if req.batch:
            sql = f"SELECT name, parent_contact FROM students WHERE {branch_clause} AND batch=%s AND parent_contact IS NOT NULL"
            params = base_params + [req.batch]
        else:
            sql = f"SELECT name, parent_contact FROM students WHERE {branch_clause} AND parent_contact IS NOT NULL"
            params = base_params

        cur.execute(sql, params)
        sent = 0
        for row in cur.fetchall():
            contact = row["parent_contact"]
            if not contact:
                continue
            if not contact.startswith('+'):
                contact = '+91' + contact
            if send_whatsapp(contact, f"[IBEX Notice] {msg}"):
                sent += 1
        audit_write(institute, req.branch_id, "WHATSAPP_BROADCAST", None,
                    {"sent": sent, "batch": req.batch, "branch_id": req.branch_id, "message": msg[:200]})
        return {"sent": sent}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Attendance — student_id-based
# ---------------------------------------------------------------------------

class AttendanceMarkRequest(BaseModel):
    branch_id: int
    student_id: int
    date: str
    status: str


@app.post("/api/attendance/mark")
def mark_attendance(req: AttendanceMarkRequest, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "attendance")
    verify_branch_ownership(req.branch_id, institute.id)
    if req.status not in ("Present", "Absent"):
        raise HTTPException(status_code=400, detail="Status must be 'Present' or 'Absent'")
    conn = get_conn()
    try:
        cur = conn.cursor()
        # IBEX-SEC: verify student belongs to this branch/institute
        cur.execute(
            """SELECT s.id, s.name FROM students s JOIN branches b ON b.id=s.branch_id
               WHERE s.id=%s AND s.branch_id=%s AND b.tenant_id=%s""",
            (req.student_id, req.branch_id, institute.id),
        )
        st = cur.fetchone()
        if not st:
            raise HTTPException(status_code=404, detail="Student not found in this branch")
        cur.execute("DELETE FROM attendance WHERE branch_id=%s AND student_id=%s AND date=%s",
                    (req.branch_id, req.student_id, req.date))
        cur.execute(
            "INSERT INTO attendance (branch_id, student_id, student_name, date, status) VALUES (%s,%s,%s,%s,%s)",
            (req.branch_id, req.student_id, st["name"], req.date, req.status),
        )
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, req.branch_id, "MARK_ATTENDANCE", None,
                {"student_id": req.student_id, "date": req.date, "status": req.status})
    return {"status": "success"}


@app.get("/api/attendance/history/{branch_id}")
def get_attendance_history(branch_id: int, student_id: int | None = None, student_name: str | None = None,
                           institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute, "attendance")
    verify_branch_read_access(branch_id, institute.id)
    if student_id is None and not student_name:
        raise HTTPException(status_code=400, detail="student_id or student_name is required")

    conn = get_conn()
    try:
        cur = conn.cursor()
        branch_where = "branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)" if branch_id == 0 else "branch_id = %s"
        scope_param = institute.id if branch_id == 0 else branch_id
        if student_id is not None:
            cur.execute(
                f"SELECT date, status FROM attendance WHERE {branch_where} AND student_id = %s ORDER BY date DESC",
                (scope_param, student_id),
            )
        else:
            cur.execute(
                f"SELECT date, status FROM attendance WHERE {branch_where} AND student_name = %s ORDER BY date DESC",
                (scope_param, student_name),
            )
        history = [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()
    present = sum(1 for h in history if h["status"] == "Present")
    return {
        "student_id": student_id, "student_name": student_name,
        "history": history, "total_marked": len(history),
        "present_count": present, "absent_count": len(history) - present,
    }


@app.get("/api/attendance/{branch_id}/{date}")
def get_attendance_for_date(branch_id: int, date: str, institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute, "attendance")
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        if branch_id == 0:
            cur.execute(
                "SELECT student_id, student_name, status FROM attendance WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) AND date = %s",
                (institute.id, date),
            )
        else:
            cur.execute(
                "SELECT student_id, student_name, status FROM attendance WHERE branch_id = %s AND date = %s",
                (branch_id, date),
            )
        # Return keyed by student_id (string) with name for display
        out = {}
        for row in cur.fetchall():
            key = str(row["student_id"]) if row["student_id"] is not None else f"name:{row['student_name']}"
            out[key] = {"student_id": row["student_id"], "student_name": row["student_name"], "status": row["status"]}
        return out
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Timetable
# ---------------------------------------------------------------------------

@app.get("/api/timetable/slots/{branch_id}")
def get_timetable_slots(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute, "timetables")
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        if branch_id == 0:
            cur.execute("SELECT * FROM timetables_slots WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) ORDER BY branch_id, batch_name, lecture_number", (institute.id,))
        else:
            cur.execute("SELECT * FROM timetables_slots WHERE branch_id = %s ORDER BY batch_name, lecture_number", (branch_id,))
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


@app.get("/api/timetable/configs/{branch_id}")
def list_timetable_configs(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute, "timetables")
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        if branch_id == 0:
            cur.execute("SELECT branch_id, batch_name, timings_json, teachers_config_json FROM timetable_configs WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) ORDER BY branch_id, batch_name", (institute.id,))
        else:
            cur.execute("SELECT branch_id, batch_name, timings_json, teachers_config_json FROM timetable_configs WHERE branch_id = %s ORDER BY batch_name", (branch_id,))
        configs = []
        for row in cur.fetchall():
            try: timings = json.loads(row["timings_json"] or "[]")
            except (TypeError, ValueError): timings = []
            try: teachers_config = json.loads(row["teachers_config_json"] or "[]")
            except (TypeError, ValueError): teachers_config = []
            configs.append({"batch_name": row["batch_name"],
                            "timings": timings if isinstance(timings, list) else [],
                            "teachers_config": teachers_config if isinstance(teachers_config, list) else []})
        return configs
    finally:
        conn.close()


class TimingSlot(BaseModel):
    lecture_number: int
    time_slot: str


class TimetableGenerateRequest(BaseModel):
    branch_id: int
    batch_name: str
    teachers_config: list
    timings: list[TimingSlot]


def _parse_time_range(time_slot: str):
    m = re.match(r"\s*(\d{1,2}:\d{2}\s*[AaPp][Mm])\s*-\s*(\d{1,2}:\d{2}\s*[AaPp][Mm])\s*", time_slot or "")
    if not m:
        return None, None
    try:
        start = datetime.strptime(m.group(1).upper().replace(" ", ""), "%I:%M%p").time()
        end = datetime.strptime(m.group(2).upper().replace(" ", ""), "%I:%M%p").time()
        return start, end
    except ValueError:
        return None, None


def _time_ranges_overlap(a: str, b: str) -> bool:
    a0, a1 = _parse_time_range(a)
    b0, b1 = _parse_time_range(b)
    if not all((a0, a1, b0, b1)):
        return a.strip() == b.strip()
    return a0 < b1 and b0 < a1


def _safe_int(value, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, str):
        value = value.strip()
        if value == "":
            return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _generate_timetable_impl(req: "TimetableGenerateRequest", institute: "CurrentInstitute"):
    check_module_access(institute, "timetables")
    verify_branch_ownership(req.branch_id, institute.id)
    if not req.timings:
        raise HTTPException(status_code=400, detail="Add at least one lecture timing")
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM timetables_slots WHERE branch_id = %s AND batch_name = %s", (req.branch_id, req.batch_name))
        cursor.execute("SELECT room_no, capacity FROM classrooms WHERE branch_id = %s AND COALESCE(capacity, 0) > 0 ORDER BY capacity, id", (req.branch_id,))
        available_rooms = [(row["room_no"], int(row["capacity"])) for row in cursor.fetchall() if row["room_no"]]
        cursor.execute("SELECT COUNT(*) AS c FROM students WHERE branch_id = %s AND batch = %s", (req.branch_id, req.batch_name))
        batch_size = int(cursor.fetchone()["c"] or 0)
        if batch_size and not any(capacity >= batch_size for _, capacity in available_rooms):
            raise HTTPException(status_code=400, detail=f"Batch has {batch_size} students, but no registered classroom has enough capacity.")

        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
        day_index = {day: i for i, day in enumerate(days)}
        timings_sorted = sorted(req.timings, key=lambda t: t.lecture_number)
        generated_slots, warnings = [], []
        batch_load = {day: 0 for day in days}

        def slot_is_free(day, timing, teacher_name):
            slot_time = timing.time_slot
            cursor.execute("SELECT time_slot, teacher FROM timetables_slots WHERE branch_id = %s AND day = %s AND (batch_name = %s OR teacher = %s)",
                           (req.branch_id, day, req.batch_name, teacher_name))
            for existing in cursor.fetchall():
                if _time_ranges_overlap(slot_time, existing["time_slot"]):
                    return False
            return True

        def free_room(day, slot_time):
            for candidate_room, capacity in available_rooms:
                if batch_size and capacity < batch_size:
                    continue
                cursor.execute("SELECT time_slot FROM timetables_slots WHERE branch_id = %s AND day = %s AND room = %s",
                               (req.branch_id, day, candidate_room))
                if all(not _time_ranges_overlap(slot_time, row["time_slot"]) for row in cursor.fetchall()):
                    return candidate_room
            return "Unassigned (no room with sufficient capacity)" if available_rooms else "Unassigned (add a classroom)"

        for t_config in req.teachers_config:
            if not isinstance(t_config, dict):
                continue
            teacher_name = str(t_config.get('name', '') or '').strip()
            subject = str(t_config.get('subject', '') or '').strip()
            target_lectures = max(0, _safe_int(t_config.get('lectures_per_week', 0), default=0))
            unavailable = {str(d).strip() for d in (t_config.get('unavailable_days') or [])}
            if not teacher_name or target_lectures == 0:
                continue
            assigned_count = 0
            used_days = []
            used_lecture_nums_by_day = defaultdict(list)
            eligible_days = [d for d in days if d not in unavailable]
            if target_lectures <= 1:
                preferred_day_indices = [0] if eligible_days else []
            elif target_lectures <= len(eligible_days):
                preferred_day_indices = [round(i * (len(eligible_days) - 1) / (target_lectures - 1)) for i in range(target_lectures)]
            else:
                preferred_day_indices = [i % len(eligible_days) for i in range(target_lectures)] if eligible_days else []

            for lecture_index in range(target_lectures):
                candidates = []
                desired_idx = preferred_day_indices[lecture_index] if preferred_day_indices else 0
                desired_day = eligible_days[desired_idx] if eligible_days else None
                for day in days:
                    if day in unavailable:
                        continue
                    for timing in timings_sorted:
                        if not slot_is_free(day, timing, teacher_name):
                            continue
                        room = free_room(day, timing.time_slot)
                        idx = day_index[day]
                        min_distance = min((abs(idx - used) for used in used_days), default=5)
                        other_unused_days_exist = any(day_index[d] not in used_days for d in eligible_days)
                        same_day_penalty = 1_000_000 if (idx in used_days and other_unused_days_exist) else 0
                        consecutive_penalty = 0
                        if idx in used_days:
                            for other_lc in used_lecture_nums_by_day.get(idx, []):
                                if abs(other_lc - timing.lecture_number) == 1:
                                    consecutive_penalty += 500
                        preferred_distance = abs(idx - day_index[desired_day]) if desired_day else 0
                        score = (preferred_distance * 100 + same_day_penalty + consecutive_penalty
                                 + batch_load[day] * 25 - min_distance * 2 + idx * 0.01
                                 + timing.lecture_number * 0.001)
                        candidates.append((score, day, timing, room))
                if not candidates:
                    break
                _, day, timing, room = min(candidates, key=lambda x: x[0])
                cursor.execute(
                    "INSERT INTO timetables_slots (branch_id, batch_name, day, time_slot, lecture_number, subject, teacher, room) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                    (req.branch_id, req.batch_name, day, timing.time_slot, timing.lecture_number, subject, teacher_name, room),
                )
                generated_slots.append({"day": day, "time_slot": timing.time_slot, "lecture_number": timing.lecture_number,
                                        "subject": subject, "teacher": teacher_name, "room": room})
                assigned_count += 1
                batch_load[day] += 1
                used_days.append(day_index[day])
                used_lecture_nums_by_day[day_index[day]].append(timing.lecture_number)
            if assigned_count < target_lectures:
                warnings.append(f"{teacher_name}: only scheduled {assigned_count}/{target_lectures} lectures (not enough free day/time slots without a conflict).")

        cursor.execute("SELECT id FROM timetable_configs WHERE branch_id = %s AND batch_name = %s", (req.branch_id, req.batch_name))
        existing_config = cursor.fetchone()
        timings_json = json.dumps([t.dict() for t in req.timings])
        teachers_config_json = json.dumps(req.teachers_config)
        now_iso = _utcnow().isoformat()
        if existing_config:
            cursor.execute("UPDATE timetable_configs SET timings_json = %s, teachers_config_json = %s, updated_at = %s WHERE id = %s",
                           (timings_json, teachers_config_json, now_iso, existing_config["id"]))
        else:
            cursor.execute("INSERT INTO timetable_configs (branch_id, batch_name, timings_json, teachers_config_json, updated_at) VALUES (%s,%s,%s,%s,%s)",
                           (req.branch_id, req.batch_name, timings_json, teachers_config_json, now_iso))
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, req.branch_id, "GENERATE_TIMETABLE", None,
                {"batch_name": req.batch_name, "slots": generated_slots, "warnings": warnings})
    return {"status": "success", "slots": generated_slots, "warnings": warnings}


@app.post("/api/timetable/generate")
def generate_timetable(req: TimetableGenerateRequest, institute: CurrentInstitute = Depends(require_write_access)):
    try:
        return _generate_timetable_impl(req, institute)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=_safe_error("generate_timetable", exc))


@app.delete("/api/timetable/all/{branch_id}")
def delete_all_timetables(branch_id: int, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "timetables")
    verify_branch_ownership(branch_id, institute.id)
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM timetables_slots WHERE branch_id = %s", (branch_id,))
        slots_deleted = cursor.rowcount
        cursor.execute("DELETE FROM timetable_configs WHERE branch_id = %s", (branch_id,))
        configs_deleted = cursor.rowcount
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, branch_id, "DELETE_TIMETABLES",
                {"slots_deleted": slots_deleted, "configs_deleted": configs_deleted}, None)
    return {"status": "cleared", "slots_deleted": slots_deleted, "configs_deleted": configs_deleted}


class TimetableSlotEdit(BaseModel):
    day: str
    time_slot: str
    subject: str
    teacher: str
    room: str


@app.patch("/api/timetable/slots/{slot_id}")
def edit_timetable_slot(slot_id: int, req: TimetableSlotEdit, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "timetables")
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT timetables_slots.* FROM timetables_slots
               JOIN branches ON branches.id = timetables_slots.branch_id
               WHERE timetables_slots.id = %s AND branches.tenant_id = %s""",
            (slot_id, institute.id),
        )
        existing = cursor.fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Slot not found")

        # IBEX-SEC: real time-range overlap checks (not exact-string equality)
        cursor.execute(
            "SELECT time_slot FROM timetables_slots WHERE branch_id = %s AND id <> %s AND day = %s AND teacher = %s",
            (existing["branch_id"], slot_id, req.day, req.teacher),
        )
        for row in cursor.fetchall():
            if _time_ranges_overlap(req.time_slot, row["time_slot"]):
                raise HTTPException(status_code=409, detail="Teacher already has another lecture overlapping this time slot.")

        cursor.execute(
            "SELECT time_slot FROM timetables_slots WHERE branch_id = %s AND id <> %s AND day = %s AND room = %s",
            (existing["branch_id"], slot_id, req.day, req.room),
        )
        for row in cursor.fetchall():
            if _time_ranges_overlap(req.time_slot, row["time_slot"]):
                raise HTTPException(status_code=409, detail="Room is already occupied during this time.")

        cursor.execute(
            "SELECT time_slot FROM timetables_slots WHERE branch_id = %s AND id <> %s AND day = %s AND batch_name = %s",
            (existing["branch_id"], slot_id, req.day, existing["batch_name"]),
        )
        for row in cursor.fetchall():
            if _time_ranges_overlap(req.time_slot, row["time_slot"]):
                raise HTTPException(status_code=409, detail="This batch already has a lecture overlapping this time slot.")

        # Room must be in the same branch
        cursor.execute("SELECT capacity FROM classrooms WHERE branch_id = %s AND room_no = %s",
                       (existing["branch_id"], req.room))
        room_capacity = cursor.fetchone()
        if not room_capacity:
            raise HTTPException(status_code=400, detail="Selected room is not registered in this branch.")
        cursor.execute("SELECT COUNT(*) AS c FROM students WHERE branch_id = %s AND batch = %s",
                       (existing["branch_id"], existing["batch_name"]))
        batch_size = cursor.fetchone()["c"]
        if batch_size and int(room_capacity["capacity"] or 0) < batch_size:
            raise HTTPException(status_code=400, detail="Selected room does not have enough capacity for this batch.")

        cursor.execute(
            "UPDATE timetables_slots SET day = %s, time_slot = %s, subject = %s, teacher = %s, room = %s WHERE id = %s",
            (req.day, req.time_slot, req.subject, req.teacher, req.room, slot_id),
        )
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, existing["branch_id"], "UPDATE_TIMETABLE_SLOT", dict(existing),
                {"day": req.day, "time_slot": req.time_slot, "subject": req.subject, "teacher": req.teacher, "room": req.room})
    return {"status": "updated"}


# ---------------------------------------------------------------------------
# Exam seating
# ---------------------------------------------------------------------------

class SeatingGenerateRequest(BaseModel):
    branch_id: int
    exam_date: str
    room_number: str
    rows: int
    columns: int
    batches: list[str] | None = None


def _build_seating_layout(students, rows, columns):
    capacity = rows * columns
    selected = list(students[:capacity])
    if not selected:
        return []
    buckets = defaultdict(list)
    for st in selected:
        buckets[str(st.get("batch") or "").strip()].append(st)
    for v in buckets.values():
        random.shuffle(v)
    if max(map(len, buckets.values())) > (capacity + 1) // 2:
        raise HTTPException(status_code=400, detail="The seating constraints cannot be satisfied: one batch has too many students for this grid.")
    grid = [[None] * columns for _ in range(rows)]
    pos = [(r, c) for r in range(rows) for c in range(columns)]

    def ok(st, r, c):
        batch = str(st.get("batch") or "").strip()
        left = c and grid[r][c - 1] is not None and str(grid[r][c - 1].get("batch") or "").strip() == batch
        front = r and grid[r - 1][c] is not None and str(grid[r - 1][c].get("batch") or "").strip() == batch
        return not (left or front)

    def solve(i=0):
        if i == len(pos):
            return True
        r, c = pos[i]
        choices = [v for v in buckets.values() if v]
        random.shuffle(choices)
        choices.sort(key=len, reverse=True)
        for v in choices:
            st = v.pop()
            if ok(st, r, c):
                grid[r][c] = st
                if solve(i + 1):
                    return True
                grid[r][c] = None
            v.append(st)
        return False

    if not solve():
        raise HTTPException(status_code=400, detail="The seating constraints cannot be satisfied. Increase the grid size or use more than one batch.")
    return [{"row": r + 1, "column": c + 1, "student_id": grid[r][c]["id"], "name": grid[r][c]["name"],
             "batch": grid[r][c]["batch"], "roll_number": grid[r][c]["roll_number"]}
            for r in range(rows) for c in range(columns) if grid[r][c] is not None]


@app.get("/api/seating/{branch_id}")
def get_seating_layouts(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute, SEATING_MODULE)
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        if branch_id == 0:
            cur.execute("SELECT id, branch_id, exam_date, room_number, rows, columns, assignments_json, created_at FROM exam_seatings WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) ORDER BY exam_date DESC, id DESC", (institute.id,))
        else:
            cur.execute("SELECT id, branch_id, exam_date, room_number, rows, columns, assignments_json, created_at FROM exam_seatings WHERE branch_id = %s ORDER BY exam_date DESC, id DESC", (branch_id,))
        rows = cur.fetchall()
    finally:
        conn.close()
    return [{**dict(r), "assignments": json.loads(r["assignments_json"])} for r in rows]


def _generate_seating_impl(req: "SeatingGenerateRequest", institute: "CurrentInstitute"):
    check_module_access(institute, SEATING_MODULE)
    verify_branch_ownership(req.branch_id, institute.id)
    if req.rows < 1 or req.columns < 1:
        raise HTTPException(status_code=400, detail="Rows and columns must both be at least 1.")
    room_number = req.room_number.strip()
    if not room_number:
        raise HTTPException(status_code=400, detail="Room number is required.")

    conn = get_conn()
    try:
        room_cur = conn.cursor()
        # IBEX-SEC: room lookup is scoped by institute + branch + room_no
        room_cur.execute(
            """SELECT c.room_no, c.capacity FROM classrooms c
               JOIN branches b ON b.id = c.branch_id
               WHERE b.tenant_id = %s AND c.branch_id = %s AND c.room_no = %s LIMIT 1""",
            (institute.id, req.branch_id, room_number),
        )
        room = room_cur.fetchone()
        if not room:
            raise HTTPException(status_code=400, detail="Selected exam room is not registered for this branch.")
        requested_capacity = req.rows * req.columns
        room_capacity = int(room["capacity"] or 0)
        if room_capacity <= 0:
            raise HTTPException(status_code=400, detail="Selected room has no valid seating capacity.")
        if requested_capacity > room_capacity:
            raise HTTPException(status_code=400, detail=f"Grid capacity ({requested_capacity}) exceeds room capacity ({room_capacity}).")

        cursor = conn.cursor()
        selected_batches = [str(b).strip() for b in (req.batches or []) if str(b).strip()]
        if selected_batches:
            placeholders = ", ".join(["%s"] * len(selected_batches))
            cursor.execute(
                f"""SELECT id, name, COALESCE(batch, '') AS batch, COALESCE(roll_number, '') AS roll_number
                    FROM students WHERE branch_id = %s AND batch IN ({placeholders}) ORDER BY id""",
                (req.branch_id, *selected_batches),
            )
        else:
            cursor.execute(
                "SELECT id, name, COALESCE(batch, '') AS batch, COALESCE(roll_number, '') AS roll_number FROM students WHERE branch_id = %s",
                (req.branch_id,),
            )
        student_rows = [dict(r) for r in cursor.fetchall()]
        if not student_rows:
            raise HTTPException(status_code=400, detail="No students were found for the selected batch(es).")

        cursor.execute("SELECT assignments_json FROM exam_seatings WHERE branch_id = %s AND exam_date = %s AND room_number = %s",
                       (req.branch_id, req.exam_date, room_number))
        old_room = cursor.fetchone()
        old_student_ids = set()
        if old_room:
            try:
                old_student_ids = {int(a["student_id"]) for a in json.loads(old_room["assignments_json"] or "[]") if a.get("student_id") is not None}
            except (TypeError, ValueError, KeyError):
                pass
        cursor.execute("DELETE FROM exam_seatings WHERE branch_id = %s AND exam_date = %s AND room_number = %s",
                       (req.branch_id, req.exam_date, room_number))

        cursor.execute("SELECT assignments_json FROM exam_seatings WHERE branch_id = %s AND exam_date = %s",
                       (req.branch_id, req.exam_date))
        assigned_elsewhere = set()
        for row in cursor.fetchall():
            try:
                assigned_elsewhere.update(int(a["student_id"]) for a in json.loads(row["assignments_json"] or "[]") if a.get("student_id") is not None)
            except (TypeError, ValueError, KeyError):
                continue
        assigned_elsewhere.difference_update(old_student_ids)
        remaining_students = [s for s in student_rows if int(s["id"]) not in assigned_elsewhere]
        random.shuffle(remaining_students)
        if len(remaining_students) < requested_capacity:
            raise HTTPException(status_code=400, detail=f"Only {len(remaining_students)} unassigned student(s) remain; {requested_capacity} seats requested.")
        assignments = _build_seating_layout(remaining_students, req.rows, req.columns)
        cursor.execute(
            "INSERT INTO exam_seatings (branch_id, exam_date, room_number, rows, columns, assignments_json, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (req.branch_id, req.exam_date, room_number, req.rows, req.columns, json.dumps(assignments), _utcnow().isoformat()),
        )
        layout_id = cursor.fetchone()["id"]
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, req.branch_id, "GENERATE_SEATING", None,
                {"id": layout_id, "exam_date": req.exam_date, "room_number": room_number,
                 "rows": req.rows, "columns": req.columns, "batches": selected_batches, "assignments": assignments})
    return {"status": "success", "id": layout_id, "assignments": assignments}


@app.post("/api/seating/generate")
def generate_seating(req: SeatingGenerateRequest, institute: CurrentInstitute = Depends(require_write_access)):
    try:
        return _generate_seating_impl(req, institute)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=_safe_error("generate_seating", exc))


@app.delete("/api/seating/{layout_id}")
def delete_seating_layout(layout_id: int, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, SEATING_MODULE)
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT exam_seatings.* FROM exam_seatings JOIN branches ON branches.id = exam_seatings.branch_id WHERE exam_seatings.id = %s AND branches.tenant_id = %s",
            (layout_id, institute.id),
        )
        before = cursor.fetchone()
        if not before:
            raise HTTPException(status_code=404, detail="Seating layout not found")
        cursor.execute("DELETE FROM exam_seatings WHERE id = %s", (layout_id,))
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, before["branch_id"], "DELETE_SEATING", dict(before), None)
    return {"status": "deleted"}


class FeeMarkPaidRequest(BaseModel):
    utr_reference: str


@app.post("/api/fees/{fee_id}/mark-paid")
def mark_fee_paid(fee_id: int, req: FeeMarkPaidRequest,
                  institute: CurrentInstitute = Depends(require_write_access),
                  x_gate_token: str | None = Header(default=None)):
    check_module_access(institute, "fees")
    consume_gate_token(institute, "fees", x_gate_token)
    utr = req.utr_reference.strip()
    if not utr:
        raise HTTPException(status_code=400, detail="UTR / Reference No. is required.")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM fees WHERE id = %s AND branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)",
                    (fee_id, institute.id))
        before = cur.fetchone()
        if not before:
            raise HTTPException(status_code=404, detail="Fee record not found")
        cur.execute("UPDATE fees SET status='Paid', utr_reference=%s, paid_at=NOW(), paid_by=%s WHERE id=%s",
                    (utr, institute.user_id, fee_id))
        cur.execute("SELECT * FROM fees WHERE id = %s", (fee_id,))
        after = cur.fetchone()
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, before["branch_id"], "FEE_MARK_PAID", dict(before), dict(after))
    return {"status": "paid", "fee": dict(after)}


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

@app.get("/api/analytics/{branch_id}")
def get_analytics(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        scope = "branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)" if branch_id == 0 else "branch_id = %s"
        scope_param = institute.id if branch_id == 0 else branch_id

        def one(sql, params, default=0):
            try:
                cur.execute(sql, params)
                row = cur.fetchone()
                if not row:
                    return default
                # first column regardless of key
                return list(row.values())[0]
            except Exception as exc:
                conn.rollback()
                log.warning("[analytics] query failed: %s", exc)
                return default

        def all_rows(sql, params):
            try:
                cur.execute(sql, params)
                return cur.fetchall()
            except Exception as exc:
                conn.rollback()
                log.warning("[analytics] query failed: %s", exc)
                return []

        students_total = one(f"SELECT COUNT(*) FROM students WHERE {scope}", (scope_param,))
        teachers_total = one(f"SELECT COUNT(*) FROM teachers WHERE {scope}", (scope_param,))
        classrooms_total = one(f"SELECT COUNT(*) FROM classrooms WHERE {scope}", (scope_param,))
        seating_plans = one(f"SELECT COUNT(*) FROM exam_seatings WHERE {scope}", (scope_param,))

        row = all_rows(f"SELECT COALESCE(SUM(amount_inr),0) AS s, COUNT(*) AS c FROM fees WHERE {scope} AND LOWER(COALESCE(status,'')) = 'paid'", (scope_param,))
        paid_amount = row[0]["s"] if row else 0
        paid_count = row[0]["c"] if row else 0

        row = all_rows(f"SELECT COALESCE(SUM(amount_inr),0) AS s, COUNT(*) AS c FROM fees WHERE {scope} AND LOWER(COALESCE(status,'')) != 'paid'", (scope_param,))
        pending_amount = row[0]["s"] if row else 0
        pending_count = row[0]["c"] if row else 0

        now_ist = _ist_now()
        today = now_ist.date()
        week_start = today - timedelta(days=6)

        att_counts = {}
        for r in all_rows(f"SELECT status, COUNT(*) AS c FROM attendance WHERE {scope} AND date >= %s AND date <= %s GROUP BY status",
                          (scope_param, week_start.isoformat(), today.isoformat())):
            att_counts[str(r["status"])] = int(r["c"])
        marked = sum(att_counts.values())
        present = att_counts.get('Present', 0)
        absent = att_counts.get('Absent', 0)

        trend = []
        for i in range(7):
            d = week_start + timedelta(days=i)
            rows = all_rows(
                f"SELECT COUNT(*) FILTER (WHERE status='Present') AS p, COUNT(*) AS t FROM attendance WHERE {scope} AND date = %s",
                (scope_param, d.isoformat()),
            )
            p, total = (rows[0]["p"], rows[0]["t"]) if rows else (0, 0)
            trend.append({"label": d.strftime('%a'), "pct": round(100 * p / total) if total else 0,
                          "present": int(p or 0), "marked": int(total or 0)})

        by_batch = []
        # IBEX-SEC: join attendance to students on student_id (names can collide)
        rows = all_rows(
            f"""SELECT COALESCE(s.batch,'Unassigned') AS batch,
                       COUNT(*) FILTER (WHERE a.status='Present') AS present,
                       COUNT(*) AS total
                FROM attendance a
                LEFT JOIN students s ON s.id = a.student_id
                WHERE a.{'branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)' if branch_id == 0 else 'branch_id = %s'}
                  AND a.date >= %s
                GROUP BY COALESCE(s.batch,'Unassigned') ORDER BY batch""",
            (scope_param, week_start.isoformat()),
        )
        for r in rows:
            pv, tv = r["present"], r["total"]
            by_batch.append({"batch": r["batch"], "present": int(pv or 0), "total": int(tv or 0),
                             "pct": round(100 * pv / tv) if tv else 0})

        by_day = [{"day": r["day"], "count": int(r["c"])} for r in all_rows(
            f"SELECT day, COUNT(*) AS c FROM timetables_slots WHERE {scope} GROUP BY day ORDER BY MIN(id)", (scope_param,))]

        scheduled = int(one(f"SELECT COUNT(*) FROM timetables_slots WHERE {scope}", (scope_param,)))
        logged = int(one(f"SELECT COUNT(*) FROM syllabus WHERE {scope} AND lecture_date >= %s", (scope_param, week_start.isoformat())))

        revenue_rows = all_rows(f"""
            SELECT COALESCE(TO_CHAR(paid_at, 'YYYY-MM-DD'),
                            CASE WHEN due_date ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}$' THEN due_date END) AS day,
                   COALESCE(SUM(amount_inr),0) AS amt
            FROM fees
            WHERE {scope} AND LOWER(COALESCE(status,''))='paid'
            GROUP BY 1
            HAVING COALESCE(TO_CHAR(paid_at, 'YYYY-MM-DD'),
                            CASE WHEN due_date ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}$' THEN due_date END) IS NOT NULL
            ORDER BY 1 DESC LIMIT 30""", (scope_param,))
        revenue = [{"date": r["day"], "amount": float(r["amt"] or 0)} for r in revenue_rows]
    finally:
        conn.close()

    return {
        "students_total": int(students_total or 0),
        "teachers_total": int(teachers_total or 0),
        "classrooms_total": int(classrooms_total or 0),
        "seating_plans": int(seating_plans or 0),
        "attendance": {"present": present, "absent": absent, "marked": marked,
                       "pct": round(100 * present / marked) if marked else 0,
                       "trend": trend, "by_batch": by_batch},
        "fees": {"paid_amount": float(paid_amount or 0), "paid_count": int(paid_count or 0),
                 "pending_amount": float(pending_amount or 0), "pending_count": int(pending_count or 0),
                 "revenue": revenue},
        "lectures": {"scheduled_this_week": scheduled, "logged_last_7_days": logged, "by_day": by_day},
    }


@app.get("/api/analytics/slumps/{branch_id}")
def detect_slumps(branch_id: int, days: int = 30, institute: CurrentInstitute = Depends(get_current_institute)):
    verify_branch_read_access(branch_id, institute.id)
    days = max(7, min(int(days), 180))
    conn = get_conn()
    try:
        cur = conn.cursor()
        scope_att = "branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)" if branch_id == 0 else "branch_id = %s"
        scope_param = institute.id if branch_id == 0 else branch_id
        cutoff = (_ist_now() - timedelta(days=days)).date().isoformat()
        prev_cutoff = (_ist_now() - timedelta(days=days * 2)).date().isoformat()
        slumps = []
        try:
            cur.execute(
                f"""SELECT student_id, student_name,
                           COUNT(*) FILTER (WHERE date >= %s AND status='Present') AS recent_present,
                           COUNT(*) FILTER (WHERE date >= %s) AS recent_total,
                           COUNT(*) FILTER (WHERE date < %s AND date >= %s AND status='Present') AS prior_present,
                           COUNT(*) FILTER (WHERE date < %s AND date >= %s) AS prior_total
                    FROM attendance
                    WHERE {scope_att}
                    GROUP BY student_id, student_name
                    HAVING COUNT(*) FILTER (WHERE date >= %s) > 0
                       AND COUNT(*) FILTER (WHERE date < %s AND date >= %s) > 0""",
                (cutoff, cutoff, cutoff, prev_cutoff, cutoff, prev_cutoff, scope_param, cutoff, cutoff, prev_cutoff),
            )
            for row in cur.fetchall():
                rp, rt = int(row["recent_present"] or 0), int(row["recent_total"] or 0)
                pp, pt = int(row["prior_present"] or 0), int(row["prior_total"] or 0)
                if rt == 0 or pt == 0:
                    continue
                recent_pct = 100 * rp / rt
                prior_pct = 100 * pp / pt
                drop = prior_pct - recent_pct
                if drop >= 20:
                    slumps.append({
                        "student_name": row["student_name"], "student_id": row["student_id"],
                        "kind": "attendance", "recent_pct": round(recent_pct, 1),
                        "prior_pct": round(prior_pct, 1), "drop": round(drop, 1),
                        "note": f"Attendance fell from {round(prior_pct)}% to {round(recent_pct)}% over the last {days} days.",
                    })
        except Exception as exc:
            conn.rollback()
            log.warning("[slump] attendance query failed: %s", exc)
        try:
            cur.execute(
                """SELECT student_name, marks, overall_marks, exam_date
                   FROM exam_results
                   WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)
                   ORDER BY student_name, exam_date DESC""",
                (institute.id,),
            )
            by_student = defaultdict(list)
            for row in cur.fetchall():
                if row["marks"] is None or not row["overall_marks"]:
                    continue
                pct = 100 * float(row["marks"]) / float(row["overall_marks"])
                by_student[row["student_name"]].append((row["exam_date"], pct))
            for name, entries in by_student.items():
                if len(entries) < 2:
                    continue
                latest_date, latest_pct = entries[0]
                earlier = [p for _, p in entries[1:4]]
                if not earlier:
                    continue
                avg_prior = sum(earlier) / len(earlier)
                drop = avg_prior - latest_pct
                if drop >= 10:
                    slumps.append({
                        "student_name": name, "kind": "score", "recent_pct": round(latest_pct, 1),
                        "prior_pct": round(avg_prior, 1), "drop": round(drop, 1),
                        "note": f"Latest test on {latest_date} scored {round(latest_pct)}% vs a prior average of {round(avg_prior)}%.",
                    })
        except Exception as exc:
            conn.rollback()
            log.warning("[slump] score query failed: %s", exc)
    finally:
        conn.close()
    slumps.sort(key=lambda x: x["drop"], reverse=True)
    return {"window_days": days, "count": len(slumps), "slumps": slumps[:40]}


# ---------------------------------------------------------------------------
# Audit History — scoped strictly by institute_id
# ---------------------------------------------------------------------------

@app.get("/api/audit-log")
def list_audit_log(branch_id: int | None = None, limit: int = 200, offset: int = 0,
                   institute: CurrentInstitute = Depends(require_owner),
                   x_gate_token: str | None = Header(default=None)):
    consume_gate_token(institute, "audit_history", x_gate_token)
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    conn = get_conn()
    try:
        cur = conn.cursor()
        # IBEX-SEC: strictly scoped by institute_id — never leak other tenants' rows
        where = ["a.institute_id = %s"]
        params: list = [institute.id]
        if branch_id is not None:
            where.append("a.branch_id = %s")
            params.append(branch_id)
        params.extend([limit, offset])
        cur.execute(
            f"""
            SELECT a.id, a.timestamp, a.user_id, a.branch_id, a.action_type, a.before_after_payload,
                   a.actor_type, a.actor_id,
                   COALESCE(
                     CASE WHEN a.actor_type='staff' THEN s.full_name END,
                     CASE WHEN a.actor_type='owner' THEN i.full_name END,
                     CASE WHEN a.actor_type='system' THEN 'System' END,
                     s.full_name, i.full_name, i.institute_name
                   ) AS user_name,
                   b.name AS branch_name
            FROM audit_log a
            LEFT JOIN branches b ON b.id = a.branch_id AND b.tenant_id = a.institute_id
            LEFT JOIN staff_users s ON s.id = a.user_id AND s.institute_id = a.institute_id
            LEFT JOIN institutes i ON i.id = a.institute_id
            WHERE {' AND '.join(where)}
            ORDER BY a.timestamp DESC
            LIMIT %s OFFSET %s
            """,
            tuple(params),
        )
        rows = cur.fetchall()
        out = []
        for r in rows:
            payload = r["before_after_payload"]
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except (TypeError, ValueError):
                    payload = {}
            out.append({
                "id": r["id"],
                "timestamp": r["timestamp"].isoformat() if hasattr(r["timestamp"], "isoformat") else str(r["timestamp"]),
                "user_id": r["user_id"],
                "user_name": r["user_name"] or "System",
                "actor_type": r["actor_type"],
                "actor_id": r["actor_id"],
                "branch_id": r["branch_id"],
                "branch_name": r["branch_name"],
                "action_type": r["action_type"],
                "payload": payload or {},
            })
        return {"entries": out, "limit": limit, "offset": offset}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Journal
# ---------------------------------------------------------------------------

class JournalCreate(BaseModel):
    content: str
    branch_id: int | None = None


@app.get("/api/journal")
def list_journal(branch_id: int | None = None, limit: int = 200,
                 institute: CurrentInstitute = Depends(require_owner),
                 x_gate_token: str | None = Header(default=None)):
    consume_gate_token(institute, "journal", x_gate_token)
    limit = max(1, min(limit, 500))
    conn = get_conn()
    try:
        cur = conn.cursor()
        if branch_id is not None:
            cur.execute(
                """SELECT id, branch_id, author_user_id, author_name, content, created_at
                   FROM journal_entries WHERE institute_id = %s AND branch_id = %s
                   ORDER BY created_at DESC LIMIT %s""",
                (institute.id, branch_id, limit),
            )
        else:
            cur.execute(
                """SELECT id, branch_id, author_user_id, author_name, content, created_at
                   FROM journal_entries WHERE institute_id = %s
                   ORDER BY created_at DESC LIMIT %s""",
                (institute.id, limit),
            )
        rows = cur.fetchall()
        return [{"id": r["id"], "branch_id": r["branch_id"],
                 "author_user_id": r["author_user_id"], "author_name": r["author_name"] or "Director",
                 "content": r["content"],
                 "created_at": r["created_at"].isoformat() if hasattr(r["created_at"], "isoformat") else str(r["created_at"])} for r in rows]
    finally:
        conn.close()


@app.post("/api/journal")
def create_journal(req: JournalCreate, institute: CurrentInstitute = Depends(require_owner),
                   x_gate_token: str | None = Header(default=None)):
    consume_gate_token(institute, "journal", x_gate_token)
    content = (req.content or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Journal entry cannot be empty.")
    if req.branch_id is not None:
        verify_branch_ownership(req.branch_id, institute.id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO journal_entries (institute_id, branch_id, author_user_id, author_name, content)
               VALUES (%s, %s, %s, %s, %s) RETURNING id, created_at""",
            (institute.id, req.branch_id, institute.user_id, institute.full_name or institute.institute_name, content),
        )
        row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, req.branch_id, "CREATE_JOURNAL", None, {"id": row["id"]})
    return {"id": row["id"], "created_at": row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else str(row["created_at"])}


@app.delete("/api/journal/{entry_id}")
def delete_journal(entry_id: int, institute: CurrentInstitute = Depends(require_owner),
                   x_gate_token: str | None = Header(default=None)):
    consume_gate_token(institute, "journal", x_gate_token)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM journal_entries WHERE id = %s AND institute_id = %s", (entry_id, institute.id))
        before = cur.fetchone()
        if not before:
            raise HTTPException(status_code=404, detail="Journal entry not found")
        cur.execute("DELETE FROM journal_entries WHERE id = %s AND institute_id = %s", (entry_id, institute.id))
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, before["branch_id"], "DELETE_JOURNAL", dict(before), None)
    return {"status": "deleted"}


# ---------------------------------------------------------------------------
# Inquiry
# ---------------------------------------------------------------------------

class InquiryCreate(BaseModel):
    name: str
    phone: str | None = None
    email: str | None = None
    source: str | None = None
    interested_in: str | None = None
    status: str | None = "New"
    notes: str | None = None
    follow_up_date: str | None = None


class InquiryUpdate(BaseModel):
    name: str | None = None
    phone: str | None = None
    email: str | None = None
    source: str | None = None
    interested_in: str | None = None
    status: str | None = None
    notes: str | None = None
    follow_up_date: str | None = None


@app.get("/api/inquiries/{branch_id}")
def list_inquiries(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute, "inquiry")
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        if branch_id == 0:
            cur.execute(
                """SELECT i.* FROM inquiries i JOIN branches b ON b.id = i.branch_id
                   WHERE b.tenant_id = %s ORDER BY i.created_at DESC LIMIT 500""",
                (institute.id,),
            )
        else:
            cur.execute("SELECT * FROM inquiries WHERE branch_id = %s ORDER BY created_at DESC LIMIT 500", (branch_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


@app.post("/api/inquiries/{branch_id}")
def create_inquiry(branch_id: int, req: InquiryCreate, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "inquiry")
    verify_branch_ownership(branch_id, institute.id)
    if not (req.name or "").strip():
        raise HTTPException(status_code=400, detail="Name is required.")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO inquiries (branch_id, name, phone, email, source, interested_in, status, notes, follow_up_date)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (branch_id, req.name.strip(), req.phone, req.email, req.source, req.interested_in,
             req.status or "New", req.notes, req.follow_up_date),
        )
        row = dict(cur.fetchone())
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, branch_id, "CREATE_INQUIRY", None, {"id": row["id"], "name": row["name"]})
    return row


@app.patch("/api/inquiries/{inquiry_id}")
def update_inquiry(inquiry_id: int, req: InquiryUpdate, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "inquiry")
    updates, params = [], []
    for field in ("name", "phone", "email", "source", "interested_in", "status", "notes", "follow_up_date"):
        value = getattr(req, field)
        if value is not None:
            updates.append(f"{field} = %s")
            params.append(value)
    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update.")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            f"""UPDATE inquiries SET {', '.join(updates)}
                WHERE id = %s AND branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)
                RETURNING *""",
            (*params, inquiry_id, institute.id),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Inquiry not found")
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, row["branch_id"], "UPDATE_INQUIRY", None, {"id": inquiry_id})
    return dict(row)


@app.delete("/api/inquiries/{inquiry_id}")
def delete_inquiry(inquiry_id: int, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "inquiry")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM inquiries WHERE id = %s AND branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)",
            (inquiry_id, institute.id),
        )
        before = cur.fetchone()
        if not before:
            raise HTTPException(status_code=404, detail="Inquiry not found")
        cur.execute("DELETE FROM inquiries WHERE id = %s", (inquiry_id,))
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, before["branch_id"], "DELETE_INQUIRY", dict(before), None)
    return {"status": "deleted"}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/api/dashboard/{branch_id}")
def get_dashboard(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    try:
        cursor = conn.cursor()
        now_ist = _ist_now()
        today = now_ist.date()
        week_start = today - timedelta(days=6)
        attendance_week = []

        if institute.is_owner or "attendance" in (institute.allowed_modules or []):
            # IBEX-SEC: join on student_id (unique), not name
            cursor.execute(
                f"""SELECT s.batch, a.status
                    FROM attendance a LEFT JOIN students s ON s.id = a.student_id
                    WHERE a.{'branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)' if branch_id == 0 else 'branch_id = %s'}
                      AND a.date >= %s AND a.date <= %s""",
                (institute.id if branch_id == 0 else branch_id, week_start.isoformat(), today.isoformat()),
            )
            per_batch = {}
            for row in cursor.fetchall():
                batch = row["batch"] or "Unassigned"
                b = per_batch.setdefault(batch, {"present": 0, "total": 0})
                b["total"] += 1
                if row["status"] == "Present":
                    b["present"] += 1
            for batch, stats in sorted(per_batch.items()):
                pct = round(100 * stats["present"] / stats["total"]) if stats["total"] else 0
                attendance_week.append({"batch": batch, "present": stats["present"], "total": stats["total"], "pct": pct})

        fees_pending_total, fees_pending_count = 0, 0
        if institute.is_owner or "fees" in (institute.allowed_modules or []):
            cursor.execute(
                f"SELECT COUNT(*) AS c, COALESCE(SUM(amount_inr),0) AS s FROM fees WHERE "
                f"{'branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)' if branch_id == 0 else 'branch_id = %s'} "
                f"AND LOWER(COALESCE(status, '')) != 'paid'",
                (institute.id if branch_id == 0 else branch_id,),
            )
            r = cursor.fetchone()
            fees_pending_count, fees_pending_total = r["c"], r["s"]

        ongoing_lectures = []
        if institute.is_owner or "timetables" in (institute.allowed_modules or []):
            today_name = now_ist.strftime("%A")
            now_time = now_ist.time()
            cursor.execute(
                f"SELECT batch_name, day, time_slot, subject, teacher, room FROM timetables_slots WHERE "
                f"{'branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)' if branch_id == 0 else 'branch_id = %s'} "
                f"AND day = %s",
                (institute.id if branch_id == 0 else branch_id, today_name),
            )
            for row in cursor.fetchall():
                start, end = _parse_time_range(row["time_slot"])
                if start and end and start <= now_time <= end:
                    ongoing_lectures.append({"batch_name": row["batch_name"], "time_slot": row["time_slot"],
                                             "subject": row["subject"], "teacher": row["teacher"], "room": row["room"]})
    finally:
        conn.close()

    return {"attendance_week": attendance_week, "fees_pending_total": fees_pending_total,
            "fees_pending_count": fees_pending_count, "ongoing_lectures": ongoing_lectures,
            "as_of": now_ist.isoformat()}


# ---------------------------------------------------------------------------
# Parallax AI — data minimization
# ---------------------------------------------------------------------------

# IBEX-SEC: explicit column allowlist per table. No PII unless strictly needed
# for the specific analysis the user requested.
PARALLAX_TABLES = {
    "students": "SELECT batch, status, COUNT(*) AS n FROM students GROUP BY batch, status",
    "teachers": "SELECT subject, COUNT(*) AS n FROM teachers GROUP BY subject",
    "classrooms": "SELECT building, COUNT(*) AS n, COALESCE(AVG(capacity),0) AS avg_capacity FROM classrooms GROUP BY building",
    "syllabus": "SELECT subject, COUNT(*) AS n, COALESCE(SUM(num_lectures),0) AS lectures FROM syllabus GROUP BY subject",
    "attendance": "SELECT date, status, COUNT(*) AS n FROM attendance GROUP BY date, status",
    "timetables_slots": "SELECT day, COUNT(*) AS n FROM timetables_slots GROUP BY day",
    "invigilation": "SELECT exam_date, COUNT(*) AS n FROM invigilation GROUP BY exam_date",
    "fees": "SELECT status, COUNT(*) AS n, COALESCE(SUM(amount_inr),0) AS total FROM fees GROUP BY status",
    "exam_seatings": "SELECT exam_date, COUNT(*) AS n FROM exam_seatings GROUP BY exam_date",
}
PARALLAX_MAX_ROWS_PER_TABLE = 200


class AssistantQuery(BaseModel):
    question: str


def _parallax_gather_context(branch_id: int, institute: "CurrentInstitute") -> str:
    conn = get_conn()
    try:
        cursor = conn.cursor()
        scope_hq = branch_id == 0
        blocks = []
        for table, base_sql in PARALLAX_TABLES.items():
            module_name = "timetables" if table in ("timetables_slots",) else ("seating" if table == "exam_seatings" else table)
            if not institute.is_owner and module_name not in (institute.allowed_modules or []):
                continue
            if scope_hq:
                sql = f"SELECT * FROM ({base_sql.replace('FROM ' + table, 'FROM ' + table)} ) sub WHERE 1=1"
                # Simpler: wrap with a branch filter on the source table
                sql = f"SELECT * FROM ({base_sql}) sub"
                # We need the branch scope inside the aggregate; rebuild:
                sql = _parallax_scoped_sql(table, base_sql, scope_hq=True)
                params = (institute.id,)
            else:
                sql = _parallax_scoped_sql(table, base_sql, scope_hq=False)
                params = (branch_id,)
            try:
                cursor.execute(sql + f" LIMIT {PARALLAX_MAX_ROWS_PER_TABLE}", params)
                rows = [dict(r) for r in cursor.fetchall()]
            except Exception as exc:
                conn.rollback()
                log.warning("[parallax] query failed for %s: %s", table, exc)
                rows = []
            if rows:
                blocks.append(f"### {table} ({len(rows)} aggregate rows)\n{json.dumps(rows, default=str)}")
    finally:
        conn.close()
    return "\n\n".join(blocks) if blocks else "(no data recorded yet)"


def _parallax_scoped_sql(table: str, base_sql: str, scope_hq: bool) -> str:
    """Wrap an aggregate SELECT so it only sees rows in scope. Uses a subselect
    to keep the aggregate intact."""
    branch_filter = (
        f"branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)" if scope_hq
        else "branch_id = %s"
    )
    # base_sql is like: SELECT a, b FROM table GROUP BY a, b
    # Insert the filter before GROUP BY / end:
    upper = base_sql.upper()
    if " GROUP BY " in upper:
        idx = upper.index(" GROUP BY ")
        head, tail = base_sql[:idx], base_sql[idx:]
        if " WHERE " in head.upper():
            head += f" AND {branch_filter}"
        else:
            head += f" WHERE {branch_filter}"
        return head + tail
    else:
        if " WHERE " in upper:
            return base_sql + f" AND {branch_filter}"
        return base_sql + f" WHERE {branch_filter}"


def _parallax_call_gemini(context: str, question: str) -> str:
    if not GEMINI_API_KEY:
        raise HTTPException(status_code=503, detail="Parallax is not configured: GEMINI_API_KEY is missing on the server.")
    import urllib.request
    import urllib.error
    prompt = (
        "You are Parallax, an in-app data assistant for a school/institute management system. "
        "Answer the user's question using ONLY the aggregate data given below. The data has been "
        "pre-aggregated to protect individual privacy — no names, phone numbers, or identifiers are provided. "
        "If the data doesn't contain the answer, say so plainly. Be concise and factual. "
        "Do not use markdown emphasis, italics, bold, or asterisks."
    )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    payload = json.dumps({"contents": [{"parts": [{"text": prompt + f"\n\n=== INSTITUTE AGGREGATES ===\n{context}\n\n=== QUESTION ===\n{question}"}]}]}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        log.warning("gemini HTTP error: %s", e)
        raise HTTPException(status_code=502, detail="Parallax upstream error. Please try again shortly.")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=_safe_error("gemini", exc))
    try:
        return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except (KeyError, IndexError):
        return "Parallax couldn't produce an answer for that just now — try rephrasing."


@app.post("/api/assistant/{branch_id}")
def parallax_ask(branch_id: int, body: AssistantQuery, institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute, "assistant")
    verify_branch_read_access(branch_id, institute.id)
    question = (body.question or "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="Ask Parallax something first.")
    context = _parallax_gather_context(branch_id, institute)
    answer = _parallax_call_gemini(context, question)
    audit_write(institute, branch_id if branch_id else None, "PARALLAX_QUERY", None, {"question": question[:200]})
    return {"answer": answer}


@app.delete("/api/assistant/history/{branch_id}")
def clear_parallax_history(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute, "assistant")
    verify_branch_read_access(branch_id, institute.id)
    return {"status": "cleared", "persistent_history": False}


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

HTML_CONTENT = Path(__file__).with_name("index.html").read_text(encoding="utf-8")


@app.get("/", response_class=HTMLResponse)
def read_root():
    return HTMLResponse(content=HTML_CONTENT, status_code=200)


MANIFEST_PATH = Path(__file__).with_name("manifest.json")
SERVICE_WORKER_PATH = Path(__file__).with_name("sw.js")
ICONS_DIR = Path(__file__).with_name("icons")


@app.get("/manifest.json")
def get_manifest():
    return FileResponse(MANIFEST_PATH, media_type="application/manifest+json")


@app.get("/sw.js")
def get_service_worker():
    return FileResponse(SERVICE_WORKER_PATH, media_type="application/javascript")


if ICONS_DIR.exists():
    app.mount("/icons", StaticFiles(directory=str(ICONS_DIR)), name="icons")


# ---------------------------------------------------------------------------
# Exam Results / History / Performance
# ---------------------------------------------------------------------------

class ExamResultPayload(BaseModel):
    branch_id: int
    batch_name: str
    subjects: str
    topics: str
    exam_date: str
    overall_marks: float
    student_id: int | None = None
    student_name: str
    roll_number: str | None = None
    marks: float | None = None


class ExamHistoryPayload(BaseModel):
    branch_id: int
    subject: str
    topic: str
    batch_name: str
    exam_date: str


def _exam_branch_check(institute, branch_id: int, module: str):
    check_module_access(institute, module)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM branches WHERE id=%s AND tenant_id=%s", (branch_id, institute.id))
        if not cur.fetchone():
            raise HTTPException(status_code=403, detail="Branch access denied")
    finally:
        conn.close()


def _valid_marks(marks, overall):
    if marks is None:
        return None
    if marks < 0 or marks > overall:
        raise HTTPException(status_code=400, detail="Student marks must be between 0 and the overall marks.")
    return marks


@app.get("/api/exam/results/students/{branch_id}")
def exam_result_students(branch_id: int, batch: str, institute: CurrentInstitute = Depends(get_current_institute)):
    _exam_branch_check(institute, branch_id, "results")
    if not batch.strip():
        raise HTTPException(status_code=400, detail="Batch is required")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, name, COALESCE(roll_number, '') AS roll_number
            FROM students
            WHERE branch_id=%s AND LOWER(TRIM(COALESCE(batch,'')))=LOWER(TRIM(%s))
            ORDER BY LOWER(COALESCE(name,'')), LOWER(COALESCE(roll_number,''))
        """, (branch_id, batch))
        return {"students": [dict(r) for r in cur.fetchall()]}
    finally:
        conn.close()


@app.get("/api/exam/results/{branch_id}")
def list_exam_results(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    _exam_branch_check(institute, branch_id, "results")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, branch_id, batch_name, subjects, topics, exam_date,
                   overall_marks, student_id, student_name, roll_number, marks,
                   created_at, updated_at
            FROM exam_results WHERE branch_id=%s
            ORDER BY exam_date DESC, batch_name, student_name, id
        """, (branch_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


@app.post("/api/exam/results")
def create_exam_result(payload: ExamResultPayload, institute: CurrentInstitute = Depends(require_write_access)):
    _exam_branch_check(institute, payload.branch_id, "results")
    overall = float(payload.overall_marks)
    if overall <= 0:
        raise HTTPException(status_code=400, detail="Overall marks must be greater than zero.")
    marks = _valid_marks(payload.marks, overall)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO exam_results
            (branch_id,batch_name,subjects,topics,exam_date,overall_marks,student_id,student_name,roll_number,marks)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *
        """, (payload.branch_id, payload.batch_name.strip(), payload.subjects.strip(), payload.topics.strip(),
              payload.exam_date, overall, payload.student_id, payload.student_name.strip(), payload.roll_number, marks))
        row = dict(cur.fetchone())
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, payload.branch_id, "CREATE_EXAM_RESULT", None, row)
    return row


@app.patch("/api/exam/results/{result_id}")
def update_exam_result(result_id: int, payload: ExamResultPayload, institute: CurrentInstitute = Depends(require_write_access)):
    _exam_branch_check(institute, payload.branch_id, "results")
    marks = _valid_marks(payload.marks, float(payload.overall_marks))
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM exam_results WHERE id=%s AND branch_id=%s", (result_id, payload.branch_id))
        before = cur.fetchone()
        if not before:
            raise HTTPException(status_code=404, detail="Result record not found")
        cur.execute("""
            UPDATE exam_results SET batch_name=%s, subjects=%s, topics=%s, exam_date=%s,
              overall_marks=%s, student_id=%s, student_name=%s, roll_number=%s, marks=%s, updated_at=NOW()
            WHERE id=%s AND branch_id=%s RETURNING *
        """, (payload.batch_name.strip(), payload.subjects.strip(), payload.topics.strip(), payload.exam_date,
              payload.overall_marks, payload.student_id, payload.student_name.strip(), payload.roll_number,
              marks, result_id, payload.branch_id))
        after = dict(cur.fetchone())
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, payload.branch_id, "UPDATE_EXAM_RESULT", dict(before), after)
    return after


@app.delete("/api/exam/results/{result_id}")
def delete_exam_result(result_id: int, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "results")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM exam_results WHERE id=%s AND branch_id IN (SELECT id FROM branches WHERE tenant_id=%s)",
                    (result_id, institute.id))
        before = cur.fetchone()
        if not before:
            raise HTTPException(status_code=404, detail="Result record not found")
        cur.execute("DELETE FROM exam_results WHERE id=%s", (result_id,))
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, before["branch_id"], "DELETE_EXAM_RESULT", dict(before), None)
    return {"status": "success"}


@app.get("/api/exam/history/{branch_id}")
def list_exam_history(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    _exam_branch_check(institute, branch_id, "history")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, branch_id, subject, topic, batch_name, exam_date, created_at, updated_at FROM exam_history WHERE branch_id=%s ORDER BY exam_date DESC, id DESC", (branch_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


@app.post("/api/exam/history")
def create_exam_history(payload: ExamHistoryPayload, institute: CurrentInstitute = Depends(require_write_access)):
    _exam_branch_check(institute, payload.branch_id, "history")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO exam_history (branch_id,subject,topic,batch_name,exam_date) VALUES (%s,%s,%s,%s,%s) RETURNING *",
                    (payload.branch_id, payload.subject.strip(), payload.topic.strip(), payload.batch_name.strip(), payload.exam_date))
        row = dict(cur.fetchone())
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, payload.branch_id, "CREATE_EXAM_HISTORY", None, row)
    return row


@app.patch("/api/exam/history/{history_id}")
def update_exam_history(history_id: int, payload: ExamHistoryPayload, institute: CurrentInstitute = Depends(require_write_access)):
    _exam_branch_check(institute, payload.branch_id, "history")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM exam_history WHERE id=%s AND branch_id=%s", (history_id, payload.branch_id))
        before = cur.fetchone()
        if not before:
            raise HTTPException(status_code=404, detail="History record not found")
        cur.execute("UPDATE exam_history SET subject=%s, topic=%s, batch_name=%s, exam_date=%s, updated_at=NOW() WHERE id=%s AND branch_id=%s RETURNING *",
                    (payload.subject.strip(), payload.topic.strip(), payload.batch_name.strip(), payload.exam_date, history_id, payload.branch_id))
        after = dict(cur.fetchone())
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, payload.branch_id, "UPDATE_EXAM_HISTORY", dict(before), after)
    return after


@app.delete("/api/exam/history/{history_id}")
def delete_exam_history(history_id: int, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "history")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM exam_history WHERE id=%s AND branch_id IN (SELECT id FROM branches WHERE tenant_id=%s)",
                    (history_id, institute.id))
        before = cur.fetchone()
        if not before:
            raise HTTPException(status_code=404, detail="History record not found")
        cur.execute("DELETE FROM exam_history WHERE id=%s", (history_id,))
        conn.commit()
    finally:
        conn.close()
    audit_write(institute, before["branch_id"], "DELETE_EXAM_HISTORY", dict(before), None)
    return {"status": "success"}


PASS_THRESHOLD_PCT = 40.0


@app.get("/api/exam/performance/{branch_id}")
def exam_performance(branch_id: int, batch: str | None = None, institute: CurrentInstitute = Depends(get_current_institute)):
    _exam_branch_check(institute, branch_id, "performance")
    conn = get_conn()
    try:
        cur = conn.cursor()
        where = ["branch_id=%s", "marks IS NOT NULL", "overall_marks > 0"]
        params: list = [branch_id]
        if batch and batch.strip():
            where.append("LOWER(TRIM(batch_name))=LOWER(TRIM(%s))")
            params.append(batch)
        cur.execute(f"""
            SELECT id, batch_name, subjects, topics, exam_date, overall_marks,
                   student_name, roll_number, marks
            FROM exam_results WHERE {' AND '.join(where)}
            ORDER BY batch_name, student_name
        """, params)
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    if not rows:
        return {"batch": batch or "All Batches", "attempt_count": 0,
                "overall_average_pct": None, "subject_averages": [],
                "toppers": [], "failing": [], "distribution": []}

    for r in rows:
        r["pct"] = round((float(r["marks"]) / float(r["overall_marks"])) * 100, 2)
    overall_avg = round(sum(r["pct"] for r in rows) / len(rows), 2)

    by_subject: dict = defaultdict(list)
    for r in rows:
        subj = (r["subjects"] or "General").strip()
        by_subject[subj].append(r["pct"])
    subject_averages = [{"subject": s, "average_pct": round(sum(v) / len(v), 2), "attempts": len(v)}
                        for s, v in sorted(by_subject.items())]

    by_student: dict = defaultdict(list)
    for r in rows:
        by_student[(r["student_name"] or "Unnamed", r["roll_number"] or "")].append(r["pct"])
    student_avgs = [{"student_name": k[0], "roll_number": k[1], "average_pct": round(sum(v) / len(v), 2)}
                    for k, v in by_student.items()]
    student_avgs.sort(key=lambda x: x["average_pct"], reverse=True)
    toppers = student_avgs[:10]
    failing = sorted([s for s in student_avgs if s["average_pct"] < PASS_THRESHOLD_PCT], key=lambda x: x["average_pct"])[:25]

    buckets = [(0, 40), (40, 50), (50, 60), (60, 70), (70, 80), (80, 90), (90, 100.01)]
    distribution = []
    for lo, hi in buckets:
        count = sum(1 for r in rows if lo <= r["pct"] < hi)
        label = f"{int(lo)}-{int(hi) if hi <= 100 else 100}%"
        distribution.append({"range": label, "count": count})

    return {"batch": batch or "All Batches", "attempt_count": len(rows),
            "overall_average_pct": overall_avg, "pass_threshold_pct": PASS_THRESHOLD_PCT,
            "subject_averages": subject_averages, "toppers": toppers,
            "failing": failing, "distribution": distribution}
