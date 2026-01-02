import base64
import hmac
import os
import sqlite3
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from flask import Flask, Response, abort, redirect, render_template, request


ALLOWED_CODES = {301, 302, 307, 308}


def get_env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return default if value is None or value == "" else value


def get_db_path() -> str:
    return get_env("DB_PATH", "/app/data/redirects.db")


def init_db() -> None:
    db_path = get_db_path()
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rules (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              host TEXT NULL,
              path_prefix TEXT NULL,
              target_base TEXT NOT NULL,
              code INTEGER NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              strip_prefix INTEGER NOT NULL DEFAULT 0,
              sort_order INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        # Auto-upgrade older DBs (no migrations).
        try:
            conn.execute("ALTER TABLE rules ADD COLUMN strip_prefix INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            # Column already exists (or table missing, which would be unexpected after CREATE).
            pass
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rules_host ON rules(host)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rules_sort ON rules(sort_order)")
        conn.commit()


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def normalize_host(host: Optional[str]) -> str:
    if not host:
        return ""
    h = host.strip().lower()
    # Strip port if present.
    if ":" in h:
        h = h.split(":", 1)[0]
    return h


def get_request_host() -> str:
    # Respect reverse proxy header first.
    xf_host = request.headers.get("X-Forwarded-Host", "")
    if xf_host:
        # Can be a comma-separated list; first is original host.
        first = xf_host.split(",")[0].strip()
        return normalize_host(first)
    return normalize_host(request.host)


def clean_optional_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    v = value.strip()
    return v if v != "" else None


def parse_int(value: str, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def validate_target_base(target_base: str) -> str:
    tb = target_base.strip()
    if not tb:
        raise ValueError("target_base is required.")
    parts = urlsplit(tb)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("target_base must be a full URL like https://example.com or https://example.com/base")
    return tb


def validate_code(code: int) -> int:
    if code not in ALLOWED_CODES:
        raise ValueError(f"code must be one of {sorted(ALLOWED_CODES)}")
    return code


def join_target_url(target_base: str, req_path: str, req_query: str) -> str:
    base = urlsplit(target_base)

    base_path = base.path or ""
    # req_path can be "" (meaning: don't append anything), or a path starting with "/".
    if req_path == "":
        # Don't add a trailing slash (important for targets like ".../file.html").
        joined_path = base_path
    elif base_path in ("", "/"):
        joined_path = req_path
    else:
        joined_path = base_path.rstrip("/") + "/" + req_path.lstrip("/")

    base_query = base.query or ""
    if base_query and req_query:
        final_query = f"{base_query}&{req_query}"
    else:
        final_query = base_query or req_query

    return urlunsplit((base.scheme, base.netloc, joined_path, final_query, base.fragment or ""))


@dataclass(frozen=True)
class Rule:
    id: int
    host: Optional[str]
    path_prefix: Optional[str]
    target_base: str
    code: int
    enabled: bool
    strip_prefix: bool
    sort_order: int

    @staticmethod
    def from_row(row: sqlite3.Row) -> "Rule":
        keys = set(row.keys())
        return Rule(
            id=int(row["id"]),
            host=row["host"],
            path_prefix=row["path_prefix"],
            target_base=row["target_base"],
            code=int(row["code"]),
            enabled=bool(int(row["enabled"])),
            strip_prefix=bool(int(row["strip_prefix"])) if "strip_prefix" in keys else False,
            sort_order=int(row["sort_order"]),
        )


def rule_matches(rule: Rule, req_host: str, req_path: str) -> bool:
    if not rule.enabled:
        return False
    rule_host = normalize_host(rule.host)
    if rule_host and rule_host != req_host:
        return False
    prefix = (rule.path_prefix or "").strip()
    if prefix:
        if not prefix.startswith("/"):
            prefix = "/" + prefix
        # Segment boundary match:
        # - /prefix matches /prefix and /prefix/...
        # - does NOT match /prefixfoo
        return req_path == prefix or req_path.startswith(prefix + "/")
    return True


def rule_sort_key(rule: Rule, req_host: str):
    rule_host = normalize_host(rule.host)
    host_priority = 0 if rule_host == req_host and rule_host else 1
    prefix = (rule.path_prefix or "").strip()
    if prefix and not prefix.startswith("/"):
        prefix = "/" + prefix
    prefix_len = len(prefix)
    return (host_priority, -prefix_len, rule.sort_order, rule.id)


def find_best_rule(req_host: str, req_path: str) -> Optional[Rule]:
    with db_connect() as conn:
        rows = conn.execute("SELECT * FROM rules WHERE enabled = 1").fetchall()
        candidates = [Rule.from_row(r) for r in rows]

    matches = [r for r in candidates if rule_matches(r, req_host=req_host, req_path=req_path)]
    if not matches:
        return None
    matches.sort(key=lambda r: rule_sort_key(r, req_host=req_host))
    return matches[0]


def apply_strip_prefix(rule: Rule, req_path: str) -> str:
    """
    If rule.strip_prefix is enabled and rule.path_prefix matches, remove that prefix
    from the request path before appending to target_base.

    Examples:
      prefix=/shadow, req=/shadow      -> /
      prefix=/shadow, req=/shadow/foo  -> /foo
    """
    if not rule.strip_prefix:
        return req_path
    prefix = (rule.path_prefix or "").strip()
    if not prefix:
        return req_path
    if not prefix.startswith("/"):
        prefix = "/" + prefix
    # Use the same segment boundary logic as matching.
    if not (req_path == prefix or req_path.startswith(prefix + "/")):
        return req_path
    remainder = req_path[len(prefix) :]
    # If it's an exact match (/prefix) or just a trailing slash (/prefix/),
    # do NOT force a trailing slash on the target URL.
    if remainder == "" or remainder == "/":
        return ""
    if not remainder.startswith("/"):
        remainder = "/" + remainder
    return remainder


def basic_auth_ok() -> bool:
    expected_user = get_env("ADMIN_USER", "admin")
    expected_pass = get_env("ADMIN_PASS", "admin")

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False

    try:
        decoded = base64.b64decode(auth.split(" ", 1)[1].strip()).decode("utf-8")
        user, pw = decoded.split(":", 1)
    except Exception:
        return False

    return hmac.compare_digest(user, expected_user) and hmac.compare_digest(pw, expected_pass)


def require_basic_auth() -> Optional[Response]:
    if basic_auth_ok():
        return None
    return Response(
        "Authentication required.",
        401,
        {"WWW-Authenticate": 'Basic realm="Redirector Admin", charset="UTF-8"'},
    )


app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.before_request
def _ensure_db():
    # Idempotent, cheap enough for small app; guarantees DB exists in container/volume.
    init_db()


@app.get("/admin")
def admin_index():
    auth_resp = require_basic_auth()
    if auth_resp is not None:
        return auth_resp

    with db_connect() as conn:
        rows = conn.execute("SELECT * FROM rules ORDER BY sort_order ASC, id ASC").fetchall()
    rules = [Rule.from_row(r) for r in rows]
    return render_template("index.html", rules=rules, allowed_codes=sorted(ALLOWED_CODES))


@app.get("/admin/new")
def admin_new():
    auth_resp = require_basic_auth()
    if auth_resp is not None:
        return auth_resp

    return render_template(
        "edit.html",
        rule=None,
        allowed_codes=sorted(ALLOWED_CODES),
        error=None,
    )


@app.get("/admin/edit/<int:rule_id>")
def admin_edit(rule_id: int):
    auth_resp = require_basic_auth()
    if auth_resp is not None:
        return auth_resp

    with db_connect() as conn:
        row = conn.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if row is None:
        abort(404)
    return render_template(
        "edit.html",
        rule=Rule.from_row(row),
        allowed_codes=sorted(ALLOWED_CODES),
        error=None,
    )


@app.post("/admin/save")
def admin_save():
    auth_resp = require_basic_auth()
    if auth_resp is not None:
        return auth_resp

    form = request.form
    rule_id = form.get("id", "").strip()
    host = clean_optional_text(form.get("host"))
    path_prefix = clean_optional_text(form.get("path_prefix"))
    target_base = (form.get("target_base") or "").strip()
    code = parse_int(form.get("code", ""), 302)
    enabled = 1 if form.get("enabled") == "on" else 0
    strip_prefix = 1 if form.get("strip_prefix") == "on" else 0
    sort_order = parse_int(form.get("sort_order", ""), 0)

    # Normalize stored host a bit.
    if host:
        host = normalize_host(host)
    if path_prefix:
        path_prefix = path_prefix.strip()

    try:
        target_base = validate_target_base(target_base)
        code = validate_code(code)
    except ValueError as e:
        # Re-render form with error.
        temp_rule = Rule(
            id=int(rule_id) if rule_id.isdigit() else 0,
            host=host,
            path_prefix=path_prefix,
            target_base=target_base,
            code=code,
            enabled=bool(enabled),
            strip_prefix=bool(strip_prefix),
            sort_order=sort_order,
        )
        return render_template(
            "edit.html",
            rule=temp_rule if rule_id else None,
            allowed_codes=sorted(ALLOWED_CODES),
            error=str(e),
        )

    with db_connect() as conn:
        if rule_id and rule_id.isdigit():
            conn.execute(
                """
                UPDATE rules
                   SET host = ?,
                       path_prefix = ?,
                       target_base = ?,
                       code = ?,
                       enabled = ?,
                       strip_prefix = ?,
                       sort_order = ?
                 WHERE id = ?
                """,
                (host, path_prefix, target_base, code, enabled, strip_prefix, sort_order, int(rule_id)),
            )
        else:
            conn.execute(
                """
                INSERT INTO rules (host, path_prefix, target_base, code, enabled, strip_prefix, sort_order)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (host, path_prefix, target_base, code, enabled, strip_prefix, sort_order),
            )
        conn.commit()

    return redirect("/admin")


@app.post("/admin/delete/<int:rule_id>")
def admin_delete(rule_id: int):
    auth_resp = require_basic_auth()
    if auth_resp is not None:
        return auth_resp

    with db_connect() as conn:
        conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        conn.commit()
    return redirect("/admin")


@app.route("/", defaults={"path": ""}, methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def redirector(path: str):
    # Never redirect /admin - those are admin-only.
    if request.path.startswith("/admin"):
        return Response("Not found.", 404, {"Content-Type": "text/plain; charset=utf-8"})

    req_host = get_request_host()
    req_path = request.path  # always includes leading slash
    req_query = request.query_string.decode("utf-8", errors="ignore")

    rule = find_best_rule(req_host=req_host, req_path=req_path)
    if rule is None:
        return render_template("whoops.html"), 404

    final_path = apply_strip_prefix(rule, req_path=req_path)
    location = join_target_url(rule.target_base, req_path=final_path, req_query=req_query)
    return redirect(location, code=rule.code)


if __name__ == "__main__":
    port = int(get_env("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)


