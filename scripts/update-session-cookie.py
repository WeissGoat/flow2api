#!/usr/bin/env python3
"""Update a Flow2API account's Google cookies without overwriting token settings.

Google Flow moved from labs.google (NextAuth session-token) to flow.google.com,
which authenticates with first-party Google cookies (OSID / __Secure-OSID on
flow.google.com plus SID, HSID, SSID, APISID, SAPISID, __Secure-1PSID, ... on
google.com). Cookies can be supplied as JSON exports (e.g. Cookie-Editor) or as
a "name=value; name2=value2" Cookie header, from one or more files or stdin.
Several JSON exports (one per domain) are merged into a single list.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any


FLOW_SESSION_COOKIES = frozenset({"OSID", "__Secure-OSID"})
GOOGLE_ACCOUNT_COOKIES = frozenset(
    {"SID", "HSID", "SSID", "APISID", "SAPISID", "__Secure-1PSID", "__Secure-3PSID"}
)
SECRET_COOKIE_RE = re.compile(
    r"((?:OSID|SID|HSID|SSID|APISID|SAPISID|__Secure-[0-9A-Za-z_-]+)\s*=\s*)[^;\s\"]+",
    re.IGNORECASE,
)
DEFAULT_BASE_URL = "http://127.0.0.1:38000"
DEFAULT_TOKEN_ID = 1
DEFAULT_ROUTE_KEY = "9223"

# These are the editable fields accepted by PUT /api/tokens/{id}. Keeping the
# values returned by GET /api/tokens avoids resetting deployment-specific data.
PRESERVED_FIELDS = (
    "project_id",
    "project_name",
    "remark",
    "captcha_proxy_url",
    "extension_route_key",
    "image_enabled",
    "video_enabled",
    "image_concurrency",
    "video_concurrency",
    "proxy_url",
    "auto_refresh_enabled",
    "refresh_interval_minutes",
)

class FlowApiError(RuntimeError):
    """An API request failed without exposing request secrets."""


def short_error(value: str) -> str:
    value = SECRET_COOKIE_RE.sub(r"\1<redacted>", value)
    value = re.sub(r"Bearer\s+\S+", "Bearer <redacted>", value, flags=re.IGNORECASE)
    return " ".join(value.split())[:300]


class FlowApi:
    def __init__(self, base_url: str, timeout: float):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        session_token: str | None = None,
    ) -> Any:
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if session_token:
            headers["Authorization"] = f"Bearer {session_token}"

        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="replace")
            except Exception:
                detail = ""
            raise FlowApiError(
                f"HTTP {exc.code} {method} {path}: {short_error(detail) or exc.reason}"
            ) from None
        except urllib.error.URLError as exc:
            raise FlowApiError(f"连接失败 {method} {path}: {short_error(str(exc.reason))}") from None
        except TimeoutError:
            raise FlowApiError(f"请求超时 {method} {path}") from None

        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise FlowApiError(f"响应不是有效 JSON: {method} {path}") from None

    def login(self, username: str, password: str) -> str:
        result = self.request(
            "POST",
            "/api/admin/login",
            payload={"username": username, "password": password},
        )
        token = result.get("token") if isinstance(result, dict) else None
        if not token:
            raise FlowApiError("管理员登录成功但未返回会话 Token")
        return str(token)


def parse_global_setting(path: Path, key: str) -> str | None:
    """Read a simple string from [global] without requiring Python 3.11 TOML."""
    if not path.is_file():
        return None
    in_global = False
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=\s*(.*?)\s*(?:#.*)?$")
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_global = line == "[global]"
            continue
        if not in_global:
            continue
        match = pattern.match(raw_line)
        if not match:
            continue
        value = match.group(1).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            return value[1:-1]
        return value
    return None


def read_cookie_inputs(input_paths: list[str]) -> list[str]:
    if input_paths and input_paths != ["-"]:
        return [Path(path).read_text(encoding="utf-8") for path in input_paths]
    if sys.stdin.isatty():
        print(
            "Paste the Google cookies (JSON export or name=value; ...), then press Ctrl-D to submit.",
            file=sys.stderr,
        )
    return [sys.stdin.read()]


def _cookie_names_from_header(text: str) -> list[str]:
    names = []
    for chunk in text.split(";"):
        if "=" in chunk:
            names.append(chunk.split("=", 1)[0].strip())
    return names


def build_google_cookies(texts: list[str]) -> tuple[str, set[str]]:
    """Merge inputs into the storage text accepted by PUT /api/tokens/{id}."""
    json_cookies: list[dict[str, Any]] = []
    header_parts: list[str] = []
    for raw in texts:
        text = raw.strip()
        if text.lower().startswith("cookie:"):
            text = text.split(":", 1)[1].strip()
        if not text:
            continue
        if text[:1] in {"[", "{"}:
            payload = json.loads(text)
            if isinstance(payload, dict):
                payload = payload.get("cookies", [payload])
            if not isinstance(payload, list):
                raise ValueError("Cookie JSON 格式无法识别（应为数组或 {cookies: [...]}）")
            json_cookies.extend(item for item in payload if isinstance(item, dict))
        else:
            header_parts.append(" ".join(text.split()).strip("; "))

    if json_cookies and header_parts:
        raise ValueError("不能混用 JSON 导出和 name=value 格式，请统一一种格式")
    if json_cookies:
        storage = json.dumps(json_cookies, ensure_ascii=False, separators=(",", ":"))
        names = {str(item.get("name", "")) for item in json_cookies}
    else:
        storage = "; ".join(part for part in header_parts if part)
        names = set(_cookie_names_from_header(storage))
    if not storage:
        raise ValueError("未读取到任何 Cookie")
    if "__Secure-next-auth.session-token" in names and len(names) <= 3:
        raise ValueError(
            "输入看起来是旧版 labs.google 的 session-token；新版需要 flow.google.com 和 google.com 的 Google Cookies"
        )
    if not names & (FLOW_SESSION_COOKIES | GOOGLE_ACCOUNT_COOKIES):
        raise ValueError(
            "未找到 OSID/__Secure-OSID 或 SID/SAPISID 等 Google 登录 Cookie，请确认导出的是 flow.google.com 和 google.com 的 Cookie"
        )
    return storage, names


def backup_database(db_path: Path) -> Path:
    if not db_path.is_file():
        raise FileNotFoundError(f"数据库不存在: {db_path}")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = db_path.with_name(f"{db_path.name}.bak.google-cookies-{stamp}")
    suffix = 1
    while backup_path.exists():
        backup_path = db_path.with_name(
            f"{db_path.name}.bak.google-cookies-{stamp}-{suffix}"
        )
        suffix += 1

    source = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    target = sqlite3.connect(backup_path)
    try:
        source.execute("PRAGMA busy_timeout=10000")
        source.backup(target)
        target.commit()
    finally:
        target.close()
        source.close()
    os.chmod(backup_path, 0o600)
    return backup_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Update the Google Flow (flow.google.com) Google cookies of a Flow2API account. "
            "Input is read from stdin unless files are supplied."
        )
    )
    parser.add_argument(
        "input_files",
        nargs="*",
        help="cookie files (JSON export or name=value; ...); several files are merged; '-' for stdin",
    )
    parser.add_argument(
        "--file",
        dest="file_option",
        action="append",
        default=[],
        help="cookie file (repeatable, alternative to positional files)",
    )
    parser.add_argument(
        "--login-account",
        default=os.environ.get("FLOW2API_LOGIN_ACCOUNT"),
        help="Google account email; defaults to the stored login_account/email",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("FLOW2API_BASE_URL", DEFAULT_BASE_URL),
        help=f"Flow2API base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(
            os.environ.get("FLOW2API_CONFIG_FILE", str(Path(__file__).resolve().parents[1] / "config" / "setting.toml"))
        ),
        help="setting.toml path",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path(
            os.environ.get("FLOW2API_DB_FILE", str(Path(__file__).resolve().parents[1] / "data" / "flow.db"))
        ),
        help="flow.db path used for the pre-update backup",
    )
    parser.add_argument(
        "--token-id",
        type=int,
        default=int(os.environ.get("FLOW2API_TOKEN_ID", str(DEFAULT_TOKEN_ID))),
        help=f"token record ID (default: {DEFAULT_TOKEN_ID})",
    )
    parser.add_argument(
        "--route-key",
        default=None,
        help="override extension route key; otherwise preserve the stored value",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("FLOW2API_HTTP_TIMEOUT", "180")),
        help="HTTP timeout in seconds (default: 180)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate input and show target state without writing",
    )
    parser.add_argument(
        "--no-enable",
        action="store_true",
        help="do not enable the token after a successful update",
    )
    return parser.parse_args()


def get_credentials(config_path: Path) -> tuple[str, str]:
    username = os.environ.get("FLOW2API_ADMIN_USERNAME") or parse_global_setting(
        config_path, "admin_username"
    )
    password = os.environ.get("FLOW2API_ADMIN_PASSWORD") or parse_global_setting(
        config_path, "admin_password"
    )
    if not username:
        username = input("Flow2API admin username: ").strip()
    if not password:
        password = getpass.getpass("Flow2API admin password: ")
    if not username or not password:
        raise ValueError("管理员用户名或密码为空")
    return username, password


def find_token(tokens: Any, token_id: int) -> dict[str, Any]:
    if not isinstance(tokens, list):
        raise FlowApiError("/api/tokens 返回格式不是数组")
    for item in tokens:
        if isinstance(item, dict) and int(item.get("id", -1)) == token_id:
            return item
    raise FlowApiError(f"未找到 Token ID {token_id}")


def token_summary(token: dict[str, Any]) -> str:
    return (
        f"id={token.get('id')} active={bool(token.get('is_active'))} "
        f"at_expired={bool(token.get('at_expired'))} "
        f"credits={token.get('credits')} "
        f"at_expires={token.get('at_expires') or '-'} "
        f"mode={token.get('protocol_mode') or '-'} "
        f"route_key={token.get('extension_route_key') or '-'}"
    )


def main() -> int:
    args = parse_args()
    input_paths = list(args.input_files) + list(args.file_option)
    google_cookies, cookie_names = build_google_cookies(read_cookie_inputs(input_paths))
    flow_names = sorted(cookie_names & FLOW_SESSION_COOKIES)
    account_names = sorted(cookie_names & GOOGLE_ACCOUNT_COOKIES)
    print(
        f"Parsed {len(cookie_names)} cookie name(s); "
        f"flow session: {', '.join(flow_names) or '-'}; "
        f"google account: {', '.join(account_names) or '-'}"
    )
    if not flow_names:
        print("Warning: 未包含 OSID/__Secure-OSID（flow.google.com），服务端可能无法校验登录态。", file=sys.stderr)

    api = FlowApi(args.base_url, args.timeout)
    username, password = get_credentials(args.config)
    session_token: str | None = None
    backup_path: Path | None = None
    try:
        session_token = api.login(username, password)
        current = find_token(
            api.request("GET", "/api/tokens", session_token=session_token),
            args.token_id,
        )
        print(f"Current token: {token_summary(current)}")

        login_account = (
            args.login_account
            or current.get("login_account")
            or current.get("email")
            or ""
        ).strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", login_account):
            raise ValueError("缺少有效的 Google 账号邮箱，请用 --login-account 指定")

        payload: dict[str, Any] = {}
        for field in PRESERVED_FIELDS:
            if field in current:
                payload[field] = current[field]
        payload.update(
            {
                "protocol_mode": "protocol",
                "google_cookies": google_cookies,
                "login_account": login_account,
            }
        )

        route_key = str(current.get("extension_route_key") or "").strip()
        if args.route_key is not None:
            route_key = args.route_key.strip()
        elif not route_key:
            route_key = os.environ.get("FLOW2API_EXTENSION_ROUTE_KEY", DEFAULT_ROUTE_KEY).strip()
        payload["extension_route_key"] = route_key or None

        if args.dry_run:
            print(
                f"Dry run: would update token {args.token_id} ({login_account}); "
                f"route_key={route_key or '-'}; no database or API state changed."
            )
            return 0

        backup_path = backup_database(args.db)
        print(f"Database backup: {backup_path}")

        api.request(
            "PUT",
            f"/api/tokens/{args.token_id}",
            payload=payload,
            session_token=session_token,
        )
        print("Google cookies update: success")

        if not args.no_enable:
            api.request(
                "POST",
                f"/api/tokens/{args.token_id}/enable",
                session_token=session_token,
            )
            print("Token enable: success")

        updated = find_token(
            api.request("GET", "/api/tokens", session_token=session_token),
            args.token_id,
        )
        health = api.request("GET", "/health")
        print(f"Updated token: {token_summary(updated)}")
        if isinstance(health, dict):
            print(
                "Health: "
                f"backend_running={health.get('backend_running')} "
                f"has_active_tokens={health.get('has_active_tokens')} "
                f"total_tokens={health.get('total_tokens')} "
                f"tokens_expired={health.get('tokens_expired')} "
                f"captcha_method={health.get('captcha_method')}"
            )
        else:
            print("Health: response format unexpected")

        if not args.no_enable and not updated.get("is_active"):
            raise FlowApiError("更新完成但 Token 仍未启用")
        if updated.get("at_expired"):
            raise FlowApiError("更新完成但 AT 仍显示已过期，请检查 extension 是否在线")
        if isinstance(health, dict) and not health.get("backend_running"):
            raise FlowApiError("Flow2API health 检查失败: backend_running=false")
        return 0
    finally:
        if session_token:
            try:
                api.request("POST", "/api/admin/logout", session_token=session_token)
            except Exception:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FlowApiError, FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        raise SystemExit(130)
