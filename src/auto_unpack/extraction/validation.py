"""URL DNS/HTTP 验证。

网络探测具有副作用且结果受时间、地域和鉴权影响，因此默认不启用。调用方必须显式
请求；静态提取结果始终保留，并通过 validation 字段区分语法、DNS 与 HTTP 状态。
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.client import HTTPException, HTTPResponse
from urllib.parse import urlsplit, urlunsplit


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve(host: str, port: int) -> tuple[str, list[str], str | None]:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None:
        return "literal", [str(ip)], None
    try:
        rows = socket.getaddrinfo(
            host.rstrip("."),
            port,
            type=socket.SOCK_STREAM,
        )
    except (OSError, socket.gaierror) as exc:
        return "unresolved", [], str(exc)
    addresses = sorted({row[4][0].split("%", 1)[0] for row in rows if row[4]})
    return ("resolved" if addresses else "unresolved"), addresses, None


def _all_public(addresses: list[str]) -> bool:
    try:
        return bool(addresses) and all(ipaddress.ip_address(addr).is_global for addr in addresses)
    except ValueError:
        return False


def _probe_http(
    url: str,
    addresses: list[str],
    timeout: float,
) -> tuple[str, int | None, str | None]:
    """向已经过策略检查的 IP 发 HEAD，避免二次 DNS 解析造成重绑定绕过。"""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        return "unreachable", None, str(exc)
    target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    host_header = f"[{host}]" if ":" in host else host
    if port != (443 if parts.scheme == "https" else 80):
        host_header += f":{port}"
    request = (
        f"HEAD {target} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: auto-unpack-url-validator/1.0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")

    last_error: Exception | None = None
    for address in addresses:
        sock = None
        try:
            sock = socket.create_connection((address, port), timeout=timeout)
            sock.settimeout(timeout)
            if parts.scheme == "https":
                sock = ssl.create_default_context().wrap_socket(
                    sock,
                    server_hostname=host.rstrip("."),
                )
            sock.sendall(request)
            response = HTTPResponse(sock)
            response.begin()
            status = int(response.status)
            response.close()
            return "responded", status, None
        except (OSError, HTTPException, UnicodeError, ValueError) as exc:
            last_error = exc
        finally:
            if sock is not None:
                sock.close()
    return "unreachable", None, str(last_error or "no address responded")


def validate_indicator_network(
    item: dict,
    *,
    check_http: bool = False,
    timeout: float = 3.0,
    allow_private_http: bool = False,
) -> dict:
    """就地补充单条指标的 DNS/HTTP 状态并返回该指标。"""
    validation = dict(item.get("validation") or {})
    validation.setdefault("syntax", "valid")
    validation["checked_at"] = _now_iso()
    host = item.get("host") or ""
    scheme = item.get("scheme") or ""
    port = item.get("port") or (443 if scheme in ("https", "wss") else 80)
    dns_status, addresses, dns_error = _resolve(host, port)
    validation["dns"] = dns_status
    validation["addresses"] = addresses
    if dns_error:
        validation["dns_error"] = dns_error[:300]

    if not check_http:
        validation["http"] = "not_checked"
    elif scheme not in ("http", "https"):
        validation["http"] = "not_applicable"
    elif not addresses:
        validation["http"] = "skipped_unresolved"
    elif not allow_private_http and not _all_public(addresses):
        validation["http"] = "blocked_non_public"
    else:
        status, code, error = _probe_http(
            item.get("canonical") or item.get("url") or "",
            addresses,
            timeout,
        )
        validation["http"] = status
        if code is not None:
            validation["http_status"] = code
        if error:
            validation["http_error"] = error[:300]
    item["validation"] = validation
    return item


def validate_indicators_network(
    items: list[dict],
    *,
    check_http: bool = False,
    timeout: float = 3.0,
    allow_private_http: bool = False,
    workers: int = 8,
) -> list[dict]:
    """有界并发验证指标；顺序与输入一致。"""
    if not items:
        return items

    def validate(item: dict) -> dict:
        return validate_indicator_network(
            item,
            check_http=check_http,
            timeout=timeout,
            allow_private_http=allow_private_http,
        )

    with ThreadPoolExecutor(max_workers=max(1, min(workers, 32))) as pool:
        return list(pool.map(validate, items))
