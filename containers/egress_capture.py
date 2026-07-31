"""Bounded, fail-closed HTTP(S) download capture for mitmproxy."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from typing import Any

from mitmproxy import http
from mitmproxy.proxy import server_hooks

from egress_policy import (
    BLOCKED_HEADER_NAMES,
    HOP_BY_HOP_HEADER_NAMES,
    DestinationBlocked,
    allowed_port,
    normalized_host,
    resolve_public_host,
    sanitized_headers,
)


def positive_env(name: str, default: int) -> int:
    value = int(os.environ.get(name, str(default)))
    if value <= 0:
        raise RuntimeError(f"{name} must be greater than zero")
    return value


class BoundedDownloadCapture:
    def __init__(self) -> None:
        self.evidence_path = os.environ.get(
            "SKILLSISSUE_EGRESS_EVIDENCE_FILE",
            "/run/evidence/egress-network.jsonl",
        )
        if not os.path.isabs(self.evidence_path):
            raise RuntimeError("egress evidence path must be absolute")
        self.max_requests = positive_env("SKILLSISSUE_EGRESS_MAX_REQUESTS", 32)
        self.max_response_bytes = positive_env(
            "SKILLSISSUE_EGRESS_MAX_RESPONSE_BYTES", 16 * 1024 * 1024
        )
        self.max_total_response_bytes = positive_env(
            "SKILLSISSUE_EGRESS_MAX_TOTAL_RESPONSE_BYTES", 32 * 1024 * 1024
        )
        self.max_url_bytes = positive_env("SKILLSISSUE_EGRESS_MAX_URL_BYTES", 4096)
        self.max_header_bytes = positive_env(
            "SKILLSISSUE_EGRESS_MAX_HEADER_BYTES", 32 * 1024
        )
        self.request_count = 0
        self.total_response_bytes = 0
        self.sequence = 0
        self.lock = threading.Lock()
        metadata = os.stat(self.evidence_path, follow_symlinks=False)
        if not os.path.isfile(self.evidence_path) or os.path.islink(self.evidence_path):
            raise RuntimeError("egress evidence path must be a pre-created regular file")
        if metadata.st_size:
            raise RuntimeError("egress evidence file must start empty")

    @staticmethod
    def header_pairs(message: http.Message) -> list[tuple[str, str]]:
        return [
            (
                name.decode("latin-1", "replace"),
                value.decode("latin-1", "replace"),
            )
            for name, value in message.headers.fields
        ]

    @staticmethod
    def reject(flow: http.HTTPFlow, status: int, reason: str) -> None:
        flow.metadata["skillsissue_blocked_reason"] = reason
        flow.response = http.Response.make(
            status,
            json.dumps(
                {"error": "skillsissue_egress_blocked", "reason": reason},
                separators=(",", ":"),
            ).encode(),
            {"content-type": "application/json", "cache-control": "no-store"},
        )

    def validate_request(self, flow: http.HTTPFlow) -> None:
        request = flow.request
        method = request.method.upper()
        if method not in {"GET", "HEAD"}:
            raise DestinationBlocked("method_not_allowed")
        if request.raw_content:
            raise DestinationBlocked("request_body_not_allowed")
        if request.scheme not in {"http", "https"}:
            raise DestinationBlocked("scheme_not_allowed")
        port = request.port
        if not allowed_port(request.scheme, port):
            raise DestinationBlocked("port_not_allowed")
        if len(request.pretty_url.encode("utf-8", "replace")) > self.max_url_bytes:
            raise DestinationBlocked("url_too_large")
        header_pairs = self.header_pairs(request)
        if (
            sum(len(name.encode()) + len(value.encode()) + 4 for name, value in header_pairs)
            > self.max_header_bytes
        ):
            raise DestinationBlocked("headers_too_large")
        if request.headers.get("upgrade"):
            raise DestinationBlocked("protocol_upgrade_not_allowed")
        host = normalized_host(request.host)
        selected_ip = resolve_public_host(host, port)
        flow.metadata["skillsissue_resolved_ip"] = selected_ip
        connection_tokens = {
            token.strip().lower()
            for token in request.headers.get("connection", "").split(",")
            if token.strip()
        }
        for name in list(request.headers.keys()):
            if (
                name.lower() in BLOCKED_HEADER_NAMES
                or name.lower() in HOP_BY_HOP_HEADER_NAMES
                or name.lower() in connection_tokens
            ):
                del request.headers[name]

    def request(self, flow: http.HTTPFlow) -> None:
        with self.lock:
            self.request_count += 1
            over_limit = self.request_count > self.max_requests
        if over_limit:
            self.reject(flow, 429, "request_limit_exceeded")
            return
        try:
            self.validate_request(flow)
        except DestinationBlocked as error:
            self.reject(flow, 403, str(error))

    def http_connect(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host
        port = flow.request.port
        try:
            normalized_host(host)
            if port != 443:
                raise DestinationBlocked("connect_port_not_allowed")
            resolve_public_host(host, port)
        except DestinationBlocked as error:
            self.reject(flow, 403, str(error))

    def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        if data.server.address is None:
            data.server.error = "skillsissue_egress_blocked:missing_server_address"
            return
        host, port = data.server.address
        try:
            selected_ip = resolve_public_host(host, port)
            data.server.address = (selected_ip, port)
        except DestinationBlocked as error:
            data.server.error = f"skillsissue_egress_blocked:{error}"

    def base_record(self, flow: http.HTTPFlow) -> dict[str, Any]:
        request = flow.request
        with self.lock:
            self.sequence += 1
            sequence = self.sequence
        return {
            "schema_version": 1,
            "capture": "intercepted-http-egress",
            "sequence": sequence,
            "recorded_at_unix_ms": str(time.time_ns() // 1_000_000),
            "transport": "tls" if request.scheme == "https" else "cleartext",
            "tls_intercepted": request.scheme == "https",
            "method": request.method.upper(),
            "remote_origin": f"{request.scheme}://{request.host}:{request.port}",
            "url": request.pretty_url,
            "host": request.host,
            "port": request.port,
            "resolved_ip": (
                flow.server_conn.peername[0]
                if flow.server_conn.peername
                else flow.metadata.get("skillsissue_resolved_ip")
            ),
            "failure": flow.metadata.get("skillsissue_blocked_reason"),
            "request": {
                "headers": sanitized_headers(self.header_pairs(request)),
                "body_base64": "",
                "original_bytes": len(request.raw_content or b""),
                "capture_truncated": False,
            },
        }

    def append_record(self, record: dict[str, Any]) -> bool:
        encoded = json.dumps(
            record, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode() + b"\n"
        try:
            with self.lock:
                descriptor = os.open(
                    self.evidence_path,
                    os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    offset = 0
                    while offset < len(encoded):
                        written = os.write(descriptor, encoded[offset:])
                        if written <= 0:
                            raise OSError("short evidence write")
                        offset += written
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            return True
        except OSError:
            return False

    def response(self, flow: http.HTTPFlow) -> None:
        assert flow.response is not None
        record = self.base_record(flow)
        body = flow.response.raw_content or b""
        response_headers = self.header_pairs(flow.response)
        response_headers_too_large = (
            sum(
                len(name.encode()) + len(value.encode()) + 4
                for name, value in response_headers
            )
            > self.max_header_bytes
        )
        blocked = "skillsissue_blocked_reason" in flow.metadata
        body_unavailable = flow.response.raw_content is None and (
            flow.response.headers.get("content-length") not in {None, "0"}
            or bool(flow.response.headers.get("transfer-encoding"))
        )
        protocol_rejected = (
            flow.response.status_code == 101
            or bool(flow.response.headers.get("upgrade"))
        )
        capture_truncated = False
        if not blocked:
            if response_headers_too_large:
                capture_truncated = True
                record["failure"] = "response_headers_too_large"
                body = b""
                response_headers = []
            elif body_unavailable:
                capture_truncated = True
                record["failure"] = "response_body_unavailable"
                body = b""
            else:
                with self.lock:
                    next_total = self.total_response_bytes + len(body)
                    allowed = (
                        len(body) <= self.max_response_bytes
                        and next_total <= self.max_total_response_bytes
                    )
                    if allowed:
                        self.total_response_bytes = next_total
                if not allowed:
                    capture_truncated = True
                    record["failure"] = "response_evidence_limit_exceeded"
                    body = b""
                elif protocol_rejected:
                    record["failure"] = "protocol_upgrade_not_allowed"
        record["response"] = {
            "status": flow.response.status_code,
            "headers": sanitized_headers(response_headers),
            "body_base64": base64.b64encode(body).decode("ascii"),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "original_bytes": len(flow.response.raw_content or b""),
            "capture_truncated": capture_truncated,
        }
        if not self.append_record(record):
            os._exit(70)
        if capture_truncated:
            self.reject(flow, 502, "evidence_capture_failed")
        elif protocol_rejected:
            self.reject(flow, 502, "protocol_upgrade_not_allowed")

    def error(self, flow: http.HTTPFlow) -> None:
        record = self.base_record(flow)
        record["failure"] = (
            flow.metadata.get("skillsissue_blocked_reason")
            or (flow.error.msg if flow.error else "upstream_error")
        )
        record["response"] = {
            "status": None,
            "headers": [],
            "body_base64": "",
            "body_sha256": hashlib.sha256(b"").hexdigest(),
            "original_bytes": 0,
            "capture_truncated": False,
        }
        if not self.append_record(record):
            os._exit(70)


addons = [BoundedDownloadCapture()]
