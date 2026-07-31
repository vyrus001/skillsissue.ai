"""Pure policy helpers for the detonation HTTP(S) interception proxy."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable


BLOCKED_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "proxy-authenticate",
        "set-cookie",
    }
)
HOP_BY_HOP_HEADER_NAMES = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
LOCAL_NAME_SUFFIXES = (
    ".home",
    ".home.arpa",
    ".internal",
    ".lan",
    ".local",
    ".localdomain",
    ".localhost",
)


class DestinationBlocked(ValueError):
    """The destination is not a public HTTP(S) endpoint."""


def normalized_host(host: str) -> str:
    candidate = host.strip().strip("[]").rstrip(".").lower()
    if not candidate or len(candidate) > 253 or any(ord(char) < 33 for char in candidate):
        raise DestinationBlocked("invalid_host")
    if candidate == "localhost" or candidate.endswith(LOCAL_NAME_SUFFIXES):
        raise DestinationBlocked("local_hostname")
    return candidate


def public_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError as error:
        raise DestinationBlocked("invalid_ip") from error
    if (
        not address.is_global
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_private
        or address.is_reserved
        or address.is_unspecified
    ):
        raise DestinationBlocked("non_public_ip")
    return address


def resolve_public_host(
    host: str,
    port: int,
    resolver=socket.getaddrinfo,
) -> str:
    candidate = normalized_host(host)
    try:
        return str(public_ip(candidate))
    except DestinationBlocked as literal_error:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            if "." not in candidate:
                raise DestinationBlocked("single_label_hostname") from literal_error
        else:
            raise

    try:
        answers = resolver(candidate, port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise DestinationBlocked("dns_resolution_failed") from error
    addresses: list[str] = []
    for answer in answers:
        address = answer[4][0]
        public_ip(address)
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise DestinationBlocked("dns_no_addresses")
    return addresses[0]


def sanitized_headers(
    headers: Iterable[tuple[str, str]],
) -> list[list[str]]:
    output: list[list[str]] = []
    connection_tokens: set[str] = set()
    materialized = [(name.lower(), value) for name, value in headers]
    for name, value in materialized:
        if name == "connection":
            connection_tokens.update(
                token.strip().lower() for token in value.split(",") if token.strip()
            )
    for name, value in materialized:
        if (
            name in BLOCKED_HEADER_NAMES
            or name in HOP_BY_HOP_HEADER_NAMES
            or name in connection_tokens
        ):
            continue
        output.append([name, value])
    return output


def allowed_port(scheme: str, port: int) -> bool:
    return (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
