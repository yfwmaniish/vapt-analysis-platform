"""Shared networking utilities for scanner modules."""

from __future__ import annotations

import asyncio
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse

import aiohttp


def normalize_target(target: str) -> str:
    """Ensure a target has a scheme. Defaults to https://."""
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def extract_domain(target: str) -> str:
    """Extract the domain name from a target string."""
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.hostname or target
    # Could be domain or IP directly
    return target.split(":")[0].split("/")[0]


def extract_port(target: str, default: int = 443) -> int:
    """Extract port from target, defaulting to 443."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.port or default
    if ":" in target:
        parts = target.rsplit(":", 1)
        try:
            return int(parts[1])
        except ValueError:
            pass
    return default


async def resolve_host(domain: str) -> Optional[str]:
    """Resolve a domain to an IP address."""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
        if result:
            return result[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return None


async def fetch_url(
    url: str,
    timeout: int = 10,
    method: str = "GET",
    headers: Optional[dict] = None,
    follow_redirects: bool = True,
) -> Tuple[int, str, dict]:
    """
    Fetch a URL and return (status_code, body, response_headers).

    Returns (-1, error_message, {}) on failure.
    """
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }
    if headers:
        default_headers.update(headers)

    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.request(
                method,
                url,
                headers=default_headers,
                allow_redirects=follow_redirects,
                ssl=False,  # Don't verify SSL for scanning purposes
            ) as response:
                body = await response.text()
                resp_headers = dict(response.headers)
                return response.status, body, resp_headers
    except asyncio.TimeoutError:
        return -1, "Connection timed out", {}
    except aiohttp.ClientError as exc:
        return -1, str(exc), {}
    except Exception as exc:
        return -1, str(exc), {}
