"""Secret redaction for log output and error messages.

Ported by hand from upstream alpadalar/ActiveDirectoryMCP (4fa2bef, b99cd1b).
Standard library only; imports nothing from this package, so it can be
installed before anything else logs.

Secrets registered here -- and their URL-quoted, base64, JSON/repr-escaped and
``unicodePwd`` wire encodings -- are replaced by ``***REDACTED***``:

* in every ``LogRecord`` at creation (:func:`install_record_factory`), whatever
  logger emits it: ours, ldap3, uvicorn, the root logger, records emitted
  before logging is configured and handlers added later;
* in error text sent back to clients, through :func:`redact`.

It is never applied to successful tool payloads: the operator must still
receive the password a reset set or generated.

Differences from upstream: a value shorter than :data:`MIN_SECRET_LENGTH` is
not registered (replacing "x" would destroy every log line, and no AD password
policy allows that length), and a non-string value (an all-digit password typed
without quotes reaches the config as an int) is registered as its text.
"""

import base64
import json
import logging
import threading
import urllib.parse
from collections import OrderedDict
from typing import Any, Dict, Set

REDACTED = "***REDACTED***"
SUPPRESSED = "<log record suppressed: redaction failed>"

MIN_SECRET_LENGTH = 6

# Runtime secrets (passwords handed to create/reset) live in a bounded LRU so a
# long-lived server cannot grow the registry without limit. Persistent secrets
# (bind passwords, the API token) are never evicted.
MAX_RUNTIME_SECRETS = 64

_lock = threading.Lock()
_persistent: Dict[str, Set[str]] = {}
_runtime: "OrderedDict[str, Set[str]]" = OrderedDict()


def _variants(secret: str) -> Set[str]:
    out = {
        secret,
        urllib.parse.quote(secret),
        urllib.parse.quote(secret, safe=""),
        urllib.parse.quote_plus(secret),
    }
    raw = secret.encode("utf-8")
    out.add(base64.b64encode(raw).decode("ascii"))
    out.add(base64.urlsafe_b64encode(raw).decode("ascii"))
    # JSON / repr escaped forms, plus a second level for escaped text embedded
    # in another JSON string or repr.
    for dumped in (json.dumps(secret), json.dumps(secret, ensure_ascii=False)):
        inner = dumped[1:-1]
        out.add(inner)
        out.add(json.dumps(inner)[1:-1])
    out.add(repr(secret)[1:-1])
    out.add(repr(repr(secret))[1:-1])
    # AD unicodePwd wire form: UTF-16-LE of the double-quoted password, as
    # bytes repr and as base64.
    quoted = ('"' + secret + '"').encode("utf-16-le")
    out.add(base64.b64encode(quoted).decode("ascii"))
    out.add(repr(quoted)[2:-1])
    return {v for v in out if len(v) >= MIN_SECRET_LENGTH}


def register_secret(secret: Any, *, persistent: bool = True) -> None:
    """Register a secret for redaction; empty or too-short values are ignored.

    ``persistent=False`` registers a short-lived runtime secret in a bounded LRU.
    """
    if secret is None or isinstance(secret, bool):
        return
    getter = getattr(secret, "get_secret_value", None)
    if callable(getter):
        secret = getter()
    if isinstance(secret, (int, float)):
        secret = str(secret)
    if not isinstance(secret, str) or len(secret) < MIN_SECRET_LENGTH:
        return
    variants = _variants(secret)
    with _lock:
        if persistent:
            _persistent[secret] = variants
            _runtime.pop(secret, None)
        elif secret not in _persistent:
            _runtime[secret] = variants
            _runtime.move_to_end(secret)
            while len(_runtime) > MAX_RUNTIME_SECRETS:
                _runtime.popitem(last=False)


def clear_secrets() -> None:
    """Forget all registered secrets (used by tests)."""
    with _lock:
        _persistent.clear()
        _runtime.clear()


def redact(text: Any) -> Any:
    """Replace every registered secret in ``text``, longest first.

    Non-string input is returned unchanged, so callers can pass whatever an
    exception carried.
    """
    if not isinstance(text, str) or not text:
        return text
    with _lock:
        pool: Set[str] = set()
        for variants in _persistent.values():
            pool |= variants
        for variants in _runtime.values():
            pool |= variants
    for secret in sorted(pool, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, REDACTED)
    return text


def sanitize_record(record: logging.LogRecord) -> None:
    """Redact a record in place: formatted message, exception and stack text.

    The message is formatted first (so a secret split across ``msg`` and
    ``args`` is still caught), then ``args`` is cleared. Raises on failure;
    callers fail closed.
    """
    record.msg = redact(record.getMessage())
    record.args = ()
    if record.exc_info and not record.exc_text:
        record.exc_text = logging.Formatter().formatException(record.exc_info)
    if record.exc_text:
        record.exc_text = redact(record.exc_text)
    if record.stack_info:
        record.stack_info = redact(record.stack_info)


def _suppress(record: logging.LogRecord) -> None:
    record.msg = SUPPRESSED
    record.args = ()
    record.exc_info = None
    record.exc_text = None
    record.stack_info = None


class RedactingFilter(logging.Filter):
    """Scrub registered secrets from a record; fails closed."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            sanitize_record(record)
        except Exception:  # noqa: BLE001 - never let a raw record through
            _suppress(record)
        return True


_FACTORY_MARK = "_ad_mcp_redacting_factory"


def install_record_factory() -> None:
    """Redact every LogRecord at creation, whatever logger or handler emits it.

    Idempotent: installing twice does not wrap the factory twice.
    """
    current = logging.getLogRecordFactory()
    if getattr(current, _FACTORY_MARK, False):
        return

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = current(*args, **kwargs)
        try:
            sanitize_record(record)
        except Exception:  # noqa: BLE001 - fail closed
            _suppress(record)
        return record

    setattr(factory, _FACTORY_MARK, True)
    logging.setLogRecordFactory(factory)
