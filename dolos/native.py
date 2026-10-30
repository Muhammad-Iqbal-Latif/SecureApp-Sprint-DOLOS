"""Validate event types using the bounds-checked native C parser."""
import ctypes
from functools import lru_cache
from pathlib import Path
import re

LIBRARY = Path(__file__).resolve().parent.parent / "native" / "libdolos_native.so"


@lru_cache(maxsize=1)
def _validator():
    try:
        lib = ctypes.CDLL(str(LIBRARY))
    except OSError as exc:
        raise RuntimeError("Native parser missing: run `make native-library` first") from exc
    fn = lib.parse_event_tag
    fn.argtypes = [ctypes.c_char_p]
    fn.restype = ctypes.c_int
    return fn


def validate_event_tag(tag: str) -> None:
    """Reject invalid tags before they are inserted into the event database."""
    if not isinstance(tag, str) or "\x00" in tag:
        raise ValueError("Invalid event type")
    try:
        raw = tag.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Event type must be ASCII") from exc
    if _validator()(raw) < 0 or not re.fullmatch(r"[a-z][a-z0-9-]*", tag):
        raise ValueError("Invalid event type (ASCII, 1-15 bytes, lowercase/hyphen)")
