"""Serialization, content identifiers, and durable artifacts."""
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                       indent=2) + "\n").encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def reject_constant(value):
    raise ValueError(f"nonfinite JSON number: {value}")


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)


def load(path):
    return decode(Path(path).read_bytes())


def save(path, value, *, immutable=False):
    write(path, encode(value), immutable=immutable)


def write(path, raw, *, immutable=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        if immutable:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def now():
    return datetime.now(timezone.utc).isoformat()


def config(path=None):
    c = load(path or HERE / "config.json")
    if c["repetitions"] != 3 or c["max_attempts"] != 2:
        raise ValueError("this method requires three repetitions and at most two attempts")
    if c["version"] != "1.1.0" or c["structured_output"] != "json_schema" or c["seed_policy"] != "shared_repetition":
        raise ValueError("v1.1 requires schema constraints and shared repetition seeds")
    if not 0.98 <= c["minimum_schema_valid_rate"] <= 1:
        raise ValueError("final-method schema-adherence threshold must be at least 98%")
    return c


def seed_for(c, repetition):
    raw = f"generation:{c['master_seed']}:{repetition}".encode()
    return int(digest(raw)[:8], 16) & 0x7fffffff


def method_files():
    names = [p for pattern in ("*.py", "*.json", "*.md", "*.jinja", "requirements.txt")
             for p in HERE.glob(pattern) if p.name != "README.md"]
    names.append(HERE.parent / "ghidra" / "record_schema.json")
    return {str(p.relative_to(HERE.parent)): file_hash(p) for p in sorted(names)}
