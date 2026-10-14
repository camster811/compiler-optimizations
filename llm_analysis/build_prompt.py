"""Allowlisted public-record projection and stateless request construction."""
import re
from jsonschema import Draft202012Validator
from .common import HERE, decode, encode, load, seed_for

FIELDS = ("schema_version", "status", "function", "decompilation", "instructions",
          "calls", "tail_jumps", "constants", "stack_variables", "imports")
LEAK = re.compile(r"sample_\d+|cwe|juliet|(?:^|[^a-z0-9])(?:good|bad|fixed|vulnerable|retained|stripped)(?:$|[^a-z0-9])|ground[ _-]?truth|\bO[0-3s]\b|(?:/home/|[A-Za-z]:\\)|case_[sh]\d+", re.I)


def project(raw):
    record = decode(raw)
    Draft202012Validator(load(HERE.parent / "ghidra" / "record_schema.json")).validate(record)
    public = {key: record[key] for key in FIELDS}
    if LEAK.search(encode(public).decode()):
        raise ValueError("prohibited identifier or private metadata in public record")
    # Extraction diagnostics may contain paths even when record structure is valid.
    if public["decompilation"]["status"] != "ok":
        public["decompilation"] = {"status": public["decompilation"]["status"],
                                   "text": None, "error": "decompilation unavailable"}
    return public


def build_prompt(raw):
    template = (HERE / "prompt.md").read_text()
    if template.count("{{record}}") != 1:
        raise ValueError("prompt template must contain exactly one record placeholder")
    return template.replace("{{record}}", encode(project(raw)).decode().rstrip())


def request(c, raw, record_hash, repetition):
    return {"model": c["model_alias"],
            "messages": [{"role": "user", "content": build_prompt(raw)}],
            "temperature": c["temperature"], "top_p": c["top_p"],
            "top_k": c["top_k"], "min_p": c["min_p"], "samplers": c["samplers"],
            "max_tokens": c["max_tokens"], "seed": seed_for(c, record_hash, repetition),
            "stream": False, "n": 1, "cache_prompt": False, "stop": c["stop"],
            "reasoning_format": "deepseek", "reasoning_budget_tokens": -1}
