"""Validate only final answer content; never repair model output."""
from jsonschema import Draft202012Validator
from .common import HERE, decode, load


def parse_response(raw, record):
    def failure(status, detail):
        return {"status": status, "prediction": None, "detail": detail}
    try:
        response = decode(raw)
        choices = response["choices"]
        if len(choices) != 1:
            raise ValueError("expected exactly one choice")
        choice = choices[0]
        if choice["finish_reason"] == "length":
            return failure("length_limit", "generation ended at the token limit")
        if choice["finish_reason"] != "stop":
            return failure("response_invalid", "unexpected finish reason")
        message = choice["message"]
        if message.get("refusal") or message.get("tool_calls"):
            return failure("response_invalid", "refusal or tool call")
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            return failure("empty_response", "no final answer")
        try:
            prediction = decode(content)
        except (ValueError, TypeError) as e:
            return failure("invalid_json", str(e))
        errors = list(Draft202012Validator(load(HERE / "output_schema.json")).iter_errors(prediction))
        if errors:
            return failure("schema_invalid", errors[0].message[:500])
        for value in [prediction["summary"], *[e["observation"] for e in prediction["evidence"]]]:
            if not value.strip():
                return failure("schema_invalid", "blank observation or summary")
        reason = prediction["uncertainty_reason"]
        if reason is not None and not reason.strip():
            return failure("schema_invalid", "blank uncertainty reason")
        addresses = {line.split(":", 1)[0] for line in record["instructions"]}
        cited = {a for e in prediction["evidence"] for a in e["addresses"]}
        if not cited <= addresses:
            return failure("evidence_invalid", "address not present in instruction listing")
        return {"status": "valid", "prediction": prediction, "detail": None}
    except (ValueError, TypeError, KeyError, IndexError) as e:
        return failure("response_invalid", str(e))
