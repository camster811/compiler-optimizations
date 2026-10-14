import http.server
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from llm_analysis.aggregate import aggregate
from llm_analysis.build_prompt import build_prompt, generation_schema, project, request
from llm_analysis.common import HERE, config, digest, encode, load, save, seed_for, write
from jsonschema import Draft202012Validator
from llm_analysis.parse_response import parse_response
from llm_analysis.run_llm import execute_run, export, preflight, prepare, replay, verify
from llm_analysis.transport import exchange


def record():
    return {"schema_version": "1.0", "sample_id": "sample_9876", "status": "ok",
            "function": {"name": "copy_message", "entry": "0x10", "size_bytes": 1,
                         "instruction_count": 1, "basic_block_count": 1, "body_ranges": [["0x10", "0x11"]]},
            "decompilation": {"status": "ok", "text": "void copy_message(void) {}", "error": None},
            "instructions": ["0x10: RET"], "calls": [], "tail_jumps": [], "constants": [],
            "stack_variables": [], "imports": []}


def prediction(cls="uncertain", cwe=None):
    return {"classification": cls, "predicted_cwe": cwe, "confidence": 0.6,
            "evidence": [{"addresses": ["0x10"], "observation": "No object capacity is visible."}],
            "summary": "Insufficient evidence.", "uncertainty_reason": "Capacity unavailable" if cls == "uncertain" else None}


def response(p=None, finish="stop", content=None):
    return encode({"choices": [{"finish_reason": finish, "message": {
        "content": content if content is not None else json.dumps(p or prediction()),
        "reasoning_content": "Private reasoning containing {invalid JSON}."}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20}})


class ParserTests(unittest.TestCase):
    def test_classes(self):
        for cls, cwe in [("vulnerable", "CWE-121"), ("vulnerable", "CWE-122"), ("not_vulnerable", None), ("uncertain", None)]:
            self.assertEqual(parse_response(response(prediction(cls, cwe)), record())["status"], "valid")

    def test_json_failures(self):
        for text in ["", "I cannot answer.", "{broken}", "```json\n{}\n```", "prefix {}", "{} {}",
                     '{"classification":"uncertain","classification":"uncertain"}', '{"confidence":NaN}']:
            with self.subTest(text=text):
                self.assertNotEqual(parse_response(response(content=text), record())["status"], "valid")

    def test_schema_failures(self):
        cases = []
        p = prediction(); del p["summary"]; cases.append(p)
        p = prediction(); p["additional"] = 1; cases.append(p)
        for key, value in [("classification", "safe"), ("predicted_cwe", "CWE-999"), ("confidence", -0.1),
                           ("confidence", 1.1), ("confidence", True), ("uncertainty_reason", None),
                           ("summary", "   ")]:
            p = prediction(); p[key] = value; cases.append(p)
        cases.append(prediction("vulnerable", None))
        cases.append(prediction("not_vulnerable", "CWE-121"))
        for p in cases:
            self.assertEqual(parse_response(response(p), record())["status"], "schema_invalid")

    def test_address_and_length(self):
        p = prediction(); p["evidence"][0]["addresses"] = ["0x11"]
        self.assertEqual(parse_response(response(p), record())["status"], "evidence_invalid")
        self.assertEqual(parse_response(response(finish="length"), record())["status"], "length_limit")

    def test_malformed_envelope(self):
        for raw in [b"{}", b"[]", b"null", b"{", encode({"choices": []})]:
            self.assertEqual(parse_response(raw, record())["status"], "response_invalid")


class VoteTests(unittest.TestCase):
    def votes(self, values):
        runs = [{"repetition": i, "run_id": str(i), "status": "valid" if p else "timeout", "prediction": p}
                for i, p in enumerate(values, 1)]
        return aggregate("hash", runs)

    def test_vote_cases(self):
        v, n, u = prediction("vulnerable", "CWE-121"), prediction("not_vulnerable"), prediction()
        self.assertTrue(self.votes([v, v, v])["unanimous"])
        self.assertEqual(self.votes([v, v, None])["classification"], "vulnerable")
        self.assertEqual(self.votes([v, n, u])["aggregation_reason"], "insufficient_matching_votes")
        self.assertEqual(self.votes([u, u, n])["aggregation_reason"], "model_abstention")
        self.assertEqual(self.votes([v, prediction("vulnerable", "CWE-122"), n])["aggregation_reason"], "cwe_disagreement")
        self.assertIsNone(self.votes([None, None, None])["median_confidence"])
        self.assertEqual(self.votes([v, None, None])["classification"], "uncertain")

    def test_missing_duplicate_repetitions(self):
        for runs in [[], [{"repetition": 1}] * 3]:
            with self.assertRaises(ValueError):
                aggregate("hash", runs)


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.c = config()
        save(self.root / "runtime.json", {"artifacts": {}})
        write(self.root / "input.json", encode(record()))
        self.directory = prepare([self.root / "input.json"], self.root / "runtime.json", self.root / "campaigns", self.c)
        self.m = verify(self.directory)
        self.h = self.m["record_hashes"][0]
        self.flight = {"records": {self.h: {"prompt_tokens": 100, "fits_context": True}}}
        save(self.directory / "preflight.json", self.flight)
        self.calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def exchange(self, c, route, payload):
        self.calls.append(payload)
        return {"http_status": 200, "headers": [], "body": response(), "error": None, "latency_seconds": 1.0}

    def execute(self, job=None, transport=None):
        return execute_run(self.directory, job or self.m["schedule"][0], self.m, self.flight,
                           exchange_fn=transport or self.exchange, idle_fn=lambda c: None, sleep_fn=lambda s: None)

    def test_blinding_and_determinism(self):
        raw = encode(record())
        self.assertNotIn("sample_9876", build_prompt(raw))
        self.assertIn("copy_message", build_prompt(raw))
        self.assertEqual(build_prompt(raw), build_prompt(raw))
        payload = request(self.c, raw, self.h, 1)
        self.assertEqual(len(payload["messages"]), 1)
        self.assertFalse(payload["cache_prompt"])
        changed = record(); changed["function"]["name"] = "CWE121_bad"
        with self.assertRaises(ValueError):
            project(encode(changed))

    def test_shared_seeds_and_generation_schema(self):
        raw = encode(record())
        for repetition in (1, 2, 3):
            a = request(self.c, raw, "a" * 64, repetition)
            b = request(self.c, raw, "b" * 64, repetition)
            self.assertEqual(a["seed"], b["seed"])
            self.assertEqual(a["seed"], seed_for(self.c, repetition))
            schema = a["response_format"]["json_schema"]["schema"]
            validator = Draft202012Validator(schema)
            for cls, cwe in [("uncertain", None), ("not_vulnerable", None), ("vulnerable", "CWE-121"), ("vulnerable", "CWE-122")]:
                validator.validate(prediction(cls, cwe))
            p = prediction(); p["predicted_cwe"] = "CWE-121"
            self.assertFalse(validator.is_valid(p))
            p = prediction(); p["evidence"][0]["addresses"] = ["0x99"]
            self.assertFalse(validator.is_valid(p))
        self.assertEqual(len({seed_for(self.c, r) for r in (1, 2, 3)}), 3)

    def test_campaign_metadata_changes_identity_without_changing_method(self):
        binding = "a" * 64
        other = prepare([self.root / "input.json"], self.root / "runtime.json", self.root / "campaigns", self.c, experiment_sha256=binding)
        self.assertNotEqual(other, self.directory)
        self.assertEqual(verify(other)["method_id"], self.m["method_id"])
        m = load(other / "manifest.json"); m["development_data"] = False; save(other / "manifest.json", m)
        with self.assertRaises(ValueError):
            verify(other)

    def test_complete_resume_and_replay(self):
        for job in self.m["schedule"]:
            self.execute(job)
        export(self.directory)
        for job in self.m["schedule"]:
            self.assertFalse(self.execute(job)[1])
        self.assertEqual(len(self.calls), 3)
        runs, predictions = replay(self.directory)
        self.assertEqual(len(runs), 3)
        self.assertTrue(predictions[0]["unanimous"])

    def test_failure_retry(self):
        for failure in ["timeout", "transport_error", None]:
            calls = []
            job = self.m["schedule"][len(self.calls)] if self.calls else self.m["schedule"][0]
            def transport(c, route, payload):
                calls.append(payload)
                if len(calls) == 1:
                    return {"http_status": 503 if failure is None else None, "headers": [], "body": b"failure",
                            "error": {"status": failure, "detail": "test"} if failure else None, "latency_seconds": 0.1}
                return self.exchange(c, route, payload)
            result, _ = self.execute(job, transport)
            self.assertEqual(result["attempts"], 2)
            self.assertEqual(calls[0], calls[1])

    def test_no_output_retry(self):
        def transport(c, route, payload):
            self.calls.append(payload)
            return {"http_status": 200, "headers": [], "body": response(content="```json\n{}\n```"),
                    "error": None, "latency_seconds": 1.0}
        result, _ = self.execute(transport=transport)
        self.assertEqual(result["status"], "invalid_json")
        self.assertEqual(len(self.calls), 1)

    def test_interruption_and_corruption(self):
        job = self.m["schedule"][0]
        attempt = self.directory / "runs" / job["run_id"] / "attempt-1"
        save(attempt / "started.json", {"started_at": "test"})
        write(attempt / "response.body", b"partial", immutable=True)
        result, _ = self.execute(job)
        self.assertEqual(result["attempts"], 2)
        self.assertEqual((attempt / "response.body").read_bytes(), b"partial")
        self.assertEqual(load(attempt / "response.json")["error"]["status"], "interrupted")
        write(self.directory / "records" / f"{self.h}.json", b"{}")
        with self.assertRaises(ValueError):
            verify(self.directory)

    def test_context_overflow_does_not_generate(self):
        self.flight["records"][self.h]["fits_context"] = False
        result, _ = self.execute()
        self.assertEqual(result["status"], "context_overflow")
        self.assertEqual(self.calls, [])

    def test_retry_exhaustion_and_permanent_http_error(self):
        for index, status in enumerate([503, 401]):
            calls = []
            def transport(c, route, payload):
                calls.append(payload)
                return {"http_status": status, "headers": [], "body": b"error", "error": None, "latency_seconds": 0.1}
            result, _ = self.execute(self.m["schedule"][index], transport)
            self.assertEqual(result["status"], "http_error")
            self.assertEqual(result["attempts"], 2 if status == 503 else 1)
            self.assertEqual(len(calls), result["attempts"])

    def test_missing_extra_and_method_drift(self):
        with self.assertRaises(ValueError):
            replay(self.directory)
        for job in self.m["schedule"]:
            self.execute(job)
        (self.directory / "runs" / "unexpected").mkdir()
        with self.assertRaises(ValueError):
            replay(self.directory)
        manifest = load(self.directory / "manifest.json")
        manifest["method"]["config"]["temperature"] = 0.1
        save(self.directory / "manifest.json", manifest)
        with self.assertRaises(ValueError):
            verify(self.directory)

    def test_preflight_trailing_newline_and_template_drift(self):
        (self.directory / "preflight.json").unlink()
        props = {"total_slots": 1, "default_generation_settings": {"n_ctx": self.c["context_tokens"]},
                 "model_path": self.c["model_path"], "chat_template": (HERE / "chat_template.jinja").read_text().rstrip("\n")}
        def call(c, route, payload=None):
            return {"/health": {"status": "ok"}, "/props": props,
                    "/apply-template": {"prompt": "prefix<｜Assistant｜><think>\n"},
                    "/tokenize": {"tokens": [1] * 100}}[route]
        with patch("llm_analysis.run_llm.json_call", side_effect=call):
            result = preflight(self.directory)
            self.assertEqual(result["records"][self.h]["prompt_tokens"], 100)
            props["chat_template"] = "wrong template"
            with self.assertRaises(RuntimeError):
                preflight(self.directory)

    def test_missing_extra_runs_and_tampering(self):
        for job in self.m["schedule"]:
            self.execute(job)
        export(self.directory)
        payload_path = self.directory / "runs" / self.m["schedule"][0]["run_id"] / "request.json"
        payload = load(payload_path); payload["messages"].append({"role": "user", "content": "extra history"})
        save(payload_path, payload)
        with self.assertRaises(ValueError):
            replay(self.directory)


class TransportTests(unittest.TestCase):
    def test_http_body_and_deadline(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/slow":
                    time.sleep(0.15)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                try:
                    self.wfile.write(b"{}")
                except BrokenPipeError:
                    pass
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            c = dict(config(), endpoint=f"http://127.0.0.1:{server.server_port}", request_deadline_s=0.05)
            self.assertEqual(exchange(c, "/fast")["body"], b"{}")
            self.assertEqual(exchange(c, "/slow")["error"]["status"], "timeout")
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == "__main__":
    unittest.main()
