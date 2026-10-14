"""Prepare, preflight, execute, and replay blinded inference campaigns."""
import argparse
import fcntl
import random
import time
from pathlib import Path
from .aggregate import aggregate
from .build_prompt import project, request
from .common import HERE, config, decode, digest, encode, file_hash, load, method_files, now, save, write
from .parse_response import parse_response
from .transport import exchange, json_call, wait_idle


def run_id(h, repetition):
    return f"{h}-r{repetition}"


def prepare(inputs, runtime_path, output, c, *, development_data=True, experiment_sha256=None):
    records = {}
    for p in inputs:
        for path in sorted(p.glob("*.json")) if p.is_dir() else [p]:
            raw = path.read_bytes()
            project(raw)
            records[digest(raw)] = raw
    if not records:
        raise ValueError("no records")
    if type(development_data) is not bool:
        raise ValueError("development_data must be a boolean")
    if experiment_sha256 is not None and (len(experiment_sha256) != 64 or any(x not in '0123456789abcdef' for x in experiment_sha256)):
        raise ValueError("invalid experiment digest")
    if not development_data and experiment_sha256 is None:
        raise ValueError("final campaigns require a frozen experiment binding")
    method = {"version": c["version"], "config": c, "files": method_files(), "runtime": load(runtime_path)}
    method_id = digest(encode(method))
    if not development_data:
        pointer = load(HERE / "frozen" / "current.json")
        receipt_path = HERE.parent / pointer["receipt_path"]
        receipt = load(receipt_path)
        if file_hash(receipt_path) != pointer["receipt_sha256"] or pointer["method_id"] != method_id or receipt["method"] != method:
            raise ValueError("final campaigns require the selected frozen method without changes")
    input_id = digest(encode(sorted(records)))
    metadata = {"development_data": development_data, "experiment_sha256": experiment_sha256}
    campaign_id = digest(encode({"method_id": method_id, "input_set_sha256": input_id, "metadata": metadata}))
    directory = output / campaign_id
    schedule = [{"record_sha256": h, "repetition": r, "run_id": run_id(h, r)}
                for h in sorted(records) for r in range(1, c["repetitions"] + 1)]
    random.Random(c["master_seed"]).shuffle(schedule)
    manifest = {"campaign_id": campaign_id, "method_id": method_id, "input_set_sha256": input_id,
                "method": method, "record_hashes": sorted(records), "schedule": schedule,
                "development_data": development_data, "metadata": metadata}
    if directory.exists():
        if load(directory / "manifest.json") != manifest:
            raise ValueError("campaign manifest mismatch")
    else:
        directory.mkdir(parents=True)
        for h, raw in records.items():
            write(directory / "records" / f"{h}.json", raw, immutable=True)
        save(directory / "manifest.json", manifest, immutable=True)
    verify(directory)
    return directory


def verify(directory, check_runtime=False):
    m = load(directory / "manifest.json")
    if digest(encode(m["method"])) != m["method_id"]:
        raise ValueError("method fingerprint mismatch")
    if method_files() != m["method"]["files"]:
        raise ValueError("method files changed; prepare a new campaign")
    hashes = m["record_hashes"]
    if len(hashes) != len(set(hashes)) or sorted(hashes) != hashes:
        raise ValueError("duplicate or unordered record hashes")
    if digest(encode(hashes)) != m["input_set_sha256"]:
        raise ValueError("input fingerprint mismatch")
    identity = {"method_id": m["method_id"], "input_set_sha256": m["input_set_sha256"], "metadata": m["metadata"]}
    if m["development_data"] != m["metadata"]["development_data"] or type(m["development_data"]) is not bool:
        raise ValueError("campaign data-split mismatch")
    if not m["development_data"] and m["metadata"]["experiment_sha256"] is None:
        raise ValueError("final campaign is not bound to an experiment")
    expected_id = digest(encode(identity))
    if m["campaign_id"] != expected_id or directory.name != expected_id:
        raise ValueError("campaign identity mismatch")
    actual = {p.stem for p in (directory / "records").glob("*.json")}
    if actual != set(hashes):
        raise ValueError("record set mismatch")
    c = m["method"]["config"]
    expected = [{"record_sha256": h, "repetition": r, "run_id": run_id(h, r)}
                for h in hashes for r in range(1, c["repetitions"] + 1)]
    random.Random(c["master_seed"]).shuffle(expected)
    if m["schedule"] != expected:
        raise ValueError("execution schedule mismatch")
    for h in hashes:
        raw = (directory / "records" / f"{h}.json").read_bytes()
        if digest(raw) != h:
            raise ValueError("record content drift")
        project(raw)
    if check_runtime:
        for path, h in m["method"]["runtime"]["artifacts"].items():
            if file_hash(path) != h:
                raise ValueError(f"runtime artifact drift: {path}")
    return m


def preflight(directory):
    m = verify(directory, check_runtime=True)
    c = m["method"]["config"]
    json_call(c, "/health")
    props = json_call(c, "/props")
    if props["total_slots"] != 1 or props["default_generation_settings"]["n_ctx"] != c["context_tokens"]:
        raise RuntimeError("server slot count or context differs from frozen configuration")
    if props["model_path"] != c["model_path"]:
        raise RuntimeError("server model path differs")
    if props["chat_template"].rstrip("\n") != (HERE / "chat_template.jinja").read_text().rstrip("\n"):
        raise RuntimeError("running server template differs from frozen template")
    if (directory / "preflight.json").exists():
        return load(directory / "preflight.json")
    counts = {}
    for h in m["record_hashes"]:
        raw = (directory / "records" / f"{h}.json").read_bytes()
        payload = request(c, raw, h, 1)
        rendered = json_call(c, "/apply-template", {"messages": payload["messages"], "add_generation_prompt": True})["prompt"]
        if not rendered.endswith("<｜Assistant｜><think>\n"):
            raise RuntimeError("chat template does not open R1 reasoning")
        tokenized = json_call(c, "/tokenize", {"content": rendered, "add_special": False, "parse_special": True})
        counts[h] = {"prompt_tokens": len(tokenized["tokens"]), "rendered_prompt_sha256": digest(rendered.encode()),
                     "fits_context": len(tokenized["tokens"]) + c["max_tokens"] + c["context_reserve"] <= c["context_tokens"]}
    result = {"method_id": m["method_id"], "server_properties": props, "records": counts, "checked_at": now()}
    save(directory / "preflight.json", result, immutable=True)
    return result


def terminal_from_attempt(meta, body, record, c):
    if meta["error"]:
        if meta["error"]["status"] not in {"timeout", "transport_error", "interrupted"}:
            raise ValueError("unknown operational failure status")
        result = {"status": meta["error"]["status"], "prediction": None, "detail": meta["error"]["detail"]}
        retry = True
    elif meta["http_status"] != 200:
        result = {"status": "http_error", "prediction": None, "detail": f"HTTP {meta['http_status']}"}
        retry = meta["http_status"] in c["retry_http_statuses"]
    else:
        result, retry = parse_response(body, record), False
    return result, retry


def normalized_result(base, meta, body, record, c, attempt):
    parsed, _ = terminal_from_attempt(meta, body, record, c)
    usage, finish_reason = None, None
    if meta["http_status"] == 200 and not meta["error"]:
        try:
            decoded = decode(body)
            usage = decoded.get("usage")
            finish_reason = decoded["choices"][0].get("finish_reason")
        except (ValueError, KeyError, TypeError, IndexError, AttributeError):
            pass
    return {**base, **parsed, "attempts": attempt, "usage": usage,
            "finish_reason": finish_reason, "latency_seconds": meta["latency_seconds"]}


def execute_run(directory, job, m, flight, exchange_fn=exchange, idle_fn=wait_idle, sleep_fn=time.sleep):
    c, h, rid = m["method"]["config"], job["record_sha256"], job["run_id"]
    raw = (directory / "records" / f"{h}.json").read_bytes()
    record = project(raw)
    payload = request(c, raw, h, job["repetition"])
    run_dir = directory / "runs" / rid
    result_path = run_dir / "result.json"
    if result_path.exists():
        return load(result_path), False
    run_dir.mkdir(parents=True, exist_ok=True)
    request_path = run_dir / "request.json"
    if request_path.exists():
        if request_path.read_bytes() != encode(payload):
            raise ValueError("saved request differs")
    else:
        write(request_path, encode(payload), immutable=True)
    base = {**job, "seed": payload["seed"], "request_sha256": file_hash(request_path)}
    if not flight["records"][h]["fits_context"]:
        result = {**base, "status": "context_overflow", "prediction": None,
                  "detail": "full prompt plus generation budget exceeds context", "attempts": 0}
        save(result_path, result, immutable=True)
        return result, False
    made_request = False
    for attempt in range(1, c["max_attempts"] + 1):
        attempt_dir = run_dir / f"attempt-{attempt}"
        meta_path = attempt_dir / "response.json"
        if meta_path.exists():
            meta = load(meta_path)
            body = (attempt_dir / "response.body").read_bytes()
            if digest(body) != meta["response_sha256"]:
                raise ValueError("raw response hash mismatch")
        elif attempt_dir.exists():
            # The process may have died after receiving bytes but before metadata commit.
            body_path = attempt_dir / "response.body"
            body = body_path.read_bytes() if body_path.exists() else b""
            meta = {"attempt": attempt, "http_status": None, "headers": [], "latency_seconds": None,
                    "started_at": load(attempt_dir / "started.json")["started_at"], "ended_at": now(),
                    "error": {"status": "interrupted", "detail": "attempt did not commit a complete response"},
                    "response_sha256": digest(body)}
            if not body_path.exists():
                write(body_path, body, immutable=True)
            save(meta_path, meta, immutable=True)
        else:
            idle_fn(c)
            if attempt > 1:
                sleep_fn(c["retry_delay_s"])
            attempt_dir.mkdir()
            started = now()
            save(attempt_dir / "started.json", {"started_at": started}, immutable=True)
            response = exchange_fn(c, "/v1/chat/completions", request_path.read_bytes())
            made_request = True
            body = response.pop("body")
            write(attempt_dir / "response.body", body, immutable=True)
            meta = {**response, "attempt": attempt, "started_at": started, "ended_at": now(),
                    "response_sha256": digest(body)}
            save(meta_path, meta, immutable=True)
        result, retry = terminal_from_attempt(meta, body, record, c)
        if retry and attempt < c["max_attempts"]:
            continue
        result = normalized_result(base, meta, body, record, c, attempt)
        save(result_path, result, immutable=True)
        return result, made_request
    raise AssertionError("attempt limit exhausted without a terminal result")


def replay(directory):
    m = verify(directory)
    jobs = {j["run_id"]: j for j in m["schedule"]}
    run_dirs = list((directory / "runs").iterdir()) if (directory / "runs").exists() else []
    if {p.name for p in run_dirs} != set(jobs):
        raise ValueError("missing or extra run directories")
    results = []
    flight = load(directory / "preflight.json")
    for rid, job in sorted(jobs.items()):
        run_dir = directory / "runs" / rid
        result = load(run_dir / "result.json")
        h = job["record_sha256"]
        raw = (directory / "records" / f"{h}.json").read_bytes()
        wanted_request = encode(request(m["method"]["config"], raw, h, job["repetition"]))
        if (run_dir / "request.json").read_bytes() != wanted_request:
            raise ValueError("request isolation or payload mismatch")
        if result["request_sha256"] != digest(wanted_request):
            raise ValueError("request hash mismatch")
        count = result["attempts"]
        if count not in (0, 1, 2):
            raise ValueError("illegal attempt count")
        actual_attempts = {p.name for p in run_dir.glob("attempt-*")}
        if actual_attempts != {f"attempt-{a}" for a in range(1, count + 1)}:
            raise ValueError("attempt set mismatch")
        if count == 0:
            if flight["records"][h]["fits_context"] or result["status"] != "context_overflow":
                raise ValueError("invalid context-overflow result")
            expected = {**job, "seed": request(m["method"]["config"], raw, h, job["repetition"])["seed"],
                        "request_sha256": digest(wanted_request), "status": "context_overflow",
                        "prediction": None, "detail": "full prompt plus generation budget exceeds context", "attempts": 0}
            if result != expected:
                raise ValueError("invalid context-overflow envelope")
        for a in range(1, count + 1):
            attempt_dir = run_dir / f"attempt-{a}"
            meta = load(attempt_dir / "response.json")
            body = (attempt_dir / "response.body").read_bytes()
            if meta["attempt"] != a or digest(body) != meta["response_sha256"]:
                raise ValueError("attempt identity or response hash mismatch")
            parsed, retry = terminal_from_attempt(meta, body, project(raw), m["method"]["config"])
            if a < count and not retry:
                raise ValueError("nonoperational failure was retried")
            if a == count and any(result[key] != parsed[key] for key in ("status", "prediction", "detail")):
                raise ValueError("saved parse differs from offline parsing")
            if a == count:
                base = {**job, "seed": request(m["method"]["config"], raw, h, job["repetition"])["seed"],
                        "request_sha256": digest(wanted_request)}
                if result != normalized_result(base, meta, body, project(raw), m["method"]["config"], a):
                    raise ValueError("saved run metadata differs from raw response")
        if any(result[k] != v for k, v in job.items()):
            raise ValueError("run identity mismatch")
        if result["seed"] != request(m["method"]["config"], raw, h, job["repetition"])["seed"]:
            raise ValueError("seed mismatch")
        results.append(result)
    predictions = [aggregate(h, [r for r in results if r["record_sha256"] == h]) for h in m["record_hashes"]]
    return results, predictions


def export(directory):
    runs, predictions = replay(directory)
    save(directory / "run_results.json", runs)
    save(directory / "predictions.json", predictions)
    files = sorted(p for p in directory.rglob("*") if p.is_file() and p.name not in {"checksums.sha256", ".lock"})
    raw = "".join(f"{file_hash(p)}  {p.relative_to(directory)}\n" for p in files).encode()
    write(directory / "checksums.sha256", raw)
    return runs, predictions


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=["prepare", "preflight", "run", "replay"])
    ap.add_argument("inputs", nargs="*", type=Path)
    ap.add_argument("--campaign", type=Path)
    ap.add_argument("--config", type=Path)
    ap.add_argument("--runtime", type=Path, default=HERE / "output" / "runtime.json")
    ap.add_argument("--output", type=Path, default=HERE / "output" / "campaigns")
    ap.add_argument("--input-manifest", type=Path, help="blinded input manifest, never the private experiment")
    ap.add_argument("--data-split", choices=["development", "final"], default="development")
    ap.add_argument("--experiment-sha256")
    args = ap.parse_args()
    if args.command == "prepare":
        if args.input_manifest:
            if args.inputs or args.experiment_sha256 or args.data_split != "development":
                ap.error("input-manifest supplies records, split, and experiment binding")
            public = load(args.input_manifest)
            if set(public) != {"record_paths", "experiment_sha256", "development_data"}:
                ap.error("input manifest contains unexpected fields")
            inputs = [args.input_manifest.parent / p for p in public["record_paths"]]
            split, binding = public["development_data"], public["experiment_sha256"]
        else:
            inputs, split, binding = args.inputs, args.data_split == "development", args.experiment_sha256
        print(prepare(inputs, args.runtime, args.output, config(args.config), development_data=split, experiment_sha256=binding))
        return
    if args.campaign is None:
        ap.error("--campaign is required")
    directory = args.campaign.resolve()
    with (directory / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == "preflight":
            flight = preflight(directory)
            lengths = [r["prompt_tokens"] for r in flight["records"].values()]
            print(f"Preflight: {len(lengths)} records, prompt tokens {min(lengths)}..{max(lengths)}")
        elif args.command == "replay":
            runs, predictions = export(directory)
            print(f"Offline replay: {len(runs)} runs, {len(predictions)} predictions")
        else:
            m = verify(directory, check_runtime=True)
            completed = all((directory / "runs" / j["run_id"] / "result.json").exists() for j in m["schedule"])
            flight = load(directory / "preflight.json") if completed else preflight(directory)
            generated = 0
            for index, job in enumerate(m["schedule"], 1):
                result, did_request = execute_run(directory, job, m, flight)
                generated += int(did_request)
                print(f"{index}/{len(m['schedule'])} {job['run_id'][:12]} r{job['repetition']} {result['status']}"
                      f" {'new' if did_request else 'saved'}", flush=True)
            export(directory)
            print(f"Complete: {len(m['schedule'])} terminal runs; {generated} runs requested inference", flush=True)


if __name__ == "__main__":
    main()
