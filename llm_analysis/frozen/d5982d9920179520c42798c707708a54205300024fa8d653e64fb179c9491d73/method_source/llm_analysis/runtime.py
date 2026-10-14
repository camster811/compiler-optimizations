"""Inventory or launch the existing CUDA backend without modifying its installation."""
import argparse
import json
import struct
import subprocess
from pathlib import Path
from urllib.parse import urlsplit
from .common import HERE, config, file_hash, now, save


def metadata(path):
    with Path(path).open("rb") as f:
        def read(fmt):
            return struct.unpack("<" + fmt, f.read(struct.calcsize("<" + fmt)))[0]
        def string():
            return f.read(read("Q")).decode("utf-8")
        formats = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f",
                   7: "?", 10: "Q", 11: "q", 12: "d"}
        def value(kind):
            if kind == 8:
                return string()
            if kind == 9:
                subtype, count = read("I"), read("Q")
                for _ in range(count):
                    value(subtype)
                return {"array_length": count}
            return read(formats[kind])
        if f.read(4) != b"GGUF":
            raise ValueError("not a GGUF file")
        out = {"gguf_version": read("I"), "tensor_count": read("Q")}
        count = read("Q")
        for _ in range(count):
            key, kind = string(), read("I")
            item = value(kind)
            if key.startswith(("general.", "qwen2.")) or key == "tokenizer.chat_template":
                out[key] = item
        return out


def launch_arguments(c):
    s = c["server"]
    return [c["executable"], "--model", c["model_path"], "--alias", c["model_alias"],
            "--host", "127.0.0.1", "--port", str(urlsplit(c["endpoint"]).port or 80),
            "--ctx-size", str(c["context_tokens"]), "--gpu-layers", s["gpu_layers"],
            "--parallel", str(s["parallel"]), "--cache-type-k", s["cache_type_k"],
            "--cache-type-v", s["cache_type_v"], "--flash-attn", s["flash_attention"],
            "--batch-size", str(s["batch_size"]), "--ubatch-size", str(s["ubatch_size"]),
            "--threads", str(s["threads"]), "--threads-batch", str(s["threads_batch"]),
            "--jinja", "--chat-template-file", str(HERE / "chat_template.jinja"),
            "--reasoning", "on", "--reasoning-format", "deepseek", "--reasoning-budget",
            str(s["reasoning_budget"]), "--no-context-shift", "--fit", "off", "--slots", "--no-webui", "-lv", "4"]


def inventory(c):
    binary = Path(c["executable"])
    files = {binary.resolve(), Path(c["model_path"]).resolve(), Path(c["source_archive"]).resolve()}
    files.update(p.resolve() for p in binary.parent.glob("*.so*"))
    cache = binary.parent.parent / "CMakeCache.txt"
    files.add(cache)
    gpu = subprocess.check_output(["/usr/lib/wsl/lib/nvidia-smi", "--query-gpu=name,memory.total,driver_version",
                                   "--format=csv,noheader"], text=True).strip()
    return {"artifacts": {str(p): file_hash(p) for p in sorted(files)},
            "backend_version": subprocess.check_output([str(binary), "--version"], text=True, stderr=subprocess.STDOUT).strip(),
            "cuda_version": subprocess.check_output(["/usr/local/cuda/bin/nvcc", "--version"], text=True).strip(),
            "gpu": gpu, "gguf_metadata": metadata(c["model_path"]),
            "launch_arguments": launch_arguments(c), "model_provenance": c["model_provenance"]}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=["inventory", "serve"])
    ap.add_argument("--config", type=Path)
    ap.add_argument("--output", type=Path, default=HERE / "output" / "runtime.json")
    args = ap.parse_args()
    c = config(args.config)
    if args.command == "inventory":
        save(args.output, inventory(c))
        print(f"Runtime inventory saved to {args.output}", flush=True)
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    log = args.output.parent / "server.log"
    with log.open("ab", buffering=0) as stream:
        process = subprocess.Popen(launch_arguments(c), stdout=stream, stderr=stream)
        save(args.output.parent / "server_process.json", {"pid": process.pid, "started_at": now(),
                                                          "arguments": launch_arguments(c)})
        print(f"Server PID {process.pid}; log: {log}", flush=True)
        try:
            with (args.output.parent / "gpu_memory.jsonl").open("a", buffering=1) as telemetry:
                while True:
                    try:
                        memory = subprocess.check_output([
                            "/usr/lib/wsl/lib/nvidia-smi", "--query-gpu=memory.total,memory.used,memory.free",
                            "--format=csv,noheader,nounits"], text=True, stderr=subprocess.STDOUT).strip()
                        telemetry.write(json.dumps({"time": now(), "memory_mib": memory}) + "\n")
                    except subprocess.CalledProcessError as e:
                        telemetry.write(json.dumps({"time": now(), "error": e.output}) + "\n")
                    try:
                        code = process.wait(timeout=5)
                        break
                    except subprocess.TimeoutExpired:
                        continue
        except KeyboardInterrupt:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            code = 0
        raise SystemExit(code)


if __name__ == "__main__":
    main()
