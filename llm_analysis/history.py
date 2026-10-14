"""Audit old campaigns using their exact frozen implementation in a subprocess."""
import subprocess
import sys
from pathlib import Path
from .common import HERE, digest, encode, file_hash, load, method_files


def replay_campaign(campaign):
    manifest = load(campaign / "manifest.json")
    if digest(encode(manifest["method"])) != manifest["method_id"]:
        raise ValueError("historical method fingerprint mismatch")
    if manifest["method"]["files"] == method_files():
        from .run_llm import replay
        return manifest, *replay(campaign)
    frozen = HERE / "frozen" / manifest["campaign_id"]
    receipt = load(frozen / "method.json")
    if receipt["method"] != manifest["method"]:
        raise ValueError("historical receipt differs from campaign")
    source = frozen / "method_source"
    for name, h in manifest["method"]["files"].items():
        if file_hash(source / name) != h:
            raise ValueError("historical method source drift")
    program = "import sys,json; from pathlib import Path; sys.path.insert(0,sys.argv[1]); from llm_analysis.run_llm import replay; print(json.dumps(replay(Path(sys.argv[2]))))"
    raw = subprocess.check_output([sys.executable, "-c", program, str(source), str(campaign.resolve())], cwd=source)
    from .common import decode
    runs, predictions = decode(raw)
    return manifest, runs, predictions
