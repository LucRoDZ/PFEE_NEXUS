"""Run every measurement the report needs, then print the values ready to paste.

    python demo/measure.py              # demo + G5 + load tests + red team (about 3 minutes)
    python demo/measure.py --with-g4    # also the G4 egress test with Docker

Everything lands in measurements/<date-time>/, with SUMMARY.md holding the text
for each [MEASURE] cell of the report (§6.1, §6.2, §7, §8).
"""
import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VAR = ROOT / "var"
PY = sys.executable


def run(*args, check=True):
    print(f"\n$ {' '.join(args)}", flush=True)
    result = subprocess.run(list(args), cwd=ROOT)
    if check and result.returncode != 0:
        raise SystemExit(f"step failed: {' '.join(args)}")
    return result.returncode


def keep(out: Path, name: str, required=True):
    src = VAR / name
    if src.exists():
        shutil.copy(src, out / name)
    elif required:
        raise SystemExit(f"missing {src}")


def load(out: Path, name: str):
    path = out / name
    return json.loads(path.read_text()) if path.exists() else None


def ms(x):
    return f"{x:,.0f}" if x is not None else "?"


def summary(out: Path, label: str) -> str:
    r = load(out, "results.json")
    s1, s2, s3, s5 = r["scene1"], r["scene2"], r["scene3"], r.get("scene5", {})
    checks = {k: v for s in (s1, s2, s3, s5) for k, v in s.get("checks", {}).items()}
    passed = sum(checks.values())
    up, rd, fu, rv = (load(out, f"loadtest-{m}.json") for m in ("upload", "read", "full", "revoke"))
    rt = load(out, "redteam.json")
    g4 = load(out, "g4.json")
    held = lambda *keys: all(checks.get(k) for k in keys)  # noqa: E731

    g4_text = ("Not measured: run `make g4` (Docker) or the kubectl probe on k3s." if not g4 else
               f"From a container on the HDG network: HTTPS {g4['https']}; direct TCP to a public IP "
               f"{g4['tcp_1.1.1.1_443']}; DNS {g4['dns']}.")
    g4_verdict = "[ ]" if not g4 else ("**Held**" if g4["egress_blocked"] else "**Not held**")

    lines = [
        f"# NEXUS measurements, {label}",
        "",
        f"Checks: **{passed} of {len(checks)} passed**.",
        "",
        "## §6.1 results table",
        "",
        "| Guarantee | Result | Verdict |",
        "|---|---|---|",
        f"| G1 | Entropy {s1['entropy_bits_per_byte']:.3f} bits/byte on all {s1.get('objects_read_by_admin', 3)} objects "
        f"(8 = random); readable markers: {', '.join(s1.get('markers_found') or []) or 'none'}. HDG's key request refused "
        f"(\"{s1.get('hdg_key_request_answer')}\") and logged in the patient's history. No key file on HDG's side. | "
        f"{'**Held** for storage, transit and backups; **partial** in the AI zone until a TEE' if held('storage_ciphertext_only', 'hdg_key_request_denied', 'no_keys_at_hdg') else '**Not held**'} |",
        f"| G2 | {s2.get('allowed_before_revocation')} keys released before, {s2['allowed_after_revocation']} after "
        f"({s2.get('requests_after_revocation')} requests). Revocation recorded at the hospital and at HDG in "
        f"{ms(s2['revocation_round_trip_ms'])} ms; first refusal {ms(s2['click_to_first_denial_ms'])} ms after the click. "
        f"After erasure, backup copy plus new grant refused: \"{s2.get('erasure_answer')}\". | "
        f"{'**Held**' if held('allowed_before', 'denied_after', 'under_5s', 'crypto_shredding') else '**Not held**'} |",
        f"| G3 | Edit detected at the exact entry (#{s3.get('edit_detected_at')}). After the full rewrite, HDG's own check "
        f"{'passed' if s3.get('rewrite_passes_hdg_check') else 'failed'}; the hospital's anchors caught it (first mismatch "
        f"at #{s3.get('rewrite_first_anchor_mismatch')}, the first anchor taken after the deleted entry). | "
        f"{'**Held**' if held('intact_before', 'edit_detected', 'rewrite_detected') else '**Not held**'} |",
        f"| G4 | {g4_text} | {g4_verdict} |",
        f"| G5 | {s5.get('images_processed')} images processed: none of the {len(s5.get('fields_searched', []))} identity fields "
        f"({', '.join(s5.get('fields_searched', []))}) found in the decrypted inputs or in the output. After the patient "
        f"withdrew consent, the next run used {s5.get('next_run_used')} images and excluded {s5.get('next_run_excluded')}. "
        f"Burned-in file quarantined at the source. | "
        f"{'**Held** for header identifiers; pixel content is handled by quarantine only' if held('no_identity_in_ai_inputs', 'no_identity_in_ai_output', 'revoked_excluded_from_ai', 'burned_in_quarantined') else '**Not held**'} |",
        "",
        "## §6.2 load-test table",
        "",
        "| Mode | p95 latency (ms) | Throughput (req/s) | Target |",
        "|---|---|---|---|",
        f"| Upload (0.5 MB image, {up['concurrency']} in parallel) | {ms(up['p95_ms'])} | {up['throughput_rps']:.0f} | "
        f"No error: **{up['errors']} errors out of {up['requests']}** |",
        f"| Ciphertext download only (baseline) | {ms(rd['p95_ms'])} | {rd['throughput_rps']:.0f} | Reference |",
        f"| Fully protected read; key decision alone | {ms(fu['p95_ms'])}; key decision {ms(fu['key_decision_p95_ms'])} | "
        f"{fu['throughput_rps']:.0f} | Key decision p95 under 300 ms: **{'met' if fu['key_decision_p95_ms'] < 300 else 'not met'}** |",
        f"| Revocation during the load | First refusal {ms(rv['first_revocation_denial_after_click_ms'])} ms after the click; "
        f"**{rv['allowed_after_revocation']} keys released out of {rv['requests_started_after_revocation']:,} requests** made "
        f"after the revocation | | Zero key released: **{'met' if rv['allowed_after_revocation'] == 0 else 'not met'}** |",
        "",
        f"Cost of the protections: {ms(fu['p95_ms'] - rd['p95_ms'])} ms at p95; throughput {fu['throughput_rps']:.0f} "
        f"against {rd['throughput_rps']:.0f} req/s. Errors: upload {up['errors']}, read {rd['errors']}, full {fu['errors']}, "
        f"revoke {rv['errors']}. Revocation round trip {ms(rv['revocation_round_trip_ms'])} ms.",
        "",
        "## §7 incident-response table",
        "",
        "| Step | When |",
        "|---|---|",
        f"| Detect, contain | Detected T+{rt.get('detect_s')} s; account disabled T+{rt.get('contain_s')} s; attacker's next "
        f"request refused T+{rt.get('attacker_blocked_s')} s |",
        f"| Analyse | {ms(rt.get('analysis_ms'))} ms: {rt['analysis']['events']} events, "
        f"{rt['analysis']['patients_targeted']} patient references targeted, {rt['analysis']['keys_released']} keys released |",
        "",
        f"Keys obtained by the attacker: **{rt['keys_obtained_by_attacker']}**; raw storage entropy "
        f"{rt['raw_storage_entropy']:.3f} bits/byte; the pod's token got: {rt['pod_token_answers']}.",
        "",
        "## §8 audit table",
        "",
        f"- No unauthorised transfer: {'**Held**' if g4 and g4['egress_blocked'] else '**Partial:** key refused; outbound test pending'}",
        f"- Breach handling: {'**Held**' if rt['keys_obtained_by_attacker'] == 0 and rt.get('contain_s') else '**Not held**'}: "
        f"detected and contained in {rt.get('contain_s')} s, 0 keys obtained, analysed from the audit chain in "
        f"{ms(rt.get('analysis_ms'))} ms",
    ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--with-g4", action="store_true", help="also run the G4 egress test with Docker")
    parser.add_argument("--seconds", type=int, default=30, help="duration of each load-test mode")
    args = parser.parse_args()
    label = datetime.now().strftime("%Y-%m-%d %H:%M")
    out = ROOT / "measurements" / datetime.now().strftime("%Y%m%d-%H%M")
    out.mkdir(parents=True, exist_ok=True)

    try:
        run(PY, "demo/stack.py", "start", "--fresh")
        run(PY, "demo/scenes.py", "all")
        keep(out, "results.json")
        run(PY, "demo/stack.py", "stop")

        run(PY, "demo/stack.py", "start", "--fresh")
        run(PY, "demo/scenes.py", "setup")
        run(PY, "demo/loadtest.py", "--mode", "upload", "--count", "50", "--concurrency", "5")
        for mode in ("read", "full", "revoke"):
            run(PY, "demo/loadtest.py", "--mode", mode, "--seconds", str(args.seconds), "--concurrency", "20")
        for mode in ("upload", "read", "full", "revoke"):
            keep(out, f"loadtest-{mode}.json")
        run(PY, "demo/redteam.py")
        keep(out, "redteam.json")
    finally:
        run(PY, "demo/stack.py", "stop", check=False)

    if args.with_g4:
        if run("bash", "demo/g4_egress.sh", check=False) == 0:
            keep(out, "g4.json")
        keep(out, "g4-control.json", required=False)

    text = summary(out, label)
    (out / "SUMMARY.md").write_text(text)
    print("\n" + "=" * 72 + "\n" + text + "=" * 72)
    print(f"\nSaved in {out}/ (SUMMARY.md has the text for each report cell)")


if __name__ == "__main__":
    main()
