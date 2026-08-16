#!/usr/bin/env python3
"""
Symbiote report analyzer.

Reads a Symbiote dump/report.json and produces a plain-text engineering
analysis: which spoof vectors are active, unpacker status, tool coverage,
and heuristic notes for a follow-up manual session.

Fully offline. Optionally pipe the analysis into a LOCAL model CLI:

    python tools/ai_analyze.py dump/report.json
    python tools/ai_analyze.py dump/report.json --llm "ollama run llama3.2"

Research framing: analyze binaries you legally own. No cloud APIs, no keys.
"""
import argparse
import json
import shutil
import subprocess
import sys


def analyze(report: dict) -> str:
    lines = []
    lines.append(f"# Symbiote analysis report")
    lines.append(f"- target: `{report.get('target', '?')}`")
    if report.get('unpacked'):
        lines.append(f"- unpacked: `{report['unpacked']}`")
    lines.append(f"- stealth always-on: {report.get('stealth_always_on', '?')}")
    lines.append(f"- hypervisor rail: `{report.get('hypervisor_mode', '?')}`")

    vec = report.get('spoof_vectors', {})
    lines.append("\n## Spoof vectors")
    for name, on in vec.items():
        lines.append(f"- {name}: {'active' if on else 'PASSTHROUGH'}")

    tools = report.get('tools', [])
    avail = sum(1 for t in tools if t.get('available'))
    lines.append(f"\n## External tools ({avail}/{len(tools)} configured)")
    for t in tools:
        state = "OK" if t.get("available") else "missing"
        lines.append(f"- {t.get('name', '?')}: {state}")

    unpackers = [t for t in tools if t.get('name', '').lower() in
                 ('steamless (steamstub unpacker)', 'gbe', 'opensteamtools',
                  'steamsls', 'steamvent', 'steamdira')]
    unpack_ready = any(t.get('available') for t in unpackers)
    lines.append("\n## Notes")
    if report.get('unpacked'):
        lines.append("- target was unpacked before launch (SteamStub layer removed).")
    elif not unpack_ready:
        lines.append("- no unpacker configured: if the binary still has a stub, "
                     "add a path in [tools] and re-run with --unpack.")
    else:
        lines.append("- unpacker configured but not run: use `launcher.exe --unpack`.")

    if not report.get('stealth_always_on', True):
        lines.append("- WARNING: stealth always-on is DISABLED (`[stealth] always_on=0`); "
                     "vectors leak unless each section opts in. Turn it back on for analysis runs.")

    if report.get('hypervisor_mode') != 'whp':
        lines.append("- hypervisor rail is not 'whp': only the primary WHP rail is built; "
                     "the driver rail fails loud when selected.")

    nfiles = report.get('dump_file_count', 0)
    lines.append(f"- dump directory contains {nfiles} file(s).")
    if nfiles > 0:
        lines.append("  Inspect them (strings/entropy/imports) alongside this report.")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("report", help="path to report.json")
    ap.add_argument("--llm", default="", help="optional local model CLI, e.g. 'ollama run llama3.2'")
    args = ap.parse_args()

    with open(args.report, "r", encoding="utf-8-sig", errors="replace") as f:
        report = json.load(f)

    text = analyze(report)
    print(text)

    if args.llm:
        llm = shutil.which(args.llm.split()[0])
        if not llm:
            print(f"\n[!] LLM command not found: {args.llm}", file=sys.stderr)
            return 1
        prompt = (f"Act as a reverse-engineering assistant. Summarize risks and next "
                  f"steps from this Symbiote analysis report (research on legally owned "
                  f"binaries only):\n\n{text}")
        subprocess.run([args.llm, prompt] if len(args.llm.split()) == 1
                       else args.llm.split() + [prompt])
    return 0


if __name__ == "__main__":
    sys.exit(main())