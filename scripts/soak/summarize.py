"""Summarizes one soak run directory written by windows-wsl.ps1. Prints no address.

usage: python -I summarize.py RUN_DIR
"""
import csv
import json
import pathlib
import statistics
import sys


def rows(path):
    if not path.exists():
        return []
    with path.open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def logcounts(text):
    counts = {}
    for pair in (text or '').split():
        key, _, value = pair.partition('=')
        if value.isdigit():
            counts[key] = int(value)
    return counts


def main(run):
    run = pathlib.Path(run)
    summary = json.loads((run / 'summary.json').read_text(encoding='utf-8-sig')) if (run / 'summary.json').exists() else {}
    samples = rows(run / 'samples.csv')
    requests = rows(run / 'requests.csv')
    downloads = rows(run / 'downloads.csv')

    print(f"run: {run.name}")
    for key in ('started', 'ended', 'exit_reason', 'recoveries', 'journal_bytes_start', 'journal_bytes_end', 'leftovers'):
        if key in summary:
            print(f"  {key}: {summary[key]}")

    if requests:
        results = [r['result'] for r in requests]
        seconds = sorted(float(r['seconds']) for r in requests if r['result'] == 'match' and r['seconds'])
        print(f"requests: {len(results)}  match {results.count('match')}  mismatch {results.count('mismatch')}  fail {results.count('fail')}")
        if seconds:
            pct = lambda p: seconds[min(len(seconds) - 1, int(len(seconds) * p))]
            print(f"  matched latency: median {statistics.median(seconds):.1f} s, p95 {pct(0.95):.1f} s, max {seconds[-1]:.1f} s")
        exits = {}
        for r in requests:
            if r['result'] == 'fail':
                exits[r['curl_exit']] = exits.get(r['curl_exit'], 0) + 1
        if exits:
            print(f"  failures by curl exit: {dict(sorted(exits.items()))}")

    print(f"downloads ended: {len(downloads)}")
    for d in downloads:
        print(f"  {d['started'][11:19]} to {d['ended'][11:19]}: curl {d['curl_exit']}, http {d['http']}, {d['bytes']} B in {d['seconds']} s")

    if samples:
        def series(name):
            return [float(s[name]) for s in samples if s.get(name) not in (None, '')]
        for name, unit in (('helper_rss_kb', 'KB'), ('helper_fds', ''), ('helper_threads', ''), ('lab_ws_mb', 'MB'),
                           ('lab_handles', ''), ('lab_threads', ''), ('wsl_processes', ''), ('proxy_processes', '')):
            values = series(name)
            if values:
                print(f"{name}: first {values[0]:g}{unit}, min {min(values):g}, max {max(values):g}, last {values[-1]:g}")
        last = logcounts(samples[-1].get('log'))
        print("helper log (whole run): " + ', '.join(f"{k} {v}" for k, v in sorted(last.items()) if not k.startswith('end_')))
        ends = {k[4:]: v for k, v in last.items() if k.startswith('end_')}
        if ends:
            print("stream ends: " + ', '.join(f"{k} {v}" for k, v in sorted(ends.items(), key=lambda kv: -kv[1])))

    steps = []
    clock = run / 'clocksteps.log'
    if clock.exists():
        for line in clock.read_text(encoding='utf-8-sig', errors='replace').splitlines():
            parts = line.split()
            if len(parts) == 2:
                steps.append(float(parts[1]))
    if steps:
        print(f"clock steps: {len(steps)}, over 1 s: {sum(1 for s in steps if abs(s) > 1)}, range {min(steps):+.3f} to {max(steps):+.3f} s")

    events = run / 'events.log'
    if events.exists():
        print("events:")
        for line in events.read_text(encoding='utf-8-sig').splitlines():
            print(f"  {line}")


if __name__ == '__main__':
    main(sys.argv[1])
