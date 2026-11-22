#!/usr/bin/env python3
"""Бенчмарк: сравнивает простую версию (naive, v1) и loghunter (v2) на синтетических логах.

Для каждого размера лога:
  1) при необходимости генерирует логи (tools/gen_logs.py);
  2) запускает каждую версию в ОТДЕЛЬНОМ процессе (чтобы честно измерить пик памяти);
  3) считает время, строк в секунду, МБ/с, пик памяти;
  4) сверяет найденные алерты с эталоном truth.json: точность, полнота, ложные срабатывания.

Пример:
    python tools/benchmark.py --sizes 100000 1000000 --repeat 3
"""
import argparse
import json
import os
import resource
import statistics
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
YEAR = 2026


def child(impl, auth, nginx):
    sys.path.insert(0, ROOT)
    if impl == "naive":
        from naive.naive_analyzer import analyze
        run = lambda: analyze(auth, nginx, YEAR)
    else:
        from loghunter.auth import analyze_auth
        from loghunter.web import analyze_nginx
        run = lambda: analyze_auth(auth, YEAR) + analyze_nginx(nginx)
    t = time.perf_counter()
    alerts = run()
    seconds = time.perf_counter() - t
    rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Linux: КБ -> МБ
    print(json.dumps({"seconds": seconds, "rss_mb": rss_mb,
                      "alerts": sorted([a["type"], a["key"]] for a in alerts)}))


def evaluate(found, truth):
    found = {tuple(x) for x in found}
    truth = {tuple(x) for x in truth}
    tp = len(found & truth)
    fp = len(found - truth)
    fn = len(truth - found)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {"expected": len(truth), "found": len(found), "tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall}


def run_child(impl, auth, nginx):
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "--child", impl, auth, nginx],
                         capture_output=True, text=True, check=True, cwd=ROOT)
    return json.loads(out.stdout)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[100_000, 1_000_000], help="строк в каждом файле")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--skip-naive", action="store_true", help="не запускать медленную версию (для очень больших логов)")
    ap.add_argument("--data-dir", default=os.path.join(ROOT, "data"))
    ap.add_argument("--out", default=os.path.join(ROOT, "benchmark_results.json"))
    ap.add_argument("--child", nargs=3, metavar=("IMPL", "AUTH", "NGINX"), help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.child:
        child(*args.child)
        return

    results = []
    for size in args.sizes:
        d = os.path.join(args.data_dir, str(size))
        if not os.path.exists(os.path.join(d, "truth.json")):
            subprocess.run([sys.executable, os.path.join(ROOT, "tools", "gen_logs.py"),
                            "--lines", str(size), "--out", d], check=True)
        auth, nginx = os.path.join(d, "auth.log"), os.path.join(d, "access.log")
        truth = json.load(open(os.path.join(d, "truth.json")))["alerts"]
        total_mb = (os.path.getsize(auth) + os.path.getsize(nginx)) / 1e6
        lines = 2 * size

        row = {"lines_per_file": size, "total_lines": lines, "total_mb": round(total_mb, 1)}
        for impl in (("loghunter",) if args.skip_naive else ("naive", "loghunter")):
            runs = [run_child(impl, auth, nginx) for _ in range(args.repeat)]
            secs = [r["seconds"] for r in runs]
            med = statistics.median(secs)
            row[impl] = {
                "seconds_median": round(med, 2),
                "seconds_min": round(min(secs), 2),
                "lines_per_sec": round(lines / med),
                "mb_per_sec": round(total_mb / med, 1),
                "peak_rss_mb": round(max(r["rss_mb"] for r in runs)),
                "quality": evaluate(runs[0]["alerts"], truth),
            }
            print(f"{size:>9} строк/файл  {impl:<9} {med:7.2f} с  {lines / med:>10,.0f} строк/с  "
                  f"RSS {row[impl]['peak_rss_mb']:>4} МБ  "
                  f"найдено {row[impl]['quality']['tp']}/{len(truth)}  ложных {row[impl]['quality']['fp']}",
                  flush=True)
        if "naive" in row:
            row["speedup"] = round(row["naive"]["seconds_median"] / row["loghunter"]["seconds_median"], 1)
            row["memory_ratio"] = round(row["naive"]["peak_rss_mb"] / max(1, row["loghunter"]["peak_rss_mb"]), 1)
            print(f"{'':>9} ускорение v2/v1: x{row['speedup']}, памяти меньше в {row['memory_ratio']} раз", flush=True)
        results.append(row)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print("результаты:", args.out)


if __name__ == "__main__":
    main()
