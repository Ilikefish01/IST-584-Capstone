import argparse
import random
import shutil
import sys
import time
from pathlib import Path

from watchdog.observers import Observer
from watcher import DetectorHandler
from BenignWorkload import BenignWorkloadGenerator

DEFAULT_CLEAN = Path(r"C:\Users\kritt\Desktop\PSU\Term 8\IST 584\CleanData")
DEFAULT_LIVE = Path(r"C:\Users\kritt\Desktop\PSU\Term 8\IST 584\TestFolder")
DEFAULT_LOG_DIR = Path("logs")
DEFAULT_DATASET = DEFAULT_LOG_DIR / "dataset.csv"
DEFAULT_EVENTS_LOG = DEFAULT_LOG_DIR / "events.log"
DEFAULT_SCENARIOS = [
    "mass_copy",
    "mass_zip",
    "mass_extract",
    "mass_delete",
    "mass_move",
    "mass_rename",
    "bulk_append",
    "temp_churn",
    "backup_snapshot",
]


def count_files(root):
    return sum(1 for p in root.rglob("*") if p.is_file()) if root.exists() else 0


def reset_dataset(clean_root, live_root, timeout=60, poll=0.25):
    if not clean_root.exists():
        raise FileNotFoundError(f"Clean dataset folder not found: {clean_root}")
    if live_root.exists():
        shutil.rmtree(live_root)
    shutil.copytree(clean_root, live_root)

    expected = count_files(clean_root)
    end = time.time() + timeout
    while time.time() < end:
        if live_root.exists() and count_files(live_root) == expected:
            time.sleep(0.5)
            return
        time.sleep(poll)
    raise TimeoutError(f"Reset did not stabilize within {timeout} seconds")


def build_schedule(scenarios, runs, rng, shuffle=True):
    out = []
    while len(out) < runs:
        batch = list(scenarios)
        if shuffle:
            rng.shuffle(batch)
        out.extend(batch)
    return out[:runs]


def start_detector(live_root):
    handler = DetectorHandler(label=0)
    observer = Observer()
    observer.schedule(handler, str(live_root), recursive=True)
    observer.start()
    return handler, observer


def stop_detector(observer):
    observer.stop()
    observer.join(timeout=10)


def init_log(path, header, fresh=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if fresh and path.exists():
        path.unlink()
    if not path.exists():
        path.write_text(header + "\n", encoding="utf-8")


def maybe_fresh_dataset(path, fresh):
    if fresh and path.exists():
        path.unlink()
        print(f"[INFO] Removed existing dataset file: {path}")


def append_log(path, run_number, value):
    with path.open("a", encoding="utf-8") as f:
        f.write(f"{run_number} | {value}\n")


def run_trial(i, total, scenario, args):
    print("\n" + "=" * 72)
    print(f"[RUN {i}/{total}] Scenario: {scenario}")
    print("=" * 72)

    handler, observer = start_detector(args.live_root)
    try:
        time.sleep(args.startup_delay)
        BenignWorkloadGenerator(
            root=args.live_root,
            scenario=scenario,
            intensity=args.intensity,
            min_delay=args.min_delay,
            max_delay=args.max_delay,
            seed=args.seed + i,
            max_source_files=args.max_source_files,
            max_file_size_mb=args.max_file_size_mb,
        ).run()
        time.sleep(args.post_run_wait)
        handler.save_dataset()
        result = {
            "detected": handler.detected,
            "max_probability": round(handler.max_probability, 4),
            "files_changed": len(handler.unique_files),
            "header_mismatch_count": handler.header_mismatch_count,
        }
        print("[RUN RESULT]", result)
        return result
    finally:
        stop_detector(observer)


def parse_args():
    p = argparse.ArgumentParser(description="Run benign workload batches with reset between runs.")
    p.add_argument("--clean-root", type=Path, default=DEFAULT_CLEAN)
    p.add_argument("--live-root", type=Path, default=DEFAULT_LIVE)
    p.add_argument("--runs", type=int, default=180)
    p.add_argument("--intensity", type=int, default=1)
    p.add_argument("--min-delay", type=float, default=0.003)
    p.add_argument("--max-delay", type=float, default=0.02)
    p.add_argument("--startup-delay", type=float, default=0.75)
    p.add_argument("--post-run-wait", type=float, default=1.5)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--fresh-dataset", action="store_true")
    p.add_argument("--max-source-files", type=int, default=500)
    p.add_argument("--max-file-size-mb", type=int, default=25)
    p.add_argument("--continue-on-error", action="store_true")
    p.add_argument("--no-shuffle", action="store_true")
    p.add_argument("--scenarios", nargs="+", default=DEFAULT_SCENARIOS, choices=DEFAULT_SCENARIOS)
    return p.parse_args()


def main():
    args = parse_args()
    rng = random.Random(args.seed)
    maybe_fresh_dataset(DEFAULT_DATASET, args.fresh_dataset)
    init_log(DEFAULT_EVENTS_LOG, "Run Number | File Behavior", args.fresh_dataset)
    schedule = build_schedule(args.scenarios, args.runs, rng, not args.no_shuffle)

    print(f"[INFO] Benign batch starting | runs={args.runs} | scenarios={args.scenarios}")
    completed = detections = 0

    for i, scenario in enumerate(schedule, 1):
        try:
            print(f"[RESET] Preparing run {i}/{args.runs}...")
            reset_dataset(args.clean_root, args.live_root)
            append_log(DEFAULT_EVENTS_LOG, i, scenario)
            result = run_trial(i, args.runs, scenario, args)
            completed += 1
            detections += int(result["detected"])
            print(f"[RESET] Cleaning after run {i}/{args.runs}...")
            reset_dataset(args.clean_root, args.live_root)
            print(f"[PROGRESS] completed={completed}/{args.runs} | false_positive_runs={detections}")
        except KeyboardInterrupt:
            print("\n[INFO] Batch interrupted by user.")
            break
        except Exception as exc:
            print(f"\n[ERROR] Run {i}/{args.runs} failed on '{scenario}': {exc}")
            if not args.continue_on_error:
                raise

    print("\n" + "=" * 72)
    print(f"[FINAL SUMMARY]\nCompleted benign runs: {completed}\nFalse positive benign runs: {detections}")
    print(f"Dataset file: {DEFAULT_DATASET.resolve()}\nEvents log: {DEFAULT_EVENTS_LOG.resolve()}")
    print("=" * 72)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[FATAL] {exc}")
        sys.exit(1)
