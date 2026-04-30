import argparse
import getpass
import shutil
import sys
import time
from pathlib import Path

from watchdog.observers import Observer
from watcher import DetectorHandler
from Ransomware import collect_files, process_file

DEFAULT_CLEAN = Path(r"C:\Users\kritt\Desktop\PSU\Term 8\IST 584\CleanData")
DEFAULT_LIVE = Path(r"C:\Users\kritt\Desktop\PSU\Term 8\IST 584\TestFolder")
DEFAULT_LOG_DIR = Path("logs")
DEFAULT_DATASET = DEFAULT_LOG_DIR / "dataset.csv"
DEFAULT_EVENTS_LOG = DEFAULT_LOG_DIR / "events.log"

SCENARIOS = [
    {"name": "baseline", "scenario": "baseline", "delay": 0.002, "benign_ext": ".bak", "partial_pct": 100},
    {"name": "no_extension", "scenario": "no_extension", "delay": 0.002, "benign_ext": ".bak", "partial_pct": 100},
    {"name": "benign_extension_bak", "scenario": "benign_extension", "delay": 0.002, "benign_ext": ".bak", "partial_pct": 100},
    {"name": "benign_extension_tmp", "scenario": "benign_extension", "delay": 0.002, "benign_ext": ".tmp", "partial_pct": 100},
    {"name": "inplace_overwrite", "scenario": "inplace_overwrite", "delay": 0.002, "benign_ext": ".bak", "partial_pct": 100},
    {"name": "reduced_speed", "scenario": "reduced_speed", "delay": 0.15, "benign_ext": ".bak", "partial_pct": 100},
    {"name": "partial_10pct", "scenario": "partial_encryption", "delay": 0.002, "benign_ext": ".bak", "partial_pct": 10},
    {"name": "partial_25pct", "scenario": "partial_encryption", "delay": 0.002, "benign_ext": ".bak", "partial_pct": 25},
    {"name": "targeted_filetypes", "scenario": "targeted_filetypes", "delay": 0.002, "benign_ext": ".bak", "partial_pct": 100},
    {"name": "random_bytes", "scenario": "random_bytes", "delay": 0.002, "benign_ext": ".bak", "partial_pct": 100},
]


def count_files(root):
    return sum(1 for p in root.rglob("*") if p.is_file()) if root.exists() else 0


def reset_dataset(clean_root, live_root, timeout=60, poll=0.25):
    if not clean_root.exists():
        raise FileNotFoundError(f"Clean dataset not found: {clean_root}")
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
    raise TimeoutError(f"Reset did not stabilize within {timeout}s")


def start_detector(live_root):
    handler = DetectorHandler(label=1)
    observer = Observer()
    observer.schedule(handler, str(live_root), recursive=True)
    observer.start()
    return handler, observer


def stop_detector(observer):
    observer.stop()
    observer.join(timeout=10)


def init_log(path, fresh=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if fresh and path.exists():
        path.unlink()
    if not path.exists():
        path.write_text("Run Number | Scenario\n", encoding="utf-8")


def append_log(path, run_number, name):
    with path.open("a", encoding="utf-8") as f:
        f.write(f"{run_number} | {name}\n")


def maybe_fresh_dataset(path, fresh):
    if fresh and path.exists():
        path.unlink()
        print(f"[INFO] Removed existing dataset: {path}")


def run_trial(i, total, cfg, live_root, user_key, startup_delay, post_run_wait):
    print("\n" + "=" * 72)
    print(f"[RUN {i}/{total}] scenario={cfg['name']}")
    print("=" * 72)

    handler, observer = start_detector(live_root)
    try:
        time.sleep(startup_delay)
        files = collect_files(str(live_root), cfg["scenario"], cfg["partial_pct"])
        print(f"[INFO] Files targeted: {len(files)}")

        attempted = 0
        for path in files:
            if handler.detected:
                print(f"[STOPPED] Detector fired after {attempted} file(s) attempted.")
                break
            process_file(path, user_key, cfg["scenario"], cfg["benign_ext"], cfg["delay"])
            attempted += 1

        time.sleep(post_run_wait)
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
    names = [s["name"] for s in SCENARIOS]
    p = argparse.ArgumentParser(description="Run anomalous workload batches with reset between runs.")
    p.add_argument("--clean-root", type=Path, default=DEFAULT_CLEAN)
    p.add_argument("--live-root", type=Path, default=DEFAULT_LIVE)
    p.add_argument("--startup-delay", type=float, default=0.75)
    p.add_argument("--post-run-wait", type=float, default=1.5)
    p.add_argument("--fresh-dataset", action="store_true")
    p.add_argument("--continue-on-error", action="store_true")
    p.add_argument("--scenarios", nargs="+", default=names, choices=names)
    return p.parse_args()


def main():
    args = parse_args()
    selected = [s for s in SCENARIOS if s["name"] in args.scenarios]
    user_key = getpass.getpass("Enter encryption key (used for AES workloads): ")

    maybe_fresh_dataset(DEFAULT_DATASET, args.fresh_dataset)
    init_log(DEFAULT_EVENTS_LOG, args.fresh_dataset)

    completed = detections = 0
    total = len(selected)
    print(f"\n[INFO] Anomalous batch starting | runs={total}")

    for i, cfg in enumerate(selected, 1):
        try:
            print(f"[RESET] Preparing run {i}/{total} ({cfg['name']})...")
            reset_dataset(args.clean_root, args.live_root)
            append_log(DEFAULT_EVENTS_LOG, i, cfg["name"])
            result = run_trial(i, total, cfg, args.live_root, user_key, args.startup_delay, args.post_run_wait)
            completed += 1
            detections += int(result["detected"])
            print(f"[RESET] Cleaning after run {i}/{total}...")
            reset_dataset(args.clean_root, args.live_root)
            print(f"[PROGRESS] completed={completed}/{total} | detected={detections}")
        except KeyboardInterrupt:
            print("\n[INFO] Batch interrupted by user.")
            break
        except Exception as exc:
            print(f"\n[ERROR] Run {i}/{total} failed on '{cfg['name']}': {exc}")
            if not args.continue_on_error:
                raise

    print("\n" + "=" * 72)
    print(f"[FINAL SUMMARY]\n  Completed : {completed}/{total}\n  Detected  : {detections}")
    print(f"  Dataset   : {DEFAULT_DATASET.resolve()}\n  Events log: {DEFAULT_EVENTS_LOG.resolve()}")
    print("=" * 72)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[FATAL] {exc}")
        sys.exit(1)
