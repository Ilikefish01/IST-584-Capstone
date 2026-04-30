import csv
import threading
import time
from pathlib import Path

import psutil
from watchdog.events import FileSystemEventHandler

from behavioral import BehavioralTracker
from content import (
    byte_histogram_probs,
    distance_to_uniform,
    file_entropy,
    header_matches_expected,
    sample_bytes,
)
from model import predict_proba

THRESHOLD = 0.5
MIN_SUSPICIOUS_EVENTS = 0
QUIET_PERIOD = 0.3

FEATURES = [
    "entropy",
    "uniform_dist",
    "write_burst",
    "dir_spread",
    "rename_burst",
    "suspicious_rename_target",
    "header_mismatch",
    "files_per_sec",
    "extension_change_ratio",
]

CSV_HEADERS = [
    "label",
    "detected",
    "files_changed",
    "files_before_detection",
    "time_to_detect_sec",
    "max_probability",
    *FEATURES,
    "entropy_mean",
    "entropy_max",
    "uniform_mean",
    "files_per_sec_max",
    "write_burst_seen",
    "dir_spread_seen",
    "rename_burst_seen",
    "suspicious_rename_target_seen",
    "extension_change_ratio_max",
    "header_mismatch_count",
]


class DetectorHandler(FileSystemEventHandler):
    def __init__(self, label):
        self.label = label
        self.detector_pid = psutil.Process().pid
        self.behavior = BehavioralTracker()

        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        self.dataset_file = self.log_dir / "dataset.csv"
        self._ensure_dataset_file()

        self.entropy_vals = []
        self.uniform_vals = []
        self.files_per_sec_vals = []
        self.extension_ratio_vals = []
        self.header_mismatch_count = 0

        self.seen = {
            "write_burst": 0,
            "dir_spread": 0,
            "rename_burst": 0,
            "suspicious_rename_target": 0,
        }

        self.max_probability = 0.0
        self.detected = 0
        self.unique_files = set()
        self.suspicious_event_count = 0
        self.start_time = None
        self.detection_time = None
        self.files_at_detection = 0
        self.last_event_time = time.time()
        self.dataset_saved = False
        self.best_features = dict.fromkeys(FEATURES, 0.0)

        threading.Thread(target=self._monitor_quiet, daemon=True).start()

    def _ensure_dataset_file(self):
        if not self.dataset_file.exists():
            return self._write_header()

        try:
            with self.dataset_file.open("r", newline="", encoding="utf-8") as f:
                old_header = next(csv.reader(f), None)
        except Exception:
            old_header = None

        if old_header != CSV_HEADERS:
            backup = self.log_dir / f"dataset_legacy_{time.strftime('%Y%m%d_%H%M%S')}.csv"
            self.dataset_file.rename(backup)
            self._write_header()
            print(f"[DATASET] Schema changed, old file moved to {backup}")

    def _write_header(self):
        with self.dataset_file.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(CSV_HEADERS)

    def _monitor_quiet(self):
        while True:
            if self.detected and not self.dataset_saved:
                if time.time() - self.last_event_time > QUIET_PERIOD:
                    self.save_dataset()
            time.sleep(0.05)

    def _summary_stats(self):
        def mean(values):
            return round(sum(values) / len(values), 4) if values else 0

        def maxv(values):
            return round(max(values), 4) if values else 0

        return [
            mean(self.entropy_vals),
            maxv(self.entropy_vals),
            mean(self.uniform_vals),
            maxv(self.files_per_sec_vals),
            self.seen["write_burst"],
            self.seen["dir_spread"],
            self.seen["rename_burst"],
            self.seen["suspicious_rename_target"],
            maxv(self.extension_ratio_vals),
            self.header_mismatch_count,
        ]

    def save_dataset(self):
        if self.dataset_saved:
            return
        self.dataset_saved = True

        if self.start_time is not None and self.detection_time is not None:
            time_to_detect = round(self.detection_time - self.start_time, 3)
        else:
            time_to_detect = -1

        bf = self.best_features
        row = [
            self.label,
            self.detected,
            len(self.unique_files),
            self.files_at_detection,
            time_to_detect,
            round(self.max_probability, 4),
            round(bf["entropy"], 4),
            round(bf["uniform_dist"], 4),
            int(bf["write_burst"]),
            int(bf["dir_spread"]),
            int(bf["rename_burst"]),
            int(bf["suspicious_rename_target"]),
            int(bf["header_mismatch"]),
            round(bf["files_per_sec"], 4),
            round(bf["extension_change_ratio"], 4),
            *self._summary_stats(),
        ]

        with self.dataset_file.open("a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)

        print("\n[DATASET] Row saved:")
        print(dict(zip(CSV_HEADERS, row)))

    def kill(self):
        print("[ACTION] Killing suspicious process...")
        killed = False
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["pid"] == self.detector_pid:
                    continue
                if (proc.info["name"] or "").lower() == "python.exe":
                    proc.kill()
                    killed = True
                    print(f"[KILL] PID {proc.info['pid']} (python.exe)")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if not killed:
            print("[KILL] No other python.exe process found")

    @staticmethod
    def clean_name(path):
        return path.name.replace(".locked", "")

    def _event_path(self, event):
        if event.event_type == "moved" and hasattr(event, "dest_path"):
            src = Path(event.src_path)
            dst = Path(event.dest_path)
            self.behavior.record_rename(src, dst)
            expected_ext = src.suffix.lower() if src.suffix else None
            return dst, expected_ext

        path = Path(event.src_path)
        self.behavior.record_write(path)
        return path, None

    def on_any_event(self, event):
        if event.is_directory:
            return

        self.last_event_time = time.time()
        raw_path, expected_ext = self._event_path(event)
        if not raw_path.exists():
            return

        try:
            path = raw_path.resolve()
            entropy = file_entropy(path)
            uniform = distance_to_uniform(byte_histogram_probs(sample_bytes(path)))
            header_ok = header_matches_expected(path, expected_ext=expected_ext)
        except Exception:
            return

        if header_ok is False:
            self.header_mismatch_count += 1

        flags = self.behavior.flags()
        features = {
            "entropy": entropy / 8.0,
            "uniform_dist": uniform,
            "write_burst": int(flags["write_burst"]),
            "dir_spread": int(flags["dir_spread"]),
            "rename_burst": int(flags["rename_burst"]),
            "suspicious_rename_target": int(flags["suspicious_rename_target"]),
            "header_mismatch": int(header_ok is False),
            "files_per_sec": flags["files_per_sec"],
            "extension_change_ratio": flags["extension_change_ratio"],
        }

        count_flag = (
            flags["write_burst"]
            or flags["files_per_sec"] > 0
            or flags["rename_burst"]
            or flags["extension_change_ratio"] > 0
            or entropy > 7.5
            or header_ok is False
        )
        if count_flag:
            self.unique_files.add(str(path))
            self.suspicious_event_count += 1
            if self.start_time is None:
                self.start_time = time.time()

        self.entropy_vals.append(entropy)
        self.uniform_vals.append(uniform)
        self.files_per_sec_vals.append(flags["files_per_sec"])
        self.extension_ratio_vals.append(flags["extension_change_ratio"])
        for key in self.seen:
            self.seen[key] = int(self.seen[key] or flags[key])

        prob = predict_proba(features)
        if prob > self.max_probability:
            self.max_probability = prob
            self.best_features = features.copy()

        active = [k for k, v in features.items() if v > 0]
        print(
            f"[PROB] {round(prob, 3)} | events={self.suspicious_event_count} "
            f"| flags={active} | {self.clean_name(path)}"
        )

        if prob > THRESHOLD and self.suspicious_event_count > MIN_SUSPICIOUS_EVENTS and not self.detected:
            print("RANSOMWARE DETECTED")
            self.detected = 1
            self.detection_time = time.time()
            self.files_at_detection = len(self.unique_files)
            self.kill()
