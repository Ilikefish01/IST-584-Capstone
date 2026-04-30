import argparse
import json
import random
import shutil
import string
import time
import zipfile
from pathlib import Path

DEFAULT_ROOT = Path(r"C:\Users\kritt\Desktop\PSU\Term 8\IST 584\TestFolder")
WORKSPACE_NAME = "__benign_sim__"
SUSPICIOUS_SUFFIXES = {".locked", ".enc", ".crypt", ".crypto"}
TEXT_EXTENSIONS = {".txt", ".csv", ".json", ".log", ".md", ".ini", ".cfg", ".xml", ".html", ".py"}


class BenignWorkloadGenerator:
    def __init__(self, root, scenario, intensity=1, min_delay=0.003, max_delay=0.02, seed=None, max_source_files=500, max_file_size_mb=25):
        self.root = root.resolve()
        self.workspace = self.root / WORKSPACE_NAME
        self.logs_dir = self.workspace / "logs"
        self.scenario = scenario
        self.intensity = max(1, intensity)
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.rng = random.Random(seed)
        self.max_source_files = max_source_files
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.run_id = time.strftime("%Y%m%d_%H%M%S")
        self.run_dir = self.workspace / f"run_{self.run_id}"
        self.manifest = []

        if not self.root.exists():
            raise FileNotFoundError(f"Root folder not found: {self.root}")

        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.source_files = self._collect_source_files()
        if not self.source_files:
            raise RuntimeError(f"No usable source files found under {self.root}")

    def _collect_source_files(self):
        files = []
        for path in self.root.rglob("*"):
            if not path.is_file() or self.workspace in path.parents:
                continue
            if any(s.lower() in SUSPICIOUS_SUFFIXES for s in path.suffixes):
                continue
            try:
                if path.stat().st_size <= self.max_file_size_bytes:
                    files.append(path)
            except OSError:
                pass
        files.sort()
        return self.rng.sample(files, self.max_source_files) if len(files) > self.max_source_files else files

    def _sleep(self):
        time.sleep(self.rng.uniform(self.min_delay, self.max_delay))

    def _record(self, action, src=None, dst=None, extra=None):
        self.manifest.append({"ts": round(time.time(), 6), "action": action, "src": src, "dst": dst, "extra": extra})

    def _token(self, n=6):
        return "".join(self.rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))

    def _scale(self, n):
        return max(1, n * self.intensity)

    def _pick_files(self, count, require_text=False):
        candidates = self.source_files
        if require_text:
            candidates = [p for p in candidates if p.suffix.lower() in TEXT_EXTENSIONS]
        return self.rng.sample(candidates, min(count, len(candidates))) if candidates else []

    def _dirs(self, base, count):
        dirs = []
        for i in range(count):
            d = base / f"group_{i + 1:02d}"
            d.mkdir(parents=True, exist_ok=True)
            dirs.append(d)
        return dirs

    def _safe_name(self, src, prefix="", suffix=""):
        return f"{prefix}{src.stem}_{self._token()}{suffix}{src.suffix}"

    def _retry(self, fn, attempts=12):
        for i in range(attempts):
            try:
                return fn()
            except (PermissionError, OSError):
                if i == attempts - 1:
                    raise
                time.sleep(0.03 * (i + 1))

    def _copy(self, src, dst):
        dst.parent.mkdir(parents=True, exist_ok=True)
        self._retry(lambda: shutil.copy2(src, dst))
        self._record("copy", str(src), str(dst))
        self._sleep()

    def _write(self, dst, lines):
        dst.parent.mkdir(parents=True, exist_ok=True)
        self._retry(lambda: dst.write_text("\n".join(lines) + "\n", encoding="utf-8"))
        self._record("write_text", None, str(dst), {"lines": len(lines)})
        self._sleep()

    def _append(self, dst, lines):
        def op():
            with dst.open("a", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        self._retry(op)
        self._record("append_text", str(dst), str(dst), {"lines": len(lines)})
        self._sleep()

    def _rename(self, src, dst):
        dst.parent.mkdir(parents=True, exist_ok=True)
        self._retry(lambda: src.rename(dst))
        self._record("rename", str(src), str(dst))
        self._sleep()

    def _move(self, src, dst):
        dst.parent.mkdir(parents=True, exist_ok=True)
        self._retry(lambda: shutil.move(str(src), str(dst)))
        self._record("move", str(src), str(dst))
        self._sleep()

    def _delete(self, path):
        if path.exists():
            self._retry(lambda: path.unlink())
            self._record("delete", str(path), None)
            self._sleep()

    def _stage_files(self, folder, count, prefix="stage_"):
        folder.mkdir(parents=True, exist_ok=True)
        staged = []
        for src in self._pick_files(count):
            dst = folder / self._safe_name(src, prefix=prefix)
            self._copy(src, dst)
            staged.append(dst)
        return staged

    def scenario_mass_copy(self):
        files = self._pick_files(self._scale(25))
        targets = self._dirs(self.run_dir / "mass_copy", max(3, self.intensity + 2))
        print(f"[SCENARIO] mass_copy | files={len(files)} | dirs={len(targets)}")
        for i, src in enumerate(files):
            self._copy(src, targets[i % len(targets)] / self._safe_name(src, prefix="copy_"))

    def _make_zip(self, archive_path, files):
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for src in files:
                zf.write(src, arcname=f"{src.parent.name}_{src.name}")
        self._record("zip_create", None, str(archive_path), {"members": len(files)})
        self._sleep()

    def scenario_mass_zip(self):
        folder = self.run_dir / "mass_zip"
        folder.mkdir(parents=True, exist_ok=True)
        print(f"[SCENARIO] mass_zip")
        for i in range(self._scale(4)):
            self._make_zip(folder / f"archive_{i + 1:02d}_{self._token()}.zip", self._pick_files(self._scale(6)))

    def scenario_mass_extract(self):
        prep = self.run_dir / "mass_extract"
        zips = prep / "archives"
        out = prep / "extracted"
        zips.mkdir(parents=True, exist_ok=True)
        out.mkdir(parents=True, exist_ok=True)
        print(f"[SCENARIO] mass_extract")
        archives = []
        for i in range(self._scale(3)):
            archive = zips / f"batch_{i + 1:02d}_{self._token()}.zip"
            self._make_zip(archive, self._pick_files(self._scale(5)))
            archives.append(archive)
        for archive in archives:
            target = out / archive.stem
            target.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(archive, "r") as zf:
                zf.extractall(target)
            self._record("zip_extract", str(archive), str(target))
            self._sleep()

    def scenario_mass_delete(self):
        staged = self._stage_files(self.run_dir / "mass_delete_stage", self._scale(30))
        print(f"[SCENARIO] mass_delete | staged_files={len(staged)}")
        for path in self.rng.sample(staged, max(1, int(len(staged) * 0.8))):
            self._delete(path)

    def scenario_mass_move(self):
        staged = self._stage_files(self.run_dir / "mass_move" / "incoming", self._scale(24), "incoming_")
        targets = self._dirs(self.run_dir / "mass_move" / "sorted", max(4, self.intensity + 3))
        print(f"[SCENARIO] mass_move | files={len(staged)}")
        self.rng.shuffle(staged)
        for i, src in enumerate(staged):
            self._move(src, targets[i % len(targets)] / src.name)

    def scenario_mass_rename(self):
        staged = self._stage_files(self.run_dir / "mass_rename", self._scale(28), "original_")
        print(f"[SCENARIO] mass_rename | files={len(staged)}")
        for src in staged:
            self._rename(src, src.with_name(f"{src.stem}_reviewed_{self._token()}{src.suffix}"))

    def scenario_bulk_append(self):
        folder = self.run_dir / "bulk_append"
        folder.mkdir(parents=True, exist_ok=True)
        total = self._scale(22)
        staged = []
        print(f"[SCENARIO] bulk_append | target_files={total}")
        for i, src in enumerate(self._pick_files(total, require_text=True)):
            dst = folder / f"editable_{i + 1:02d}_{self._token()}{src.suffix}"
            self._copy(src, dst)
            staged.append(dst)
        while len(staged) < total:
            dst = folder / f"generated_{len(staged) + 1:02d}_{self._token()}.txt"
            self._write(dst, [f"generated line {i}" for i in range(1, 6)])
            staged.append(dst)
        for dst in staged:
            self._append(dst, [f"timestamp={time.time()}", f"note=benign edit {self._token(8)}", "user_action=append"])

    def scenario_temp_churn(self):
        folder = self.run_dir / "temp_churn"
        folder.mkdir(parents=True, exist_ok=True)
        total = self._scale(35)
        print(f"[SCENARIO] temp_churn | temp_files={total}")
        created = []
        for i in range(total):
            dst = folder / f"temp_{i + 1:03d}_{self._token()}.tmp"
            self._write(dst, ["temporary build artifact", f"id={self._token(10)}", f"ts={time.time()}"])
            created.append(dst)
        renamed = []
        for src in self.rng.sample(created, max(1, total // 2)):
            dst = src.with_name(f"{src.stem}_cache.log")
            self._rename(src, dst)
            renamed.append(dst)
        delete_pool = renamed + [p for p in created if p.exists()]
        for path in self.rng.sample(delete_pool, max(1, int(len(delete_pool) * 0.7))):
            self._delete(path)

    def scenario_backup_snapshot(self):
        files = self._pick_files(self._scale(40))
        folder = self.run_dir / "backup_snapshot"
        print(f"[SCENARIO] backup_snapshot | files={len(files)}")
        for src in files:
            self._copy(src, folder / src.parent.name / self._safe_name(src, prefix="backup_"))

    def scenario_mixed(self):
        print("[SCENARIO] mixed")
        for action in self.rng.sample([
            self.scenario_mass_copy,
            self.scenario_mass_zip,
            self.scenario_mass_move,
            self.scenario_mass_rename,
            self.scenario_bulk_append,
            self.scenario_temp_churn,
        ], 3):
            action()

    def save_manifest(self):
        path = self.logs_dir / f"benign_run_{self.run_id}.json"
        payload = {
            "run_id": self.run_id,
            "scenario": self.scenario,
            "root": str(self.root),
            "workspace": str(self.workspace),
            "run_dir": str(self.run_dir),
            "intensity": self.intensity,
            "source_file_count": len(self.source_files),
            "actions": self.manifest,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"[LOG] Manifest written to: {path}")

    def run(self):
        scenarios = {
            "mass_copy": self.scenario_mass_copy,
            "mass_zip": self.scenario_mass_zip,
            "mass_extract": self.scenario_mass_extract,
            "mass_delete": self.scenario_mass_delete,
            "mass_move": self.scenario_mass_move,
            "mass_rename": self.scenario_mass_rename,
            "bulk_append": self.scenario_bulk_append,
            "temp_churn": self.scenario_temp_churn,
            "backup_snapshot": self.scenario_backup_snapshot,
            "mixed": self.scenario_mixed,
        }
        if self.scenario == "random":
            self.scenario = self.rng.choice(list(scenarios))
            print(f"[INFO] Randomly selected scenario: {self.scenario}")
        if self.scenario not in scenarios:
            raise ValueError(f"Unknown scenario: {self.scenario}")

        started = time.time()
        scenarios[self.scenario]()
        elapsed = round(time.time() - started, 3)
        self._record("run_complete", None, None, {"scenario": self.scenario, "elapsed_sec": elapsed})
        self.save_manifest()
        print(f"\n[SUMMARY]\n  scenario: {self.scenario}\n  run_dir: {self.run_dir}\n  actions recorded: {len(self.manifest)}\n  elapsed_sec: {elapsed}")


def build_parser():
    p = argparse.ArgumentParser(description="Generate benign filesystem activity.")
    p.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    p.add_argument("--scenario", default="random", choices=[
        "random", "mass_copy", "mass_zip", "mass_extract", "mass_delete", "mass_move",
        "mass_rename", "bulk_append", "temp_churn", "backup_snapshot", "mixed",
    ])
    p.add_argument("--intensity", type=int, default=1)
    p.add_argument("--min-delay", type=float, default=0.003)
    p.add_argument("--max-delay", type=float, default=0.02)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--max-source-files", type=int, default=500)
    p.add_argument("--max-file-size-mb", type=int, default=25)
    return p


def main():
    args = build_parser().parse_args()
    BenignWorkloadGenerator(
        args.root,
        args.scenario,
        args.intensity,
        args.min_delay,
        args.max_delay,
        args.seed,
        args.max_source_files,
        args.max_file_size_mb,
    ).run()


if __name__ == "__main__":
    main()
