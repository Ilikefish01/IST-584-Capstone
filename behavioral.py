import time
from collections import deque

BAD_EXTENSIONS = {".locked", ".enc", ".crypt", ".crypto"}


def is_suspicious_extension(ext):
    return ext.lower() in BAD_EXTENSIONS


class BehavioralTracker:
    def __init__(self, window=10):
        self.window = window
        self.writes = deque()
        self.renames = deque()

    def _prune(self):
        cutoff = time.time() - self.window
        while self.writes and self.writes[0][0] < cutoff:
            self.writes.popleft()
        while self.renames and self.renames[0][0] < cutoff:
            self.renames.popleft()

    def record_write(self, path):
        self.writes.append((time.time(), path))
        self._prune()

    def record_rename(self, src, dst):
        self.renames.append((time.time(), src, dst))
        self._prune()

    def flags(self):
        self._prune()
        files = {p for _, p in self.writes}
        dirs = {p.parent for p in files}
        suspicious = sum(is_suspicious_extension(dst.suffix) for _, _, dst in self.renames)
        nfiles = len(files) or 1

        return {
            "write_burst": len(files) > 8,
            "dir_spread": len(dirs) > 3,
            "rename_burst": suspicious > 3,
            "suspicious_rename_target": suspicious > 0,
            "files_per_sec": len(files) / self.window,
            "extension_change_ratio": suspicious / nfiles,
        }
