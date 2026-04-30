import math
from collections import Counter

RANSOM_EXTENSIONS = {".locked", ".enc", ".crypt", ".crypto"}


def shannon_entropy_bytes(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def file_entropy(path):
    with path.open("rb") as f:
        return shannon_entropy_bytes(f.read(100000))


def sample_bytes(path):
    with path.open("rb") as f:
        return f.read(4096)


def byte_histogram_probs(data):
    if not data:
        return [0.0] * 256
    counts = Counter(data)
    n = len(data)
    return [counts.get(i, 0) / n for i in range(256)]


def distance_to_uniform(probs):
    expected = 1 / 256
    return sum(abs(p - expected) for p in probs)


def _read_header(path, size=32):
    try:
        with path.open("rb") as f:
            return f.read(size)
    except Exception:
        return b""


def _effective_extension(path, expected_ext=None):
    if expected_ext:
        return expected_ext.lower()
    suffixes = [s.lower() for s in path.suffixes]
    if not suffixes:
        return ""
    if suffixes[-1] in RANSOM_EXTENSIONS and len(suffixes) >= 2:
        return suffixes[-2]
    return suffixes[-1]


def header_matches_expected(path, expected_ext=None):
    ext = _effective_extension(path, expected_ext)
    header = _read_header(path)
    if not header:
        return None

    if ext == ".pdf":
        return header.startswith(b"%PDF-")
    if ext == ".png":
        return header.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in (".jpg", ".jpeg"):
        return header.startswith(b"\xff\xd8\xff")
    if ext == ".gif":
        return header.startswith((b"GIF87a", b"GIF89a"))
    if ext in (".zip", ".docx", ".xlsx", ".pptx"):
        return header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
    if ext in (".mp4", ".m4v", ".mov"):
        return len(header) >= 8 and header[4:8] == b"ftyp"
    if ext == ".wav":
        return len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WAVE"
    if ext in (".exe", ".dll"):
        return header.startswith(b"MZ")
    return None
