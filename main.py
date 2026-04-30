import sys
import time
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from watchdog.observers import Observer
from watcher import DetectorHandler

WATCH_PATH = Path(r"C:\Users\kritt\Desktop\PSU\Term 8\IST 584\TestFolder").resolve()


def main():
    if not WATCH_PATH.exists():
        raise FileNotFoundError(f"Watch folder not found: {WATCH_PATH}")

    print("Enter run type:\n0 = benign\n1 = ransomware")
    label = int(input("Label: "))
    print(f"\nWatching: {WATCH_PATH}\nPress Ctrl+C to stop.\n")

    handler = DetectorHandler(label=label)
    observer = Observer()
    observer.schedule(handler, str(WATCH_PATH), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping...")
        observer.stop()
        handler.save_dataset()

    observer.join()


if __name__ == "__main__":
    main()
