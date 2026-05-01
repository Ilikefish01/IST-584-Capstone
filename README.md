# Real-Time Ransomware Watcher

## What This Is

Real-Time Ransomware Watcher is a local Python-based security prototype that monitors a protected folder for ransomware-like filesystem behavior.

Instead of relying on known malware signatures, the watcher looks for suspicious file activity such as rapid writes, suspicious renames, extension changes, header mismatches, and encrypted-looking file content. It then scores the activity using a logistic risk model and can terminate the suspicious process when the risk score crosses a set threshold.

This software is designed as a local defensive monitoring tool and proof of concept. It is not meant to replace an antivirus, but as another layer of precaution.

## What It Does

The watcher performs five main tasks:

1. Monitors a target folder in real time.
2. Extracts behavioral and content-based features from file events.
3. Calculates a ransomware probability score.
4. Logs event and detection data to a CSV file.
5. Responds when ransomware-like behavior is detected.

## Main Files

| File | Purpose |
|---|---|
| `main.py` | Starts the watcher and selects the run label |
| `watcher.py` | Main detection engine for monitoring, scoring, logging, and response |
| `behavioral.py` | Tracks write bursts, rename bursts, directory spread, and file activity rate (what the file is) |
| `content.py` | Calculates entropy, byte distribution, and file header mismatch (what is happening to the file) |
| `model.py` | Converts extracted features into a ransomware probability score |

## How It Works

### 1. Folder Monitoring

The watcher monitors a target folder using Python’s `watchdog` library. When a file is created, modified, renamed, or moved, the watcher receives a filesystem event and processes it.

The watched folder is set in `main.py`:

```python
WATCH_PATH = Path(r"C:\Users\dummy\Desktop\dummyFolder").resolve()
```

Change this path if you want to monitor a different folder.

---

### 2. Behavioral Analysis

The watcher tracks filesystem behavior over a 10-second sliding window.

It checks for behavior such as:

- Many files being modified quickly
- Files being renamed to suspicious extensions
- Activity spreading across multiple folders
- High file-change rate
- Repeated rename activity

These signals are generated in `behavioral.py`.

Behavioral features include:

| Feature | Meaning |
|---|---|
| `write_burst` | Many unique files were modified within the time window |
| `dir_spread` | File activity spread across multiple folders |
| `rename_burst` | Multiple suspicious renames occurred |
| `suspicious_rename_target` | A file was renamed to a suspicious extension |
| `files_per_sec` | Rate of file modifications |
| `extension_change_ratio` | Ratio of suspicious renames to total modified files |

---

### 3. Content Analysis

The watcher also analyzes file content.

It checks:

- Shannon entropy
- Byte distribution uniformity
- Whether the file header matches the expected file type

For example, if a file still has a `.pdf` extension but no longer starts with a valid PDF header, the watcher treats that as suspicious.

These checks are handled in `content.py`.

Content features include:

| Feature | Meaning |
|---|---|
| `entropy` | Measures randomness in file bytes |
| `uniform_dist` | Measures how close byte distribution is to uniform randomness |
| `header_mismatch` | Detects when file content does not match the expected file type |

---

### 4. Risk Scoring

The extracted features are passed into `model.py`, which calculates a ransomware probability score.

The model uses a weighted logistic scoring function:

```text
P(ransomware) = sigmoid(bias + weighted feature sum)
```

Each feature contributes to the final probability score. A higher score means the current activity looks more like ransomware.

---

### 5. Detection and Response

The detection settings are controlled in `watcher.py`:

```python
THRESHOLD = 0.5
MIN_SUSPICIOUS_EVENTS = 0
QUIET_PERIOD = 0.3
```

If the ransomware probability score is above the threshold and the suspicious event condition is met, the watcher marks ransomware as detected.

When detection occurs, the watcher:

- Prints `RANSOMWARE DETECTED`
- Records detection details
- Saves a row to `logs/dataset.csv`
- Attempts to terminate suspicious Python processes

---

## Important Safety Note

The current response logic is designed for a controlled prototype environment.

When ransomware-like behavior is detected, the watcher attempts to terminate other running `python.exe` processes. This was designed for a test setup where the ransomware simulator runs as a Python process.

Do not run this watcher on a production machine or on a system where important Python processes are running.

---

## Requirements

Install the required Python packages:

```bash
pip install watchdog psutil
```

The watcher uses:

- Python 3
- `watchdog`
- `psutil`
- Standard Python libraries

---

## How to Use

### 1. Place the Files Together

Make sure these files are in the same project folder:

```text
main.py
watcher.py
behavioral.py
content.py
model.py
```

---

### 2. Set the Folder to Monitor

Open `main.py` and update the watched folder path if needed:

```python
WATCH_PATH = Path(r"C:\Users\dummy\Desktop\dummyFolder").resolve()
```

The folder must exist before starting the watcher.

---

### 3. Start the Watcher

Run:

```bash
python main.py
```

The program will ask for a run label (this can be skipped if not using for tests):

```text
Enter run type:
0 = benign
1 = ransomware
Label:
```

Enter:

```text
0
```

for a benign run, or:

```text
1
```

for a ransomware/anomalous run.

This label is used for logging the run in the CSV output.

---

### 4. Leave the Watcher Running

After starting, the watcher monitors the selected folder continuously.

Example output:

```text
Watching: "C:\Users\dummy\Desktop\dummyFolder"
Press Ctrl+C to stop.
```

As file events occur, the watcher prints probability scores and active feature flags.

Example:

```text
[PROB] 0.742 | events=3 | flags=['files_per_sec', 'header_mismatch'] | report.docx
```

---

### 5. Stop the Watcher

Press:

```text
Ctrl+C
```

When stopped, the watcher saves the current run data to:

```text
logs/dataset.csv
```

---

## Output

The watcher creates a `logs` folder and writes detection data to:

```text
logs/dataset.csv
```

The CSV includes:

| Column | Description |
|---|---|
| `label` | User-provided run label: benign or ransomware |
| `detected` | Whether ransomware-like behavior was detected |
| `files_changed` | Number of unique files involved in suspicious activity |
| `files_before_detection` | Number of files changed before detection triggered |
| `time_to_detect_sec` | Time from first suspicious event to detection |
| `max_probability` | Highest ransomware probability score during the run |
| `entropy` | Entropy value from the highest-risk event |
| `uniform_dist` | Byte-distribution uniformity score |
| `write_burst` | Whether a write burst was active |
| `dir_spread` | Whether activity spread across directories |
| `rename_burst` | Whether repeated suspicious renames occurred |
| `suspicious_rename_target` | Whether a suspicious rename target was observed |
| `header_mismatch` | Whether file header mismatch was detected |
| `files_per_sec` | File modification rate |
| `extension_change_ratio` | Ratio of suspicious extension changes |
| `entropy_mean` | Average entropy across observed events |
| `entropy_max` | Maximum entropy observed |
| `uniform_mean` | Average uniform distribution score |
| `files_per_sec_max` | Maximum file activity rate |
| `write_burst_seen` | Whether any write burst occurred |
| `dir_spread_seen` | Whether any directory spread occurred |
| `rename_burst_seen` | Whether any rename burst occurred |
| `suspicious_rename_target_seen` | Whether any suspicious rename target occurred |
| `extension_change_ratio_max` | Maximum suspicious extension-change ratio |
| `header_mismatch_count` | Number of header mismatches observed |

---

## Example Workflow

Start the watcher:

```bash
python main.py
```

Enter a label when prompted:

```text
0
```

Then interact with files inside the watched folder. The watcher will monitor the activity, calculate risk scores, print output to the terminal, and save a dataset row when stopped.

---

## Configuration

The main detection settings are in `watcher.py`.

```python
THRESHOLD = 0.5
MIN_SUSPICIOUS_EVENTS = 0
QUIET_PERIOD = 0.3
```

| Setting | Meaning |
|---|---|
| `THRESHOLD` | Probability required to trigger detection |
| `MIN_SUSPICIOUS_EVENTS` | Minimum suspicious event count required before detection |
| `QUIET_PERIOD` | Time to wait before automatically saving after detection |

Model weights are stored in `model.py`.

---

## Limitations

This watcher is a prototype, not a production-ready security product.

Current limitations include:

- The watched folder path is manually configured.
- The process termination logic is simplified.
- The watcher is designed for local controlled use.
- The model may miss some ransomware-like behavior.
- The model may need recalibration for different machines or folders.
- The watcher operates at the user-space level, so very fast attacks may modify files before detection occurs.
- The current response logic targets Python processes because the prototype was tested in a controlled Python-based environment.

---

## Ethical Use Notice

This project is for educational and defensive cybersecurity research only.

The watcher should only be used in a controlled environment and should not be used on production systems, shared machines, or folders containing important data.

---
