# README - Video Showcases

## Showcase 1: Benign and Anomalous Runs

This demo video shows two complete runs of the ransomware watcher prototype.
https://drive.google.com/file/d/1UE6Yr8K2HCCz7nfiEg_lM_0k96DqVK-9/view?usp=sharing

### 1. Benign Run

The benign run demonstrates normal filesystem activity being monitored without triggering ransomware detection.

The video shows:

- The watcher starting and monitoring the protected test folder.
- A benign mass-copy workload running.
- The watcher scoring the activity without triggering ransomware detection.
- The output being logged with:
  - `label = 0`
  - `detected = 0`

### 2. Anomalous Run

The anomalous run demonstrates ransomware-like behavior being detected by the watcher.

The video shows:

- The watcher starting again with the ransomware/anomalous label.
- The controlled anomalous simulator modifying and renaming files.
- The watcher detecting ransomware-like behavior using behavioral and content-based signals.
- The terminal displaying:

```text
RANSOMWARE DETECTED
```

- The output being logged with:
  - `label = 1`
  - `detected = 1`

### Additional Evidence

The screenshots provide additional evidence of:

- Project structure
- Model scoring code
- Threshold settings
- Terminal outputs
- Generated dataset logs

---

## Showcase 2: Ransomware Runs

This video demonstrates how the prototype responds during ransomware-style behavior.
https://drive.google.com/file/d/1EHuNRmb3uvMtMd4i_0OkZYmcnn6Q0SSd/view?usp=sharing

The video shows the following sequence:

### 1. Ransomware Running Normally

The controlled ransomware simulator runs without the watcher response stopping it immediately.

This shows that previously normal files are modified and renamed with the `.locked` extension.

### 2. Reset Script Running

The reset script is executed to restore the test folder.

This shows the files reverting back to their pre-ransomware version.

### 3. Watcher Running During Ransomware Activity

The watcher is started before running the ransomware simulator again.

This shows:

- The watcher monitoring the protected folder.
- The ransomware simulator beginning to modify and rename files.
- The watcher detecting ransomware-like behavior.
- Only a few files being encrypted before detection and response occur.
- The detection result being logged in the dataset output.

---
