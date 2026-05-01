# README - Video Showcases

## Showcase 1: Benign and Anomalous Runs

This demo video shows two complete runs of the ransomware watcher prototype.

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