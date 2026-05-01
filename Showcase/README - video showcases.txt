README - video showcases:


Showcase for benign and anomalous runs

The demo video shows two complete runs:

1. Benign run
   - The watcher starts and monitors the protected test folder.
   - A benign mass-copy workload runs.
   - The watcher scores the activity but does not trigger ransomware detection.
   - The output is logged with `label = 0` and `detected = 0`.

2. Anomalous run
   - The watcher starts again with the ransomware/anomalous label.
   - The controlled anomalous simulator modifies and renames files.
   - The watcher detects ransomware-like behavior using behavioral and content-based signals.
   - The terminal shows `RANSOMWARE DETECTED`.
   - The output is logged with `label = 1` and `detected = 1`.

The screenshots provide additional evidence of the project structure, model scoring code, threshold settings, terminal outputs, and generated dataset logs.



Showcase for ransomware runs

The video shows the following runs:

Ransomware running normally, showing that the previously normal files now have a .locked extension on them
Reset script running, showing the files reverting back to their pre ransomware version
Watcher running, then running the ransomware, showing that only a few files were encrypted before 