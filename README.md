# 🛠️ System Health Monitor – Cross Platform Utility

## ✅ Overview

This is a lightweight, cross-platform system utility that monitors system health metrics, reports changes to a remote API, and runs as a background daemon. It supports:

- ✅ Disk encryption status
- ✅ OS update status
- ✅ Antivirus presence and state
- ✅ Inactivity sleep settings (should be ≤ 10 mins)

## 📦 Deliverables

- ✅ **System Utility** – macOS implemented, tested, and ready.
- 🔁 **Daemon Mode** – Periodically checks system health and reports on change.
- ✅ Dry-run mode for testing without daemon.
- 📊 Detailed logging and memory optimization (≤ 50 MB).
- 📤 Sends secure POST request to API on status change.

---

## 🚀 How to Run

### 1. Setup Environment

```bash
python3 -m venv system_monitor
source system_monitor/bin/activate
pip install -r requirements.txt
```
### 2. Run Dry Test (no daemon)
```bash
python3 system_monitor.py --dry-run
```
### 3. Start as Background Daemon
```bash
nohup python3 system_monitor.py > monitor.log 2>&1 &
```
### 4. Kill Background Process
```bash
ps aux | grep system_monitor.py
kill <PID>
```
## Screenshot
<img width="877" height="126" alt="image" src="https://github.com/user-attachments/assets/c9b77a93-c565-49a9-a18c-58568ffbc4e1" />
<img width="877" height="126" alt="image" src="https://github.com/user-attachments/assets/bc12c690-8a77-4fd2-8ccc-5aa214f65fd3" />


