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
