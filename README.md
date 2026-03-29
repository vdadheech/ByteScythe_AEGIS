# 🛡️ Project AEGIS
### Cyber-Infrastructure Defense — Real-Time SOC Command Console

![FastAPI](https://img.shields.io/badge/FastAPI-Production-009688?style=flat-square&logo=fastapi&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white)
![WebSockets](https://img.shields.io/badge/Streaming-WebSockets-E95420?style=flat-square)
![scikit-learn](https://img.shields.io/badge/ML-Isolation%20Forest-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-120%2B%20Passing-brightgreen?style=flat-square)
![Coverage](https://img.shields.io/badge/Coverage-100%25-success?style=flat-square)

---

> **Nexus City is under attack.**  
> *Shadow Controller* — a rogue entity — is infiltrating critical infrastructure via deceptive payloads, schema mutations, and stealth malware.  
> **AEGIS** detects it. Adapts to it. Stops it.

---

## 📸 Demo

| Forensic Map | Anomaly Heatmap | Asset Registry |
|:---:|:---:|:---:|
| ![Map](assets/map.png) | ![Heatmap](assets/heatmap.png) | ![Table](assets/table.png) |

---

## ✨ What Makes AEGIS Different

This is not a static dashboard — it's a **production-grade, event-driven cyber defense system**.

| Feature | Detail |
|---|---|
| ⚡ Real-time streaming | WebSocket telemetry at **50ms intervals** |
| 🧠 Dynamic schema adaptation | V1 → V2 rotation with **zero downtime** |
| 🤖 ML anomaly detection | Unsupervised **Isolation Forest** model |
| 🎯 Live quarantine system | Click-to-contain with instant WebSocket feedback |
| 🧪 Production-grade testing | **120+ assertions, 100% passing** |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────┐
│              Frontend UI                 │
│        D3.js · Chart.js · Vanilla JS     │
└──────────┬────────────────┬──────────────┘
           │  REST (Control)│  WebSocket (Live Feed)
           ▼                ▼
┌──────────────────────────────────────────┐
│             FastAPI Backend              │
│  ┌──────────────────────────────────┐    │
│  │  API Layer  │  Streaming Engine  │    │
│  │  (Routes)   │  (50ms loop)       │    │
│  └──────────────────────────────────┘    │
│  ┌──────────────────────────────────┐    │
│  │  Schema Adapter  │  Threat Engine│    │
│  │  (V1 ↔ V2)      │  (Rules + ML)  │    │
│  └──────────────────────────────────┘    │
└─────────┬─────────────┬──────────────────┘
          │             │
   ┌──────┴───┐   ┌─────┴───────────┐
   │ SQLite   │   │   ML Engine     │
   │ Telemetry│   │ Isolation Forest│
   └──────────┘   └─────────────────┘
```

### Data Flow

```
SQLite DB → Streaming Engine (50ms) → Schema Adapter
         → Threat Detection (Rules + ML)
         → WebSocket Broadcast → Frontend Dashboard
         → User Action → REST API → DB Update → WebSocket Sync
```

---

## 🔍 Threat Detection

### Spoofing Detection
Catches payload mismatches where JSON status reads `"OPERATIONAL"` but HTTP response is `>= 400`.

### DDoS Detection
Identifies abnormal request frequency spikes by comparing against rolling network medians.

### Sleeper Malware (ML)
Isolation Forest flags latency anomalies exceeding **300% of baseline** — catching threats that rule-based logic misses.

---

## 🖥️ Dashboard

### 🌐 Forensic City Map
A physics-based D3.js node graph displaying live infrastructure state.

| Color | Status |
|---|---|
| 🟢 Green | Healthy |
| 🟡 Yellow | DDoS / Spoofing |
| 🔴 Red | Compromised |
| 🟣 Purple | Quarantined |

### ⚡ One-Click Quarantine

```
Click 🔴 node  →  Open Inspector  →  [ QUARANTINE NODE ]
  →  POST /api/nodes/{id}/quarantine
  →  DB Updated  →  WebSocket Broadcast  →  Node turns 🟣
```

### 🔥 Sleeper Heatmap
Chart.js visualization tracking anomaly intensity over time.

### 📊 Asset Registry
Live-updating table with decoded serials and threat scores.

---

### 🛠️ Tech Stack

* **Backend:** Python (FastAPI)
* **Database:** SQLAlchemy, SQLite
* **Frontend:** React.js, TypeScript, Vite, CSS Modules
* **Analysis:** NumPy, Pandas, Scikit-learn (Isolation Forest)
* **DevOps:** Pytest for backend testing

---

## 📁 Project Structure

```
aegis-console/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── db/
│   │   └── seed_db.py       # Database seeding
│   ├── engine/
│   │   └── detection.py     # Streaming + threat engine
│   └── requirements.txt
├── frontend-react/          # React.js dashboard powered by Vite
│   ├── src/
│   │   ├── api/             # WebSocket and REST client logic
│   │   ├── components/      # Reusable UI components
│   │   ├── sections/        # Major dashboard modules (Map, Console, etc.)
│   │   └── styles/          # Global and modular CSS
├── data/
├── logs/
├── .env.example
├── start.bat
└── README.md
```

---

## 🚀 Getting Started

### Option A — One-Click (Windows)
```bash
start.bat
```

### Option B — Manual Setup

> ⚠️ All backend commands must be run from the `backend/` directory.

**1. Install dependencies**
```bash
cd backend
pip install -r requirements.txt
```

**2. Seed the database**
```bash
python -m db.seed_db
```

**3. Start the detection engine**
```bash
python -m engine.detection
```

**4. Run the backend**
```bash
uvicorn main:app --reload
```

**5. Serve the frontend** *(in a new terminal)*
```bash
cd ../frontend
python -m http.server 8080
```

**6. Open the dashboard**
```
http://localhost:8080
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

```
✔ 120+ assertions
✔ 100% passing
```


## 🏁 Summary

AEGIS is a **live cyber-defense system** — not a prototype, not a demo.  
It streams real data, adapts to changing schemas, detects threats intelligently, and lets operators respond in real time.

> 🛡️ **Detect. Adapt. Defend.**
