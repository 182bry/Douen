---

#  AI-Powered Security Operations Centre (SOC)

An end-to-end intrusion detection pipeline that processes network flow data, detects attacks using machine learning, handles class imbalance with synthetic data, and integrates into a live Flask dashboard.

---

##  Overview

This project implements a **Security Operations Centre (SOC)** system that:

* Processes network flow data (CICIDS2017)
* Detects malicious traffic using machine learning
* Improves rare attack detection using **CTGAN**
* Uses a **specialist + ensemble model** for weak classes
* Detects unknown attacks via **anomaly detection (Isolation Forest)**
* Displays results in a **real-time dashboard (Flask + Streamlit-style UI)**

---

##  Key Features

* Multi-class intrusion detection (XGBoost)
*  Binary classification (benign vs malicious)
*  CTGAN synthetic data generation for minority classes
*  Specialist model for web-based attacks
*  Ensemble system with intelligent routing
*  Isolation Forest for anomaly (zero-day) detection
*  Alert correlation + dashboard visualization
*  Live ingestion via API (`/api/ingest`)
*  Simulator for generating network flows

---

##  Architecture

```text
CICIDS2017 Data
        ↓
Preprocessing + Feature Engineering
        ↓
General Model (XGBoost)
        ↓
CTGAN (Synthetic Data)
        ↓
Specialist Model (Web Attacks)
        ↓
Ensemble Routing (Confidence + Labels)
        ↓
Anomaly Detection (Isolation Forest)
        ↓
Flask API (/api/ingest)
        ↓
Dashboard + Alerts + LLM Insight
```

---

##  Dataset

* **CICIDS2017**
* ~2.8 million network flow records
* Includes:

  * DoS / DDoS
  * Brute force (FTP/SSH)
  * Web attacks (XSS, SQL Injection)
  * Infiltration

---

## Problem Addressed

### Class Imbalance

* BENIGN ≈ 99% of dataset
* Rare attacks (e.g. SQLInjection) have extremely few samples

 Baseline models ignore these classes (F1 ≈ 0.0)

---

##  Solution Approach

### 1. CTGAN

* Generates synthetic samples for minority classes
* Preserves feature relationships (better than SMOTE)

---

### 2. Specialist Model

Focused on:

* WebAttack_BruteForce
* WebAttack_XSS
* WebAttack_SQLInjection
* Infiltration

---

### 3. Ensemble Model

Routing logic:

* If general model predicts web attack → use specialist
* If model confidence is low → use specialist

---

### 4. Anomaly Detection

* Isolation Forest trained on BENIGN data
* Detects unknown or zero-day attacks

---

## 📈 Results

| Metric      | Value   |
| ----------- | ------- |
| Accuracy    | ~0.998  |
| Weighted F1 | ~0.9982 |

### Per-Class Improvements

| Attack        | Before | After |
| ------------- | ------ | ----- |
| SQL Injection | 0.20   | 0.50  |
| XSS           | 0.34   | 0.37  |

 Improvements are focused on **rare, high-risk attacks**

---

##  Project Structure

```text
Douen/
│
├── src/                        # ML pipeline
│   ├── ingest.py
│   ├── preprocess.py
│   ├── train_model.py
│   ├── train_ctgan.py
│   ├── train_specialist_model.py
│   ├── ensemble.py
│   ├── run_pipeline.py
│
├── App/                        # Flask application
│   ├── services/
│   │   ├── model_service.py
│   │   ├── ingest_service.py
│   │   ├── state.py
│   │
│   ├── views/
│   ├── templates/
│   ├── static/
│   ├── trained_models/
│
├── data/
│   ├── raw/
│   ├── processed/
│
├── models/                     # Local trained models (not committed)
├── notebooks/
├── simulator/
└── README.md
```

---

##  Setup

### 1. Clone repo

```bash
git clone https://github.com/your-repo/Douen.git
cd Douen
```

---

### 2. Create virtual environment

```bash
python -m venv .venv
.\.venv\Scripts\Activate   # Windows
```

---

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

##  Running the Pipeline

### Full pipeline:

```bash
python -m src.run_pipeline
```

---

### From CTGAN stage:

```bash
python -m src.run_pipeline --from ctgan_augmentation --force
```

---

### Evaluate ensemble:

```bash
python -m src.run_pipeline --only evaluate_ensemble --force
```

---

##  Running the App

```bash
python run.py
```

Then open:

```text
http://127.0.0.1:5000/
```

---

##  API Usage

### Ingest flows

```http
POST /api/ingest
```

Example:

```json
{
  "flows": [
    {
      "src_port": 1234,
      "dst_port": 80,
      "packet_rate": 200,
      "total_packets": 150
    }
  ]
}
```

---

##  Simulator

Run:

```bash
python simulator/simulate_sender.py
```

Generates synthetic traffic and sends to:

```text
/api/ingest
```

---

##  LLM Integration

* Generates real-time insights based on alerts
* Uses OpenAI-compatible API
* Optional (configure in dashboard)

---

## Limitations

* Synthetic data quality depends on real samples
* Rare classes still difficult to generalize
* Slight temporal leakage due to seeding
* Not fully real-time (batch processing)

---

##  Future Work

* Cross-dataset evaluation (UNSW, CTU-13)
* Real-time streaming pipeline
* Improved anomaly detection
* Automated retraining pipeline

---

##  License

For academic use only.

---

##  Final Insight

> This project demonstrates that improving detection of rare attacks is more important than improving overall accuracy.

---

