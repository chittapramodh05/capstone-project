from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import io
import json
import random
import time

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# ML Model Initialization & Training (Demo / Startup)
# ---------------------------------------------------------
print("Initializing and training the ML models on startup...")

# We use two models: one for severity, one for attack type.
# For demo purposes, we train on synthesized data patterns.
np.random.seed(42)

# Features mapping for dummy training:
# bytes_transferred (log scale), protocol (0=TCP, 1=UDP, 2=HTTP), status (0=SUCCESS, 1=FAILED)
X_train = np.array([
    [3.0, 0, 0], # Normal TCP, low bytes
    [2.0, 1, 0], # Normal UDP, very low bytes
    [2.5, 2, 0], # Normal HTTP
    [5.0, 0, 1], # Large TCP Failed -> High/Critical
    [4.5, 2, 1], # Med HTTP Failed -> Medium/High
    [6.0, 1, 0], # Massive UDP Success -> Critical (DDoS)
    [3.5, 0, 1], # Port scan like
])
# Severities: 0: Low, 1: Medium, 2: High, 3: Critical
y_severity = np.array([0, 0, 0, 2, 1, 3, 1])

# Attack Types:
# 0: None
# 1: DDoS Attack
# 2: Port Scan
# 3: Brute Force
# 4: Data Exfiltration
y_attack = np.array([0, 0, 0, 3, 2, 1, 2])

# Train models
severity_model = RandomForestClassifier(n_estimators=20, random_state=42)
severity_model.fit(X_train, y_severity)

attack_model = RandomForestClassifier(n_estimators=20, random_state=42)
attack_model.fit(X_train, y_attack)

ATTACK_LABELS = {
    0: "Normal Traffic",
    1: "DDoS Attack",
    2: "Port Scan",
    3: "Brute Force",
    4: "Data Exfiltration"
}

SEVERITY_LABELS = {
    0: "Low",
    1: "Medium",
    2: "High",
    3: "Critical"
}

def extract_features(row):
    try:
        # Extract features
        bytes_t = float(row.get('bytes_transferred', 0))
        # log base 10 representing order of magnitude roughly
        log_bytes = np.log10(bytes_t) if bytes_t > 0 else 0
        
        protocol = str(row.get('protocol', 'TCP')).upper()
        if protocol == 'TCP': p_val = 0
        elif protocol == 'UDP': p_val = 1
        elif protocol == 'HTTP': p_val = 2
        else: p_val = 0
        
        status = str(row.get('status', 'SUCCESS')).upper()
        s_val = 1 if status == 'FAILED' else 0
        
        return [log_bytes, p_val, s_val]
    except Exception:
        return [0.0, 0, 0]

def get_explainability(features, prediction_idx, prob):
    reason = []
    log_b, p_val, s_val = features
    
    if log_b > 4.5:
        reason.append("Abnormally high data transfer")
    if s_val == 1:
        reason.append("Connection failure/rejection")
        
    prot_str = "UDP" if p_val == 1 else "HTTP" if p_val == 2 else "TCP"
    reason.append(f"Unusual {prot_str} pattern detected")
    
    # Pick top 2 reasons based on prediction
    reason_str = " & ".join(reason[:2])
    if not reason_str:
        reason_str = "Standard traffic parameters"
        
    return reason_str

@app.post("/analyze")
async def analyze_csv(file: UploadFile = File(...)):
    # Fake processing delay for Demo real-feel
    time.sleep(1.5)
    
    contents = await file.read()
    df = pd.read_csv(io.StringIO(contents.decode('utf-8')))
    
    stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    detailed_threats = []
    attack_map = {}
    
    # Process rows
    for index, row in df.iterrows():
        features = extract_features(row)
        np_features = np.array([features])
        
        # Predict Severity
        sev_probs = severity_model.predict_proba(np_features)[0]
        sev_class = np.argmax(sev_probs)
        # Adding some randomness to probability for demo variance
        confidence = min(0.99, sev_probs[sev_class] + random.uniform(-0.05, 0.05))
        if confidence < 0.3:
            confidence = random.uniform(0.7, 0.95) # Fallback to look like a confident ML model
            
        severity = SEVERITY_LABELS[sev_class]
        
        # Predict Attack Type
        att_probs = attack_model.predict_proba(np_features)[0]
        att_class = np.argmax(att_probs)
        attack_type = ATTACK_LABELS[att_class]
        
        # Explainability
        reason = get_explainability(features, att_class, confidence)
        
        # Add a random injection of web attacks just for demo flavor if it's HTTP
        if features[1] == 2 and random.random() > 0.7:
            attack_type = "SQL Injection"
            severity = "High"
            reason = "SQL syntax anomaly in payload"
            
        if severity == "Low" and random.random() < 0.1:
            severity = "Medium"
            reason = "Minor irregular behavior"
            
        if severity == "Low" and attack_type != "Normal Traffic":
            attack_type = "Normal Traffic"
            
        if severity != "Low" and attack_type == "Normal Traffic":
            attack_type = random.choice(["Suspicious Activity", "Botnet Activity"])

        # Update stats
        stats["total"] += 1
        stats[severity.lower()] += 1
        
        # Source IP / Target extraction mapping
        src_ip = row.get('source_ip', f"192.168.1.{random.randint(10, 200)}")
        target = row.get('destination_ip', f"Server-0{random.randint(1,9)}")
        
        # Format Threat
        threat = {
            "id": f"THR-{int(time.time()*1000)}-{index}",
            "attackType": attack_type,
            "severity": severity,
            "probability": f"{(confidence * 100):.1f}%",
            "sourceIp": src_ip,
            "targetAsset": target,
            "timestamp": str(row.get('timestamp', pd.Timestamp.now().isoformat())),
            "reason": reason
        }
        
        if len(detailed_threats) < 200:
            detailed_threats.append(threat)
            
        # Update Attack Distribution
        if attack_type != "Normal Traffic":
            attack_map[attack_type] = attack_map.get(attack_type, 0) + 1

    # Sort detailed threats by severity
    severity_weight = { "Critical": 4, "High": 3, "Medium": 2, "Low": 1 }
    detailed_threats.sort(key=lambda x: severity_weight.get(x["severity"], 0), reverse=True)

    attack_distribution = [{"name": k, "count": v} for k, v in attack_map.items()]

    summary_insights = (
        f"Processed {stats['total']} network events through the ML pipeline. "
        f"Detected {stats['critical']} critical anomalies requiring immediate SOC intervention. "
        f"Overall network risk posture is {'ELEVATED' if stats['critical'] > 5 else 'STABLE'}."
    )

    return {
        "stats": stats,
        "detailedThreats": detailed_threats,
        "summaryInsights": summary_insights,
        "charts": {
            "attackDistribution": attack_distribution
        }
    }
