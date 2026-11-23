"""SentinelLab: offline, synthetic-only SOC training workflow.

This code NEVER connects to or changes a real endpoint. It is educational software,
not an operational intrusion detection platform. Each 'agent' is a deterministic role.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
import json
from typing import Any

import pandas as pd

REQUIRED = ["event_id", "timestamp", "source_ip", "user", "event_type", "resource", "status", "details"]
PLAYBOOK_FILE = Path(__file__).parent / "data" / "playbooks.json"


def parse_events(csv_file: str | Path) -> pd.DataFrame:
    """Ingestion agent: validate, normalize, and order a synthetic training CSV."""
    df = pd.read_csv(csv_file).fillna("")
    missing = set(REQUIRED) - set(df.columns)
    if missing:
        raise ValueError(f"Missing expected fields: {', '.join(sorted(missing))}")
    if len(df) > 100000:
        raise ValueError("Training CSV exceeds 100,000 rows")
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    if df["timestamp"].isna().any():
        raise ValueError("All timestamps must be valid ISO-8601 values")
    if df["event_id"].astype(str).duplicated().any():
        raise ValueError("Each event_id must be unique")
    for c in REQUIRED:
        if c != "timestamp":
            df[c] = df[c].astype(str).str.strip()
    return df.sort_values("timestamp").reset_index(drop=True)


def alert(alert_type: str, severity: str, summary: str, items: pd.DataFrame, explanation: str, tags: list[str] | None = None) -> dict[str, Any]:
    ids = sorted(items["event_id"].astype(str).tolist())
    unique = f'{alert_type}|{";".join(ids)}'
    return {
        "alert_id": sha256(unique.encode()).hexdigest()[:12].upper(),
        "type": alert_type,
        "severity": severity,
        "summary": summary,
        "subject_user": str(items["user"].iloc[0]) if len(items) else "unknown",
        "evidence_event_ids": ids,
        "first_seen": items["timestamp"].min().isoformat(),
        "last_seen": items["timestamp"].max().isoformat(),
        "explanation": explanation,
        "tags": tags or [],
        "status": "REVIEW_REQUIRED",
    }


def detect_alerts(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Detection agent: interpretable rules; no network probes or exploitation."""
    alerts: list[dict[str, Any]] = []
    failures = df[(df["event_type"] == "login") & (df["status"] == "failed")]
    for (ip, user), g in failures.groupby(["source_ip", "user"]):
        g = g.sort_values("timestamp")
        if len(g) < 4:
            continue
        for i in range(len(g) - 3):
            window = g.iloc[i : i + 4]
            if window["timestamp"].iloc[-1] - window["timestamp"].iloc[0] <= timedelta(minutes=10):
                whole = g[g["timestamp"].between(window["timestamp"].iloc[0], window["timestamp"].iloc[0] + timedelta(minutes=10))]
                alerts.append(alert("REPEATED_LOGIN_FAILURES", "HIGH", f"Repeated failed sign-ins for {user} from {ip}", whole,
                      "At least four unsuccessful sign-ins from one source within ten minutes; may indicate password guessing.", ["authentication", "identity"]))
                break
    successes = df[(df["event_type"] == "login") & (df["status"] == "success")]
    for _, success in successes.iterrows():
        previous = failures[(failures["user"] == success["user"]) & (failures["source_ip"] == success["source_ip"]) &
            (failures["timestamp"] < success["timestamp"]) &
            (failures["timestamp"] >= success["timestamp"] - timedelta(minutes=15))]
        if len(previous) >= 3:
            events = pd.concat([previous, success.to_frame().T], ignore_index=True)
            alerts.append(alert("FAILURES_FOLLOWED_BY_SUCCESS", "CRITICAL", f"Login success after multiple failures for {success['user']}", events,
                        "A success after repeated failures warrants verification of account ownership and access scope.", ["authentication", "account"]))
    for _, ev in df.iterrows():
        evt = ev["event_type"].lower()
        if evt == "sensitive_access" and ev["status"].lower() in {"denied", "failed"}:
            alerts.append(alert("RESTRICTED_RESOURCE_ACCESS", "MEDIUM", f"Denied restricted-resource access by {ev['user']}", ev.to_frame().T,
                          "Restricted-resource access was denied; review authorization policy and context.", ["access-control"]))
        if evt == "data_transfer" and ev["status"] == "high_volume":
            alerts.append(alert("UNUSUAL_DATA_TRANSFER", "HIGH", f"Unusually large simulated transfer by {ev['user']}", ev.to_frame().T,
                          "A training threshold flagged an unusual transfer; validate against authorized activity.", ["data-protection"]))
        if evt == "endpoint_alert" and ev["status"] == "flagged":
            alerts.append(alert("ENDPOINT_SECURITY_ALERT", "HIGH", f"Simulated endpoint security alert on {ev['resource']}", ev.to_frame().T,
                          "Endpoint security telemetry marked an event for analyst assessment; no real endpoint is accessed.", ["endpoint"]))
        if evt == "privilege_change" and ev["status"] == "unapproved":
            alerts.append(alert("UNAPPROVED_PRIVILEGE_CHANGE", "CRITICAL", f"Unapproved privilege change involving {ev['user']}", ev.to_frame().T,
                          "An unapproved privilege change may elevate risk; verify authorization and preserve evidence.", ["identity", "privilege"]))
    return sorted(alerts, key=lambda a: (dict(CRITICAL=0, HIGH=1, MEDIUM=2, LOW=3).get(a["severity"], 4), a["first_seen"]))


def correlate_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Correlation agent: combines related evidence into analyst-review cases."""
    by_user = defaultdict(list)
    for a in alerts:
        # alert summaries refer to simulated user names, no personally identifying data
        user = a["subject_user"]
        by_user[user].append(a)
    cases = []
    for user, group in by_user.items():
        severity = min((x["severity"] for x in group), key=lambda s: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(s))
        cases.append({"case_id": sha256((user + "|" + "|".join(sorted(x["alert_id"] for x in group))).encode()).hexdigest()[:12].upper(),
                      "user_or_asset": user, "severity": severity, "alert_types": sorted({x["type"] for x in group}),
                      "alert_count": len(group), "evidence_event_ids": sorted({e for x in group for e in x["evidence_event_ids"]}),
                      "summary": f"Review {len(group)} alert(s): " + ", ".join(sorted({x["type"].replace("_", " ").lower() for x in group})),
                      "status": "PENDING_INSTRUCTOR_REVIEW"})
    return sorted(cases, key=lambda c: (["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(c["severity"]), c["case_id"]))


def retrieve_playbook(query: str, k: int = 3) -> list[dict[str, Any]]:
    """Guidance agent: extractive TF-IDF retrieval, never invents a response action."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    corpus = json.loads(PLAYBOOK_FILE.read_text(encoding="utf-8"))
    docs = [f"{x['name']} {x['triggers']} {x['procedure']}" for x in corpus]
    vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
    mat = vectorizer.fit_transform(docs + [query])
    scores = cosine_similarity(mat[-1], mat[:-1]).ravel()
    ids = scores.argsort()[::-1][: min(k, len(corpus))]
    return [{**corpus[int(i)], "similarity": round(float(scores[int(i)]), 3)} for i in ids if float(scores[int(i)]) > 0]


def triage(df: pd.DataFrame) -> dict[str, Any]:
    """Orchestrator: ingestion -> detection -> correlation -> grounded guidance."""
    alerts = detect_alerts(df)
    cases = correlate_alerts(alerts)
    for c in cases:
        c["suggested_guidance"] = retrieve_playbook(" ".join(c["alert_types"]), 2)
    return {"events": len(df), "alerts": alerts, "cases": cases,
            "severity_counts": dict(Counter(a["severity"] for a in alerts)),
            "workflow": ["Validate training data", "Detect indicators", "Correlate evidence", "Retrieve approved playbooks", "Human instructor review"]}


def append_review(audit_path: str | Path, case_id: str, instructor: str, decision: str, note: str) -> dict[str, str]:
    """Instructor agent: append a tamper-evident hash-chained training decision.

    The recorded decision is NOT an action on any external system.
    """
    if decision not in {"APPROVE_TRAINING_RECOMMENDATION", "REJECT", "NEEDS_MORE_EVIDENCE"}:
        raise ValueError("Unknown review decision")
    if not case_id or not instructor.strip():
        raise ValueError("Case ID and instructor name required")
    audit_path = Path(audit_path)
    audit_path.parent.mkdir(exist_ok=True, parents=True)
    previous_hash = "0" * 64
    if audit_path.exists():
        lines = [line.strip() for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            previous_hash = json.loads(lines[-1])["record_hash"]
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), "case_id": case_id,
              "instructor": instructor.strip()[:80], "decision": decision,
              "note": note.strip()[:1000], "previous_hash": previous_hash}
    record["record_hash"] = sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with audit_path.open("a", encoding="utf-8") as out:
        out.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def verify_audit(audit_path: str | Path) -> tuple[bool, int]:
    audit_path = Path(audit_path)
    if not audit_path.exists():
        return True, 0
    previous = "0" * 64
    for n, line in enumerate(audit_path.read_text(encoding="utf-8").splitlines(), start=1):
        rec = json.loads(line)
        actual = rec.pop("record_hash")
        expected = sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if actual != expected or rec["previous_hash"] != previous:
            return False, n
        previous = actual
    return True, n if 'n' in locals() else 0


def evaluate(df: pd.DataFrame, result: dict[str, Any]) -> dict[str, float | int]:
    """Educational event coverage only; NOT an operational IDS accuracy metric."""
    if "training_label" not in df:
        return {}
    true = set(df.loc[df["training_label"].astype(str).str.lower().eq("suspicious"), "event_id"].astype(str))
    pred = {str(e) for a in result["alerts"] for e in a["evidence_event_ids"]}
    tp, fp, fn = len(true & pred), len(pred - true), len(true - pred)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
            "labeled_events": len(df)}
