"""Streamlit presentation layer for offline instructor-led SOC training."""
from pathlib import Path
import json
import pandas as pd
import streamlit as st
from sentinel import parse_events, triage, evaluate, retrieve_playbook, append_review, verify_audit

ROOT = Path(__file__).parent
DEFAULT = ROOT / "data" / "synthetic_soc_events.csv"
AUDIT = ROOT / "data" / "instructor_audit.jsonl"
st.set_page_config(page_title="SentinelLab | SOC Training", page_icon="🛡️", layout="wide")
st.title("🛡️ SentinelLab")
st.caption("Agentic workflow demo • Cyber defence training • Synthetic data only • Not affiliated with the Indian Army or IIT Roorkee")
st.info("Offline, instructor-led simulation. It detects patterns in mock logs; it does not connect to networks, execute commands, or alter actual systems.")
upload = st.file_uploader("Use your own synthetic training CSV (same schema)", type="csv")
try:
    df = parse_events(upload if upload is not None else DEFAULT)
    result = triage(df)
except (ValueError, pd.errors.ParserError) as err:
    st.error(f"Invalid training data: {err}")
    st.stop()
metrics = evaluate(df,result)
tabs = st.tabs(["Operational overview", "Analyst workbench", "Grounded response guidance", "Instructor approval & audit", "Learning assessment"])
with tabs[0]:
    a,b,c,d = st.columns(4)
    a.metric("Synthetic events",result['events'])
    b.metric("Triggered alerts",len(result['alerts']))
    c.metric("Correlated cases",len(result['cases']))
    d.metric("Critical alerts",result['severity_counts'].get('CRITICAL',0))
    st.markdown("**Local workflow**  →  ".join(result['workflow']))
    st.subheader("Alerts by severity")
    sc = pd.DataFrame([{'severity':k, 'alerts':v} for k,v in result['severity_counts'].items()])
    if not sc.empty:st.bar_chart(sc.set_index('severity'))
    st.subheader("Event sample")
    st.dataframe(df.tail(20), use_container_width=True, hide_index=True)
with tabs[1]:
    st.subheader("Explainable alerts")
    st.dataframe(pd.DataFrame([{k:v for k,v in a.items() if k not in ('tags',)} for a in result['alerts']]),use_container_width=True, hide_index=True)
    if result['cases']:
        sel = st.selectbox("Inspect a case", [c['case_id'] for c in result['cases']])
        chosen = next(c for c in result['cases'] if c['case_id']==sel)
        st.json({k:v for k,v in chosen.items() if k!='suggested_guidance'})
        st.caption("Every alert retains originating event IDs for reproducibility.")
with tabs[2]:
    st.subheader("Retrieval-grounded training playbooks")
    query=st.text_input("Describe a training issue", value="repeated login failures followed by success")
    matched=retrieve_playbook(query)
    if matched:
        for m in matched:
            with st.expander(f"{m['name']} · {m['id']} · relevance {m['similarity']}",expanded=True):
                for step in m['procedure']:st.write('• '+step)
                st.caption(m['reference'])
    else:st.warning("No relevant approved playbook found; seek an instructor.")
    st.caption("TF-IDF extractive retrieval, not an LLM. Guidance is copied from locally reviewed playbooks.")
with tabs[3]:
    st.subheader("Human-in-the-loop control")
    if not result['cases']:
        st.info("No cases to review in this dataset.")
    else:
        case_id=st.selectbox("Case",[c['case_id'] for c in result['cases']],key='approve_case')
        instructor=st.text_input("Instructor / reviewer (training name only)","Instructor Demo")
        decision=st.selectbox("Training decision",["NEEDS_MORE_EVIDENCE", "APPROVE_TRAINING_RECOMMENDATION", "REJECT"])
        note=st.text_area("Rationale", "Mock review only; no production actions performed.")
        if st.button("Record instructor decision"):
            try:
                record=append_review(AUDIT,case_id,instructor,decision,note)
                st.success(f"Saved audit record {record['record_hash'][:12]}...")
            except ValueError as exc:st.error(str(exc))
    ok, count=verify_audit(AUDIT)
    st.write(f"Audit integrity: {'PASS' if ok else 'FAIL'} · Records checked: {count}")
    if AUDIT.exists():
        st.download_button("Export audit log",AUDIT.read_bytes(),file_name='instructor_audit.jsonl',mime='application/x-ndjson')
with tabs[4]:
    st.subheader("Evaluation — synthetic teaching data only")
    if metrics:
        x,y,z=st.columns(3)
        x.metric("Precision",f"{metrics['precision']:.1%}")
        y.metric("Recall",f"{metrics['recall']:.1%}")
        z.metric("F1",f"{metrics['f1']:.1%}")
        st.caption("Scores measure event ID coverage on a small hand-labeled synthetic fixture. Not real-world detection accuracy.")
    st.subheader("Instructor quiz")
    answer=st.radio("Why are human approvals required for a suggested containment action?",["To make the program faster", "To validate evidence, authorization, and possible operational impact", "Because automated alerts are always correct"],index=None)
    if st.button("Check answer"):
        if answer == "To validate evidence, authorization, and possible operational impact":st.success("Correct. Human oversight is crucial in sensitive environments.")
        else:st.info("Review evidence quality, authorization, and operational consequences before acting.")
