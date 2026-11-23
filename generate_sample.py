"""Reproducible synthetic-only fixtures. No real users, networks, or Army data."""
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).parent / "data" / "synthetic_soc_events.csv"
rows=[]
start=datetime(2026,11,1,9,0,tzinfo=timezone.utc)
def ev(minutes,ip,user,kind,resource,status,details,label="benign"):
    rows.append({"event_id":f"EVT-{len(rows)+1:04d}","timestamp":(start+timedelta(minutes=minutes)).isoformat(),"source_ip":ip,"user":user,"event_type":kind,"resource":resource,"status":status,"details":details,"training_label":label})
# Baseline routine training events
for i in range(48):
    ev(i*3, f"10.10.0.{(i%9)+10}", f"trainee{(i%6)+1}", "login" if i%3 else "file_access", "lab-vm-a" if i%3 else "public-runbook", "success", "Scheduled classroom activity")
# Simulated authentication abuse sequence
for i in range(5): ev(200+i,"203.0.113.25","trainee7","login","training-portal","failed","Synthetic repeated authentication failure","suspicious")
ev(205,"203.0.113.25","trainee7","login","training-portal","success","Synthetic login after multiple failures","suspicious")
# Additional realistic standalone alerts
for i in range(2): ev(230+i*4,"198.51.100.33","trainee8","sensitive_access","restricted-lab-notes","denied","Access control blocked simulated request","suspicious")
ev(245,"10.10.0.41","trainee9","data_transfer","lab-file-server","high_volume","Synthetic transfer exceeded lab threshold","suspicious")
ev(251,"10.10.0.43","trainee10","endpoint_alert","lab-vm-b","flagged","Synthetic endpoint protection signal","suspicious")
ev(260,"10.10.0.44","trainee11","privilege_change","lab-directory","unapproved","Synthetic privilege change without approval","suspicious")
for i in range(20):ev(300+i*4, f"10.10.0.{(i%12)+20}",f"trainee{(i%6)+1}","file_access","public-training-folder","allowed","Routine lab access")
with OUT.open("w",newline="",encoding="utf-8") as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
print(f"Wrote {len(rows)} synthetic events -> {OUT}")
