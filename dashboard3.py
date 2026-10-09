import json
from pathlib import Path

import pandas as pd
import streamlit as st

from src.privacy_detector import detect_sensitive_data
from src.privacy_redactor import redact_sensitive_data
from src.outlet_comparison_data import get_outlet_comparison
from src.privacy_risk_scorer import calculate_privacy_risk
from src.internal_visible_overlap import analyze_internal_visible_overlap

st.set_page_config(page_title="AI Agent Privacy Guard", page_icon="🔐", layout="wide")

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "experiments.json"
DETAILS_PATH = ROOT / "reports" / "evaluation_details.csv"
SUMMARY_PATH = ROOT / "reports" / "evaluation_summary.csv"

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
:root{--bg:#080b14;--panel:#111626;--line:rgba(148,163,184,.16);--text:#edf2ff;--muted:#94a3b8;--purple:#9b8cff;--cyan:#51e0d0}
html,body,[class*="css"]{font-family:'Manrope',sans-serif}
.stApp{background:radial-gradient(ellipse at 12% 0%,rgba(112,84,255,.13),transparent 34%),radial-gradient(ellipse at 90% 10%,rgba(46,213,200,.08),transparent 28%),var(--bg);color:var(--text)}
[data-testid="stHeader"]{background:rgba(8,11,20,.72)}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#101426,#0b0f1c);border-right:1px solid var(--line)}
.block-container{padding-top:1.7rem;padding-bottom:3rem;max-width:1500px}
h1,h2,h3{color:var(--text)!important;letter-spacing:-.035em}
[data-testid="stMetric"]{background:linear-gradient(145deg,rgba(21,28,47,.96),rgba(13,18,32,.96));border:1px solid var(--line);border-radius:18px;padding:18px 20px;box-shadow:0 10px 30px rgba(0,0,0,.12);min-height:112px}
[data-testid="stMetricLabel"]{color:var(--muted)!important;font-size:.82rem!important;font-weight:600!important}
[data-testid="stMetricValue"]{color:#f4f6ff!important;font-weight:800!important;letter-spacing:-.045em}
[data-testid="stVerticalBlockBorderWrapper"]{border-color:var(--line)!important;border-radius:18px!important;background:rgba(17,22,38,.65)}
.stButton>button,.stDownloadButton>button{border-radius:11px;border:1px solid rgba(155,140,255,.45);background:linear-gradient(110deg,rgba(115,91,255,.95),rgba(64,180,208,.88));color:white;font-weight:800;min-height:2.8rem}
.stButton>button:hover,.stDownloadButton>button:hover{filter:brightness(1.12);border-color:rgba(81,224,208,.75);color:white}
.stTextArea textarea{background:#0d1220!important;color:#eef2ff!important;border:1px solid rgba(148,163,184,.25)!important;border-radius:12px!important}
[data-testid="stDataFrame"]{border:1px solid var(--line);border-radius:12px;overflow:hidden}
.hero{padding:28px 30px;border-radius:24px;border:1px solid rgba(155,140,255,.24);background:radial-gradient(circle at 90% 5%,rgba(81,224,208,.16),transparent 32%),linear-gradient(120deg,rgba(24,27,52,.97),rgba(14,22,38,.97));box-shadow:0 18px 50px rgba(0,0,0,.22);margin-bottom:22px}
.kicker{color:var(--cyan);font-size:.74rem;font-family:'DM Mono',monospace;letter-spacing:.16em;text-transform:uppercase;font-weight:500;margin-bottom:9px}
.hero-title{color:#f7f8ff;font-size:clamp(1.7rem,3.4vw,2.65rem);line-height:1.12;font-weight:800;letter-spacing:-.055em;margin:0}
.hero-copy{color:#aab5cc;max-width:760px;line-height:1.7;margin-top:12px;margin-bottom:0;font-size:.96rem}
.pill{display:inline-block;margin-top:17px;padding:7px 11px;border:1px solid rgba(81,224,208,.25);border-radius:999px;background:rgba(81,224,208,.08);color:#8ef0df;font-size:.76rem;font-family:'DM Mono',monospace}
.eyebrow{color:var(--purple);text-transform:uppercase;font-size:.72rem;font-family:'DM Mono',monospace;letter-spacing:.14em;margin-bottom:4px}
.muted{color:#94a3b8;font-size:.88rem;line-height:1.6}
hr{border-color:var(--line)!important}
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("""<div style="padding:6px 8px 18px"><div style="font-size:2rem">🔐</div><div style="font-size:1.04rem;font-weight:800;color:#f2f4ff;margin-top:8px">PRIVACY GUARD</div><div style="font-size:.72rem;color:#94a3b8;letter-spacing:.12em;margin-top:4px">AI AGENT SECURITY LAB</div></div>""", unsafe_allow_html=True)
    st.markdown("---")
    page = st.radio("WORKSPACE", ["Overview", "Detection & Records", "Displacement Analysis", "Overlap Analysis", "Redaction Lab", "Risk Analysis", "Evaluation Reports"])
    st.markdown("---")
    st.caption("● Prototype workspace")
    st.caption("Synthetic experiment data only")

@st.cache_data
def load_experiments():
    with DATA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)

try:
    cases = load_experiments()
except (FileNotFoundError, json.JSONDecodeError) as exc:
    st.error(f"Could not load experiment data: {exc}")
    st.stop()

rows = []
tp = fp = fn = tn = 0
for case in cases:
    findings = detect_sensitive_data(case.get("text", ""))
    expected_type = case.get("data_type", "NONE")
    detected = {x["type"] for x in findings}
    expected_positive = expected_type != "NONE"
    predicted_positive = bool(findings)
    if expected_positive and predicted_positive:
        if expected_type in detected:
            tp += 1
        else:
            fn += 1
            fp += 1
    elif expected_positive:
        fn += 1
    elif predicted_positive:
        fp += 1
    else:
        tn += 1
    rows.append({
        "Case ID": case.get("case_id", ""), "Channel": case.get("channel", ""),
        "Visibility": case.get("visibility", ""), "Expected Type": expected_type,
        "Detected Types": ", ".join(sorted(detected)) or "None",
        "Detection Match": expected_type in detected if expected_positive else not predicted_positive,
        "Authorized Label": case.get("authorized", "Not provided"),
    })

total = len(cases)
denom = tp + tn + fp + fn
accuracy = (tp + tn) / denom if denom else 0
precision = tp / (tp + fp) if tp + fp else 0
recall = tp / (tp + fn) if tp + fn else 0
f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
visible = [x for x in cases if x.get("visibility") == "visible"]
internal = [x for x in cases if x.get("visibility") == "internal"]
visible_sensitive = [x for x in visible if x.get("data_type", "NONE") != "NONE"]
displaced = [x for x in visible_sensitive if x.get("channel") != x.get("expected_channel")]
authorized = sum(x.get("authorized") is True for x in visible)
unauthorized = sum(x.get("authorized") is False for x in visible)
displacement_rate = len(displaced) / len(visible_sensitive) if visible_sensitive else 0

st.markdown("""<div class="hero"><div class="kicker">AI SECURITY · RESEARCH WORKSPACE</div><div class="hero-title">AI Agent Privacy Guard</div><p class="hero-copy">Inspect sensitive-data exposure across agent outputs, compare visibility channels, evaluate privacy-risk heuristics, and test redaction workflows from one unified security dashboard.</p><div class="pill">● SYNTHETIC DATA MODE &nbsp; / &nbsp; RESEARCH PROTOTYPE</div></div>""", unsafe_allow_html=True)

if page == "Overview":
    st.markdown('<div class="eyebrow">01 / Command center</div>', unsafe_allow_html=True)
    st.header("Evaluation overview")
    st.markdown('<p class="muted">Metrics use the current synthetic dataset and are not estimates of real-world performance.</p>', unsafe_allow_html=True)
    a,b,c,d = st.columns(4)
    a.metric("Test records", total); b.metric("Accuracy", f"{accuracy:.1%}"); c.metric("Precision", f"{precision:.1%}"); d.metric("Recall", f"{recall:.1%}")
    a,b,c,d = st.columns(4)
    a.metric("Visible records", len(visible)); b.metric("Internal traces", len(internal)); c.metric("Sensitive exposures", len(visible_sensitive)); d.metric("Displacement rate", f"{displacement_rate:.1%}")
    left,right = st.columns(2)
    with left:
        with st.container(border=True):
            st.subheader("Visibility distribution")
            st.bar_chart(pd.DataFrame({"Classification":["Visible","Internal trace"],"Records":[len(visible),len(internal)]}), x="Classification", y="Records")
    with right:
        with st.container(border=True):
            st.subheader("Detection outcomes")
            st.bar_chart(pd.DataFrame({"Outcome":["True positive","False positive","False negative","True negative"],"Count":[tp,fp,fn,tn]}), x="Outcome", y="Count")
    with st.container(border=True):
        st.subheader("Research notes")
        x,y = st.columns(2)
        x.markdown("**Prototype capabilities**\n- Sensitive-data detection\n- Redaction for supported patterns\n- Heuristic risk scoring\n- Outlet displacement and overlap analysis")
        y.markdown("**Interpret carefully**\n- Small synthetic datasets\n- Authorization labels not independently verified\n- Risk scores are not incident probabilities\n- Exact matching can miss alternate representations")

elif page == "Detection & Records":
    st.markdown('<div class="eyebrow">02 / Detection telemetry</div>', unsafe_allow_html=True)
    st.header("Detection & experiment records")
    a,b,c,d = st.columns(4)
    a.metric("True positives",tp); b.metric("False positives",fp); c.metric("False negatives",fn); d.metric("True negatives",tn)
    st.bar_chart(pd.DataFrame({"Classification":["True positive","False positive","False negative","True negative"],"Count":[tp,fp,fn,tn]}), x="Classification", y="Count")
    df = pd.DataFrame(rows)
    a,b,c = st.columns(3)
    vis = a.selectbox("Visibility", ["All","visible","internal"])
    typ = b.selectbox("Expected type", ["All"] + sorted(df["Expected Type"].dropna().unique().tolist()))
    chan = c.selectbox("Channel", ["All"] + sorted(df["Channel"].dropna().unique().tolist()))
    if vis != "All": df = df[df["Visibility"] == vis]
    if typ != "All": df = df[df["Expected Type"] == typ]
    if chan != "All": df = df[df["Channel"] == chan]
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.download_button("Download filtered records (CSV)", df.to_csv(index=False).encode("utf-8"), "experiment_records_filtered.csv", "text/csv")
    st.divider()
    st.subheader("Visible authorization labels")
    l,r = st.columns(2)
    auth_df = pd.DataFrame({"Status":["Authorized","Unauthorized"],"Count":[authorized,unauthorized]})
    l.bar_chart(auth_df, x="Status", y="Count"); r.dataframe(auth_df, use_container_width=True, hide_index=True)
    st.caption("Authorization results use synthetic labels; permissions are not independently verified.")

elif page == "Displacement Analysis":
    st.markdown('<div class="eyebrow">03 / Channel analysis</div>', unsafe_allow_html=True)
    st.header("Outlet displacement analysis")
    try:
        comp = get_outlet_comparison()
        a,b,c = st.columns(3)
        a.metric("Expected-only recovery", f"{comp['expected_rate']:.1%}", f"{comp['expected_recovered']} of {comp['total']}")
        b.metric("All-visible recovery", f"{comp['all_rate']:.1%}", f"{comp['all_recovered']} of {comp['total']}")
        c.metric("Missed by expected-only", comp["missed"], f"{comp['missed_rate']:.1%} of recovered exposures")
        comp_df = pd.DataFrame({"Strategy":["Expected outlet only","All visible channels"],"Recovery rate (%)":[comp["expected_rate"]*100,comp["all_rate"]*100]})
        l,r = st.columns([1,1.3])
        l.bar_chart(comp_df, x="Strategy", y="Recovery rate (%)")
        r.dataframe(pd.DataFrame(comp["details"]), use_container_width=True, hide_index=True)
        st.download_button("Download outlet comparison (CSV)", pd.DataFrame(comp["details"]).to_csv(index=False).encode("utf-8"), "outlet_displacement_details.csv", "text/csv")
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError) as exc:
        st.error(f"Could not run outlet comparison: {exc}")

elif page == "Overlap Analysis":
    st.markdown('<div class="eyebrow">04 / Trace visibility</div>', unsafe_allow_html=True)
    st.header("Internal-to-visible entity overlap")
    try:
        overlap = analyze_internal_visible_overlap()
        a,b,c,d = st.columns(4)
        a.metric("Sessions",overlap["session_count"]); b.metric("Internal entities",overlap["internal_entity_count"]); c.metric("Visible entities",overlap["visible_entity_count"]); d.metric("Overlapping entities",overlap["overlap_count"])
        st.metric("Internal-to-visible overlap rate", f"{overlap['internal_to_visible_overlap_rate']:.1%}")
        df = pd.DataFrame([{"Session":x["session_id"],"Internal entities":x["internal_entity_count"],"Visible entities":x["visible_entity_count"],"Overlap count":x["overlap_count"]} for x in overlap["details"]])
        st.subheader("Session-wise overlap"); st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button("Download overlap details (CSV)", df.to_csv(index=False).encode("utf-8"), "internal_visible_overlap.csv", "text/csv")
        safe = [{"Session":x["session_id"],"Type":e["type"],"Value":"[REDACTED]"} for x in overlap["details"] for e in x["overlapping_entities"]]
        st.subheader("Overlapping entity types")
        if safe: st.dataframe(pd.DataFrame(safe), use_container_width=True, hide_index=True)
        else: st.info("No exact overlapping entities were found.")
        st.caption("Rate = exact internal entities also found in visible outputs divided by unique internal entities counted across sessions.")
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError) as exc:
        st.error(f"Could not run overlap experiment: {exc}")

elif page == "Redaction Lab":
    st.markdown('<div class="eyebrow">05 / Interactive privacy lab</div>', unsafe_allow_html=True)
    st.header("Sensitive-data redaction lab")
    st.markdown('<p class="muted">Inspect synthetic text, detect supported patterns, and preview redacted output.</p>', unsafe_allow_html=True)
    st.warning("Use synthetic examples only. This prototype does not guarantee detection of every secret or personal-data format.")
    sample = "Contact: student@example.com, Phone: 987-654-3210, Obfuscated: student [at] example [dot] com, Key: sk-AbCdEfGh1234"
    text = st.text_area("Text to inspect", value=sample, height=170, key="redaction_input")
    if st.button("🔍 Analyze and redact text", type="primary", use_container_width=True):
        findings = detect_sensitive_data(text)
        redacted = redact_sensitive_data(text)
        if findings:
            counts = {}
            for f in findings: counts[f["type"]] = counts.get(f["type"],0)+1
            cols = st.columns(max(1,len(counts)))
            for i,(kind,count) in enumerate(sorted(counts.items())): cols[i].metric(kind.replace("_"," "),count)
            st.success(f"Detected {len(findings)} supported sensitive pattern(s).")
            st.dataframe(pd.DataFrame([{"Type":f["type"],"Matched text":"[REDACTED]","Start":f["start"],"End":f["end"]} for f in findings]), use_container_width=True, hide_index=True)
        else: st.info("No supported sensitive patterns were detected.")
        st.subheader("Redacted output"); st.code(redacted, language="text")
        st.download_button("Download redacted text", redacted.encode("utf-8"), "redacted_output.txt", "text/plain")
        st.caption("Redaction only covers patterns supported by the current detector. Verify results before using them in a real system.")

elif page == "Risk Analysis":
    st.markdown('<div class="eyebrow">06 / Heuristic risk scoring</div>', unsafe_allow_html=True)
    st.header("Privacy risk analysis")
    st.markdown('<p class="muted">Scores are prototype heuristic points, not calibrated probabilities of privacy incidents.</p>', unsafe_allow_html=True)
    risk_rows = []
    for case in cases:
        try:
            report = calculate_privacy_risk(text=case.get("text",""), visibility=case.get("visibility","visible"), authorized=case.get("authorized") is True)
        except ValueError:
            continue
        risk_rows.append({"Case ID":case.get("case_id",""),"Channel":case.get("channel",""),"Visibility":case.get("visibility","visible"),"Detected Types":", ".join(report["detected_types"]) or "None","Authorized label":case.get("authorized") is True,"Risk Score":report["risk_score"],"Finding Count":report["finding_count"]})
    risk_df = pd.DataFrame(risk_rows)
    if not risk_df.empty:
        risk_df = risk_df.sort_values("Risk Score", ascending=False).reset_index(drop=True)
        a,b,c = st.columns(3)
        a.metric("Records scored",len(risk_df)); b.metric("Non-zero scores",int((risk_df["Risk Score"]>0).sum())); c.metric("Highest risk score",f"{risk_df['Risk Score'].max():.2f}")
        st.metric("Sum of heuristic scores",f"{risk_df['Risk Score'].sum():.2f}")
        l,r = st.columns([1.1,1])
        l.dataframe(risk_df, use_container_width=True, hide_index=True)
        r.bar_chart(risk_df[["Case ID","Risk Score"]].set_index("Case ID"))
        st.download_button("Download risk report (CSV)",risk_df.to_csv(index=False).encode("utf-8"),"privacy_risk_report.csv","text/csv")
        st.info("Higher scores reflect the current heuristic. They do not indicate a known probability of a privacy incident.")
    else: st.info("No records were available for risk scoring.")

elif page == "Evaluation Reports":
    st.markdown('<div class="eyebrow">07 / Export center</div>', unsafe_allow_html=True)
    st.header("Evaluation reports")
    st.markdown('<p class="muted">Download case-level evaluation results and summary metrics for offline analysis.</p>', unsafe_allow_html=True)
    l,r = st.columns(2)
    with l:
        with st.container(border=True):
            st.subheader("Detailed test results")
            st.caption("One row per synthetic test case.")
            if DETAILS_PATH.exists():
                data = DETAILS_PATH.read_bytes()
                st.download_button("⬇ Download detailed results",data,"evaluation_details.csv","text/csv",key="download_details",use_container_width=True)
                try:
                    preview = pd.read_csv(DETAILS_PATH)
                    st.caption(f"{len(preview)} cases available")
                    with st.expander("Preview report"): st.dataframe(preview.head(10),use_container_width=True,hide_index=True)
                except (pd.errors.ParserError,UnicodeDecodeError): pass
            else: st.warning("Report missing. Run `python -m src.export_evaluation_report` first.")
    with r:
        with st.container(border=True):
            st.subheader("Summary metrics")
            st.caption("Aggregate metrics and confusion counts.")
            if SUMMARY_PATH.exists():
                data = SUMMARY_PATH.read_bytes()
                st.download_button("⬇ Download summary metrics",data,"evaluation_summary.csv","text/csv",key="download_summary",use_container_width=True)
                try:
                    preview = pd.read_csv(SUMMARY_PATH)
                    st.dataframe(preview,use_container_width=True,hide_index=True)
                except (pd.errors.ParserError,UnicodeDecodeError): pass
            else: st.warning("Report missing. Run `python -m src.export_evaluation_report` first.")
    st.caption("Reports use synthetic test data only; results are not real-world performance estimates.")

st.divider()
l,r = st.columns([2,1])
l.caption("🔐 AI Agent Privacy Guard · Experimental research prototype")
r.caption("Synthetic data mode · redesigned UI")
