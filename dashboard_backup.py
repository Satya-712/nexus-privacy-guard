
import json
from pathlib import Path

import csv
import io


import pandas as pd
import streamlit as st

from src.privacy_detector import detect_sensitive_data
from src.privacy_redactor import redact_sensitive_data
from src.outlet_comparison_data import get_outlet_comparison
from src.privacy_risk_scorer import calculate_privacy_risk
from src.internal_visible_overlap import analyze_internal_visible_overlap


# ---------------- PAGE CONFIGURATION ----------------

st.set_page_config(
    page_title="AI Agent Privacy Guard",
    page_icon="🔐",
    layout="wide",
)

DATA_PATH = Path(__file__).resolve().parent / "data" / "experiments.json"


@st.cache_data
def load_experiments():
    with DATA_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


st.title("🔐 AI Agent Privacy Guard")
st.caption("Research prototype | Synthetic experiment datasets")


# ---------------- LOAD DATA ----------------

try:
    cases = load_experiments()
except (FileNotFoundError, json.JSONDecodeError) as error:
    st.error(f"Could not load experiment data: {error}")
    st.stop()


# ---------------- DETECTION EVALUATION ----------------

all_rows = []
tp = fp = fn = tn = 0

for case in cases:
    findings = detect_sensitive_data(case.get("text", ""))
    expected_type = case.get("data_type", "NONE")

    detected_types = {item["type"] for item in findings}
    expected_positive = expected_type != "NONE"
    predicted_positive = bool(findings)

    if expected_positive and predicted_positive:
        # Count a true positive only when the expected type is detected.
        if expected_type in detected_types:
            tp += 1
        else:
            fn += 1
            fp += 1
    elif expected_positive and not predicted_positive:
        fn += 1
    elif not expected_positive and predicted_positive:
        fp += 1
    else:
        tn += 1

    all_rows.append({
        "Case ID": case.get("case_id", ""),
        "Channel": case.get("channel", ""),
        "Visibility": case.get("visibility", ""),
        "Expected Type": expected_type,
        "Detected Types": ", ".join(sorted(detected_types)) or "None",
        "Detection Match": (
            expected_type in detected_types
            if expected_positive
            else not predicted_positive
        ),
        "Authorized Label": case.get("authorized", "Not provided"),
    })


total_records = len(cases)
accuracy = (
    (tp + tn) / (tp + tn + fp + fn)
    if (tp + tn + fp + fn) else 0.0
)
precision = tp / (tp + fp) if (tp + fp) else 0.0
recall = tp / (tp + fn) if (tp + fn) else 0.0

visible_cases = [
    case for case in cases
    if case.get("visibility") == "visible"
]
internal_cases = [
    case for case in cases
    if case.get("visibility") == "internal"
]

visible_sensitive = [
    case for case in visible_cases
    if case.get("data_type", "NONE") != "NONE"
]

visible_displaced = [
    case for case in visible_sensitive
    if case.get("channel") != case.get("expected_channel")
]

authorized_visible = sum(
    case.get("authorized") is True for case in visible_cases
)
unauthorized_visible = sum(
    case.get("authorized") is False for case in visible_cases
)

displacement_rate = (
    len(visible_displaced) / len(visible_sensitive)
    if visible_sensitive else 0.0
)


# ---------------- OVERVIEW ----------------

st.header("📊 Evaluation Overview")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Test Records", total_records)
m2.metric("Accuracy", f"{accuracy:.1%}")
m3.metric("Precision", f"{precision:.1%}")
m4.metric("Recall", f"{recall:.1%}")

m5, m6, m7 = st.columns(3)
m5.metric("Visible Sensitive Exposures", len(visible_sensitive))
m6.metric("Visible Displaced Exposures", len(visible_displaced))
m7.metric("Displacement Rate", f"{displacement_rate:.1%}")

st.caption(
    "Detection metrics use the supplied synthetic labels. "
    "They are not estimates of real-world performance."
)


# ---------------- VISIBILITY CLASSIFICATION ----------------

st.divider()
st.header("👁️ Visibility Classification")

v1, v2 = st.columns(2)
v1.metric("Visible Records", len(visible_cases))
v2.metric("Internal Trace Records", len(internal_cases))

visibility_df = pd.DataFrame({
    "Classification": ["Visible", "Internal Trace"],
    "Records": [len(visible_cases), len(internal_cases)],
})
st.bar_chart(visibility_df, x="Classification", y="Records")


# ---------------- CONFUSION COUNTS ----------------

st.subheader("Detection Confusion Counts")

confusion_df = pd.DataFrame({
    "Classification": [
        "True Positive",
        "False Positive",
        "False Negative",
        "True Negative",
    ],
    "Count": [tp, fp, fn, tn],
})

st.bar_chart(confusion_df, x="Classification", y="Count")
st.dataframe(confusion_df, width="stretch", hide_index=True)


# ---------------- AUTHORIZATION ----------------

st.divider()
st.subheader("🔒 Visible Authorization Labels")

auth_df = pd.DataFrame({
    "Status": ["Authorized", "Unauthorized"],
    "Count": [authorized_visible, unauthorized_visible],
})

st.bar_chart(auth_df, x="Status", y="Count")
st.dataframe(auth_df, width="stretch", hide_index=True)

st.caption(
    "Authorization results use synthetic dataset labels; "
    "permissions are not independently verified."
)


# ---------------- EXPERIMENT RECORDS ----------------

st.divider()
st.subheader("🧪 Experiment Records")

st.dataframe(
    pd.DataFrame(all_rows),
    width="stretch",
    hide_index=True,
)


# ---------------- OUTLET COMPARISON ----------------

st.divider()
st.header("🔬 Outlet Displacement Comparison")

try:
    comparison = get_outlet_comparison()

    a, b, c = st.columns(3)
    a.metric(
        "Expected-Only Recovery",
        f"{comparison['expected_rate']:.1%}",
        f"{comparison['expected_recovered']} of {comparison['total']}",
    )
    b.metric(
        "All-Visible Recovery",
        f"{comparison['all_rate']:.1%}",
        f"{comparison['all_recovered']} of {comparison['total']}",
    )
    c.metric(
        "Missed by Expected-Only",
        comparison["missed"],
        f"{comparison['missed_rate']:.1%} of recovered exposures",
    )

    comparison_df = pd.DataFrame({
        "Strategy": ["Expected outlet only", "All visible channels"],
        "Recovery Rate (%)": [
            comparison["expected_rate"] * 100,
            comparison["all_rate"] * 100,
        ],
    })

    st.bar_chart(
        comparison_df,
        x="Strategy",
        y="Recovery Rate (%)",
    )

    st.dataframe(
        pd.DataFrame(comparison["details"]),
        width="stretch",
        hide_index=True,
    )

except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError) as error:
    st.error(f"Could not run outlet comparison: {error}")


# ---------------- INTERNAL-VISIBLE OVERLAP ----------------

st.divider()
st.header("🔁 Internal-to-Visible Entity Overlap")

try:
    overlap = analyze_internal_visible_overlap()

    o1, o2, o3, o4 = st.columns(4)
    o1.metric("Sessions", overlap["session_count"])
    o2.metric("Internal Entities", overlap["internal_entity_count"])
    o3.metric("Visible Entities", overlap["visible_entity_count"])
    o4.metric("Overlapping Entities", overlap["overlap_count"])

    st.metric(
        "Internal-to-Visible Overlap Rate",
        f"{overlap['internal_to_visible_overlap_rate']:.1%}",
    )

    st.caption(
        "Rate = exact internal entities also found in visible outputs, "
        "divided by the number of unique internal entities counted "
        "across sessions."
    )

    session_df = pd.DataFrame([
        {
            "Session": item["session_id"],
            "Internal Entities": item["internal_entity_count"],
            "Visible Entities": item["visible_entity_count"],
            "Overlap Count": item["overlap_count"],
        }
        for item in overlap["details"]
    ])

    st.subheader("Session-wise Overlap")
    st.dataframe(session_df, width="stretch", hide_index=True)

    # Show entity types only, not the raw matched values.
    overlap_details = []
    for item in overlap["details"]:
        for entity in item["overlapping_entities"]:
            overlap_details.append({
                "Session": item["session_id"],
                "Type": entity["type"],
                "Value": "[REDACTED]",
            })

    st.subheader("Overlapping Entity Types")
    if overlap_details:
        st.dataframe(
            pd.DataFrame(overlap_details),
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No exact overlapping entities were found.")

except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError) as error:
    st.error(f"Could not run overlap experiment: {error}")


# ---------------- PRIVACY REDACTION DEMO ----------------

st.divider()
st.header("🛡️ Sensitive Data Redaction Demo")

st.write(
    "Enter synthetic sample text to detect supported sensitive-data "
    "patterns and replace them with redaction labels."
)

st.warning(
    "Use synthetic examples only. This demo is a prototype and does not "
    "guarantee that every secret or personal-data format will be detected."
)

sample_text = (
    "Contact: student@example.com, "
    "Phone: 9876543210, "
    "Key: sk-AbCdEfGh1234"
)

user_text = st.text_area(
    "Text to inspect",
    value=sample_text,
    height=130,
    key="redaction_input",
)

if st.button("🔍 Detect and Redact", type="primary"):
    findings = detect_sensitive_data(user_text)
    redacted_text = redact_sensitive_data(user_text)

    st.subheader("Detection Summary")

    if findings:
        type_counts = {}
        for finding in findings:
            kind = finding["type"]
            type_counts[kind] = type_counts.get(kind, 0) + 1

        cols = st.columns(max(1, len(type_counts)))
        for index, (kind, count) in enumerate(sorted(type_counts.items())):
            cols[index].metric(kind, count)

        st.success(f"Detected {len(findings)} sensitive pattern(s).")
    else:
        st.info("No supported sensitive patterns were detected.")

    st.subheader("Redacted Output")
    st.code(redacted_text, language="text")

    st.caption(
        "Redaction only covers patterns supported by the current "
        "regular-expression detector. Always verify results before "
        "using them in a real system."
    )


# ---------------- PRIVACY RISK ANALYSIS ----------------

st.divider()
st.header("🚨 Privacy Risk Analysis")

st.caption(
    "Scores use prototype heuristic weights and synthetic authorization "
    "labels. They are for demonstration, not validated risk measurements."
)

risk_rows = []

for case in cases:
    text = case.get("text", "")
    visibility = case.get("visibility", "visible")

    # Use the dataset's authorization label.
    # Missing or non-boolean labels are treated as unauthorized
    # for this prototype demonstration.
    authorized = case.get("authorized") is True

    try:
        report = calculate_privacy_risk(
            text=text,
            visibility=visibility,
            authorized=authorized,
        )
    except ValueError:
        continue

    risk_rows.append({
        "Case ID": case.get("case_id", ""),
        "Channel": case.get("channel", ""),
        "Visibility": visibility,
        "Detected Types": ", ".join(report["detected_types"]) or "None",
        "Authorized Label": authorized,
        "Risk Score": report["risk_score"],
        "Finding Count": report["finding_count"],
    })

risk_df = pd.DataFrame(risk_rows)

if not risk_df.empty:
    risk_df = risk_df.sort_values(
        by="Risk Score",
        ascending=False,
    ).reset_index(drop=True)

    highest_score = risk_df["Risk Score"].max()
    nonzero_records = int((risk_df["Risk Score"] > 0).sum())
    total_score = risk_df["Risk Score"].sum()

    r1, r2, r3 = st.columns(3)
    r1.metric("Records Scored", len(risk_df))
    r2.metric("Records with Non-zero Score", nonzero_records)
    r3.metric("Highest Risk Score", f"{highest_score:.2f}")

    st.metric("Sum of Heuristic Scores", f"{total_score:.2f}")

    st.subheader("Record-wise Risk Scores")
    st.dataframe(
        risk_df,
        width="stretch",
        hide_index=True,
    )
    
    st.download_button(
        label="📥 Download Risk Report (CSV)",
        data=risk_df.to_csv(index=False).encode("utf-8"),
        file_name="privacy_risk_report.csv",
        mime="text/csv",
    )


    chart_df = risk_df[["Case ID", "Risk Score"]].set_index("Case ID")
    st.subheader("Risk Score Comparison")
    st.bar_chart(chart_df)

    st.info(
        "A higher score means the current heuristic assigned more points "
        "to the detected patterns and labels. It does not mean a known "
        "probability of a privacy incident."
    )
else:
    st.info("No records were available for risk scoring.")

# ---------------- RESEARCH LIMITATIONS ----------------

st.divider()
st.info(
    "Research limitation: results are based on small synthetic datasets. "
    "They are not real-world performance estimates or reproduced results "
    "from the original research paper. Exact matching may miss alternate "
    "representations, and channel visibility depends on the actual system."
)

st.caption("AI Agent Privacy Guard | Experimental research prototype")

# ---------------- EVALUATION REPORT DOWNLOADS ----------------

st.divider()
st.header("Evaluation Reports")

ROOT_DIR = Path(__file__).resolve().parent
DETAILS_PATH = ROOT_DIR / "reports" / "evaluation_details.csv"
SUMMARY_PATH = ROOT_DIR / "reports" / "evaluation_summary.csv"

st.write(
    "Download the expanded dataset evaluation reports for "
    "offline analysis and documentation."
)

report_col1, report_col2 = st.columns(2)

with report_col1:
    st.subheader("Detailed Test Results")

    if DETAILS_PATH.exists():
        with DETAILS_PATH.open("rb") as file:
            details_csv = file.read()

        st.download_button(
            label="Download Detailed Results (CSV)",
            data=details_csv,
            file_name="evaluation_details.csv",
            mime="text/csv",
            key="download_evaluation_details",
        )
    else:
        st.warning(
            "Detailed report not found. Run "
            "`python -m src.export_evaluation_report` first."
        )

with report_col2:
    st.subheader("Summary Metrics")

    if SUMMARY_PATH.exists():
        with SUMMARY_PATH.open("rb") as file:
            summary_csv = file.read()

        st.download_button(
            label="Download Summary Metrics (CSV)",
            data=summary_csv,
            file_name="evaluation_summary.csv",
            mime="text/csv",
            key="download_evaluation_summary",
        )
    else:
        st.warning(
            "Summary report not found. Run "
            "`python -m src.export_evaluation_report` first."
        )

st.caption(
    "Evaluation metrics are calculated from synthetic test data "
    "and should not be interpreted as real-world performance."
)

