import os
import joblib
import pandas as pd
import numpy as np
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
 
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
 
from config.settings import (
    X_VALID, Y_VALID,
    MODEL_PATH, MULTICLASS_MODEL_PATH,
    XGBOOST_BINARY_PATH, XGBOOST_MULTICLASS_PATH,
    ANOMALY_MODEL_PATH,
    ALERTS_CORRELATED,
    CICIDS_TRAIN, CICIDS_VALID, CICIDS_TEST,
    PROCESSED_DIR,
)
 
# New paths for specialist pipeline
 
PER_CLASS_REPORT_PATH  = os.path.join(PROCESSED_DIR, "per_class_report.csv")
SPECIALIST_MODEL_PATH  = "models/specialist_model.pkl"
SPECIALIST_REPORT_PATH = os.path.join(PROCESSED_DIR, "specialist_report.csv")
CTGAN_REPORT_PATH      = os.path.join(PROCESSED_DIR, "ctgan_generation_report.csv")
ENSEMBLE_REPORT_PATH   = os.path.join(PROCESSED_DIR, "ensemble_report.csv")
CTGAN_AUGMENTED_PATH   = os.path.join(PROCESSED_DIR, "ctgan_augmented_train.parquet")
WEAK_CLASSES_PATH      = os.path.join(PROCESSED_DIR, "weak_classes.txt")
 
# Page config
 
st.set_page_config(
    page_title="AI-Powered SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
 
# Styling
 
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
 
    html, body, [class*="css"] {
        font-family: 'Rajdhani', sans-serif;
    }
    .main { background-color: #0a0e1a; }
 
    .metric-card {
        background: linear-gradient(135deg, #0d1b2a 0%, #1a2744 100%);
        border: 1px solid #1e3a5f;
        border-radius: 8px;
        padding: 16px 20px;
        text-align: center;
    }
    .metric-value {
        font-family: 'Share Tech Mono', monospace;
        font-size: 2.2rem;
        font-weight: 700;
        color: #00d4ff;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #8899aa;
        text-transform: uppercase;
        letter-spacing: 0.1em;
    }
    .severity-critical { color: #ff4444; font-weight: 700; }
    .severity-high     { color: #ff8800; font-weight: 700; }
    .severity-medium   { color: #ffcc00; font-weight: 700; }
    .severity-low      { color: #44ff88; font-weight: 700; }
 
    .section-header {
        font-family: 'Share Tech Mono', monospace;
        color: #00d4ff;
        border-bottom: 1px solid #1e3a5f;
        padding-bottom: 6px;
        margin-bottom: 16px;
    }
    div[data-testid="stSidebar"] {
        background-color: #0d1420;
        border-right: 1px solid #1e3a5f;
    }
    .stSelectbox label, .stRadio label { color: #8899aa !important; }
    .weak-tag  { color: #ff4444; font-weight: 600; }
    .strong-tag{ color: #00ff88; font-weight: 600; }
    .improvement-pos { color: #00ff88; }
    .improvement-neg { color: #ff4444; }
</style>
""", unsafe_allow_html=True)
 
PLOTLY_THEME = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="#0d1b2a",
    font=dict(color="#c0cfe0", family="Rajdhani"),
)

AXIS_THEME = dict(
    gridcolor="#1e3a5f",
    linecolor="#1e3a5f",
    showline=True,
    linewidth=1,
    zeroline=False,
    ticks="outside",
    tickcolor="#5c6f88",
    automargin=True,
    tickfont=dict(color="#c0cfe0", size=12),
    title_font=dict(color="#c0cfe0", size=14),
)


def apply_plotly_theme(fig, *, height=None, xaxis=None, yaxis=None, **layout_updates):
    layout = dict(PLOTLY_THEME)
    if height is not None:
        layout["height"] = height
    layout.update(layout_updates)
    fig.update_layout(**layout)
    fig.update_xaxes(**{**AXIS_THEME, **(xaxis or {})})
    fig.update_yaxes(**{**AXIS_THEME, **(yaxis or {})})
    return fig
 
# Data loaders (cached)
 
@st.cache_data
def load_validation_data():
    X = pd.read_parquet(X_VALID)
    y = pd.read_parquet(Y_VALID)["Label"]
    return X, y
 
 
@st.cache_resource
def load_model(path):
    return joblib.load(path)
 
 
@st.cache_data
def compute_binary_metrics(model_path):
    X, y = load_validation_data()
    model = load_model(model_path)
    y_bin = y.apply(lambda x: 0 if x == "BENIGN" else 1)
 
    if isinstance(model, dict):
        raw_pred = model["model"].predict(X)
        y_pred = raw_pred
    else:
        y_pred = model.predict(X)
 
    return {
        "accuracy" : accuracy_score(y_bin, y_pred),
        "precision": precision_score(y_bin, y_pred, zero_division=0),
        "recall"   : recall_score(y_bin, y_pred, zero_division=0),
        "f1"       : f1_score(y_bin, y_pred, zero_division=0),
        "cm"       : confusion_matrix(y_bin, y_pred),
        "fpr"      : (y_pred[y_bin == 0] == 1).mean(),
        "adr"      : (y_pred[y_bin == 1] == 1).mean(),
        "y_true"   : y_bin,
        "y_pred"   : pd.Series(y_pred),
    }
 
 
@st.cache_data
def compute_multiclass_metrics(model_path):
    X, y = load_validation_data()
    obj = load_model(model_path)
 
    if isinstance(obj, dict):
        model = obj["model"]
        id_to_label = obj["id_to_label"]
        y_pred_ids = model.predict(X)
        y_pred = pd.Series(y_pred_ids).map(id_to_label)
    else:
        model = obj
        y_pred = pd.Series(model.predict(X))
 
    report = classification_report(y, y_pred, zero_division=0, output_dict=True)
    report_df = pd.DataFrame(report).T.drop(
        ["accuracy", "macro avg", "weighted avg"], errors="ignore"
    )
 
    cm = confusion_matrix(y, y_pred, labels=sorted(y.unique()))
    labels = sorted(y.unique())
 
    return {
        "accuracy"  : accuracy_score(y, y_pred),
        "precision" : precision_score(y, y_pred, average="weighted", zero_division=0),
        "recall"    : recall_score(y, y_pred, average="weighted", zero_division=0),
        "f1"        : f1_score(y, y_pred, average="weighted", zero_division=0),
        "report_df" : report_df,
        "cm"        : cm,
        "cm_labels" : labels,
    }
 
 
@st.cache_data
def load_split_stats():
    stats = {}
    for name, path in [("Train", CICIDS_TRAIN), ("Valid", CICIDS_VALID), ("Test", CICIDS_TEST)]:
        if os.path.exists(path):
            df = pd.read_parquet(path, columns=["Label"])
            stats[name] = df["Label"].value_counts().to_dict()
    return stats
 
 
@st.cache_data
def load_alerts():
    if os.path.exists(ALERTS_CORRELATED):
        return pd.read_csv(ALERTS_CORRELATED)
    return None
 
 
@st.cache_data
def load_per_class_report():
    if os.path.exists(PER_CLASS_REPORT_PATH):
        return pd.read_csv(PER_CLASS_REPORT_PATH)
    return None
 
 
@st.cache_data
def load_specialist_report():
    if os.path.exists(SPECIALIST_REPORT_PATH):
        return pd.read_csv(SPECIALIST_REPORT_PATH)
    return None
 
 
@st.cache_data
def load_ctgan_report():
    if os.path.exists(CTGAN_REPORT_PATH):
        return pd.read_csv(CTGAN_REPORT_PATH)
    return None
 
 
@st.cache_data
def load_ensemble_report():
    if os.path.exists(ENSEMBLE_REPORT_PATH):
        return pd.read_csv(ENSEMBLE_REPORT_PATH)
    return None
 
 
# Sidebar
 
with st.sidebar:
    st.markdown("## 🛡️ SOC Dashboard")
    st.markdown("---")
 
    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Binary Detection",
            "Multiclass Detection",
            "Per-Class Analysis",
            "Specialist Model",
            "Ensemble",
            "Anomaly Detection",
            "Alert Correlation",
        ],
        label_visibility="collapsed"
    )
 
    st.markdown("---")
    st.markdown("**Dataset:** CICIDS2017")
    st.markdown("**Models:** RF · XGBoost · Specialist · IsolationForest")
 
 
# Page: Overview
 
def page_overview():
    st.markdown("<h1 style='color:#00d4ff;font-family:Share Tech Mono'>AI-Powered Security Operations Centre</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color:#8899aa'>CICIDS2017 · Intrusion Detection · CTGAN Augmentation · Specialist Ensemble</p>", unsafe_allow_html=True)
 
    split_stats = load_split_stats()
    if split_stats:
        st.markdown("### Dataset Split")
        cols = st.columns(3)
        for i, (split, counts) in enumerate(split_stats.items()):
            total   = sum(counts.values())
            attacks = sum(v for k, v in counts.items() if k != "BENIGN")
            with cols[i]:
                st.markdown(f"""
                <div class='metric-card'>
                    <div class='metric-value'>{total:,}</div>
                    <div class='metric-label'>{split} flows</div>
                    <div style='color:#ff6b6b;font-size:0.8rem;margin-top:6px'>
                        {attacks:,} attacks ({attacks/total*100:.1f}%)
                    </div>
                </div>""", unsafe_allow_html=True)
 
        st.markdown("### Label Distribution by Split")
        rows = []
        for split, counts in split_stats.items():
            for label, count in counts.items():
                rows.append({"Split": split, "Label": label, "Count": count})
        dist_df = pd.DataFrame(rows)
 
        fig = px.bar(
            dist_df, x="Label", y="Count", color="Split",
            barmode="group", log_y=True,
            color_discrete_sequence=["#00d4ff", "#7b2fff", "#ff6b35"]
        )
        fig.update_layout(**PLOTLY_THEME, height=380)
        apply_plotly_theme(fig, height=380)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Run the pipeline first to populate this page.")
        st.code("python -m src.run_pipeline", language="bash")
 
    st.markdown("### Pipeline Status")
    checks = [
        ("Preprocessing",     os.path.exists(X_VALID)),
        ("RF Binary",         os.path.exists(MODEL_PATH)),
        ("RF Multiclass",     os.path.exists(MULTICLASS_MODEL_PATH)),
        ("XGBoost Binary",    os.path.exists(XGBOOST_BINARY_PATH)),
        ("XGBoost Multi",     os.path.exists(XGBOOST_MULTICLASS_PATH)),
        ("Anomaly Model",     os.path.exists(ANOMALY_MODEL_PATH)),
        ("Per-Class Report",  os.path.exists(PER_CLASS_REPORT_PATH)),
        ("CTGAN Augmentation",os.path.exists(CTGAN_AUGMENTED_PATH)),
        ("Specialist Model",  os.path.exists(SPECIALIST_MODEL_PATH)),
        ("Alert Correlation", os.path.exists(ALERTS_CORRELATED)),
    ]
    cols = st.columns(5)
    for i, (label, exists) in enumerate(checks):
        icon = "✅" if exists else "⬜"
        cols[i % 5].markdown(f"{icon} {label}")
 
 
# Page: Binary Detection
 
def page_binary():
    st.markdown("<h2 class='section-header'>Binary Intrusion Detection</h2>", unsafe_allow_html=True)
    st.caption("BENIGN (0) vs ATTACK (1)")
 
    model_choice = st.selectbox("Model", ["RF Binary", "XGBoost Binary"])
    path_map     = {"RF Binary": MODEL_PATH, "XGBoost Binary": XGBOOST_BINARY_PATH}
    model_path   = path_map[model_choice]
 
    if not os.path.exists(model_path):
        st.warning(f"Model not found: {model_path}. Run the pipeline first.")
        return
 
    with st.spinner("Computing metrics..."):
        m = compute_binary_metrics(model_path)
 
    c1, c2, c3, c4 = st.columns(4)
    for col, label, value, color in [
        (c1, "Accuracy",  m["accuracy"],  "#00d4ff"),
        (c2, "Precision", m["precision"], "#7b2fff"),
        (c3, "Recall",    m["recall"],    "#ff6b35"),
        (c4, "F1 Score",  m["f1"],        "#00ff88"),
    ]:
        col.markdown(f"""
        <div class='metric-card'>
            <div class='metric-value' style='color:{color}'>{value:.4f}</div>
            <div class='metric-label'>{label}</div>
        </div>""", unsafe_allow_html=True)
 
    st.markdown("---")
    col_cm, col_sec = st.columns(2)
 
    with col_cm:
        st.markdown("#### Confusion Matrix")
        cm = m["cm"]
        fig = px.imshow(
            cm, text_auto=True,
            x=["Pred BENIGN", "Pred ATTACK"],
            y=["True BENIGN", "True ATTACK"],
            color_continuous_scale="Blues",
        )
        apply_plotly_theme(fig, height=320)
        st.plotly_chart(fig, use_container_width=True)
 
    with col_sec:
        st.markdown("#### Security Metrics")
        fpr_pct = m["fpr"] * 100
        adr_pct = m["adr"] * 100
 
        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=["False Positive Rate", "Attack Detection Rate"],
            y=[fpr_pct, adr_pct],
            marker_color=["#ff4444", "#00ff88"],
            text=[f"{fpr_pct:.2f}%", f"{adr_pct:.2f}%"],
            textposition="outside",
        ))
        apply_plotly_theme(
            fig,
            height=320,
            yaxis=dict(range=[0, 110], title_text="Percentage (%)"),
        )
        st.plotly_chart(fig, use_container_width=True)
 
 
# Page: Multiclass Detection
 
def page_multiclass():
    st.markdown("<h2 class='section-header'>Multiclass Attack Classification</h2>", unsafe_allow_html=True)
    st.caption("Per-attack-type precision, recall, and F1")
 
    model_choice = st.selectbox("Model", ["RF Multiclass", "XGBoost Multiclass"])
    path_map     = {
        "RF Multiclass"      : MULTICLASS_MODEL_PATH,
        "XGBoost Multiclass" : XGBOOST_MULTICLASS_PATH,
    }
    model_path = path_map[model_choice]
 
    if not os.path.exists(model_path):
        st.warning(f"Model not found: {model_path}. Run the pipeline first.")
        return
 
    with st.spinner("Computing multiclass metrics..."):
        m = compute_multiclass_metrics(model_path)
 
    c1, c2, c3, c4 = st.columns(4)
    for col, label, value, color in [
        (c1, "Accuracy",           m["accuracy"],  "#00d4ff"),
        (c2, "Weighted Precision", m["precision"], "#7b2fff"),
        (c3, "Weighted Recall",    m["recall"],    "#ff6b35"),
        (c4, "Weighted F1",        m["f1"],        "#00ff88"),
    ]:
        col.markdown(f"""
        <div class='metric-card'>
            <div class='metric-value' style='color:{color}'>{value:.4f}</div>
            <div class='metric-label'>{label}</div>
        </div>""", unsafe_allow_html=True)
 
    st.markdown("---")
 
    report_df = m["report_df"][["precision", "recall", "f1-score", "support"]].copy()
    report_df = report_df[report_df["support"] > 0]
    report_df.index.name = "Attack Type"
    report_df = report_df.reset_index()
 
    fig = go.Figure()
    for metric, color in [("precision", "#00d4ff"), ("recall", "#ff6b35"), ("f1-score", "#00ff88")]:
        fig.add_trace(go.Bar(
            name=metric.capitalize(),
            x=report_df["Attack Type"],
            y=report_df[metric],
            marker_color=color,
        ))
    apply_plotly_theme(
        fig,
        barmode="group",
        height=420,
        title="Per-Class Precision / Recall / F1",
        xaxis=dict(tickangle=-30),
    )
    st.plotly_chart(fig, use_container_width=True)
 
    st.markdown("#### Confusion Matrix")
    labels = [str(l) for l in m["cm_labels"]]
    fig2 = px.imshow(
        m["cm"], text_auto=True, x=labels, y=labels,
        color_continuous_scale="Blues",
        labels=dict(x="Predicted", y="True"),
    )
    apply_plotly_theme(fig2, height=520)
    st.plotly_chart(fig2, use_container_width=True)
 
    with st.expander("Full Classification Report"):
        st.dataframe(report_df.set_index("Attack Type").round(4))
 
 
# Page: Per-Class Analysis
 
def page_per_class():
    st.markdown("<h2 class='section-header'>Per-Class Isolated Evaluation</h2>", unsafe_allow_html=True)
    st.caption(
        "Each attack type is extracted independently and evaluated in isolation. "
        "This shows exactly which threats the general model handles well vs. poorly."
    )
 
    report_df = load_per_class_report()
 
    if report_df is None:
        st.warning(
            "Per-class report not found. Run the pipeline stage:\n\n"
            "`python -m src.run_pipeline --only per_class_evaluation`"
        )
        return
 
    # Summary cards
    weak   = report_df[report_df["status"] == "WEAK"]
    strong = report_df[report_df["status"] == "STRONG"]
 
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(f"""<div class='metric-card'><div class='metric-value'>{len(report_df)}</div>
        <div class='metric-label'>Total Classes</div></div>""", unsafe_allow_html=True)
    c2.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#00ff88'>
        {len(strong)}</div><div class='metric-label'>Strong (F1 ≥ 0.70)</div></div>""", unsafe_allow_html=True)
    c3.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#ff4444'>
        {len(weak)}</div><div class='metric-label'>Weak (F1 < 0.70)</div></div>""", unsafe_allow_html=True)
    avg_f1 = report_df["f1_score"].mean()
    c4.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#ffcc00'>
        {avg_f1:.3f}</div><div class='metric-label'>Avg F1</div></div>""", unsafe_allow_html=True)
 
    st.markdown("---")
 
    # F1 bar chart — colour by WEAK/STRONG
    fig = go.Figure()
    colours = ["#ff4444" if s == "WEAK" else "#00ff88" for s in report_df["status"]]
    fig.add_trace(go.Bar(
        x=report_df["attack_type"],
        y=report_df["f1_score"],
        marker_color=colours,
        text=report_df["f1_score"].round(3),
        textposition="outside",
    ))
    fig.add_hline(
        y=0.70, line_dash="dash", line_color="#ffcc00",
        annotation_text="Weak threshold (0.70)", annotation_position="top left"
    )
    fig.update_layout(
        **PLOTLY_THEME, height=420,
        title="Per-Class F1 Score — Red = Weak, Green = Strong",
        xaxis_tickangle=-30,
        yaxis=dict(range=[0, 1.1], gridcolor="#1e3a5f"),
    )
    apply_plotly_theme(
        fig,
        height=420,
        xaxis=dict(tickangle=-30),
        yaxis=dict(range=[0, 1.1]),
    )
    st.plotly_chart(fig, use_container_width=True)
 
    # Precision / Recall scatter
    st.markdown("#### Precision vs Recall per Class")
    fig2 = px.scatter(
        report_df,
        x="precision", y="recall",
        color="status",
        color_discrete_map={"WEAK": "#ff4444", "STRONG": "#00ff88"},
        size="support", size_max=40,
        text="attack_type",
        hover_data=["f1_score", "support"],
    )
    fig2.update_traces(textposition="top center")
    fig2.update_layout(**PLOTLY_THEME, height=480,
                       xaxis=dict(range=[0, 1.05]), yaxis=dict(range=[0, 1.05]))
    apply_plotly_theme(
        fig2,
        height=480,
        xaxis=dict(range=[0, 1.05]),
        yaxis=dict(range=[0, 1.05]),
    )
    st.plotly_chart(fig2, use_container_width=True)
 
    # Full table
    with st.expander("Full Per-Class Table"):
        display = report_df.copy()
        display["status"] = display["status"].apply(
            lambda s: f"🔴 {s}" if s == "WEAK" else f"🟢 {s}"
        )
        st.dataframe(display, use_container_width=True)
 
    if len(weak):
        st.markdown("---")
        st.markdown("#### Weak Classes — Targeted for Specialist Model")
        st.markdown(
            "These classes will be used as the training target for the specialist model. "
            "Run the specialist training stage to improve detection on these attack types."
        )
        for _, row in weak.sort_values("f1_score").iterrows():
            st.markdown(
                f"- **{row['attack_type']}** — F1: `{row['f1_score']:.4f}` | "
                f"Precision: `{row['precision']:.4f}` | Recall: `{row['recall']:.4f}` | "
                f"Support: `{row['support']:,}`"
            )
        st.code(
            "python -m src.train_ctgan\n"
            "python -m src.train_specialist_model --use-ctgan",
            language="bash",
        )
 
 
# Page: Specialist Model
 
def page_specialist():
    st.markdown("<h2 class='section-header'>Specialist Model + CTGAN Augmentation</h2>", unsafe_allow_html=True)
    st.caption(
        "A specialist XGBoost model trained exclusively on the attack types the "
        "general model handles poorly. CTGAN synthesises extra training samples for "
        "rare classes before the specialist is trained."
    )
 
    # ── Architecture explanation ──
    with st.expander("How the ensemble works", expanded=False):
        st.markdown("""
**Step 1 — General model** classifies all traffic (BENIGN + 14 attack types).
 
**Step 2 — Per-class evaluation** runs isolated tests on each attack type and flags
classes with F1 < 0.70 as "weak".
 
**Step 3 — CTGAN augmentation** trains a Conditional Tabular GAN on each weak
class and generates synthetic but realistic network flow records to boost training size.
 
**Step 4 — Specialist model** is trained on only the weak classes + BENIGN samples,
using the CTGAN-augmented data. It uses higher-depth XGBoost with per-class sample
weighting so rare attacks are prioritised.
 
**Ensemble inference**: for any flow the general model classifies as a weak class,
the specialist's prediction takes precedence. For everything else, the general model
is used unchanged.
        """)
 
    tabs = st.tabs(["CTGAN Augmentation", "Specialist Performance", "Side-by-Side Comparison"])
 
    # ── Tab 1: CTGAN ──────────────────────────────────────────
    with tabs[0]:
        st.markdown("#### Synthetic Data Generation Report")
        ctgan_report = load_ctgan_report()
 
        if ctgan_report is None:
            st.warning(
                "CTGAN report not found. Run:\n\n"
                "`python -m src.run_pipeline --only ctgan_augmentation`"
            )
        else:
            total_synth = ctgan_report["synth_count"].sum()
            total_real  = ctgan_report["real_count"].sum()
            success     = (ctgan_report["status"] == "success").sum()
 
            c1, c2, c3 = st.columns(3)
            c1.markdown(f"""<div class='metric-card'><div class='metric-value'>{total_real:,}</div>
                <div class='metric-label'>Real samples (weak classes)</div></div>""", unsafe_allow_html=True)
            c2.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#7b2fff'>
                {total_synth:,}</div><div class='metric-label'>Synthetic samples generated</div></div>""",
                unsafe_allow_html=True)
            c3.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#00ff88'>
                {success}/{len(ctgan_report)}</div><div class='metric-label'>Classes augmented</div></div>""",
                unsafe_allow_html=True)
 
            st.markdown("---")
 
            fig = go.Figure()
            fig.add_trace(go.Bar(name="Real samples", x=ctgan_report["label"],
                                  y=ctgan_report["real_count"], marker_color="#00d4ff"))
            fig.add_trace(go.Bar(name="Synthetic (CTGAN)", x=ctgan_report["label"],
                                  y=ctgan_report["synth_count"], marker_color="#7b2fff"))
            fig.update_layout(
                **PLOTLY_THEME, barmode="stack", height=380,
                title="Real vs CTGAN-Synthesised Samples per Weak Class",
                xaxis_tickangle=-20,
            )
            apply_plotly_theme(
                fig,
                barmode="stack",
                height=380,
                xaxis=dict(tickangle=-20),
            )
            st.plotly_chart(fig, use_container_width=True)
 
            with st.expander("Full generation report"):
                st.dataframe(ctgan_report, use_container_width=True)
 
    # ── Tab 2: Specialist performance ─────────────────────────
    with tabs[1]:
        st.markdown("#### Specialist Model — Isolated Class Performance")
        specialist_report = load_specialist_report()
 
        if specialist_report is None:
            st.warning(
                "Specialist report not found. Run:\n\n"
                "`python -m src.run_pipeline --only train_specialist`"
            )
        else:
            # Show only weak classes (not BENIGN)
            weak_report = specialist_report[
                specialist_report["attack_type"] != "BENIGN"
            ].copy() if "attack_type" in specialist_report.columns else specialist_report.copy()
 
            fig = go.Figure()
            fig.add_trace(go.Bar(
                name="Specialist F1",
                x=weak_report.get("attack_type", weak_report.index),
                y=weak_report["specialist_f1"],
                marker_color="#00ff88",
                text=weak_report["specialist_f1"].round(3),
                textposition="outside",
            ))
            if "general_f1" in weak_report.columns:
                fig.add_trace(go.Bar(
                    name="General Model F1",
                    x=weak_report.get("attack_type", weak_report.index),
                    y=weak_report["general_f1"],
                    marker_color="#ff6b35",
                    text=weak_report["general_f1"].round(3),
                    textposition="outside",
                ))
            fig.add_hline(y=0.70, line_dash="dash", line_color="#ffcc00",
                          annotation_text="Weak threshold")
            fig.update_layout(
                **PLOTLY_THEME, barmode="group", height=420,
                title="Specialist vs General F1 on Weak Classes",
                xaxis_tickangle=-30,
                yaxis=dict(range=[0, 1.15]),
            )
            apply_plotly_theme(
                fig,
                barmode="group",
                height=420,
                xaxis=dict(tickangle=-30),
                yaxis=dict(range=[0, 1.15]),
            )
            st.plotly_chart(fig, use_container_width=True)
 
    # ── Tab 3: Side-by-side comparison ────────────────────────
    with tabs[2]:
        st.markdown("#### General vs Specialist — Detailed Comparison")
        specialist_report = load_specialist_report()
 
        if specialist_report is None:
            st.warning("Run the specialist training stage first.")
        else:
            has_gen = "general_f1" in specialist_report.columns
            display = specialist_report.copy()
 
            if has_gen:
                display["F1 Δ"] = (display["specialist_f1"] - display["general_f1"]).round(4)
 
                # Colour-coded improvement
                def colour_delta(val):
                    if val > 0:
                        return "color: #00ff88"
                    elif val < 0:
                        return "color: #ff4444"
                    return ""
 
                cols_show = ["attack_type", "support",
                             "general_f1", "specialist_f1", "F1 Δ"]
                if all(c in display.columns for c in cols_show):
                    styled = (
                        display[cols_show]
                        .set_index("attack_type")
                        .style
                        .applymap(colour_delta, subset=["F1 Δ"])
                        .format({
                            "general_f1"   : "{:.4f}",
                            "specialist_f1": "{:.4f}",
                            "F1 Δ"         : "{:+.4f}",
                        })
                    )
                    st.dataframe(styled, use_container_width=True)
 
                    # Improvement chart
                    imp_df = display[display["attack_type"] != "BENIGN"].copy()
                    imp_df = imp_df.sort_values("F1 Δ", ascending=True)
                    colours = ["#00ff88" if v >= 0 else "#ff4444" for v in imp_df["F1 Δ"]]
                    fig = go.Figure(go.Bar(
                        x=imp_df["attack_type"],
                        y=imp_df["F1 Δ"],
                        marker_color=colours,
                        text=imp_df["F1 Δ"].apply(lambda x: f"{x:+.4f}"),
                        textposition="outside",
                    ))
                    fig.add_hline(y=0, line_color="#8899aa")
                    fig.update_layout(
                        **PLOTLY_THEME, height=380,
                        title="F1 Improvement: Specialist vs General (positive = specialist wins)",
                        xaxis_tickangle=-30,
                    )
                    apply_plotly_theme(
                        fig,
                        height=380,
                        xaxis=dict(tickangle=-30),
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.dataframe(display, use_container_width=True)
 
 
# Page: Anomaly Detection
 
def page_anomaly():
    st.markdown("<h2 class='section-header'>Anomaly Detection — Isolation Forest</h2>", unsafe_allow_html=True)
    st.caption("Unsupervised zero-day / unknown threat detection")
 
    results_path = "data/processed/anomaly_validation_results.csv"
 
    if not os.path.exists(results_path):
        st.warning("Anomaly results not found. Run `python -m src.train_anomaly_model` first.")
        return
 
    df = pd.read_csv(results_path)
    df["is_attack"] = df["true_label"] != "BENIGN"
 
    benign  = df[~df["is_attack"]]
    attacks = df[df["is_attack"]]
 
    fpr = benign["predicted_anomaly"].mean() * 100
    adr = attacks["predicted_anomaly"].mean() * 100
 
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(f"""<div class='metric-card'><div class='metric-value'>{len(df):,}</div>
        <div class='metric-label'>Flows tested</div></div>""", unsafe_allow_html=True)
    c2.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#ff6b35'>
        {fpr:.2f}%</div><div class='metric-label'>False Positive Rate</div></div>""", unsafe_allow_html=True)
    c3.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#00ff88'>
        {adr:.2f}%</div><div class='metric-label'>Attack Detection Rate</div></div>""", unsafe_allow_html=True)
    anomaly_rate = df["predicted_anomaly"].mean() * 100
    c4.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#00d4ff'>
        {anomaly_rate:.2f}%</div><div class='metric-label'>Overall Anomaly Rate</div></div>""", unsafe_allow_html=True)
 
    st.markdown("---")
    st.markdown("#### Detection Rate by Attack Type")
 
    summary = df.groupby("true_label")["predicted_anomaly"].agg(
        Total="count", Flagged="sum"
    ).reset_index()
    summary["Detection Rate %"] = (summary["Flagged"] / summary["Total"] * 100).round(2)
    summary = summary.sort_values("Detection Rate %", ascending=False)
 
    fig = px.bar(
        summary, x="true_label", y="Detection Rate %",
        color="Detection Rate %",
        color_continuous_scale=["#ff4444", "#ffcc00", "#00ff88"],
        text="Detection Rate %",
    )
    fig.update_layout(**PLOTLY_THEME, height=400, xaxis_tickangle=-30,
                      title="Anomaly Detection Rate per Label")
    apply_plotly_theme(
        fig,
        height=400,
        xaxis=dict(tickangle=-30),
    )
    st.plotly_chart(fig, use_container_width=True)
 
    with st.expander("Full results table"):
        st.dataframe(summary)
 
 
# Page: Alert Correlation
 
def page_alerts():
    st.markdown("<h2 class='section-header'>Alert Correlation Engine</h2>", unsafe_allow_html=True)
    st.caption("Correlated, deduplicated, severity-scored alerts with MITRE ATT&CK mapping")
 
    alerts = load_alerts()
 
    if alerts is None:
        st.warning("No correlated alerts found. Run `python -m src.alert_correlation --generate-demo`")
        return
 
    alerts["first_seen"] = pd.to_datetime(alerts["first_seen"])
    alerts["last_seen"]  = pd.to_datetime(alerts["last_seen"])
 
    sev_counts = alerts["severity"].value_counts()
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.markdown(f"""<div class='metric-card'><div class='metric-value'>{len(alerts):,}</div>
        <div class='metric-label'>Correlated Events</div></div>""", unsafe_allow_html=True)
    for col, sev, color in [(c2,"CRITICAL","#ff4444"),(c3,"HIGH","#ff8800"),(c4,"MEDIUM","#ffcc00"),(c5,"LOW","#44ff88")]:
        col.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:{color}'>
            {sev_counts.get(sev, 0)}</div><div class='metric-label'>{sev}</div></div>""", unsafe_allow_html=True)
 
    st.markdown("---")
    col_sev, col_tactic = st.columns(2)
 
    with col_sev:
        st.markdown("#### Severity Distribution")
        sev_order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sev_colors = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#44ff88"}
        sev_df     = alerts["severity"].value_counts().reindex(sev_order).dropna().reset_index()
        sev_df.columns = ["Severity", "Count"]
        fig = px.pie(sev_df, names="Severity", values="Count",
                     color="Severity", color_discrete_map=sev_colors, hole=0.4)
        fig.update_layout(**PLOTLY_THEME, height=300)
        apply_plotly_theme(fig, height=300)
        st.plotly_chart(fig, use_container_width=True)
 
    with col_tactic:
        st.markdown("#### MITRE ATT&CK Tactic Coverage")
        tactic_counts = alerts["tactic"].value_counts().reset_index()
        tactic_counts.columns = ["Tactic", "Events"]
        fig2 = px.bar(tactic_counts, x="Events", y="Tactic", orientation="h",
                      color="Events", color_continuous_scale="Blues")
        fig2.update_layout(**PLOTLY_THEME, height=300)
        apply_plotly_theme(fig2, height=300)
        st.plotly_chart(fig2, use_container_width=True)
 
    st.markdown("#### Top Attacking IPs")
    top_ips = (alerts.groupby("src_ip")["alert_count"].sum()
               .nlargest(15).reset_index()
               .rename(columns={"alert_count": "Total Alerts"}))
    fig3 = px.bar(top_ips, x="src_ip", y="Total Alerts",
                  color="Total Alerts", color_continuous_scale="Reds")
    fig3.update_layout(**PLOTLY_THEME, height=320, xaxis_tickangle=-30)
    apply_plotly_theme(fig3, height=320, xaxis=dict(tickangle=-30))
    st.plotly_chart(fig3, use_container_width=True)
 
    st.markdown("#### Alert Timeline")
    timeline = alerts.groupby(alerts["first_seen"].dt.floor("10min"))["alert_count"].sum().reset_index()
    timeline.columns = ["Time", "Alert Count"]
    fig4 = px.area(timeline, x="Time", y="Alert Count",
                   color_discrete_sequence=["#00d4ff"])
    fig4.update_layout(**PLOTLY_THEME, height=280)
    apply_plotly_theme(fig4, height=280)
    st.plotly_chart(fig4, use_container_width=True)
 
    st.markdown("#### Correlated Alert Log")
    severity_filter = st.multiselect(
        "Filter by severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH"]
    )
    display_cols = ["severity", "src_ip", "predicted_label", "alert_count",
                    "avg_confidence", "first_seen", "mitre_id", "technique", "tactic"]
    filtered = alerts[alerts["severity"].isin(severity_filter)][display_cols]
    st.dataframe(filtered, height=400, use_container_width=True)
 
 
# Page: Ensemble
 
def page_ensemble():
    st.markdown("<h2 class='section-header'>Ensemble — General + Specialist</h2>", unsafe_allow_html=True)
    st.caption(
        "The ensemble routes predictions: if the general model flags a flow as a weak-class "
        "attack (WebAttack_XSS, WebAttack_SQLInjection), the specialist model's prediction "
        "is used instead. For everything else, the general model stands."
    )
 
    with st.expander("Routing logic", expanded=False):
        st.code("""
# Pseudocode — see src/ensemble.py for the real implementation
gen_prediction = general_model.predict(flow)
 
if gen_prediction in specialist_classes:
    final_prediction = specialist_model.predict(flow)
else:
    final_prediction = gen_prediction
        """, language="python")
 
    report = load_ensemble_report()
 
    if report is None:
        st.warning(
            "Ensemble report not found. Run:\n\n"
            "`python -m src.run_pipeline --only evaluate_ensemble`"
        )
        return
 
    # ── Summary cards ──
    specialist_rows = report[report["routed_to_spec"] == True]
    has_gen = "general_f1" in report.columns
 
    if has_gen and len(specialist_rows):
        avg_gen_f1  = specialist_rows["general_f1"].mean()
        avg_ens_f1  = specialist_rows["ensemble_f1"].mean()
        avg_delta   = specialist_rows["f1_delta"].mean()
        total_rows  = report["support"].sum()
        routed_rows = specialist_rows["support"].sum()
 
        c1, c2, c3, c4 = st.columns(4)
        c1.markdown(f"""<div class='metric-card'><div class='metric-value'>{len(specialist_rows)}</div>
            <div class='metric-label'>Classes rerouted to specialist</div></div>""", unsafe_allow_html=True)
        c2.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#ff6b35'>
            {avg_gen_f1:.3f}</div><div class='metric-label'>General Avg F1 (weak classes)</div></div>""", unsafe_allow_html=True)
        c3.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#00ff88'>
            {avg_ens_f1:.3f}</div><div class='metric-label'>Ensemble Avg F1 (weak classes)</div></div>""", unsafe_allow_html=True)
        c4.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#7b2fff'>
            {avg_delta:+.3f}</div><div class='metric-label'>Avg F1 Improvement</div></div>""", unsafe_allow_html=True)
 
    st.markdown("---")
 
    # ── Per-class F1 comparison bar chart ──
    if has_gen:
        st.markdown("#### Per-Class F1: General vs Ensemble")
        all_classes = report[report["support"] > 0].copy()
 
        fig = go.Figure()
        fig.add_trace(go.Bar(
            name="General Model",
            x=all_classes["attack_type"],
            y=all_classes["general_f1"],
            marker_color="#ff6b35",
            text=all_classes["general_f1"].round(3),
            textposition="outside",
        ))
        fig.add_trace(go.Bar(
            name="Ensemble",
            x=all_classes["attack_type"],
            y=all_classes["ensemble_f1"],
            marker_color="#00ff88",
            text=all_classes["ensemble_f1"].round(3),
            textposition="outside",
        ))
        fig.add_hline(y=0.70, line_dash="dash", line_color="#ffcc00",
                      annotation_text="Weak threshold (0.70)")
        fig.update_layout(
            **PLOTLY_THEME, barmode="group", height=420,
            title="F1 Score by Class — General Model vs Ensemble",
            xaxis_tickangle=-30,
            yaxis=dict(range=[0, 1.15]),
        )
        apply_plotly_theme(
            fig,
            barmode="group",
            height=420,
            xaxis=dict(tickangle=-30),
            yaxis=dict(range=[0, 1.15]),
        )
        st.plotly_chart(fig, use_container_width=True)
 
        # ── Delta chart (improvement only) ──
        st.markdown("#### F1 Improvement from Ensemble (Δ = Ensemble − General)")
        delta_df = all_classes.sort_values("f1_delta", ascending=True)
        colours  = ["#00ff88" if v >= 0 else "#ff4444" for v in delta_df["f1_delta"]]
 
        fig2 = go.Figure(go.Bar(
            x=delta_df["attack_type"],
            y=delta_df["f1_delta"],
            marker_color=colours,
            text=delta_df["f1_delta"].apply(lambda x: f"{x:+.4f}"),
            textposition="outside",
        ))
        fig2.add_hline(y=0, line_color="#8899aa")
        fig2.update_layout(
            **PLOTLY_THEME, height=360,
            title="Ensemble Δ F1 (green = ensemble wins, red = ensemble hurts)",
            xaxis_tickangle=-30,
        )
        apply_plotly_theme(
            fig2,
            height=360,
            xaxis=dict(tickangle=-30),
        )
        st.plotly_chart(fig2, use_container_width=True)
 
    # ── Routing callout ──
    st.markdown("#### How the routing works")
    if len(specialist_rows):
        routed_classes = specialist_rows["attack_type"].tolist()
        st.info(
            f"**{len(routed_classes)} class(es) are routed to the specialist:** "
            + ", ".join(f"`{c}`" for c in routed_classes)
            + "\n\nWhen the general model predicts any of these classes, "
            "the specialist model re-evaluates that flow and its prediction is used instead."
        )
 
    with st.expander("Full ensemble comparison table"):
        display = report[report["support"] > 0].copy()
        if has_gen:
            display["routed"] = display["routed_to_spec"].apply(
                lambda x: "✅ Specialist" if x else "General"
            )
            cols = ["attack_type", "support", "general_f1", "ensemble_f1", "f1_delta", "routed"]
            st.dataframe(display[cols].set_index("attack_type").round(4), use_container_width=True)
        else:
            st.dataframe(display, use_container_width=True)
 
 
# Router
 
if page == "Overview":
    page_overview()
elif page == "Binary Detection":
    page_binary()
elif page == "Multiclass Detection":
    page_multiclass()
elif page == "Per-Class Analysis":
    page_per_class()
elif page == "Specialist Model":
    page_specialist()
elif page == "Ensemble":
    page_ensemble()
elif page == "Anomaly Detection":
    page_anomaly()
elif page == "Alert Correlation":
    page_alerts()
