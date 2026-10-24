import html
import tempfile
import time
from datetime import datetime

import altair as alt
import pandas as pd
import streamlit as st

import settings
from alert_system import AlertSystem
from anomaly_detector import AnomalyDetector
from dataset_loader import expand_paths
from engine import IntrusionDetectionSystem
from packet_sources import list_interfaces
from train_from_dataset import train_from_files

st.set_page_config(page_title="Network IDS", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

# ------------------------------------------------------------------ design tokens
# Dark, one accent colour. Severity is shown by label and by the strength of the accent, not by hue.
BG, PANEL, LINE = "#0B0F14", "#111821", "#1F2A36"
INK, MUTED, ACCENT = "#E6EDF3", "#8B98A5", "#38D1BF"
SEV = {"critical": "#38D1BF", "high": "#2A9D8F", "medium": "#1E7268", "low": "#4A5866"}
SEV_ORDER = list(SEV)
STATES = {   # key: (colour, background, title)
    "idle":     (MUTED,  "rgba(139,152,165,.08)", "Not monitoring"),
    "clear":    (ACCENT, "rgba(56,209,191,.06)",  "All clear"),
    "watch":    (ACCENT, "rgba(56,209,191,.10)",  "Watching"),
    "elevated": (ACCENT, "rgba(56,209,191,.15)",  "Elevated"),
    "attack":   (ACCENT, "rgba(56,209,191,.22)",  "Under attack"),
}
RULE_NAMES = {"ddos": "DDoS", "syn_flood": "SYN flood", "dos_flood": "DoS flood",
              "port_scan": "Port scan (fast)", "port_scan_multi": "Port scan (many ports)",
              "null_scan": "NULL scan", "xmas_scan": "XMAS scan", "syn_fin": "SYN+FIN packet",
              "isolation_forest": "Anomaly (Isolation Forest)"}
name = lambda r: RULE_NAMES.get(r, r.replace("_", " ").capitalize())

st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&display=swap');
.stApp, .stApp p, .stApp li, .stApp label, .stApp h1, .stApp h2, .stApp h3, .stApp input,
.stApp textarea, .stApp button, [data-testid="stMetricValue"] {{
  font-family: 'IBM Plex Sans', system-ui, 'Segoe UI', sans-serif; }}
#MainMenu, footer, [data-testid="stSidebar"], [data-testid="collapsedControl"] {{ display: none; }}
header[data-testid="stHeader"] {{ background: transparent; }}
.block-container {{ padding-top: 4.5rem; max-width: 1320px; }}
[data-testid="stVerticalBlockBorderWrapper"] {{ border-radius: 14px; border-color: {LINE}; background: {PANEL}; }}
[data-testid="stMetricLabel"] p {{ color: {MUTED}; font-size: .85rem; }}
[data-testid="stMetricValue"] {{ font-weight: 600; font-variant-numeric: tabular-nums; }}
button[kind="primary"], button[kind="primaryFormSubmit"] {{ color: #06201C !important; font-weight: 600; }}
.stTabs [data-baseweb="tab"] {{ font-weight: 500; padding: 0 4px; margin-right: 18px; }}
h2.panel {{ font-size: 1.02rem; font-weight: 600; line-height: 1.5; margin: 0 0 .6rem 0; padding: 0; color: {INK}; }}
.hdr {{ display:flex; align-items:center; justify-content:space-between; margin-bottom:1rem; gap:12px; flex-wrap:wrap; }}
.hdr h1 {{ font-size: 1.55rem; font-weight: 600; line-height: 1.4; margin:0; padding:0; color:{INK}; letter-spacing:-.01em; }}
.pill {{ display:inline-flex; align-items:center; gap:8px; padding:6px 14px; border-radius:999px;
  font-size:.86rem; font-weight:500; background:{PANEL}; border:1px solid {LINE}; color:{INK}; }}
.dot {{ width:9px; height:9px; border-radius:50%; background:#4A5866; }}
.pill.on .dot {{ background:{ACCENT}; animation: pulse 1.8s ease-out infinite; }}
@keyframes pulse {{ 0% {{ box-shadow: 0 0 0 0 rgba(56,209,191,.5); }} 100% {{ box-shadow: 0 0 0 9px rgba(56,209,191,0); }} }}
@media (prefers-reduced-motion: reduce) {{ .pill.on .dot {{ animation: none; }} }}
.banner {{ border-radius:14px; padding:18px 24px; margin-bottom:14px; border:1px solid {LINE}; border-left:6px solid; }}
.banner .t {{ font-size:1.35rem; font-weight:600; letter-spacing:-.01em; }}
.banner .d {{ font-size:.97rem; margin-top:2px; color:{INK}; }}
.feed-item {{ border-left:3px solid; padding:8px 12px; margin-bottom:9px; background:{BG}; border-radius:0 10px 10px 0; }}
.feed-top {{ display:flex; justify-content:space-between; font-size:.93rem; }}
.feed-sub {{ font-size:.84rem; color:{MUTED}; font-variant-numeric: tabular-nums; }}
.sevtag {{ font-weight:600; font-size:.78rem; text-transform:uppercase; letter-spacing:.04em; }}
.empty {{ color:{MUTED}; padding:26px 4px; font-size:.95rem; }}
</style>
""", unsafe_allow_html=True)

ss = st.session_state
ss.setdefault("ids", None)
ss.setdefault("anomaly", AnomalyDetector())
ss.setdefault("alerts", AlertSystem())
ss.setdefault("report", None)
ss.setdefault("benign_value", settings.BENIGN_LABEL)
ss.setdefault("my_ip", "")


# ------------------------------------------------------------------ helpers
def alerts_df():
    return pd.DataFrame(ss.alerts.get_alerts())


def source_text(ids):
    return {"simulation": "simulated traffic", "pcap": "a capture file",
            "live": f"interface {ids.interface}"}[ids.source]


def join_words(parts):
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def threat_state(df, running):
    if not running:
        return "idle", "Choose a traffic source above and press Start monitoring."
    recent = df[df.ts > time.time() - 60] if len(df) else df
    if not len(recent):
        return "clear", "No alerts in the last minute."
    n = {s: int((recent.severity == s).sum()) for s in SEV_ORDER}
    parts = [f"{n[s]} {s}" for s in SEV_ORDER if n[s]]
    top = recent.source_ip.value_counts().idxmax()
    key = "attack" if n["critical"] else "elevated" if n["high"] else "watch"
    return key, f"{join_words(parts)} {'alert' if len(recent) == 1 else 'alerts'} in the last minute. Most active source: {top}."


def empty(msg):
    st.markdown(f'<div class="empty">{msg}</div>', unsafe_allow_html=True)


def panel_title(text):
    st.markdown(f'<h2 class="panel">{text}</h2>', unsafe_allow_html=True)


def dark(chart, height):
    return (chart.properties(height=height, width="container")
            .configure(background="transparent").configure_view(stroke=None)
            .configure_axis(labelColor=MUTED, titleColor=MUTED, gridColor=LINE, domainColor=LINE, tickColor=LINE)
            .configure_legend(labelColor=MUTED))


def traffic_chart(hist):
    h = pd.DataFrame(hist)
    h["t"] = [datetime.fromtimestamp(s) for s in h.second]
    x = alt.X("t:T", axis=alt.Axis(title=None, format="%H:%M:%S", grid=False))
    area = alt.Chart(h).mark_area(color=ACCENT, opacity=0.15, interpolate="monotone",
                                  line={"color": ACCENT, "strokeWidth": 2}).encode(
        x=x, y=alt.Y("packets:Q", title="Packets per second"))
    bars = alt.Chart(h[h.alerts > 0]).mark_bar(color=INK, opacity=0.85, size=6).encode(
        x=x, y=alt.Y("alerts:Q", title="Alerts", axis=alt.Axis(orient="right", grid=False, tickMinStep=1)))
    return dark(alt.layer(area, bars).resolve_scale(y="independent"), 250)


def hbar(data, y, x, color=None, height=200):
    enc = dict(y=alt.Y(f"{y}:N", sort="-x", title=None, axis=alt.Axis(labelColor=INK, labelLimit=220)),
               x=alt.X(f"{x}:Q", title=None, axis=alt.Axis(tickMinStep=1)))
    enc["color"] = color or alt.value(ACCENT)
    return dark(alt.Chart(data).mark_bar(cornerRadiusEnd=4, size=16).encode(**enc), height)


# ------------------------------------------------------------------ header
st.markdown(f"""<div class="hdr"><h1>Network intrusion detection</h1>
<span class="pill {'on' if ss.ids and ss.ids.running else ''}"><span class="dot"></span>
{('Monitoring ' + source_text(ss.ids)) if ss.ids and ss.ids.running else 'Stopped'}</span></div>""",
            unsafe_allow_html=True)


# ------------------------------------------------------------------ controls (one row, no sidebar)
SOURCES = {"Live capture": "live", "Simulation": "simulation", "PCAP file": "pcap"}
running = bool(ss.ids and ss.ids.running)
spacer = '<div style="height:1.75rem"></div>'
with st.container(border=True):
    c = st.columns([1.3, 2.2, 1.3, 1.2], vertical_alignment="top")
    mode = c[0].selectbox("Traffic source", list(SOURCES), disabled=running)
    interface, pcap_path, attack_prob, my_ip = None, None, 0.003, ""
    if mode == "Live capture":
        ifaces = list_interfaces()
        pick = c[1].selectbox("Network interface", range(len(ifaces)), format_func=lambda k: ifaces[k][0],
                              disabled=running, help="Pick the Wi-Fi or Ethernet card that the scan will reach.")
        _, interface, my_ip = ifaces[pick]
    elif mode == "Simulation":
        attack_prob = c[1].slider("Attack frequency", 0.0005, 0.02, 0.003, 0.0005, format="%.4f", disabled=running)
    else:
        up = c[1].file_uploader("Capture file", type=["pcap", "pcapng"], disabled=running)
        if up:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                tmp.write(up.getbuffer())
                pcap_path = tmp.name
    c[2].markdown(spacer, unsafe_allow_html=True)
    use_ml = c[2].toggle("Anomaly model", value=False, disabled=not ss.anomaly.ready,
                         help="Needs a trained model (Model and dataset tab). Experimental: can raise false "
                              "alarms on real traffic. Signature rules always run.")
    c[3].markdown(spacer, unsafe_allow_html=True)
    clicked = c[3].button("Stop" if running else "Start monitoring", type="secondary" if running else "primary",
                          use_container_width=True)
    if not ss.anomaly.ready:
        st.caption("No anomaly model trained yet: only the signature rules will run. Train one in the Model and dataset tab.")

if ss.ids:
    ss.ids.detection_engine.use_anomaly = use_ml
if clicked:
    if running:
        ss.ids.stop()
    else:
        ss.alerts.clear()
        ss.my_ip = my_ip
        ss.ids = IntrusionDetectionSystem(
            interface=interface, source=SOURCES[mode], pcap_path=pcap_path,
            anomaly=ss.anomaly, alert_system=ss.alerts, attack_prob=attack_prob)
        ss.ids.detection_engine.use_anomaly = use_ml
        ss.ids.start()
    st.rerun()


# ------------------------------------------------------------------ status
@st.fragment(run_every=2)
def status():
    ids, df = ss.ids, alerts_df()
    running = bool(ids and ids.running)
    key, text = threat_state(df, running)
    color, bg, title = STATES[key]
    st.markdown(f'<div class="banner" style="background:{bg};border-left-color:{color}">'
                f'<div class="t" style="color:{color}">{title}</div><div class="d">{html.escape(text)}</div></div>',
                unsafe_allow_html=True)
    if ids and ids.capture_error:
        st.error(f"Capture problem: {ids.capture_error}")
    if ids and ids.errors:
        st.warning(f"{ids.errors} packets could not be analysed. Last error: {ids.last_error}")

    snap = ids.snapshot() if ids else {"total_packets": 0, "history": [], "top_sources": {}}
    recent = int((df.ts > time.time() - 60).sum()) if len(df) else 0
    pps = snap["history"][-1]["packets"] if snap["history"] else 0
    k = st.columns(4)
    k[0].metric("Packets analysed", f"{snap['total_packets']:,}", border=True)
    k[1].metric("Packets per second", f"{pps:,}", border=True)
    k[2].metric("Alerts, last minute", recent, help=f"{len(df):,} since the last clear.", border=True)
    k[3].metric("Anomaly model", "Ready" if ss.anomaly.ready else "Not trained",
                help="Train it in the Model and dataset tab.", border=True)


status()
tab_live, tab_alerts, tab_model = st.tabs(["Live monitor", "Alerts", "Model and dataset"])


# ------------------------------------------------------------------ tab 1: live monitor
@st.fragment(run_every=2)
def live_view():
    ids, df = ss.ids, alerts_df()
    snap = ids.snapshot() if ids else {"history": [], "top_sources": {}}
    left, right = st.columns([2, 1])
    with left:
        with st.container(border=True, height=352):
            panel_title("Traffic and alerts")
            if snap["history"]:
                st.altair_chart(traffic_chart(snap["history"]))
            else:
                hint = (f" To test, run <code>nmap -sS {ss.my_ip}</code> from another device." if ss.my_ip else "")
                empty("Traffic appears here once monitoring starts." + hint)
    with right:
        with st.container(border=True, height=352):
            panel_title("Latest alerts")
            if len(df):
                items = ""
                for a in df.sort_values("id", ascending=False).head(7).to_dict("records"):
                    c = SEV.get(a["severity"], SEV["low"])
                    items += (f'<div class="feed-item" style="border-left-color:{c}"><div class="feed-top">'
                              f'<b>{html.escape(name(a["rule"]))}</b><span class="sevtag" style="color:{c}">{a["severity"]}</span></div>'
                              f'<div class="feed-sub">{a["source_ip"]} to {a["destination_ip"]}:{a["destination_port"]}</div>'
                              f'<div class="feed-sub">{a["time"]}</div></div>')
                st.markdown(items, unsafe_allow_html=True)
            else:
                empty("No alerts yet.")
    a, b = st.columns(2)
    with a:
        with st.container(border=True):
            panel_title("Alerts by rule")
            if len(df):
                g = df.assign(rule_name=df.rule.map(name)).groupby(["rule_name", "severity"]).size().reset_index(name="count")
                col = alt.Color("severity:N", legend=None,
                                scale=alt.Scale(domain=SEV_ORDER, range=list(SEV.values())))
                st.altair_chart(hbar(g, "rule_name", "count", col))
            else:
                empty("Nothing to chart yet.")
    with b:
        with st.container(border=True):
            panel_title("Most active sources")
            if snap["top_sources"]:
                t = pd.DataFrame({"source": list(snap["top_sources"]), "alerts": list(snap["top_sources"].values())})
                st.altair_chart(hbar(t, "source", "alerts"))
            else:
                empty("Nothing to chart yet.")


with tab_live:
    live_view()


# ------------------------------------------------------------------ tab 2: alerts
@st.fragment(run_every=3)
def alerts_view():
    df = alerts_df()
    if df.empty:
        empty("No alerts yet. Start monitoring and attacks will appear here as they are detected.")
        return
    c1, c2, c3 = st.columns([2, 1.4, 1.4])
    sev = c1.multiselect("Severity", SEV_ORDER, default=SEV_ORDER, key="f_sev")
    rule = c2.selectbox("Rule", ["All rules"] + sorted(df.rule.unique()), key="f_rule")
    q = c3.text_input("Find an IP address", key="f_q", placeholder="e.g. 203.0.113")
    v = df[df.severity.isin(sev)]
    if rule != "All rules":
        v = v[v.rule == rule]
    if q:
        v = v[v.source_ip.str.contains(q, regex=False) | v.destination_ip.str.contains(q, regex=False)]
    v = v.sort_values("id", ascending=False)
    st.caption(f"Showing {len(v):,} of {len(df):,} alerts, newest first.")
    shown = v[["time", "severity", "rule", "source_ip", "destination_ip", "destination_port", "confidence"]].copy()
    shown["rule"] = shown.rule.map(name)
    st.dataframe(shown, hide_index=True, height=440, column_config={
        "time": "Time", "severity": "Severity", "rule": "Detection",
        "source_ip": "Source", "destination_ip": "Target", "destination_port": "Port",
        "confidence": st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1, format="%.2f")})
    d1, d2, _ = st.columns([1, 1, 4])
    d1.download_button("Download as CSV", v.to_csv(index=False), "alerts.csv", "text/csv")
    if d2.button("Clear alerts"):
        ss.alerts.clear()


with tab_alerts:
    alerts_view()


# ------------------------------------------------------------------ tab 3: model and dataset
with tab_model:
    left, right = st.columns([1, 1.5])
    m = ss.anomaly
    with left:
        with st.container(border=True):
            panel_title("Anomaly model")
            if m.ready:
                st.success(f"Ready. Trained on {m.n_trained_on:,} samples ({m.trained_from}).")
                st.caption("Measures: " + ", ".join(f.replace("_", " ") for f in m.features) + ".")
                if not m.live_compatible:
                    st.error("This model uses dataset-only features, so it cannot score live packets.")
            else:
                st.warning("Not trained yet. Train it from your dataset on the right.")
            st.caption("The Isolation Forest learns what normal traffic looks like from the dataset, then flags "
                       "packets that are easy to separate from it. It never sees attack labels while training.")
    with right:
        with st.container(border=True):
            panel_title("Train from the dataset")
            with st.form("dataset_form", border=False):
                ds_up = st.file_uploader("Dataset CSV files", type="csv", accept_multiple_files=True,
                                         help="Labelled flow CSVs, e.g. CICIDS2017. Leave empty to use the data/ folder.")
                with st.expander("Advanced"):
                    ds_path = st.text_input("Or read files from this path", settings.DATASET_GLOB)
                    a, b = st.columns(2)
                    label_col = a.text_input("Label column", settings.LABEL_COLUMN)
                    benign = b.text_input("Normal traffic is labelled", settings.BENIGN_LABEL)
                    c, d = st.columns(2)
                    max_rows = c.number_input("Rows to read per file (0 = all)", 0, 5_000_000,
                                              settings.MAX_ROWS_PER_FILE, 50_000)
                    contam = d.slider("Allowed false alarms", 0.001, 0.10, settings.CONTAMINATION, 0.001,
                                      format="%.3f",
                                      help="Share of normal traffic the model may flag. Higher catches more attacks "
                                           "but raises more false alarms.")
                go = st.form_submit_button("Train and evaluate", type="primary")
            if go:
                try:
                    with st.spinner("Training on normal rows, then testing on unseen traffic..."):
                        ss.report = train_from_files(ss.anomaly, ds_up or ds_path, label_col, benign,
                                                     int(max_rows), contam)
                        ss.benign_value = benign
                    st.rerun()
                except Exception as e:
                    st.error(f"Could not train: {e}")

    r = ss.report
    if r:
        st.write("")
        panel_title("Evaluation on unseen traffic")
        k = st.columns(5)
        for col, (label, val, tip) in zip(k, [
                ("Precision", r["precision"], "Of everything flagged, how much was really an attack."),
                ("Recall", r["recall"], "Of all real attacks, how many were flagged."),
                ("F1 score", r["f1"], "Balance of precision and recall."),
                ("ROC-AUC", r["auc"], "How well the model ranks attacks above normal traffic. 1.0 is perfect."),
                ("False alarm rate", r["fpr"], "Share of normal traffic wrongly flagged.")]):
            col.metric(label, f"{val:.3f}", help=tip, border=True)
        a, b = st.columns([1, 1.6])
        with a:
            with st.container(border=True):
                panel_title("Confusion matrix")
                (tn, fp), (fn, tp) = r["cm"]
                st.dataframe(pd.DataFrame([[tn, fp], [fn, tp]], index=["Actually normal", "Actually attack"],
                                          columns=["Flagged normal", "Flagged attack"]))
                st.caption(f"Trained on {r['n_train']:,} normal rows, tested on {r['n_test']:,} unseen rows.")
        with b:
            with st.container(border=True):
                panel_title("Share flagged, by traffic type")
                p = r["per_label"].reset_index()
                is_norm = p.label.str.lower() == ss.benign_value.strip().lower()
                p["kind"] = ["Normal (false alarms)" if n else "Attack (detected)" for n in is_norm]
                col = alt.Color("kind:N", legend=alt.Legend(title=None, orient="bottom"),
                                scale=alt.Scale(domain=["Attack (detected)", "Normal (false alarms)"],
                                                range=[ACCENT, "#4A5866"]))
                st.altair_chart(hbar(p, "label", "flagged_pct", col, height=max(120, 34 * len(p))))
                st.caption("For attack types, higher is better. Short bars mean the model misses that attack.")