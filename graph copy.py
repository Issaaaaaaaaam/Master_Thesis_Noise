#!/usr/bin/env python3
"""
generate_handshake_comparisons.py  (strict manual-count version)

Reads per-protocol median CSVs from
  results/complete_handshake_benchmark/<protocol>/benchmark_Initiator_<protocol>_medians.csv
and corresponding per-step breakdowns from
  results/<protocol>/benchmark_Initiator_<protocol>_medians.csv

Produces:
  • Per-protocol median tables.
  • Global stacked bar plots (Noise Steps vs Other) for Kyber512, Kyber768, X25519, and all protocols.
  • Per-pattern “All Variants” comparisons where KEM* prefixes are collapsed (e.g., KEMIN→IN),
    showing X25519 / Kyber512 / Kyber768 together if present.

IMPORTANT: No fallback/inference. All step occurrences MUST be hard-coded below
in the per-algorithm dictionaries. If a pattern is missing, the script aborts.
"""

import os
import glob
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict

# --- Configuration ---
BASE_DIR   = os.path.join("results", "complete_handshake_benchmark")
STEP_BASE  = "results"  # per-step breakdowns: results/<protocol>/benchmark_Initiator_<protocol>_medians.csv
PLOTS_DIR  = os.path.join(BASE_DIR, "plots_comparison")
TABLES_DIR = os.path.join(PLOTS_DIR, "tables")

os.makedirs(PLOTS_DIR, exist_ok=True)
os.makedirs(TABLES_DIR, exist_ok=True)

# --- Label controls (informational) ---
SUMMARY_LABELS = {"Handshake", "Total Handshake", "Handshake (total)", "Total"}

# --- HARD-CODED OCCURRENCE DICTS (you MUST fill these) ---
# Map: collapsed pattern code ("NN","NK","NX","XN","XK","XX","KN","KK","KX","IN","IK", ...) ->
#       { "Label": occurrences per handshake on the INITIATOR side }
#
# Common labels you likely have:
#   "Handshake creation", "Handshake start", "Write message", "Read message", "Handshake split"
#
# Example (uncomment & adjust):
COUNTS_X25519 = {
    "IK": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "IN": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "XX": {"Handshake creation":1, "Handshake start":1, "Write message":2, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "XN": {"Handshake creation":1, "Handshake start":1, "Write message":2, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "XK": {"Handshake creation":1, "Handshake start":1, "Write message":2, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "NN": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "NK": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "NX": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "KN": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "KK": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "KX": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
}

# If Kyber counts are the same as X25519 for your measurements, you can copy:
# COUNTS_KYBER512 = {k: v.copy() for k,v in COUNTS_X25519.items()}
COUNTS_KYBER512 = {
    "IK": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "IN": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "XX": {"Handshake creation":1, "Handshake start":1, "Write message":2, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "XN": {"Handshake creation":1, "Handshake start":1, "Write message":2, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "XK": {"Handshake creation":1, "Handshake start":1, "Write message":2, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "NN": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "NK": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "NX": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "KN": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "KK": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "KX": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":2, "Zigbee Packet TX":1, "Handshake split":1},
}
COUNTS_KYBER768 = {
    "IK": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "IN": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "XX": {"Handshake creation":1, "Handshake start":1, "Write message":2, "Read message":2, "Zigbee Packet TX":1, "Handshake split":1},
    "XN": {"Handshake creation":1, "Handshake start":1, "Write message":2, "Read message":2, "Zigbee Packet TX":1, "Handshake split":1},
    "XK": {"Handshake creation":1, "Handshake start":1, "Write message":2, "Read message":2, "Zigbee Packet TX":1, "Handshake split":1},
    "NN": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "NK": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "NX": {"Handshake creation":1, "Handshake start":1, "Write message":2, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "KN": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "KK": {"Handshake creation":1, "Handshake start":1, "Write message":1, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
    "KX": {"Handshake creation":1, "Handshake start":1, "Write message":2, "Read message":1, "Zigbee Packet TX":1, "Handshake split":1},
}

ALG_COUNTS = {
    "x25519":   COUNTS_X25519,
    "kyber512": COUNTS_KYBER512,
    "kyber768": COUNTS_KYBER768,
}

# --- Helpers ---
def _norm(s: str) -> str:
    return str(s).strip().lower()

def _algo_key(protocol_id: str) -> str:
    if "25519" in protocol_id:
        return "x25519"
    if "Kyber512" in protocol_id:
        return "kyber512"
    if "Kyber768" in protocol_id:
        return "kyber768"
    return "other"

def _manual_counts_for(protocol_id: str, pattern_code: str) -> dict:
    return ALG_COUNTS.get(_algo_key(protocol_id), {}).get(pattern_code, {})

def human_format(num):
    try:
        n = float(num)
    except:
        return str(num)
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.0f}k"
    return str(int(round(n)))

def extract_pattern_key(proto, collapse_kem_prefix=True):
    # Example: "Noise_KEMIN_Kyber512_ChaChaPoly_SHA256" -> "IN" if collapse_kem_prefix
    parts = proto.split('_')
    if len(parts) >= 2:
        pattern = parts[1]  # e.g., "KEMIN", "IN", "KEMIK", "IK"
        if collapse_kem_prefix and pattern.startswith("KEM"):
            return pattern[3:]  # strip leading "KEM"
        return pattern
    return proto

def _handshake_total(all_df, proto, metric):
    """Return the Handshake row value for a given protocol+metric (time or cycles)."""
    sub = all_df[(all_df["protocol"] == proto) & (all_df["label"].map(_norm) == "handshake")]
    if not sub.empty:
        return float(sub[metric].iloc[0])
    # Fallback: median across labels if Handshake row is missing
    sub2 = all_df[all_df["protocol"] == proto]
    if not sub2.empty:
        return float(sub2[metric].median())
    return 0.0

def _lookup_metric(df: pd.DataFrame, label: str, metric: str):
    """Find the metric value for a label, trying exact match first, then case-insensitive."""
    exact = df[df["label"] == label]
    if not exact.empty:
        return float(exact.iloc[0][metric])
    ci = df[df["label"].map(_norm) == _norm(label)]
    if not ci.empty:
        return float(ci.iloc[0][metric])
    print(f"[error] Label not found in CSV: '{label}'")
    return None

def load_step_sum(protocol_id, metric):
    """
    Strict manual mode: sum per-step medians × manual occurrences.
    If the pattern is not present in the appropriate dictionary, abort.
    """
    step_path = os.path.join(STEP_BASE, protocol_id, f"benchmark_Initiator_{protocol_id}_medians.csv")
    if not os.path.isfile(step_path):
        print(f"[error] Missing step file for {protocol_id}: {step_path}")
        raise SystemExit(2)

    df = pd.read_csv(step_path)
    required_cols = {"label", metric}
    if df.empty or not required_cols.issubset(df.columns):
        print(f"[error] Invalid step file for {protocol_id}: {step_path}")
        raise SystemExit(2)

    pattern_code = extract_pattern_key(protocol_id, collapse_kem_prefix=True)
    manual_map = _manual_counts_for(protocol_id, pattern_code)

    if not manual_map:
        algo = _algo_key(protocol_id)
        print(f"[error] No manual counts provided for pattern '{pattern_code}' (algo={algo}).")
        print(f"        Please add entries in COUNTS_{algo.upper()} for pattern '{pattern_code}'. Aborting.")
        raise SystemExit(2)

    contrib = 0.0
    debug_reads = debug_writes = None

    for label, occ in manual_map.items():
        if not isinstance(occ, int) or occ < 0:
            print(f"[error] Invalid occurrence count for '{label}' in {protocol_id}: {occ}")
            raise SystemExit(2)
        val = _lookup_metric(df, label, metric)
        if val is None:
            # Label missing/mismatched in CSV; treat as 0 but continue
            continue
        contrib += val * occ
        if _norm(label) == "write message":
            debug_writes = occ
        elif _norm(label) == "read message":
            debug_reads = occ

    if debug_reads is not None or debug_writes is not None:
        print(f"[occ] {protocol_id} ({pattern_code}): writes={debug_writes}, reads={debug_reads}")

    # Sanity vs total
    total_series = df.loc[df["label"].map(_norm).eq("handshake"), metric]
    if not total_series.empty:
        total = float(total_series.iloc[0])
        if contrib > total * 1.05:
            print(f"[warn] {protocol_id} ({pattern_code}): steps {contrib:.1f} > total {total:.1f}")

    return contrib

def csv_to_table_image(img_path, title, df):
    if df.empty:
        print(f"[info] Empty table for {title}, skipping.")
        return
    fig, ax = plt.subplots(figsize=(len(df.columns)*1.5, len(df)*0.4 + 1))
    ax.axis('off')
    tbl = ax.table(cellText=df.values,
                   colLabels=df.columns,
                   cellLoc='center',
                   loc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1.2, 1.2)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(img_path, dpi=300)
    plt.close()
    print(f"[saved] {img_path}")

def plot_grouped(all_df, protocols, metric, ylabel, title, fname):
    sub = all_df[all_df['protocol'].isin(protocols)]
    if sub.empty:
        print(f"[info] No data for {title}, skipping.")
        return

    protos = sorted(sub['protocol'].unique())
    totals = [_handshake_total(all_df, p, metric) for p in protos]
    steps  = [load_step_sum(p, metric) for p in protos]
    rest   = [max(0.0, t - s) for t, s in zip(totals, steps)]

    # Sort by totals desc for display
    order = sorted(range(len(protos)), key=lambda i: totals[i], reverse=True)
    protos = [protos[i] for i in order]
    totals = [totals[i] for i in order]
    steps  = [steps[i]  for i in order]
    rest   = [rest[i]   for i in order]

    # Labels like "IK-X25519", "IN-Kyber512", etc.
    labels = []
    for p in protos:
        pat = extract_pattern_key(p, collapse_kem_prefix=True)
        if 'Kyber512' in p:
            alg = 'Kyber512'
        elif 'Kyber768' in p:
            alg = 'Kyber768'
        elif '25519' in p:
            alg = 'X25519'
        else:
            alg = p
        labels.append(f"{pat}-{alg}")

    x = range(len(protos))
    plt.figure(figsize=(max(6, len(protos)*0.6), 4))
    plt.bar(x, steps, label="Noise Steps", color='tab:blue')
    plt.bar(x, rest, bottom=steps, label="Other", color='dimgray')
    for i, y in enumerate(totals):
        plt.text(i, y, human_format(y), ha='center', va='bottom', fontsize=7)
    plt.xticks(list(x), labels, fontsize=8, rotation=45, ha='right')
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.tight_layout()
    out = os.path.join(PLOTS_DIR, fname)
    plt.savefig(out, dpi=300)
    plt.close()
    print(f"[saved] {out}")

# --- Load all complete-handshake median CSVs ---
protocol_dfs = {}
if not os.path.isdir(BASE_DIR):
    print(f"[error] Missing base directory: {BASE_DIR}")
    raise SystemExit(1)

for proto_dir in os.listdir(BASE_DIR):
    dpath = os.path.join(BASE_DIR, proto_dir)
    if not os.path.isdir(dpath) or proto_dir == 'plots_comparison':
        continue
    for csvf in glob.glob(os.path.join(dpath, '*_medians.csv')):
        fn = os.path.basename(csvf)
        proto = fn.replace('benchmark_Initiator_', '').replace('_medians.csv', '')
        df = pd.read_csv(csvf)
        if df.empty:
            continue
        df['protocol'] = proto
        protocol_dfs[proto] = df

if not protocol_dfs:
    print(f"[error] No median CSVs under {BASE_DIR}")
    raise SystemExit(1)

all_df = pd.concat(protocol_dfs.values(), ignore_index=True)

# --- Per-protocol tables ---
for proto, df in protocol_dfs.items():
    cols = ['label', 'count', 'median_time_us', 'median_cycles']
    tbl = df[cols] if all(c in df.columns for c in cols) else df
    out = os.path.join(TABLES_DIR, f"{proto}_medians_table.png")
    csv_to_table_image(out, f"Medians: {proto}", tbl)

# --- Prepare protocol groups ---
all_protos = sorted(protocol_dfs.keys())
kyber512 = [p for p in all_protos if 'Kyber512' in p]
kyber768 = [p for p in all_protos if 'Kyber768' in p]
x25519   = [p for p in all_protos if '25519'   in p]

# --- Global stacked bar plots ---
plot_grouped(all_df, kyber512, 'median_time_us', 'Median Time (us)',   'Kyber512: Median Time',   'kyber512_time.png')
plot_grouped(all_df, kyber512, 'median_cycles',  'Median Cycles',       'Kyber512: Median Cycles', 'kyber512_cycles.png')
plot_grouped(all_df, kyber768, 'median_time_us', 'Median Time (us)',   'Kyber768: Median Time',   'kyber768_time.png')
plot_grouped(all_df, kyber768, 'median_cycles',  'Median Cycles',       'Kyber768: Median Cycles', 'kyber768_cycles.png')
plot_grouped(all_df, x25519,   'median_time_us', 'Median Time (us)',   'X25519: Median Time',     'x25519_time.png')
plot_grouped(all_df, x25519,   'median_cycles',  'Median Cycles',       'X25519: Median Cycles',   'x25519_cycles.png')
plot_grouped(all_df, all_protos,'median_time_us','Median Time (us)',   'All Protocols: Median Time', 'all_time.png')
plot_grouped(all_df, all_protos,'median_cycles', 'Median Cycles',       'All Protocols: Median Cycles','all_cycles.png')

# --- Per-pattern "All Variants" comparisons with collapsed KEM* prefixes ---
pattern_map = defaultdict(list)
for proto in all_protos:
    key = extract_pattern_key(proto, collapse_kem_prefix=True)  # merges KEMIN->IN, KEMIK->IK, etc.
    pattern_map[key].append(proto)

for code, variants in pattern_map.items():
    # Gather X25519 / Kyber512 / Kyber768 if present under collapsed key
    present = []
    labels = []
    if any('25519' in v for v in variants):
        v = next(v for v in variants if '25519' in v)
        present.append(v); labels.append('X25519')
    if any('Kyber512' in v for v in variants):
        v = next(v for v in variants if 'Kyber512' in v)
        present.append(v); labels.append('Kyber512')
    if any('Kyber768' in v for v in variants):
        v = next(v for v in variants if 'Kyber768' in v)
        present.append(v); labels.append('Kyber768')

    if not present:
        continue

    print(f"[pattern] {code}: variants present = {labels}")

    for metric, ylabel, suffix in [
        ('median_time_us', 'Median Time (us)', 'time'),
        ('median_cycles',  'Median Cycles',    'cycles')
    ]:
        totals_raw = []
        steps_vals = []
        for v in present:
            tot = _handshake_total(all_df, v, metric)
            stp = load_step_sum(v, metric)
            totals_raw.append(tot)
            steps_vals.append(min(stp, tot))  # clamp to total (safety)
            if stp > tot:
                print(f"[warn] {v} ({code}): step sum {stp:.1f} > total {tot:.1f}, clamped")
            else:
                print(f"[info] {v} ({code}): total={tot:.1f}, steps={stp:.1f}, other={tot-stp:.1f}")

        rest = [t - s for t, s in zip(totals_raw, steps_vals)]

        x = range(len(present))
        fig, ax = plt.subplots(figsize=(5, 4))
        ax.bar(x, steps_vals, label="Noise Steps", color='tab:blue')
        ax.bar(x, rest,       bottom=steps_vals, label="Other",       color='dimgray')
        for i, y in enumerate(totals_raw):
            ax.text(i, y, human_format(y), ha='center', va='bottom', fontsize=7)
        ax.set_xticks(list(x))
        ax.set_xticklabels(labels)
        ax.set_ylabel(ylabel)
        ax.set_title(f"Pattern {code}: All Variants")
        handles, lbls = ax.get_legend_handles_labels()
        by_label = dict(zip(lbls, handles))
        ax.legend(by_label.values(), by_label.keys())
        plt.tight_layout()
        out = os.path.join(PLOTS_DIR, f"pair_{code}_{suffix}.png")
        plt.savefig(out, dpi=300)
        plt.close()
        print(f"[saved] {out}")

print("✅ Done. All plots written to", PLOTS_DIR)
