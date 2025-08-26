"""
generate_handshake_comparisons.py — cycles-only, strict manual counts + crypto totals
- Zigbee Packet TX is INCLUDED inside Noise Steps.
- Crypto ops are TOTALS PER HANDSHAKE (initiator), not per message.
- If crypto_total > Noise Steps sum, we DISCARD the crypto breakdown and color the entire
  Noise Steps block as "Crypto (clamped)" (no totals changed; bar top labels use CSV totals).

Reads totals (Handshake row) from:
  results/complete_handshake_benchmark/<protocol>/benchmark_Initiator_<protocol>_medians.csv

Reads step medians from:
  results/<protocol>/benchmark_Initiator_<protocol>_medians.csv

Produces:
  • Per-protocol median tables (cycles only).
  • Stacked bar plots with breakdown:
        [<crypto primitives (colored, total per handshake)> + Noise Overhead (incl. TX)] + Other
    for Kyber512, Kyber768, X25519, and all protocols.
  • Per-pattern “All Variants” comparisons (KEM* collapsed → IN/IK/…):
    X25519 / Kyber512 / Kyber768 together if present.
"""

import os
import glob
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict, OrderedDict

BASE_DIR   = os.path.join("results", "complete_handshake_benchmark")
STEP_BASE  = "results"
PLOTS_DIR  = os.path.join(BASE_DIR, "plots_comparison")
TABLES_DIR = os.path.join(PLOTS_DIR, "tables")
os.makedirs(PLOTS_DIR, exist_ok=True)
os.makedirs(TABLES_DIR, exist_ok=True)

METRIC = "median_cycles"  
HANDSHAKE_LABEL = "Handshake"

DEBUG_VERBOSE = True

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
ALG_COUNTS = {"x25519": COUNTS_X25519, "kyber512": COUNTS_KYBER512, "kyber768": COUNTS_KYBER768}

PRIMITIVE_TOTALS = {
    "x25519": {
        "NN": {"scalarmul_fixed": 1, "scalarmul_var": 1},
        "NK": {"scalarmul_fixed": 1, "scalarmul_var": 2},
        "NX": {"scalarmul_fixed": 1, "scalarmul_var": 2},
        "XN": {"scalarmul_fixed": 1, "scalarmul_var": 2},
        "XK": {"scalarmul_fixed": 1, "scalarmul_var": 3},
        "XX": {"scalarmul_fixed": 1, "scalarmul_var": 3},
        "KN": {"scalarmul_fixed": 1, "scalarmul_var": 2},
        "KK": {"scalarmul_fixed": 1, "scalarmul_var": 4},
        "KX": {"scalarmul_fixed": 1, "scalarmul_var": 3},
        "IN": {"scalarmul_fixed": 1, "scalarmul_var": 2},
        "IK": {"scalarmul_fixed": 1, "scalarmul_var": 4},
    },
    "kyber512": {
        "NN": {"encaps": 0, "decaps": 1},
        "NK": {"encaps": 1, "decaps": 1},
        "NX": {"encaps": 1, "decaps": 1},
        "XN": {"encaps": 0, "decaps": 2},
        "XK": {"encaps": 1, "decaps": 2},
        "XX": {"encaps": 1, "decaps": 2},
        "KN": {"encaps": 0, "decaps": 2},
        "KK": {"encaps": 1, "decaps": 2},
        "KX": {"encaps": 1, "decaps": 2},
        "IN": {"encaps": 0, "decaps": 2},
        "IK": {"encaps": 1, "decaps": 2},
    },
    "kyber768": {
        "NN": {"encaps": 0, "decaps": 1},
        "NK": {"encaps": 1, "decaps": 1},
        "NX": {"encaps": 1, "decaps": 1},
        "XN": {"encaps": 0, "decaps": 2},
        "XK": {"encaps": 1, "decaps": 2},
        "XX": {"encaps": 1, "decaps": 2},
        "KN": {"encaps": 0, "decaps": 2},
        "KK": {"encaps": 1, "decaps": 2},
        "KX": {"encaps": 1, "decaps": 2},
        "IN": {"encaps": 0, "decaps": 2},
        "IK": {"encaps": 1, "decaps": 2},
    },
}

# ----------------- PRIMITIVE COSTS (cycles) — FILL THESE -----------------
PRIMITIVE_COSTS = {
    "x25519": {
        "scalarmul_fixed": 1609377,
        "scalarmul_var":   2569388,
    },
    "kyber512": {
        "encaps": 750462,   #
        "decaps": 629637,   # 
    },
    "kyber768": {
        "encaps": 1148908,   #
        "decaps": 1002022,   # 
    },
}

COMPONENT_COLORS = {
    "scalarmul_fixed": "tab:green",
    "scalarmul_var":   "tab:olive",
    "encaps":          "tab:purple",
    "decaps":          "tab:pink",
    "Crypto (clamped)": "tab:purple",
    "Noise Overhead":  "tab:blue",
    "Other":           "dimgray",
}

def _norm(s: str) -> str: return str(s).strip().lower()

def _algo_key(protocol_id: str) -> str:
    if "25519" in protocol_id:   return "x25519"
    if "Kyber512" in protocol_id:return "kyber512"
    if "Kyber768" in protocol_id:return "kyber768"
    return "other"

def _ensure_metric(df, where):
    if METRIC not in df.columns:
        raise RuntimeError(f"CSV missing column '{METRIC}' {where}. Have: {list(df.columns)}")

def human_format(n):
    try: x = float(n)
    except: return str(n)
    if x >= 1_000_000: return f"{x/1_000_000:.1f}M"
    if x >= 1_000:     return f"{x/1_000:.0f}k"
    return str(int(round(x)))

def extract_pattern_key(proto, collapse_kem_prefix=True):
    parts = proto.split('_')
    if len(parts) >= 2:
        pat = parts[1]
        return pat[3:] if (collapse_kem_prefix and pat.startswith("KEM")) else pat
    return proto

def _handshake_total(all_df, proto):
    sub = all_df[(all_df["protocol"] == proto)]
    _ensure_metric(sub, f"(totals) for protocol {proto}")
    row = sub[sub["label"].map(_norm) == _norm(HANDSHAKE_LABEL)]
    if row.empty:
        raise RuntimeError(f"No '{HANDSHAKE_LABEL}' row found for {proto}")
    return float(row[METRIC].iloc[0])

def _lookup_step_cycles(df: pd.DataFrame, label: str):
    exact = df[df["label"] == label]
    if not exact.empty: return float(exact.iloc[0][METRIC])
    ci = df[df["label"].map(_norm) == _norm(label)]
    if not ci.empty:    return float(ci.iloc[0][METRIC])
    print(f"[error] Step label not found in CSV: '{label}'")
    return None

def _step_counts_for(protocol_id: str, pattern_code: str) -> dict:
    algo = _algo_key(protocol_id)
    d = ALG_COUNTS.get(algo, {}).get(pattern_code, {})
    if not d:
        raise RuntimeError(f"Missing step counts for pattern '{pattern_code}' (algo={algo}). "
                           f"Add to COUNTS_{algo.upper()}.")
    return d  

def _primitive_total_cycles(algo: str, pattern: str) -> (OrderedDict, float):
    per_prim = OrderedDict()
    total = 0.0
    totals_map = PRIMITIVE_TOTALS.get(algo, {}).get(pattern, {})
    for prim, count in totals_map.items():
        cost = PRIMITIVE_COSTS.get(algo, {}).get(prim)
        if cost is None:
            print(f"[warn] Missing cost for primitive '{prim}' (algo={algo}); treating as 0.")
            continue
        cyc = float(cost) * float(count)
        per_prim[prim] = cyc
        total += cyc
    return per_prim, total

def compute_components(protocol_id: str, totals_df: pd.DataFrame):
    """
    Returns:
      components: OrderedDict {component_name: cycles}
        = sum(primitives) + "Noise Overhead" + "Other"
      total: handshake total (cycles) — always from CSV
    """
    
    total = _handshake_total(totals_df, protocol_id)

    
    step_path = os.path.join(STEP_BASE, protocol_id, f"benchmark_Initiator_{protocol_id}_medians.csv")
    if not os.path.isfile(step_path):
        raise RuntimeError(f"Missing step file for {protocol_id}: {step_path}")
    if DEBUG_VERBOSE:
        print(f"[file] steps_csv={step_path}")
    df = pd.read_csv(step_path)
    _ensure_metric(df, f"(steps) for {protocol_id}")
    if "label" not in df.columns:
        raise RuntimeError(f"Steps CSV missing 'label' column for {protocol_id}")

    
    pattern_code = extract_pattern_key(protocol_id, collapse_kem_prefix=True)
    algo = _algo_key(protocol_id)
    step_counts = _step_counts_for(protocol_id, pattern_code)

    steps_sum = 0.0
    dbg_rows = []  
    for step_label, occ in step_counts.items():
        val = _lookup_step_cycles(df, step_label)
        if val is None:
            continue
        contrib = val * occ
        steps_sum += contrib
        dbg_rows.append((step_label, occ, val, contrib))

    
    if DEBUG_VERBOSE:
        print(f"[steps] {protocol_id} ({pattern_code}, {algo}):")
        for lbl, occ, val, contrib in dbg_rows:
            print(f"   - {lbl:20s} occ={occ:<2d} median={val:.0f} -> {contrib:.0f}")
        msg_sum = sum(c for (lbl,_,_,c) in dbg_rows if lbl in ("Write message","Read message"))
        nonmsg_sum = steps_sum - msg_sum
        print(f"   = msg_sum={msg_sum:.0f}, nonmsg_sum={nonmsg_sum:.0f}, steps_sum={steps_sum:.0f}, handshake_total={total:.0f}")

    
    prim_detail, prim_sum = _primitive_total_cycles(algo, pattern_code)
    if DEBUG_VERBOSE:
        if prim_detail:
            pdsc = " ".join(f"{k}={v:.0f}" for k,v in prim_detail.items())
            print(f"[crypto] {protocol_id}: {pdsc} | sum={prim_sum:.0f}")
        else:
            print(f"[crypto] {protocol_id}: (none) sum=0")

    # Clamp behavior: if crypto > Noise Steps, discard breakdown and fill Noise as "Crypto (clamped)" Should not be triggered if it does it means mistake
    if prim_sum > steps_sum + 1e-9:
        print(f"[warn] {protocol_id}: crypto total ({prim_sum:.1f}) > steps sum ({steps_sum:.1f}); "
              f"discarding crypto breakdown and filling Noise Steps with 'Crypto (clamped)'.")
        prim_detail = OrderedDict([("Crypto (clamped)", steps_sum)])
        prim_sum = steps_sum
        noise_overhead = 0.0
    else:
        noise_overhead = steps_sum - prim_sum

    # 
    other = max(0.0, total - steps_sum)

    #
    order_pref = ["scalarmul_fixed", "scalarmul_var", "encaps", "decaps", "Crypto (clamped)"]
    components = OrderedDict()
    for name in order_pref:
        if prim_detail.get(name, 0.0) > 0:
            components[name] = prim_detail[name]
    for name in prim_detail:
        if name not in components:
            components[name] = prim_detail[name]
    components["Noise Overhead"] = noise_overhead
    components["Other"] = other

    for k, v in components.items():
        if v < 0 and abs(v) < 1e-6:
            components[k] = 0.0

    if DEBUG_VERBOSE:
        used_crypto = sum(v for k,v in components.items() if k not in ("Noise Overhead","Other"))
        print(f"[breakdown] {protocol_id}: steps={steps_sum:.0f} crypto_used={used_crypto:.0f} "
              f"overhead={noise_overhead:.0f} other={other:.0f} total_csv={total:.0f}")

    return components, total

def csv_to_table_image(img_path, title, df):
    if df.empty:
        print(f"[info] Empty table for {title}, skipping.")
        return
    show_cols = [c for c in ["label", "count", METRIC] if c in df.columns]
    fig, ax = plt.subplots(figsize=(len(show_cols)*1.5, len(df)*0.4 + 1))
    ax.axis('off')
    tbl = ax.table(cellText=df[show_cols].values, colLabels=show_cols, cellLoc='center', loc='center')
    tbl.auto_set_font_size(False); tbl.set_fontsize(10); tbl.scale(1.2, 1.2)
    plt.title(title); plt.tight_layout(); plt.savefig(img_path, dpi=300); plt.close()
    print(f"[saved] {img_path}")

def _stacked_bars(protos, labels_for_xticks, comp_by_proto, totals_by_proto, title, ylabel, fname):
    
    comp_names = OrderedDict()
    for p in protos:
        for name in comp_by_proto[p].keys():
            comp_names[name] = True
    pref = ["scalarmul_fixed", "scalarmul_var", "encaps", "decaps", "Crypto (clamped)", "Noise Overhead", "Other"]
    ordered_components = [c for c in pref if c in comp_names] + [c for c in comp_names if c not in pref]

    x = range(len(protos))
    bottoms = [0.0] * len(protos)
    plt.figure(figsize=(max(6, len(protos)*0.7), 4.8))

    for comp in ordered_components:
        vals = [comp_by_proto[p].get(comp, 0.0) for p in protos]
        color = COMPONENT_COLORS.get(comp, None)
        plt.bar(x, vals, bottom=bottoms, label=comp, color=color)
        bottoms = [b + v for b, v in zip(bottoms, vals)]

    
    totals = [totals_by_proto[p] for p in protos]
    for i, y in enumerate(totals):
        plt.text(i, y, human_format(y), ha='center', va='bottom', fontsize=7)

    plt.xticks(list(x), labels_for_xticks, fontsize=8, rotation=45, ha='right')
    plt.ylabel(ylabel); plt.title(title); plt.legend(ncol=3, fontsize=8)
    plt.tight_layout(); out = os.path.join(PLOTS_DIR, fname); plt.savefig(out, dpi=300); plt.close()
    print(f"[saved] {out}")

def plot_grouped_breakdown(all_df, protocols, title, fname):
    sub = all_df[all_df['protocol'].isin(protocols)]
    if sub.empty:
        print(f"[info] No data for {title}, skipping.")
        return

    protos = sorted(sub['protocol'].unique())
    comp_by_proto, totals_by_proto, xtick_labels = {}, {}, []

    for p in protos:
        comps, total = compute_components(p, all_df)
        comp_by_proto[p] = comps
        totals_by_proto[p] = total
        pat = extract_pattern_key(p, collapse_kem_prefix=True)
        alg = 'Kyber512' if 'Kyber512' in p else ('Kyber768' if 'Kyber768' in p else ('X25519' if '25519' in p else p))
        xtick_labels.append(f"{pat}-{alg}")

    
    order = sorted(range(len(protos)), key=lambda i: totals_by_proto[protos[i]], reverse=True)
    protos = [protos[i] for i in order]
    xtick_labels = [xtick_labels[i] for i in order]

    _stacked_bars(protos, xtick_labels, comp_by_proto, totals_by_proto, title, "Median Cycles", fname)


protocol_dfs = {}
if not os.path.isdir(BASE_DIR):
    print(f"[error] Missing base directory: {BASE_DIR}"); raise SystemExit(1)

for proto_dir in os.listdir(BASE_DIR):
    dpath = os.path.join(BASE_DIR, proto_dir)
    if not os.path.isdir(dpath) or proto_dir == 'plots_comparison':
        continue
    for csvf in glob.glob(os.path.join(dpath, '*_medians.csv')):
        fn = os.path.basename(csvf)
        proto = fn.replace('benchmark_Initiator_', '').replace('_medians.csv', '')
        df = pd.read_csv(csvf)
        if df.empty: continue
        df['protocol'] = proto
        protocol_dfs[proto] = df

if not protocol_dfs:
    print(f"[error] No median CSVs under {BASE_DIR}"); raise SystemExit(1)

all_df = pd.concat(protocol_dfs.values(), ignore_index=True)
if METRIC not in all_df.columns:
    raise SystemExit(f"[error] Column '{METRIC}' not found in combined medians")

for proto, df in protocol_dfs.items():
    out = os.path.join(TABLES_DIR, f"{proto}_medians_table.png")
    csv_to_table_image(out, f"Medians (cycles): {proto}", df)


all_protos = sorted(protocol_dfs.keys())
kyber512 = [p for p in all_protos if 'Kyber512' in p]
kyber768 = [p for p in all_protos if 'Kyber768' in p]
x25519   = [p for p in all_protos if '25519'   in p]


plot_grouped_breakdown(all_df, kyber512, 'Kyber512: Median Cycles', 'kyber512_cycles.png')
plot_grouped_breakdown(all_df, kyber768, 'Kyber768: Median Cycles', 'kyber768_cycles.png')
plot_grouped_breakdown(all_df, x25519,   'X25519: Median Cycles',   'x25519_cycles.png')
plot_grouped_breakdown(all_df, all_protos,'All Protocols: Median Cycles','all_cycles.png')


pattern_map = defaultdict(list)
for proto in all_protos:
    key = extract_pattern_key(proto, collapse_kem_prefix=True)
    pattern_map[key].append(proto)

for code, variants in pattern_map.items():
    present, labels = [], []
    if any('25519' in v for v in variants):
        v = next(v for v in variants if '25519' in v); present.append(v); labels.append('X25519')
    if any('Kyber512' in v for v in variants):
        v = next(v for v in variants if 'Kyber512' in v); present.append(v); labels.append('Kyber512')
    if any('Kyber768' in v for v in variants):
        v = next(v for v in variants if 'Kyber768' in v); present.append(v); labels.append('Kyber768')
    if not present: continue
    print(f"[pattern] {code}: variants present = {labels}")
    plot_grouped_breakdown(all_df, present, f"Pattern {code}: All Variants (Cycles)", f"pair_{code}_cycles.png")

print("✅ Done. All plots written to", PLOTS_DIR)
