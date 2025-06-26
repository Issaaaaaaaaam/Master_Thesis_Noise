#!/usr/bin/env python3
"""
generate_handshake_comparisons.py

Reads per-protocol median CSVs from results/complete_handshake_benchmark/<protocol>/benchmark_<protocol>_medians.csv,
then for each protocol:
  • Generates a table image of its median values.
And globally:
  • Ordered bar plots for median time and cycles across all Kyber512 protocols.
  • Ordered bar plots for median time and cycles across all X25519 protocols.
  • Ordered bar plots for median time and cycles across all protocols.
  • Pairwise bar plots (X25519 vs Kyber512) per handshake pattern, for both time and cycles.

All outputs go to results/complete_handshake_benchmark/plots_comparison/.
"""
import os
import glob
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict

# --- Configuration ---
BASE_DIR    = os.path.join("results", "complete_handshake_benchmark")
PLOTS_DIR   = os.path.join(BASE_DIR, "plots_comparison")
TABLES_DIR  = os.path.join(PLOTS_DIR, "tables")

os.makedirs(PLOTS_DIR, exist_ok=True)
os.makedirs(TABLES_DIR, exist_ok=True)

# --- Utilities ---
def extract_pattern_key(proto):
    parts = proto.split('_')
    if len(parts) >= 3:
        code = parts[2]
        if code.startswith('KEM'):
            code = code[3:]
        return code
    return proto

# Accept either a DataFrame or a CSV path
def csv_to_table_image(img_path, title, csv_path=None, df=None):
    if df is None:
        if csv_path is None:
            print(f"No data source provided for {title}, skipping.")
            return
        df = pd.read_csv(csv_path)
    if df.empty:
        print(f"Empty table for {title}, skipping image.")
        return
    fig, ax = plt.subplots(figsize=(len(df.columns)*1.5, len(df)*0.4 + 1))
    ax.axis('off')
    tbl = ax.table(cellText=df.values, colLabels=df.columns, cellLoc='center', loc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1.2, 1.2)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(img_path, dpi=300)
    plt.close(fig)
    print(f"Saved table image: {img_path}")

# Modified plot_grouped to differentiate Kyber512 vs Kyber768

def plot_grouped(df, protocols, metric, ylabel, title, fname):
    sub = df[df['protocol'].isin(protocols)]
    if sub.empty:
        print(f"No data for {title}")
        return
    agg = sub.groupby('protocol')[metric].median().sort_values(ascending=False)
    labels_full = agg.index.tolist()
    # Create unique labels: pattern code plus algorithm
    labels_short = []
    for p in labels_full:
        pattern = extract_pattern_key(p)
        if 'Kyber512' in p:
            alg = 'Kyber512'
        elif 'Kyber768' in p:
            alg = 'Kyber768'
        elif '25519' in p:
            alg = 'X25519'
        else:
            alg = p
        labels_short.append(f"{pattern}-{alg}")
    plt.figure(figsize=(max(6, len(labels_short)*0.6), 4))
    bars = plt.bar(labels_short, agg.values)
    for bar in bars:
        h = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, h, f"{h:.0f}", ha='center', va='bottom')
    plt.xticks(fontsize=8, rotation=45, ha='right')
    plt.ylabel(ylabel)
    plt.title(title)
    plt.tight_layout()
    out = os.path.join(PLOTS_DIR, fname)
    plt.savefig(out, dpi=300)
    plt.close()
    print(f"Saved plot: {out}")

# --- Load all median CSVs ---
protocol_dfs = {}
for proto_dir in os.listdir(BASE_DIR):
    dir_path = os.path.join(BASE_DIR, proto_dir)
    if not os.path.isdir(dir_path) or proto_dir == 'plots_comparison':
        continue
    for csvf in glob.glob(os.path.join(dir_path, '*_medians.csv')):
        proto_id = os.path.basename(csvf).replace('benchmark_','').replace('_medians.csv','')
        df = pd.read_csv(csvf)
        if df.empty:
            continue
        df['protocol'] = proto_id
        protocol_dfs[proto_id] = df

if not protocol_dfs:
    print(f"No median CSVs found under {BASE_DIR}")
    exit(1)

# Combine all for global plots
all_df = pd.concat(protocol_dfs.values(), ignore_index=True)

# 1) Per-protocol tables
for proto_id, df in protocol_dfs.items():
    img = os.path.join(TABLES_DIR, f"{proto_id}_medians_table.png")
    tbl_df = df[['label','count','median_time_us','median_cycles']]
    csv_to_table_image(img, f"Medians: {proto_id}", df=tbl_df)

# --- Prepare protocol groups ---
all_protos  = sorted(protocol_dfs.keys())
kyber512   = [p for p in all_protos if 'Kyber512' in p]
kyber768   = [p for p in all_protos if 'Kyber768' in p]
x25519     = [p for p in all_protos if '25519'    in p]

# 2) Global bar plots
plot_grouped(all_df, kyber512, 'median_time_us',  'Median Time (us)',   'Kyber512: Median Time',   'kyber512_time.png')
plot_grouped(all_df, kyber512, 'median_cycles',  'Median Cycles',       'Kyber512: Median Cycles', 'kyber512_cycles.png')
plot_grouped(all_df, kyber768, 'median_time_us',  'Median Time (us)',   'Kyber768: Median Time',   'kyber768_time.png')
plot_grouped(all_df, kyber768, 'median_cycles',  'Median Cycles',       'Kyber768: Median Cycles', 'kyber768_cycles.png')
plot_grouped(all_df, x25519,   'median_time_us',  'Median Time (us)',   'X25519: Median Time',     'x25519_time.png')
plot_grouped(all_df, x25519,   'median_cycles',  'Median Cycles',       'X25519: Median Cycles',   'x25519_cycles.png')
plot_grouped(all_df, all_protos,'median_time_us',  'Median Time (us)',   'All Protocols: Median Time', 'all_time.png')
plot_grouped(all_df, all_protos,'median_cycles',  'Median Cycles',       'All Protocols: Median Cycles','all_cycles.png')

# 3) Combined 3-way comparisons per handshake pattern
pattern_map = defaultdict(list)
for proto in all_protos:
    code = extract_pattern_key(proto)
    pattern_map[code].append(proto)

for code, protos in pattern_map.items():
    x_list    = [p for p in protos if '25519'    in p]
    k512_list = [p for p in protos if 'Kyber512' in p]
    k768_list = [p for p in protos if 'Kyber768' in p]
    if len(x_list)==1 and len(k512_list)==1 and len(k768_list)==1:
        x_proto, k512_proto, k768_proto = x_list[0], k512_list[0], k768_list[0]
        for metric, ylabel, suffix in [
            ('median_time_us', 'Median Time (us)', 'time'),
            ('median_cycles', 'Median Cycles',   'cycles')
        ]:
            vals = [
                all_df.loc[all_df['protocol']==x_proto, metric].iat[0],
                all_df.loc[all_df['protocol']==k512_proto, metric].iat[0],
                all_df.loc[all_df['protocol']==k768_proto, metric].iat[0]
            ]
            labels = ['X25519','Kyber512','Kyber768']
            plt.figure(figsize=(5,4))
            bars = plt.bar(labels, vals)
            for bar in bars:
                h = bar.get_height()
                plt.text(bar.get_x()+bar.get_width()/2, h, f"{h:.0f}", ha='center', va='bottom')
            plt.ylabel(ylabel)
            plt.title(f"Pattern {code}: All Variants")
            plt.tight_layout()
            out = os.path.join(PLOTS_DIR, f"pair_{code}_{suffix}.png")
            plt.savefig(out, dpi=300)
            plt.close()
            print(f"Saved combined plot: {out}")

print(f"Done. Comparison outputs under {PLOTS_DIR}")
