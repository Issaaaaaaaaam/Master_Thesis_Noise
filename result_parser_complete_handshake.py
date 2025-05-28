#!/usr/bin/env python3
"""
result_parser_csv_only.py

Parses clean_log.txt (UTF-16LE), splits by SETUP blocks,
computes per-protocol benchmark stats, and writes CSVs under
results/complete_handshake_benchmark/<setup>/:
  • Raw benchmark data
  • Summary averages
  • Median-only data
"""
import os
import re
import csv
from collections import defaultdict
from statistics import median

# --- Configuration ---
LOG_FILE    = "clean_log.txt"
BASE_DIR    = os.path.join("results", "complete_handshake_benchmark")
ENCODING    = "utf-16le"

# Ensure base directory exists
os.makedirs(BASE_DIR, exist_ok=True)

# --- Helpers ---
def remove_ansi_codes(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)

def split_log_by_protocol(lines):
    segments = defaultdict(list)
    current = None
    pattern = re.compile(r"SETUP: (Receiver|Initiator)_(Noise_[^\s]+)")
    for line in lines:
        m = pattern.search(line)
        if m:
            current = f"{m.group(1)}_{m.group(2)}"
        if current:
            segments[current].append(line)
    return segments.items()

def parse_benchmarks(lines):
    entries = []
    pattern = re.compile(r"BENCH: \[(.+?)\] Took (\d+) us and (\d+) cycles")
    for line in lines:
        m = pattern.search(line)
        if m:
            entries.append({
                'label': m.group(1).strip(),
                'time_us': int(m.group(2)),
                'cycles': int(m.group(3)),
            })
    return entries

def compute_stats(entries):
    acc = defaultdict(lambda: {'time_us': [], 'cycles': []})
    for e in entries:
        acc[e['label']]['time_us'].append(e['time_us'])
        acc[e['label']]['cycles'].append(e['cycles'])
    stats = []
    for label, data in acc.items():
        stats.append({
            'label': label,
            'count': len(data['time_us']),
            'avg_time_us': sum(data['time_us']) / len(data['time_us']),
            'median_time_us': median(data['time_us']),
            'min_time_us': min(data['time_us']),
            'max_time_us': max(data['time_us']),
            'avg_cycles': sum(data['cycles']) / len(data['cycles']),
            'median_cycles': median(data['cycles']),
            'min_cycles': min(data['cycles']),
            'max_cycles': max(data['cycles']),
        })
    return stats

# --- CSV Output ---
def write_csv(path, fieldnames, rows):
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

# --- Main workflow ---
def main():
    # Read and clean lines
    with open(LOG_FILE, 'r', encoding=ENCODING, errors='ignore') as f:
        raw_lines = f.readlines()
    lines = [remove_ansi_codes(l).strip() for l in raw_lines]

    # Split by protocol
    segments = list(split_log_by_protocol(lines))
    print(f"Found {len(segments)} protocol segments.")

    for setup, seg_lines in segments:
        print(f"Processing segment: {setup}")
        entries = parse_benchmarks(seg_lines)
        if not entries:
            print(f" No BENCH entries for {setup}")
            continue

        # Determine output directory per setup
        out_dir = os.path.join(BASE_DIR, setup.split("_",1)[1])
        os.makedirs(out_dir, exist_ok=True)

        # Raw CSV
        raw_csv = os.path.join(out_dir, f"benchmark_{setup}_raw.csv")
        write_csv(raw_csv, ['label', 'time_us', 'cycles'], entries)

        # Computed stats
        stats = compute_stats(entries)

        # Averages CSV
        avg_csv = os.path.join(out_dir, f"benchmark_{setup}_averages.csv")
        write_csv(avg_csv, [
            'label', 'count',
            'avg_time_us', 'median_time_us', 'min_time_us', 'max_time_us',
            'avg_cycles', 'median_cycles', 'min_cycles', 'max_cycles'
        ], stats)

        # Median-only CSV
        medians = [
            {
                'label': s['label'],
                'count': s['count'],
                'median_time_us': s['median_time_us'],
                'median_cycles': s['median_cycles'],
            } for s in stats
        ]
        med_csv = os.path.join(out_dir, f"benchmark_{setup}_medians.csv")
        write_csv(med_csv, ['label', 'count', 'median_time_us', 'median_cycles'], medians)

        # Copy raw lines for reference
        log_copy = os.path.join(out_dir, f"log_{setup}.txt")
        with open(log_copy, 'w', encoding='utf-8') as copy_f:
            for l in seg_lines:
                copy_f.write(remove_ansi_codes(l) + "\n")

        print(f"Saved CSVs under {out_dir}")

if __name__ == '__main__':
    main()