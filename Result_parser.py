import re
import csv
from collections import defaultdict
from statistics import median
import pandas as pd
import matplotlib.pyplot as plt
import os

LOG_FILE = "clean_log.txt"

def remove_ansi_codes(text):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

def extract_setup_info(lines):
    pattern = re.compile(r'SETUP: (Receiver|Initiator)_(Noise_[\w\d_]+)')
    for line in lines:
        match = pattern.search(line)
        if match:
            role = match.group(1)
            pattern_name = match.group(2)
            return f"{role}_{pattern_name}"
    return "Unknown_Protocol"

def parse_benchmarks(lines):
    benchmarks = []
    pattern = re.compile(r'BENCH: \[(.+?)\] Took (\d+) us and (\d+) cycles')
    for line in lines:
        match = pattern.search(line)
        if match:
            label = match.group(1).strip()
            time_us = int(match.group(2))
            cycles = int(match.group(3))
            benchmarks.append({
                'label': label,
                'time_us': time_us,
                'cycles': cycles
            })
    return benchmarks

def compute_stats(benchmarks):
    accum = defaultdict(lambda: {'time_us': [], 'cycles': []})
    for entry in benchmarks:
        label = entry['label']
        accum[label]['time_us'].append(entry['time_us'])
        accum[label]['cycles'].append(entry['cycles'])

    stats = []
    for label, data in accum.items():
        times = data['time_us']
        cycles = data['cycles']
        stats.append({
            'label': label,
            'count': len(times),
            'avg_time_us': sum(times) / len(times),
            'median_time_us': median(times),
            'min_time_us': min(times),
            'max_time_us': max(times),
            'avg_cycles': sum(cycles) / len(cycles),
            'median_cycles': median(cycles),
            'min_cycles': min(cycles),
            'max_cycles': max(cycles),
        })
    return stats

def write_csv(filename, fieldnames, data):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def csv_to_table_image(csv_file, output_image, title):
    df = pd.read_csv(csv_file)
    fig, ax = plt.subplots(figsize=(len(df.columns)*1.8, len(df)*0.6 + 1))
    ax.axis('off')
    table = ax.table(
        cellText=df.values,
        colLabels=df.columns,
        cellLoc='center',
        loc='center'
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 1.2)
    plt.tight_layout()
    plt.title(f"Benchmark: {title}", pad=20)
    plt.savefig(output_image, bbox_inches='tight', dpi=300)
    print(f"Saved table image to {output_image}")

def main():
    with open(LOG_FILE, 'r', encoding='utf-16le', errors='ignore') as f:
        raw_lines = f.readlines()
    clean_lines = [remove_ansi_codes(line).strip() for line in raw_lines]

    setup_info = extract_setup_info(clean_lines) 
    role, pattern = setup_info.split("_", 1)
    all_benchmarks = parse_benchmarks(clean_lines)

    scalar_mult_only = any("scalar_mult" in entry['label'] for entry in all_benchmarks)

    if scalar_mult_only:
        benchmarks = [entry for entry in all_benchmarks if "scalar_mult" in entry['label']]
        output_dir = os.path.join("results", "X25519")
        setup_info += "_scalar_mult_only"
    else:
        benchmarks = all_benchmarks
        output_dir = os.path.join("results", pattern)

    os.makedirs(output_dir, exist_ok=True)

    raw_csv = os.path.join(output_dir, f"benchmark_{setup_info}_raw.csv")
    avg_csv = os.path.join(output_dir, f"benchmark_{setup_info}_averages.csv")
    avg_img = os.path.join(output_dir, f"benchmark_{setup_info}_averages.png")
    median_csv = os.path.join(output_dir, f"benchmark_{setup_info}_medians.csv")
    median_img = os.path.join(output_dir, f"benchmark_{setup_info}_medians.png")
    copied_log = os.path.join(output_dir, f"log_{setup_info}.txt")

    write_csv(raw_csv, ['label', 'time_us', 'cycles'], benchmarks)

    stats = compute_stats(benchmarks)
    write_csv(avg_csv, [
        'label', 'count',
        'avg_time_us', 'median_time_us', 'min_time_us', 'max_time_us',
        'avg_cycles', 'median_cycles', 'min_cycles', 'max_cycles'
    ], stats)

    medians = [
        {
            'label': s['label'],
            'count': s['count'],
            'median_time_us': s['median_time_us'],
            'median_cycles': s['median_cycles'],
        } for s in stats
    ]
    write_csv(median_csv, ['label', 'count', 'median_time_us', 'median_cycles'], medians)

    csv_to_table_image(avg_csv, avg_img, setup_info)
    csv_to_table_image(median_csv, median_img, f"{setup_info} (Median Only)")

    with open(LOG_FILE, 'r', encoding='utf-16le', errors='ignore') as original, \
            open(copied_log, 'w', encoding='utf-8') as copy:
            for line in original:
                clean_line = remove_ansi_codes(line)
                copy.write(clean_line)

    
    print(f"Copied original log file to {copied_log}")
    print(f"Parsed {len(benchmarks)} benchmark entries.")
    print(f"Saved raw data to {raw_csv}")
    print(f"Saved stats to {avg_csv}")
    print(f"Saved median-only stats to {median_csv}")

if __name__ == "__main__":
    main()
