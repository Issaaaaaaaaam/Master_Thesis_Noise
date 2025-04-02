import re
import csv
from collections import defaultdict
from statistics import median
import pandas as pd
import matplotlib.pyplot as plt

LOG_FILE = "clean_log.txt"
RAW_CSV_FILE = "benchmark_I_raw.csv"
AVG_CSV_FILE = "benchmark_I_averages.csv"
AVG_IMG_FILE = "benchmark_I_averages.png"

def remove_ansi_codes(text):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

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

def csv_to_table_image(csv_file, output_image):
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
    plt.savefig(output_image, bbox_inches='tight', dpi=300)
    print(f"Saved table image to {output_image}")

def main():
    with open(LOG_FILE, 'r', encoding='utf-16le', errors='ignore') as f:
        raw_lines = f.readlines()
    clean_lines = [remove_ansi_codes(line).strip() for line in raw_lines]

    benchmarks = parse_benchmarks(clean_lines)
    write_csv(RAW_CSV_FILE, ['label', 'time_us', 'cycles'], benchmarks)

    stats = compute_stats(benchmarks)
    write_csv(AVG_CSV_FILE, [
        'label', 'count',
        'avg_time_us', 'median_time_us', 'min_time_us', 'max_time_us',
        'avg_cycles', 'median_cycles', 'min_cycles', 'max_cycles'
    ], stats)

    csv_to_table_image(AVG_CSV_FILE, AVG_IMG_FILE)

    print(f"Parsed {len(benchmarks)} benchmark entries.")
    print(f"Saved raw data to {RAW_CSV_FILE}")
    print(f"Saved stats to {AVG_CSV_FILE}")

if __name__ == "__main__":
    main()
