import re
import csv
from collections import defaultdict

LOG_FILE = "clean_log.txt"
RAW_CSV_FILE = "benchmark_raw.csv"
AVG_CSV_FILE = "benchmark_averages.csv"

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

def compute_averages(benchmarks):
    accum = defaultdict(lambda: {'total_time_us': 0, 'total_cycles': 0, 'count': 0})
    
    for entry in benchmarks:
        label = entry['label']
        accum[label]['total_time_us'] += entry['time_us']
        accum[label]['total_cycles'] += entry['cycles']
        accum[label]['count'] += 1
    
    averages = []
    for label, stats in accum.items():
        averages.append({
            'label': label,
            'avg_time_us': stats['total_time_us'] / stats['count'],
            'avg_cycles': stats['total_cycles'] / stats['count'],
            'count': stats['count']
        })
    return averages

def write_csv(filename, fieldnames, data):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def main():
    with open(LOG_FILE, 'r', encoding='utf-16le', errors='ignore') as f: # needs to be utf-16le to work 
        raw_lines = f.readlines()
    clean_lines = clean_lines = [remove_ansi_codes(line).strip() for line in raw_lines]
    #print (clean_lines)  # uncomment for parser debuggign 
    benchmarks = parse_benchmarks(clean_lines)
    write_csv(RAW_CSV_FILE, ['label', 'time_us', 'cycles'], benchmarks)

    averages = compute_averages(benchmarks)
    write_csv(AVG_CSV_FILE, ['label', 'avg_time_us', 'avg_cycles', 'count'], averages)

    print(f"Parsed {len(benchmarks)} benchmark entries.")
    print(f"Saved raw data to {RAW_CSV_FILE}")
    print(f"Saved averages to {AVG_CSV_FILE}")

if __name__ == "__main__":
    main()
