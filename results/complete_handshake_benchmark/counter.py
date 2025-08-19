import os
import csv

root_dir = os.path.abspath(".")  # ensures you're anchored

results = {}

for dirpath, dirnames, filenames in os.walk(root_dir):
    if dirpath == root_dir:
        continue  # skip root itself, only go into subfolders

    for filename in filenames:
        if filename.endswith("_medians.csv"):
            csv_path = os.path.join(dirpath, filename)
            folder_name = os.path.basename(dirpath)

            try:
                with open(csv_path, newline='') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        label = row['label'].strip().lower()
                        if label == 'handshake':
                            median_cycles = float(row['median_cycles'].strip())
                            results[folder_name] = median_cycles
                            print(f"✅ {folder_name}: {median_cycles} cycles from {filename}")
                            break
            except Exception as e:
                print(f"❌ Error reading {csv_path}: {e}")

# Summary output
print("\n--- Summary ---")
for folder, cycles in sorted(results.items()):
    print(f"{folder}: {cycles:.0f} cycles")
