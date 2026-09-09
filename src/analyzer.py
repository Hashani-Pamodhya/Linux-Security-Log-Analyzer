# Linux Security Log Analyzer

import re
import matplotlib.pyplot as plt
import csv
import json


log_file = "../logs/sample_auth.log"
report_file = "../reports/security_report.txt"

# Ask user for brute-force threshold
threshold_input = input("Enter brute-force threshold (default 5): ")
BRUTE_FORCE_THRESHOLD = int(threshold_input) if threshold_input.strip() else 5

user_counts = {}
ip_counts = {}
total_failed = 0

# Handle missing file gracefully
try:
    with open(log_file, "r") as file:
        lines = file.readlines()
except FileNotFoundError:
    print(f"Error: Could not find log file at {log_file}")
    exit()

for line in lines:
    match = re.search(r"Failed password for (\S+) from (\S+)", line)
    if match:
        total_failed += 1
        username = match.group(1)
        ip_address = match.group(2)

        if username in user_counts:
            user_counts[username] += 1
        else:
            user_counts[username] = 1

        if ip_address in ip_counts:
            ip_counts[ip_address] += 1
        else:
            ip_counts[ip_address] = 1

# Build the report
report_lines = []
report_lines.append("=====================================")
report_lines.append("      LINUX SECURITY LOG REPORT")
report_lines.append("=====================================")
report_lines.append("")
report_lines.append(f"Total Failed Login Attempts: {total_failed}")
report_lines.append("")
report_lines.append("Targeted Users:")
for user, count in user_counts.items():
    report_lines.append(f"{user:<10}: {count} attempts")

report_lines.append("")
report_lines.append("Suspicious IP Addresses:")
brute_force_detected = False
for ip, count in ip_counts.items():
    if count >= BRUTE_FORCE_THRESHOLD:
        report_lines.append(f"{ip:<15}: {count} attempts  <-- FLAGGED")
        brute_force_detected = True
    else:
        report_lines.append(f"{ip:<15}: {count} attempts")

report_lines.append("")
if brute_force_detected:
    report_lines.append("Possible Brute Force Attack Detected!")
else:
    report_lines.append("No brute force pattern detected.")

report_lines.append("=====================================")

report_text = "\n".join(report_lines)
print(report_text)

with open(report_file, "w") as out:
    out.write(report_text)

print(f"\nReport saved to {report_file}")

# Generate a bar chart of top attacking IPs
if ip_counts:
    ips = list(ip_counts.keys())
    counts = list(ip_counts.values())

    plt.figure(figsize=(8, 5))
    plt.bar(ips, counts, color="crimson")
    plt.title("Failed Login Attempts by IP Address")
    plt.xlabel("IP Address")
    plt.ylabel("Number of Attempts")
    plt.tight_layout()

    chart_path = "../reports/ip_attack_chart.png"
    plt.savefig(chart_path)
    print(f"Chart saved to {chart_path}")

# Export results as CSV
csv_path = "../reports/security_report.csv"
with open(csv_path, "w", newline="") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["Type", "Value", "Attempts"])
    for user, count in user_counts.items():
        writer.writerow(["User", user, count])
    for ip, count in ip_counts.items():
        flag = "FLAGGED" if count >= BRUTE_FORCE_THRESHOLD else ""
        writer.writerow(["IP", ip, count, flag] if flag else ["IP", ip, count])

print(f"CSV report saved to {csv_path}")

# Export results as JSON
json_path = "../reports/security_report.json"
report_data = {
    "total_failed_attempts": total_failed,
    "targeted_users": user_counts,
    "suspicious_ips": ip_counts,
    "brute_force_detected": brute_force_detected,
    "threshold_used": BRUTE_FORCE_THRESHOLD
}
with open(json_path, "w") as json_file:
    json.dump(report_data, json_file, indent=4)

print(f"JSON report saved to {json_path}")

