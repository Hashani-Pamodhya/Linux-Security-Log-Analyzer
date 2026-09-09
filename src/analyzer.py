# Linux Security Log Analyzer

import re

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