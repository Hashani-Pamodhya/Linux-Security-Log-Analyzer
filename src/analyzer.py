# Linux Security Log Analyzer

log_file = "../logs/sample_auth.log"
report_file = "../reports/security_report.txt"

BRUTE_FORCE_THRESHOLD = 5  # attempts from one IP to count as suspicious

user_counts = {}
ip_counts = {}
total_failed = 0

with open(log_file, "r") as file:
    for line in file:
        if "Failed password" in line:
            total_failed += 1
            words = line.split()
            username = words[8]
            ip_address = words[10]

            if username in user_counts:
                user_counts[username] += 1
            else:
                user_counts[username] = 1

            if ip_address in ip_counts:
                ip_counts[ip_address] += 1
            else:
                ip_counts[ip_address] = 1

# Build the report as a list of lines
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

# Print to screen
report_text = "\n".join(report_lines)
print(report_text)

# Save to file
with open(report_file, "w") as out:
    out.write(report_text)

print(f"\nReport saved to {report_file}")