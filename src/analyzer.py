# Linux Security Log Analyzer

log_file = "../logs/sample_auth.log"

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

            # Count usernames
            if username in user_counts:
                user_counts[username] += 1
            else:
                user_counts[username] = 1

            # Count IP addresses
            if ip_address in ip_counts:
                ip_counts[ip_address] += 1
            else:
                ip_counts[ip_address] = 1

print("Total Failed Login Attempts:", total_failed)
print("\nTargeted Users:")
for user, count in user_counts.items():
    print(f"{user}: {count} attempts")

print("\nSuspicious IP Addresses:")
for ip, count in ip_counts.items():
    print(f"{ip}: {count} attempts")