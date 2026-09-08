# Linux Security Log Analyzer

log_file = "../logs/sample_auth.log"

with open(log_file, "r") as file:
    for line in file:
        if "Failed password" in line:
            words = line.split()
            username = words[8]   # the word after "for"
            ip_address = words[10]  # the word after "from"
            print(f"User: {username} | IP: {ip_address}")