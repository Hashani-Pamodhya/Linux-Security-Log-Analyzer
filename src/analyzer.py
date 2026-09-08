# Linux Security Log Analyzer

log_file = "../logs/sample_auth.log"

with open(log_file, "r") as file:
    for line in file:
        print(line.strip())