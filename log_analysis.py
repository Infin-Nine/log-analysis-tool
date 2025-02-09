from collections import Counter, defaultdict
import re
from tabulate import tabulate  # ✅ For Better output formatting

# ✅ Suspicious Log Analysis Function
def log_analysis(log_file):
    suspicious_patterns = [
        "Error", "Unauthorized access",
        "Failed login attempt", "Multiple login attempts"
    ]
    
    suspicious_logs = []  # ✅ Empty list to store logs

    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:  # ✅ Memory efficient reading
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in suspicious_patterns):
                suspicious_logs.append(line.strip())  # ✅ `.strip()` remove extra spaces
    return suspicious_logs

# ✅ IP Address Counting Function
def ip_check(log_file):
    ip_counter = defaultdict(int)  # ✅ Default value 0

    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:
            if "Failed login" in line or "Unauthorized access" in line:
                ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
                if ip_match:
                    ip_counter[ip_match.group()] += 1  # ✅ Count update

    return ip_counter

# ✅ Main Program
try:
    log_file_path = input("📂 Enter Log File Path: ")
    suspicious_logs = log_analysis(log_file_path)
    ip_counts = ip_check(log_file_path)
    
    # ✅ Suspicious Log Printing
    if suspicious_logs:
        print("\n🚨 Suspicious Logs Found:\n")
        for entry in suspicious_logs:
            print(f"🔴 {entry}")

    # ✅ IP Attempt Counts Printing (Formatted Table)
    if ip_counts:
        print("\n🔍 Suspicious IPs and their attempt counts:\n")
        ip_table = [(ip, count) for ip, count in ip_counts.items()]
        print(tabulate(ip_table, headers=["IP Address", "Attempts"], tablefmt="fancy_grid"))  # ✅ Fancy_Grid Format Output

    else:
        print("✅ No Suspicious logs found!")
            
except FileNotFoundError:
    print("❌ Error: File does not exist!")

except KeyboardInterrupt:
    print("\nExiting... 🚪")
