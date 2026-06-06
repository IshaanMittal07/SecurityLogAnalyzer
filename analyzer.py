import re
from collections import defaultdict

LOG_FILE = "auth.log"
BRUTE_FORCE_THRESHOLD = 5

failed_attempts = defaultdict(int)
successful_logins = defaultdict(int)

with open(LOG_FILE, "r") as file:
    logs = file.readlines()

for line in logs:

    failed_match = re.search(
        r"LOGIN_FAILED user=(\w+) ip=([\d\.]+)",
        line
    )

    success_match = re.search(
        r"LOGIN_SUCCESS user=(\w+) ip=([\d\.]+)",
        line
    )

    if failed_match:
        user = failed_match.group(1)
        ip = failed_match.group(2)

        failed_attempts[ip] += 1

    elif success_match:
        user = success_match.group(1)
        ip = success_match.group(2)

        successful_logins[ip] += 1

print("=" * 50)
print("SECURITY LOG ANALYSIS REPORT")
print("=" * 50)

print("\nFailed Login Attempts:")
for ip, count in failed_attempts.items():
    print(f"{ip}: {count}")

print("\nSuccessful Logins:")
for ip, count in successful_logins.items():
    print(f"{ip}: {count}")

print("\nPotential Brute Force Attacks:")
found_attack = False

for ip, count in failed_attempts.items():
    if count >= BRUTE_FORCE_THRESHOLD:
        found_attack = True
        print(
            f"ALERT: {ip} generated {count} failed login attempts"
        )

if not found_attack:
    print("No brute force activity detected.")

print("\nAnalysis Complete.")
