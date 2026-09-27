import json
from collections import Counter

LOG_FILE = "telemetry.jsonl"

total_requests = 0
ips = set()
routes = Counter()
classifications = Counter()

with open(LOG_FILE, "r", encoding="utf-8") as file:
    for line in file:
        event = json.loads(line)

        total_requests += 1
        ips.add(event.get("ip"))
        routes[event.get("path")] += 1
        classification = event.get("classification") or "Unknown (older log)"
classifications[classification] += 1

print("\n=== TELEMETRY SUMMARY ===")
print(f"Total requests: {total_requests}")
print(f"Unique IPs: {len(ips)}")

print("\nMost requested routes:")
for route, count in routes.most_common():
    print(f"{route}: {count}")

print("\nClassifications:")
for category, count in classifications.most_common():
    print(f"{category}: {count}")