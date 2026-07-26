#!/usr/bin/env python3
"""
Test script to verify domain matching variations:
1. 'name'
2. 'name.com'
3. 'web.name.com'
Verifies that any variation added to the block list causes searches for
'name', 'name.com', or 'web.name.com' to be REJECTED (DROP).
"""

import urllib.request
import urllib.parse
import json

API_BASE = "http://localhost:8080"

def http_get(path):
    url = f"{API_BASE}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode('utf-8'))

def http_post(path, data):
    url = f"{API_BASE}{path}"
    json_bytes = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(url, data=json_bytes, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode('utf-8'))

print("=================================================================")
print("  TESTING DOMAIN VARIATIONS BLOCKING (name, name.com, web.name.com) ")
print("=================================================================")

test_matrix = [
    # (Rule to Add, Domains to Search & Expect DROP)
    ("badsite", ["badsite", "badsite.com", "web.badsite.com"]),
    ("mytest.com", ["mytest", "mytest.com", "web.mytest.com"]),
    ("web.portal.com", ["portal", "portal.com", "web.portal.com"])
]

all_passed = True

for rule, query_list in test_matrix:
    print(f"\n--- Testing Rule: '{rule}' ---")
    
    # 1. Add Rule
    status, add_res = http_post("/api/rules/add", {"domain": rule})
    print(f"Added rule '{rule}'. Response active rules: {add_res.get('blocked_domains')}")
    
    # 2. Test Queries
    for query_domain in query_list:
        status, dns_res = http_get(f"/api/query-dns?domain={urllib.parse.quote(query_domain)}")
        action = dns_res.get("action")
        resolved_ip = dns_res.get("resolved_ip")
        status_text = dns_res.get("status")
        rule_match = dns_res.get("rule_match")
        
        is_rejected = (action == "DROP") and (resolved_ip == "0.0.0.0")
        
        if is_rejected:
            print(f"  [PASS] Query '{query_domain}' -> Action: {action} ({status_text}), Rule match: {rule_match}")
        else:
            print(f"  [FAIL] Query '{query_domain}' -> Action: {action}, Resolved IP: {resolved_ip}")
            all_passed = False
            
    # 3. Cleanup Rule
    http_post("/api/rules/remove", {"domain": rule})

print("\n=================================================================")
if all_passed:
    print("RESULT: SUCCESS - All domain variations (name, name.com, web.name.com) are REJECTED correctly!")
else:
    print("RESULT: FAILURE - Some variations were not rejected.")
print("=================================================================")
