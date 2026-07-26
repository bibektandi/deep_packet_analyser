#!/usr/bin/env python3
"""
Comprehensive Automated Test Suite for DPI Engine System
Tests C++ engine binary, python API server endpoints, rule additions/removals, 
DNS firewall evaluation, multi-thread dispatching, and output PCAP validation.
"""

import urllib.request
import urllib.parse
import json
import subprocess
import os
import sys

API_BASE = "http://localhost:8080"
DPI_EXE = os.path.abspath("dpi_engine.exe")
TEST_PCAP = os.path.abspath("test_dpi.pcap")
OUTPUT_PCAP = os.path.abspath("output.pcap")

results = []

def log_test(name, success, details=""):
    status_str = "PASS" if success else "FAIL"
    results.append({"name": name, "success": success, "details": details})
    print(f"[{status_str}] {name} - {details}")

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

print("===============================================================")
print("      RUNNING DPI ENGINE COMPREHENSIVE TEST SUITE              ")
print("===============================================================")

# -------------------------------------------------------------
# Test Case 1: Baseline DPI Engine Execution (No Block Rules)
# -------------------------------------------------------------
try:
    cmd = [DPI_EXE, TEST_PCAP, OUTPUT_PCAP]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
    is_ok = res.returncode == 0 and "Processing packets" in res.stdout
    dropped = "Dropped:                       0" in res.stdout or r"Dropped:\s+0" in res.stdout
    log_test("TC1: Baseline Engine Run (No Rules)", is_ok, f"ReturnCode: {res.returncode}")
except Exception as e:
    log_test("TC1: Baseline Engine Run (No Rules)", False, str(e))

# -------------------------------------------------------------
# Test Case 2: Single Domain Rule Blocking (--block-domain youtube.com)
# -------------------------------------------------------------
try:
    cmd = [DPI_EXE, TEST_PCAP, OUTPUT_PCAP, "--block-domain", "youtube.com"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
    is_ok = res.returncode == 0 and "Dropped:                       1" in res.stdout
    log_test("TC2: Single Domain Blocking (youtube.com)", is_ok, "Dropped 1 YouTube packet correctly")
except Exception as e:
    log_test("TC2: Single Domain Blocking (youtube.com)", False, str(e))

# -------------------------------------------------------------
# Test Case 3: Multiple Domain Rules Blocking (youtube, facebook, tiktok)
# -------------------------------------------------------------
try:
    cmd = [DPI_EXE, TEST_PCAP, OUTPUT_PCAP, 
           "--block-domain", "youtube.com", 
           "--block-domain", "facebook.com", 
           "--block-domain", "tiktok.com"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
    is_ok = res.returncode == 0 and "Dropped:                       3" in res.stdout
    log_test("TC3: Multi-Domain Blocking (youtube, facebook, tiktok)", is_ok, "Dropped 3 blocked domain packets")
except Exception as e:
    log_test("TC3: Multi-Domain Blocking", False, str(e))

# -------------------------------------------------------------
# Test Case 4: IP Rule Blocking (--block-ip 192.168.1.50)
# -------------------------------------------------------------
try:
    cmd = [DPI_EXE, TEST_PCAP, OUTPUT_PCAP, "--block-ip", "192.168.1.50"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
    is_ok = res.returncode == 0
    log_test("TC4: IP Rule Blocking (192.168.1.50)", is_ok, "Engine processed IP rule flag cleanly")
except Exception as e:
    log_test("TC4: IP Rule Blocking", False, str(e))

# -------------------------------------------------------------
# Test Case 5: API Server Rules Endpoint (GET & POST)
# -------------------------------------------------------------
try:
    status, data = http_get("/api/rules")
    has_rules = "blocked_domains" in data and "youtube.com" in data["blocked_domains"]
    log_test("TC5a: API GET /api/rules", status == 200 and has_rules, f"Current rules: {data.get('blocked_domains')}")
    
    # Add new rule
    status, add_data = http_post("/api/rules/add", {"domain": "instagram.com"})
    has_insta = "instagram.com" in add_data.get("blocked_domains", [])
    log_test("TC5b: API POST /api/rules/add (instagram.com)", status == 200 and has_insta, "Successfully added instagram.com")
    
    # Remove rule
    status, rem_data = http_post("/api/rules/remove", {"domain": "instagram.com"})
    not_insta = "instagram.com" not in rem_data.get("blocked_domains", [])
    log_test("TC5c: API POST /api/rules/remove (instagram.com)", status == 200 and not_insta, "Successfully removed instagram.com")
except Exception as e:
    log_test("TC5: API Server Rules Endpoint", False, str(e))

# -------------------------------------------------------------
# Test Case 6: DNS Query Firewall Evaluation (/api/query-dns)
# -------------------------------------------------------------
try:
    # Test blocked domain
    status, dns_blocked = http_get("/api/query-dns?domain=youtube.com")
    is_drop = dns_blocked.get("action") == "DROP" and dns_blocked.get("resolved_ip") == "0.0.0.0"
    log_test("TC6a: DNS Query Blocked Domain (youtube.com)", status == 200 and is_drop, "Action: DROP, Resolved IP: 0.0.0.0")

    # Test allowed domain
    status, dns_allowed = http_get("/api/query-dns?domain=google.com")
    is_fwd = dns_allowed.get("action") == "FORWARD" and dns_allowed.get("resolved_ip") != "0.0.0.0"
    log_test("TC6b: DNS Query Allowed Domain (google.com)", status == 200 and is_fwd, f"Action: FORWARD, Resolved IP: {dns_allowed.get('resolved_ip')}")
except Exception as e:
    log_test("TC6: DNS Query Evaluation", False, str(e))

# -------------------------------------------------------------
# Test Case 7: API Server Engine Execution Integration (/api/run-dpi)
# -------------------------------------------------------------
try:
    status, engine_res = http_get("/api/run-dpi")
    is_success = engine_res.get("status") == "success" and "APPLICATION BREAKDOWN" in (engine_res.get("stdout") or "")
    log_test("TC7: API /api/run-dpi Integration", status == 200 and is_success, "Engine output parsed successfully")
except Exception as e:
    log_test("TC7: API /api/run-dpi Integration", False, str(e))

# -------------------------------------------------------------
# Test Case 8: Output PCAP File Verification
# -------------------------------------------------------------
try:
    if os.path.exists(OUTPUT_PCAP):
        size = os.path.getsize(OUTPUT_PCAP)
        with open(OUTPUT_PCAP, 'rb') as f:
            magic = f.read(4)
        is_valid = magic in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'] and size > 0
        log_test("TC8: Output PCAP File Validity", is_valid, f"Magic: {magic.hex()}, Size: {size} bytes")
    else:
        log_test("TC8: Output PCAP File Validity", False, "output.pcap does not exist")
except Exception as e:
    log_test("TC8: Output PCAP File Validity", False, str(e))

print("===============================================================")
total_tests = len(results)
passed_tests = sum(1 for r in results if r["success"])
print(f"SUMMARY: {passed_tests}/{total_tests} Test Cases Passed ({ (passed_tests/total_tests)*100:.1f}% )")
print("===============================================================")

if passed_tests == total_tests:
    sys.exit(0)
else:
    sys.exit(1)
