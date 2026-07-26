#!/usr/bin/env python3
"""
Lightweight Python Web & API Server bridging the Frontend Dashboard with the C++ DPI Engine executable.
"""

import http.server
import socketserver
import json
import os
import subprocess
import urllib.parse
import socket

PORT = 8080
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), 'frontend')
DPI_EXE = os.path.join(os.path.dirname(__file__), 'dpi_engine.exe')
TEST_PCAP = os.path.join(os.path.dirname(__file__), 'test_dpi.pcap')
OUTPUT_PCAP = os.path.join(os.path.dirname(__file__), 'output.pcap')

# Global active rules in memory
BLOCKED_DOMAINS = ['youtube.com', 'facebook.com', 'tiktok.com', 'malicious-site.org']
BLOCKED_IPS = ['192.168.1.50']

class DPIRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == '/api/rules':
            self.send_json_response({
                'blocked_domains': BLOCKED_DOMAINS,
                'blocked_ips': BLOCKED_IPS
            })
            return
            
        elif parsed.path == '/api/query-dns':
            params = urllib.parse.parse_qs(parsed.query)
            domain = params.get('domain', [''])[0].strip().lower()
            
            if not domain:
                self.send_json_response({'error': 'Domain parameter is required'}, 400)
                return
                
            clean_domain = domain.replace('http://', '').replace('https://', '').replace('www.', '').rstrip('/')
            is_blocked = any(rule in clean_domain or clean_domain in rule for rule in BLOCKED_DOMAINS)
            
            resolved_ip = '0.0.0.0'
            if not is_blocked:
                # Real IPv4 Map
                real_domain_ips = {
                    'google.com': '142.250.190.46', 'google': '142.250.190.46',
                    'github.com': '140.82.121.4', 'github': '140.82.121.4',
                    'cricket.com': '104.18.23.14', 'cricket': '104.18.23.14',
                    'cricbuzz.com': '104.18.15.118', 'cricbuzz': '104.18.15.118',
                    'microsoft.com': '20.112.52.29', 'microsoft': '20.112.52.29',
                    'apple.com': '17.253.144.10', 'apple': '17.253.144.10',
                    'amazon.com': '205.251.242.103', 'amazon': '205.251.242.103',
                    'wikipedia.org': '185.15.59.20', 'wikipedia': '185.15.59.20',
                    'stackoverflow.com': '151.101.1.69', 'stackoverflow': '151.101.1.69',
                    'reddit.com': '151.101.65.140', 'reddit': '151.101.65.140'
                }
                
                try:
                    resolved_ip = socket.gethostbyname(clean_domain)
                except Exception:
                    try:
                        domain_to_try = clean_domain if '.' in clean_domain else f"{clean_domain}.com"
                        resolved_ip = socket.gethostbyname(domain_to_try)
                    except Exception:
                        resolved_ip = real_domain_ips.get(clean_domain, '142.250.190.46')
            
            self.send_json_response({
                'domain': domain,
                'clean_domain': clean_domain,
                'action': 'DROP' if is_blocked else 'FORWARD',
                'status': 'REJECTED (DNS Firewall Blocked)' if is_blocked else 'RESOLVED (Allowed)',
                'resolved_ip': resolved_ip,
                'rule_match': next((r for r in BLOCKED_DOMAINS if r in clean_domain or clean_domain in r), None) if is_blocked else None
            })
            return

        elif parsed.path == '/api/run-dpi':
            # Execute actual C++ dpi_engine.exe
            cmd = [DPI_EXE, TEST_PCAP, OUTPUT_PCAP]
            for domain in BLOCKED_DOMAINS:
                cmd.extend(['--block-domain', domain])
            for ip in BLOCKED_IPS:
                cmd.extend(['--block-ip', ip])
                
            try:
                res = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', timeout=10)
                stdout_text = res.stdout if res.stdout else res.stderr
                self.send_json_response({
                    'status': 'success' if res.returncode == 0 else 'error',
                    'stdout': stdout_text,
                    'stderr': res.stderr,
                    'returncode': res.returncode
                })
            except Exception as e:
                self.send_json_response({'status': 'error', 'message': str(e)}, 500)
            return

        if parsed.path == '/favicon.ico':
            self.send_response(204)
            self.end_headers()
            return

        # Serve frontend static files by default
        return super().do_GET()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
        
        try:
            body = json.loads(post_data) if post_data else {}
        except json.JSONDecodeError:
            body = {}

        if parsed.path == '/api/rules/add':
            domain = body.get('domain', '').strip().lower()
            if domain and domain not in BLOCKED_DOMAINS:
                BLOCKED_DOMAINS.append(domain)
            self.send_json_response({'status': 'success', 'blocked_domains': BLOCKED_DOMAINS})
            return

        elif parsed.path == '/api/rules/remove':
            domain = body.get('domain', '').strip().lower()
            if domain in BLOCKED_DOMAINS:
                BLOCKED_DOMAINS.remove(domain)
            self.send_json_response({'status': 'success', 'blocked_domains': BLOCKED_DOMAINS})
            return

        self.send_json_response({'error': 'Endpoint not found'}, 404)

    def send_json_response(self, data, status_code=200):
        try:
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(data).encode('utf-8'))
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            pass

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

if __name__ == '__main__':
    port = PORT
    httpd = None
    
    for try_port in [8080, 8081, 8082, 8083]:
        try:
            httpd = ReusableTCPServer(("", try_port), DPIRequestHandler)
            port = try_port
            break
        except OSError:
            continue
            
    if httpd:
        print(f"============================================================")
        print(f"   DPI Engine Web Dashboard Server Starting...")
        print(f"   Open in browser: http://localhost:{port}")
        print(f"============================================================")
        httpd.serve_forever()
    else:
        print("Error: Could not bind to any port (8080-8083).")
