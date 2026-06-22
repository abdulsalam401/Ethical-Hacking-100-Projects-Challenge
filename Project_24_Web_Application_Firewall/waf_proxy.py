#!/usr/bin/env python3
"""
==============================================================
  PROJECT #24 — Web Application Firewall (WAF) Simulator
  Reverse proxy with attack detection and rate limiting
==============================================================

FEATURES:
- Reverse proxy with request inspection
- SQL injection, XSS, path traversal, command injection detection
- Rate limiting (100 requests/minute per IP)
- JSON rules engine
- Request logging and alerts

USAGE:
--------
  python waf_proxy.py --port 8000 --backend http://localhost:8080
  
  python waf_proxy.py --port 8000 --backend http://localhost:8080 --rules waf_rules.json --log waf.log

TESTING:
--------
  # Normal request
  curl http://localhost:8000/
  
  # Blocked attack
  curl "http://localhost:8000/login?user=admin&pass=' OR '1'='1"
  
  # Rate limiting
  for i in {1..150}; do curl -s http://localhost:8000/; done
==============================================================
"""

import json
import re
import time
import socket
import threading
import sys
import os
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Colors
class Colors:
    HEADER = Fore.CYAN + Style.BRIGHT
    OKBLUE = Fore.BLUE + Style.BRIGHT
    OKGREEN = Fore.GREEN + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    FAIL = Fore.RED + Style.BRIGHT
    ENDC = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Fore.LIGHTBLACK_EX
    MAGENTA = Fore.MAGENTA + Style.BRIGHT

# Default WAF rules
DEFAULT_RULES = {
    "sql_injection": {
        "patterns": [
            "('.*OR.*'.*='|%27.*OR.*%27.*%3D|;.*--|UNION.*SELECT|' OR '1'='1|' OR 1=1|SELECT.*FROM|INSERT.*INTO|DELETE.*FROM|DROP.*TABLE|1=1;|' OR 1=1 --)",
            "\\\" OR \\\"1\\\"=\\\"1",
            "OR 1=1",
            "AND 1=1",
            "information_schema",
            "sleep\\([0-9]+\\)",
            "benchmark\\([0-9]+,"
        ],
        "severity": "HIGH",
        "action": "BLOCK",
        "description": "SQL Injection attempt"
    },
    "xss": {
        "patterns": [
            "<script>",
            "alert\\(",
            "onerror=",
            "javascript:",
            "document\\.cookie",
            "onload=",
            "onmouseover=",
            "onclick=",
            "<iframe",
            "onerror"
        ],
        "severity": "MEDIUM",
        "action": "BLOCK",
        "description": "Cross-Site Scripting (XSS) attempt"
    },
    "path_traversal": {
        "patterns": [
            "\\.\\./\\.\\./",
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "C:\\\\Windows\\\\System32",
            "%2e%2e%2f",
            "%2e%2e/"
        ],
        "severity": "HIGH",
        "action": "BLOCK",
        "description": "Path traversal attempt"
    },
    "command_injection": {
        "patterns": [
            ";\\s*(ls|whoami|cat|echo|nc|bash|sh|curl|wget|id|uname|pwd|netstat|dir|type|del|rm|mkdir|ping)",
            "&&\\s*(ls|whoami|cat|echo|nc)",
            "\\|\\s*(ls|whoami|cat|echo)"
        ],
        "severity": "HIGH",
        "action": "BLOCK",
        "description": "Command injection attempt"
    }
}

class WAFProxy:
    def __init__(self, backend_host='localhost', backend_port=8080, 
                 rules_file='waf_rules.json', log_file='waf.log', 
                 rate_limit=100, rate_window=60):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.rules_file = rules_file
        self.log_file = log_file
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.rules = self.load_rules()
        self.request_counts = defaultdict(list)
        self.lock = threading.Lock()
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'allowed_requests': 0,
            'rate_limited': 0
        }
        
    def load_rules(self):
        """Load rules from JSON file or use defaults"""
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r') as f:
                    rules = json.load(f)
                print(f"{Colors.OKGREEN}[+] Loaded rules from {self.rules_file}{Colors.ENDC}")
                return rules
            except Exception as e:
                print(f"{Colors.WARNING}[!] Failed to load rules: {e}{Colors.ENDC}")
        
        print(f"{Colors.DIM}[*] Using default rules{Colors.ENDC}")
        return DEFAULT_RULES
    
    def log_request(self, client_ip, method, path, status, message=""):
        """Log request details"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {client_ip} {method} {path} -> {status} {message}"
        
        with self.lock:
            with open(self.log_file, 'a') as f:
                f.write(log_entry + '\n')
            
            if status == 403:
                print(f"{Colors.FAIL}[!] BLOCKED: {client_ip} {method} {path}{Colors.ENDC}")
            elif status == 429:
                print(f"{Colors.WARNING}[!] RATE LIMITED: {client_ip} {method} {path}{Colors.ENDC}")
            else:
                print(f"{Colors.OKGREEN}[+] {client_ip} {method} {path} -> {status}{Colors.ENDC}")
    
    def check_rate_limit(self, client_ip):
        """Check if client has exceeded rate limit"""
        current_time = time.time()
        
        with self.lock:
            # Clean old entries
            self.request_counts[client_ip] = [
                t for t in self.request_counts[client_ip] 
                if current_time - t < self.rate_window
            ]
            
            # Check limit
            if len(self.request_counts[client_ip]) >= self.rate_limit:
                self.stats['rate_limited'] += 1
                return True
            
            # Add current request
            self.request_counts[client_ip].append(current_time)
            return False
    
    def check_attacks(self, method, path, headers, body=""):
        """Check request for attack patterns"""
        # Combine all data to scan
        combined = f"{method} {path} "
        combined += " ".join([f"{k}={v}" for k, v in headers.items()])
        if body:
            combined += f" {body}"
        
        # Check each rule
        for rule_name, rule in self.rules.items():
            for pattern in rule['patterns']:
                if re.search(pattern, combined, re.IGNORECASE):
                    return {
                        'detected': True,
                        'rule': rule_name,
                        'severity': rule['severity'],
                        'description': rule['description']
                    }
        
        return {'detected': False}
    
    def forward_request(self, method, path, headers, body=""):
        """Forward request to backend server"""
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.backend_host, self.backend_port))
            sock.settimeout(10)
            
            # Build request
            request = f"{method} {path} HTTP/1.1\r\n"
            request += f"Host: {self.backend_host}:{self.backend_port}\r\n"
            
            # Forward headers (skip Host and Content-Length)
            for key, value in headers.items():
                if key.lower() not in ['host', 'content-length']:
                    request += f"{key}: {value}\r\n"
            
            # Add Content-Length if body exists
            if body:
                request += f"Content-Length: {len(body)}\r\n"
            
            request += "\r\n"
            if body:
                request += body
            
            # Send request
            sock.send(request.encode())
            
            # Receive response
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            sock.close()
            return response
            
        except Exception as e:
            error_response = f"HTTP/1.1 502 Bad Gateway\r\n\r\nBackend error: {e}"
            return error_response.encode()
    
    def handle_request(self, client_ip, method, path, headers, body=""):
        """Process a request"""
        self.stats['total_requests'] += 1
        
        # Check rate limit
        if self.check_rate_limit(client_ip):
            self.log_request(client_ip, method, path, 429, "Rate limit exceeded")
            return self.build_response(429, "Rate limit exceeded. Try again later.")
        
        # Check for attacks
        attack_result = self.check_attacks(method, path, headers, body)
        
        if attack_result['detected']:
            self.stats['blocked_requests'] += 1
            message = f"{attack_result['description']} ({attack_result['rule']})"
            self.log_request(client_ip, method, path, 403, message)
            return self.build_response(403, f"Blocked: {attack_result['description']}")
        
        # Forward to backend
        self.stats['allowed_requests'] += 1
        self.log_request(client_ip, method, path, 200, "Forwarded to backend")
        return self.forward_request(method, path, headers, body)
    
    def build_response(self, status_code, message):
        """Build HTTP response"""
        status_messages = {
            403: "Forbidden",
            429: "Too Many Requests",
            502: "Bad Gateway"
        }
        
        status_text = status_messages.get(status_code, "Unknown")
        body = f"<h1>{status_code} {status_text}</h1><p>{message}</p>"
        
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        response += f"Content-Type: text/html\r\n"
        response += f"Content-Length: {len(body)}\r\n"
        response += f"X-WAF-Blocked: true\r\n"
        response += "\r\n"
        response += body
        
        return response.encode()
    
    def print_stats(self):
        """Print statistics"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  WAF STATISTICS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Total Requests: {self.stats['total_requests']}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Allowed: {self.stats['allowed_requests']}{Colors.ENDC}")
        print(f"{Colors.FAIL}Blocked: {self.stats['blocked_requests']}{Colors.ENDC}")
        print(f"{Colors.WARNING}Rate Limited: {self.stats['rate_limited']}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

class WAFHandler(BaseHTTPRequestHandler):
    """HTTP request handler with WAF protection"""
    
    waf = None
    
    def do_GET(self):
        self.process_request('GET')
    
    def do_POST(self):
        self.process_request('POST')
    
    def do_PUT(self):
        self.process_request('PUT')
    
    def do_DELETE(self):
        self.process_request('DELETE')
    
    def do_HEAD(self):
        self.process_request('HEAD')
    
    def process_request(self, method):
        """Process request with WAF"""
        # Parse query string
        parsed = urlparse(self.path)
        path = parsed.path
        query = parsed.query
        
        # Get client IP
        client_ip = self.client_address[0]
        
        # Check X-Forwarded-For header
        if 'X-Forwarded-For' in self.headers:
            client_ip = self.headers['X-Forwarded-For'].split(',')[0].strip()
        
        # Get body for POST requests
        body = ""
        if method in ['POST', 'PUT']:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        
        # Process with WAF
        response = WAFHandler.waf.handle_request(
            client_ip, method, path, dict(self.headers), body
        )
        
        # Send response
        self.send_response_only(200)  # We'll parse the response
        self.wfile.write(response)
    
    def log_message(self, format, *args):
        """Override to prevent default logging"""
        pass

class SimpleBackend:
    """Simple backend server for testing"""
    def __init__(self, port=8080):
        self.port = port
    
    def start(self):
        """Start backend server"""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        
        class BackendHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(f"""
                <html>
                <body>
                <h1>Backend Server</h1>
                <p>Path: {self.path}</p>
                <p>Method: GET</p>
                <p>Headers: {dict(self.headers)}</p>
                </body>
                </html>
                """.encode())
            
            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length) if content_length > 0 else b''
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(f"""
                <html>
                <body>
                <h1>Backend Server (POST)</h1>
                <p>Path: {self.path}</p>
                <p>Body: {body.decode()[:100]}</p>
                </body>
                </html>
                """.encode())
        
        server = HTTPServer(('localhost', self.port), BackendHandler)
        print(f"{Colors.OKGREEN}[+] Backend server on port {self.port}{Colors.ENDC}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="WAF Proxy Server")
    parser.add_argument("--port", type=int, default=8000, help="WAF listen port")
    parser.add_argument("--backend", default="http://localhost:8080", help="Backend server URL")
    parser.add_argument("--rules", default="waf_rules.json", help="Rules file")
    parser.add_argument("--log", default="waf.log", help="Log file")
    parser.add_argument("--rate-limit", type=int, default=100, help="Max requests per minute")
    parser.add_argument("--backend-only", action="store_true", help="Run only backend server")
    
    args = parser.parse_args()
    
    if args.backend_only:
        backend = SimpleBackend(8080)
        backend.start()
        return
    
    # Parse backend URL
    backend_url = args.backend.replace('http://', '').split(':')
    backend_host = backend_url[0]
    backend_port = int(backend_url[1]) if len(backend_url) > 1 else 8080
    
    # Initialize WAF
    WAFHandler.waf = WAFProxy(
        backend_host=backend_host,
        backend_port=backend_port,
        rules_file=args.rules,
        log_file=args.log,
        rate_limit=args.rate_limit
    )
    
    # Start WAF server
    server = HTTPServer(('0.0.0.0', args.port), WAFHandler)
    
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.HEADER}  PROJECT #24 — Web Application Firewall Simulator{Colors.ENDC}")
    print(f"{Colors.OKBLUE}  Reverse proxy with attack detection and rate limiting{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    print(f"{Colors.OKGREEN}[+] WAF listening on: http://0.0.0.0:{args.port}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Backend: http://{backend_host}:{backend_port}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Log file: {args.log}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Rate limit: {args.rate_limit}/minute{Colors.ENDC}")
    print(f"{Colors.WARNING}[!] Press Ctrl+C to stop{Colors.ENDC}\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Shutting down...{Colors.ENDC}")
        server.shutdown()
        WAFHandler.waf.print_stats()

if __name__ == "__main__":
    main()