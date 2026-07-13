#!/usr/bin/env python3
"""
WAF Simulator - For testing WAF evasion techniques
"""

from flask import Flask, request, render_template_string
import re

app = Flask(__name__)

# WAF Rules - Blocks certain patterns
WAF_RULES = [
    r"' OR '1'='1",
    r"' OR 1=1",
    r"UNION SELECT",
    r"SELECT.*FROM",
    r"DROP TABLE",
    r"--",
    r"#",
    r"/\*.*\*/",
    r"OR\s+1=1",
    r"AND\s+1=1",
]

def waf_check(payload):
    """Check if payload is blocked by WAF"""
    if not payload:
        return False
    
    for rule in WAF_RULES:
        if re.search(rule, payload, re.IGNORECASE):
            return True
    return False

@app.route('/')
def index():
    return '''
    <h1>🔒 WAF Protected Test Site</h1>
    <p>Testing WAF evasion on: <a href="/search?q=test">/search?q=test</a></p>
    <p>WAF Rules:</p>
    <ul>
        <li>Blocks: ' OR '1'='1</li>
        <li>Blocks: UNION SELECT</li>
        <li>Blocks: DROP TABLE</li>
        <li>Blocks: SQL comments (--, #, /**/)</li>
    </ul>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # Check WAF
    if waf_check(query):
        return '''
        <h1>🚫 Blocked by WAF</h1>
        <p>Your request was blocked by the Web Application Firewall.</p>
        <p>Query: {}</p>
        <p style="color:red;">WAF: Malicious pattern detected</p>
        <a href="/">Back</a>
        '''.format(query), 403
    
    # If not blocked, simulate SQL query
    return '''
    <h1>Search Results</h1>
    <p>Query: {}</p>
    <p style="color:green;">✅ Request allowed by WAF</p>
    <p>Searching for: {}</p>
    <p>SQL Query: SELECT * FROM users WHERE name LIKE '%{}%'</p>
    <a href="/">Back</a>
    '''.format(query, query, query)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  🔒 WAF Simulator Running")
    print("  http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(host='127.0.0.1', port=5000, debug=True)