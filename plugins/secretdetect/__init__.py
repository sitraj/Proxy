import re
import os
import json
import time
from datetime import datetime

# Directory to store detected secrets
ResultsDir = "results/secrets"

# Common patterns for sensitive information
PATTERNS = {
    'api_key': r'(?i)(api[_-]?key|apikey)[_-]?(key)?["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\']?',
    'aws_key': r'(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?key)[_-]?(id)?["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?',
    'password': r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?',
    'token': r'(?i)(token|jwt|bearer)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_\.]{20,})["\']?',
    'private_key': r'-----BEGIN (?:RSA )?PRIVATE KEY-----\n(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\n-----END (?:RSA )?PRIVATE KEY-----',
    'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
    'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'ssn': r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',
    'phone': r'\b(?:\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b'
}

# Compile patterns for better performance
COMPILED_PATTERNS = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}

def ensure_results_dir():
    """Ensure the results directory exists"""
    if not os.path.isdir(ResultsDir):
        os.makedirs(ResultsDir, 0o755)

def save_finding(secret_type, value, context, source):
    """Save a detected secret to the results file"""
    ensure_results_dir()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{ResultsDir}/secrets_{timestamp}.json"
    
    finding = {
        "timestamp": timestamp,
        "type": secret_type,
        "value": value,
        "context": context,
        "source": source
    }
    
    # Load existing findings if file exists
    findings = []
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            try:
                findings = json.load(f)
            except json.JSONDecodeError:
                pass
    
    # Add new finding
    findings.append(finding)
    
    # Save updated findings
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2)

def scan_text(text, source):
    """Scan text for potential secrets"""
    if not text or not isinstance(text, str):
        return
    
    for secret_type, pattern in COMPILED_PATTERNS.items():
        matches = pattern.finditer(text)
        for match in matches:
            # Extract the matched value
            if secret_type == 'private_key':
                value = match.group(0)
            else:
                # For other patterns, use the last capture group
                value = match.group(match.lastindex or 0)
            
            # Get some context around the match
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            context = text[start:end]
            
            # Save the finding
            save_finding(secret_type, value, context, source)

def RequestHandler(req, req_body, threadid):
    """Process request body for secrets"""
    if req_body:
        try:
            # Try to decode if it's bytes
            if isinstance(req_body, bytes):
                body_text = req_body.decode('utf-8', errors='ignore')
            else:
                body_text = str(req_body)
            
            # Scan request body
            scan_text(body_text, f"Request: {req.path}")
            
            # Scan headers
            headers_text = "\n".join([f"{k}: {v}" for k, v in req.headers.items()])
            scan_text(headers_text, f"Request Headers: {req.path}")
        except Exception as e:
            print(f"Error in RequestHandler: {e}")
    
    return req_body, threadid

def ResponseHandler(req, req_body, res, res_body, threadid, threadid2):
    """Process response body for secrets"""
    if res_body:
        try:
            # Try to decode if it's bytes
            if isinstance(res_body, bytes):
                body_text = res_body.decode('utf-8', errors='ignore')
            else:
                body_text = str(res_body)
            
            # Scan response body
            scan_text(body_text, f"Response: {req.path}")
            
            # Scan headers
            headers_text = "\n".join([f"{k}: {v}" for k, v in res.headers.items()])
            scan_text(headers_text, f"Response Headers: {req.path}")
        except Exception as e:
            print(f"Error in ResponseHandler: {e}")
    
    return res_body 