import os
import re
import sys
import json
from pathlib import Path

# --- Configuration ---
IGNORE_DIRS = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', '.idea', '.vscode', 'tmp', 'temp'}

# Regex patterns mapped to risk levels
PATTERNS = {
    "Level_1_Credentials": {
        "API_Key": re.compile(r'(?i)(?:api[_-]?key|api[_-]?secret|apikey|api_secret)[\s\'"]*[:=][\s\'"]*([^ \'"\n\r]+)'),
        "LLM_Key": re.compile(r'sk-[a-zA-Z0-9]{20,}'),
        "AWS_Key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "Private_Key": re.compile(r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----'),
        "Token": re.compile(r'(?i)token[\s\'"]*[:=][\s\'"]*([a-zA-Z0-9_\-\.]{8,})'),
        "Password": re.compile(r'(?i)(?:password|passwd|pwd)[\s\'"]*[:=][\s\'"]*([^ \'"\n\r]+)'),
        "DB_URI": re.compile(r'(?i)(?:postgresql|mysql|mongodb|redis)://([^:\s]+:[^@\s]+)@'),
        "JWT": re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+')
    },
    "Level_2_PII": {
        "Email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "Phone_CN": re.compile(r'\b1[3-9]\d{9}\b'),
        "Internal_IP": re.compile(r'\b(10\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+|192\.168\.\d+)\.\d+\b'),
        "Absolute_Path": re.compile(r'(?:/Users/|C:\\Users\\|/home/)[^/\\\s]+'),
        "ID_Card_CN": re.compile(r'\b\d{17}[\dXx]\b')
    }
}

SUSPICIOUS_FILES = {'.env', '.DS_Store', 'Thumbs.db'}

# --- Functions ---
def is_binary(file_path):
    try:
        with open(file_path, 'tr') as check_file:
            check_file.read(1024)
            return False
    except UnicodeDecodeError:
        return True

def mask_secret(secret_str):
    if len(secret_str) <= 4:
        return "***"
    return f"{secret_str[:2]}...{secret_str[-2:]}"

def scan_file(file_path):
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                # Check Level 1
                for risk_name, regex in PATTERNS["Level_1_Credentials"].items():
                    for match in regex.finditer(line):
                        matched_val = match.group(0)
                        # mask if group(1) exists
                        if match.groups():
                            secret = match.group(1)
                            matched_val = matched_val.replace(secret, mask_secret(secret))
                        
                        findings.append({
                            "level": "🔴 Level 1",
                            "type": risk_name,
                            "line": line_num,
                            "snippet": matched_val.strip()
                        })
                # Check Level 2
                for risk_name, regex in PATTERNS["Level_2_PII"].items():
                    for match in regex.finditer(line):
                        findings.append({
                            "level": "🟡 Level 2",
                            "type": risk_name,
                            "line": line_num,
                            "snippet": match.group(0).strip()
                        })
    except Exception:
        pass # Skip unreadable files
    return findings

def check_missing_files(target_dir):
    files_found = set(f.lower() for f in os.listdir(target_dir) if os.path.isfile(os.path.join(target_dir, f)))
    missing = []
    
    if not any(f.startswith('readme') for f in files_found):
        missing.append("README")
    if not any(f.startswith('license') for f in files_found):
        missing.append("LICENSE")
    if '.gitignore' not in files_found:
        missing.append(".gitignore")
        
    deps = {'requirements.txt', 'package.json', 'cargo.toml', 'go.mod', 'pom.xml', 'build.gradle'}
    if not any(d in files_found for d in deps):
        missing.append("Dependency Declaration (e.g., requirements.txt, package.json)")
        
    return missing

def main(target_dir):
    target_path = Path(target_dir).resolve()
    
    report = {
        "target_directory": str(target_path),
        "missing_structural_files": check_missing_files(target_dir),
        "suspicious_files_found": [],
        "content_findings": {}
    }
    
    for root, dirs, files in os.walk(target_path):
        # Filter ignored dirs
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.git')]
        
        for file in files:
            file_path = Path(root) / file
            rel_path = file_path.relative_to(target_path)
            
            if file in SUSPICIOUS_FILES or file.endswith(('.pem', '.key', '.cert', '.p12', '.log')):
                report["suspicious_files_found"].append(str(rel_path))
                
            if not is_binary(file_path):
                file_findings = scan_file(file_path)
                if file_findings:
                    report["content_findings"][str(rel_path)] = file_findings

    print(json.dumps(report, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    main(target)
