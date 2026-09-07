#!/usr/bin/env python3
"""
Security Auditor Script for ML Repository.
Scans repository files (including Jupyter Notebooks) for potential exposed secrets, API keys, and sensitive tokens.
"""

import os
import re
import sys
import json
from pathlib import Path

# Regular expressions matching potential secrets or sensitive values
SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password)\s*=\s*['\"]([^'\"]{8,})['\"]", "Possible hardcoded secret/token"),
    (r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----", "Exposed private key"),
    (r"(?i)aws[_-]?(secret[_-]?access[_-]?key|access[_-]?key[_-]?id)\s*=\s*['\"]([^'\"]+)['\"]", "AWS Credential"),
]

def scan_file(filepath: Path) -> list:
    issues = []
    try:
        if filepath.suffix == ".ipynb":
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                for i, cell in enumerate(data.get("cells", [])):
                    if cell.get("cell_type") == "code":
                        source = "".join(cell.get("source", []))
                        for pattern, desc in SECRET_PATTERNS:
                            if re.search(pattern, source):
                                issues.append(f"{filepath} [Cell #{i+1}]: {desc}")
        elif filepath.suffix in [".py", ".json", ".txt", ".md", ".env", ".yml", ".yaml"]:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for pattern, desc in SECRET_PATTERNS:
                    if re.search(pattern, content):
                        issues.append(f"{filepath}: {desc}")
    except Exception as e:
        issues.append(f"Error scanning {filepath}: {e}")
    return issues

def main():
    repo_root = Path(__file__).resolve().parent.parent
    found_issues = []
    
    for root, dirs, files in os.walk(repo_root):
        # Ignore .git and .ipynb_checkpoints
        dirs[:] = [d for d in dirs if d not in [".git", ".ipynb_checkpoints", "__pycache__", "venv", ".venv"]]
        for file in files:
            filepath = Path(root) / file
            found_issues.extend(scan_file(filepath))
            
    if found_issues:
        print("❌ Security issues identified:")
        for issue in found_issues:
            print(f"  - {issue}")
        sys.exit(1)
    else:
        print("✅ Security scan passed: No hardcoded secrets or credentials detected.")
        sys.exit(0)

if __name__ == "__main__":
    main()
