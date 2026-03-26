import re

def detect_secrets(file_path, code):
    findings = []

    patterns = [
        r'API_KEY\s*=\s*["\'].*["\']',
        r'secret\s*=\s*["\'].*["\']',
        r'password\s*=\s*["\'].*["\']'
    ]

    for i, line in enumerate(code.split("\n")):
        for p in patterns:
            if re.search(p, line, re.IGNORECASE):
                findings.append({
                    "type": "Secrets",
                    "file": file_path,
                    "line": i + 1,
                    "severity": "MEDIUM",
                    "reason": "Hardcoded secret detected"
                })

    return findings
