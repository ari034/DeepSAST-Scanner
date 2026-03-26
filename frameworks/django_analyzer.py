import re


def analyze_django(file_path, code):
    findings = []
    lines = code.split("\n")

    for i, line in enumerate(lines):

        # 🔥 Detect view
        if "def " in line and "request" in line:

            block = "\n".join(lines[i:i+15])

            # 🔥 IDOR
            if "request.GET" in block or "request.POST" in block:
                if "permission" not in block and "is_authenticated" not in block:
                    findings.append({
                        "type": "IDOR",
                        "file": file_path,
                        "line": i + 1,
                        "severity": "MEDIUM",
                        "reason": "User input used without permission check"
                    })

            # 🔥 Auth bypass
            if "admin" in block.lower():
                if "is_staff" not in block and "is_superuser" not in block:
                    findings.append({
                        "type": "Auth Bypass",
                        "file": file_path,
                        "line": i + 1,
                        "severity": "HIGH",
                        "reason": "Admin logic without proper authorization"
                    })

    return findings
