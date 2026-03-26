def analyze_express(file_path, code):
    findings = []
    lines = code.split("\n")

    for i, line in enumerate(lines):

        if "router." in line or "app." in line:

            block = "\n".join(lines[i:i+12])

            # STRICT IDOR
            if "req.params" in block:
                if any(x in block for x in ["find", "get", "db", "Model"]):
                    if not any(x in block for x in ["auth", "jwt", "verify"]):
                        findings.append({
                            "type": "IDOR",
                            "file": file_path,
                            "line": i + 1,
                            "severity": "MEDIUM",
                            "reason": "req.params used in object access without auth check"
                        })

            # AUTH BYPASS
            if "admin" in block.lower():
                if not any(x in block for x in ["auth", "jwt", "verify"]):
                    findings.append({
                        "type": "Auth Bypass",
                        "file": file_path,
                        "line": i + 1,
                        "severity": "HIGH",
                        "reason": "Admin route without authentication"
                    })

    return findings
