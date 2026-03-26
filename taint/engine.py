import re

SOURCES = ["req.query", "req.body", "req.params"]

SINKS = {
    "exec": "Command Injection",
    "eval": "RCE",
    "axios.get": "SSRF",
    "fetch": "SSRF",
    "fs.readFile": "Path Traversal",
    "res.send": "XSS"
}

SEVERITY = {
    "RCE": "CRITICAL",
    "Command Injection": "CRITICAL",
    "SSRF": "HIGH",
    "Path Traversal": "HIGH",
    "Auth Bypass": "HIGH",
    "XSS": "MEDIUM",
    "IDOR": "MEDIUM",
    "Secrets": "MEDIUM"
}


def scan_file_taint(file_path, code):
    findings = []
    tainted = set()
    visited = set()

    lines = code.split("\n")

    for i, line in enumerate(lines):

        # SOURCE
        for src in SOURCES:
            if src in line:
                match = re.findall(r'(\w+)\s*=\s*.*' + re.escape(src), line)
                for var in match:
                    tainted.add(var)

        # FLOW
        for t in list(tainted):
            if t in line and "=" in line:
                new_var = line.split("=")[0].strip()
                tainted.add(new_var)

        # SINK
        for sink, vuln in SINKS.items():
            if sink in line:

                key = (file_path, i, sink)
                if key in visited:
                    continue

                for t in tainted:
                    if t in line:
                        visited.add(key)

                        findings.append({
                            "type": vuln,
                            "file": file_path,
                            "line": i + 1,
                            "severity": SEVERITY[vuln],
                            "reason": f"User input '{t}' flows into {sink}"
                        })
                        break

    return findings
