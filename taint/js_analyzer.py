import re

SOURCES = ["req.body", "req.query", "req.params"]
SINKS = ["eval", "exec", "spawn", "axios", "fetch"]


def analyze_js_file(code):
    tainted_vars = set()
    findings = []

    lines = code.split("\n")

    for i, line in enumerate(lines):

        # 🔥 Detect sources
        for src in SOURCES:
            if src in line:
                var_match = re.findall(r'(\w+)\s*=\s*.*' + re.escape(src), line)
                for v in var_match:
                    tainted_vars.add(v)

        # 🔥 Detect propagation
        for var in list(tainted_vars):
            if f"{var} =" in line:
                new_var = line.split("=")[0].strip()
                tainted_vars.add(new_var)

        # 🔥 Detect sinks
        for sink in SINKS:
            if sink in line:
                for var in tainted_vars:
                    if var in line:
                        findings.append({
                            "type": "Injection",
                            "line": i + 1,
                            "reason": f"Tainted input reaches {sink}"
                        })

    return findings
