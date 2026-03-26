import re

SOURCES = ["req.body", "req.query", "req.params"]
SINKS = ["eval", "exec", "spawn", "axios", "fetch"]


def track_taint(files):
    tainted = {}
    findings = []

    for file, code in files.items():
        lines = code.split("\n")

        for i, line in enumerate(lines):

            # Source
            if any(src in line for src in SOURCES):
                var = line.split("=")[0].strip()
                tainted[var] = (file, i + 1)

            # Propagation
            for t in list(tainted.keys()):
                if t in line:
                    new_var = line.split("=")[0].strip()
                    tainted[new_var] = tainted[t]

            # Sink
            if any(s in line for s in SINKS):
                for t in tainted:
                    if t in line:
                        findings.append({
                            "file": file,
                            "line": i + 1,
                            "reason": f"Taint flows into {line}"
                        })

    return findings
