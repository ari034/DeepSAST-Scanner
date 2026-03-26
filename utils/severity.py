def assign_severity(vuln_type):
    mapping = {
        "RCE": "CRITICAL",
        "SSRF": "HIGH",
        "Path Traversal": "HIGH",
        "IDOR": "MEDIUM",
        "XSS": "MEDIUM",
        "Secrets": "MEDIUM"
    }

    return mapping.get(vuln_type, "MEDIUM")
