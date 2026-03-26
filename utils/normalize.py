def normalize_type(llm_type, fallback):
    t = llm_type.lower()

    if "eval" in t or "command" in t:
        return "RCE"

    if "redirect" in t or "request" in t:
        return "SSRF"

    if "xss" in t:
        return "XSS"

    if "path" in t:
        return "Path Traversal"

    if "auth" in t or "idor" in t:
        return "IDOR"

    if "secret" in t or "jwt" in t:
        return "Secrets"

    return fallback
