def extract_js_context(code, line, radius=5):
    lines = code.split("\n")

    start = max(0, line - radius)
    end = min(len(lines), line + radius)

    return "\n".join(lines[start:end])
