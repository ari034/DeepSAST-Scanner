def deduplicate(findings):
    seen = set()
    result = []

    for f in findings:
        key = (f["file"], f["line"], f["type"])

        if key not in seen:
            seen.add(key)
            result.append(f)

    return result
