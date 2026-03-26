def should_scan(code):
    keywords = ["req.", "router", "app.", "axios", "eval", "exec", "fs"]
    return any(k in code for k in keywords)
