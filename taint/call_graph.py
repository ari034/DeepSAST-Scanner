import re


def extract_functions(code):
    pattern = r'function\s+(\w+)\s*\('
    return re.findall(pattern, code)


def extract_calls(code):
    pattern = r'(\w+)\('
    return re.findall(pattern, code)


def build_call_graph(files):
    graph = {}

    for file, code in files.items():
        funcs = extract_functions(code)
        calls = extract_calls(code)

        for f in funcs:
            graph[f] = calls

    return graph
