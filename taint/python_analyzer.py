import ast

class Analyzer(ast.NodeVisitor):
    def __init__(self):
        self.tainted = set()
        self.vulns = []

    def visit_Assign(self, node):
        val = ast.unparse(node.value)

        if "input" in val or "request" in val:
            for t in node.targets:
                if hasattr(t, "id"):
                    self.tainted.add(t.id)

        self.generic_visit(node)

    def visit_Call(self, node):
        func = ast.unparse(node.func)
        args = [ast.unparse(a) for a in node.args]

        sinks = ["os.system", "eval", "exec", "subprocess"]

        for sink in sinks:
            if sink in func:
                for arg in args:
                    if arg in self.tainted:
                        self.vulns.append({
                            "type": "RCE",
                            "line": node.lineno,
                            "severity": "HIGH",
                            "reason": f"Tainted input to {sink}"
                        })

        self.generic_visit(node)


def analyze_python_file(code):
    try:
        tree = ast.parse(code)
        analyzer = Analyzer()
        analyzer.visit(tree)
        return analyzer.vulns
    except:
        return []
