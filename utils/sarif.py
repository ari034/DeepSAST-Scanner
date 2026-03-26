import json

def generate_sarif(findings):
    return json.dumps({
        "version": "2.1.0",
        "runs": [{
            "results": [
                {
                    "ruleId": f["type"],
                    "message": {"text": f["reason"]},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"]},
                            "region": {"startLine": f["line"]}
                        }
                    }]
                }
                for f in findings
            ]
        }]
    }, indent=2)
