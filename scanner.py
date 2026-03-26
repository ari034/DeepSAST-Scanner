from taint.engine import scan_file_taint
from frameworks.express_analyzer import analyze_express
from utils.secrets import detect_secrets
from utils.filter import should_scan
from utils.dedup import deduplicate


def scan_repo(files, llm):
    print("[+] Running STRICT SAST pipeline...")

    findings = []

    for file, code in files.items():

        # 1. Skip noise
        if not should_scan(code):
            continue

        # 2. Taint engine (PRIMARY)
        taint_results = scan_file_taint(file, code)
        findings.extend(taint_results)

        # 3. Framework (Express)
        if file.endswith((".js", ".ts")):
            findings.extend(analyze_express(file, code))

        # 4. Secrets
        findings.extend(detect_secrets(file, code))

        # 5. LLM fallback ONLY if nothing found
        if not taint_results:
            try:
                findings.extend(llm.scan_with_type(code, file, "GENERIC"))
            except:
                pass

    return deduplicate(findings)
