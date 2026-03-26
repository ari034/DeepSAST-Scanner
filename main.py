import os
import sys
from llm_engine import LLMEngine
from scanner import scan_repo
from utils.sarif import generate_sarif


def read_files(directory):
    """
    Recursively read supported source files
    """
    files = {}

    for root, _, filenames in os.walk(directory):
        for file in filenames:
            if file.endswith((".py", ".js", ".ts")):
                path = os.path.join(root, file)

                try:
                    with open(path, "r", encoding="utf-8") as f:
                        files[path] = f.read()
                except Exception as e:
                    print(f"[WARN] Could not read {path}: {e}")

    return files


def validate_path(path):
    if not os.path.exists(path):
        print(f"[ERROR] Path does not exist: {path}")
        sys.exit(1)

    if not os.path.isdir(path):
        print(f"[ERROR] Not a directory: {path}")
        sys.exit(1)


def main():
    print("=== AI SAST Scanner ===\n")

    # 🔹 Input repo path
    target = input("Enter directory to scan: ").strip()
    validate_path(target)

    # 🔹 Model path (offline compatible)
    model_path = input(
        "Model path (press Enter for default deepseek v2-lite): "
    ).strip()

    if not model_path:
        model_path = "deepseek-ai/deepseek-coder-v2-lite-instruct"

    # 🔹 Initialize LLM
    print("\n[+] Initializing LLM...")
    llm = LLMEngine(model_path)

    # 🔹 Load files
    print("[+] Collecting files...")
    files = read_files(target)

    if not files:
        print("[!] No supported files found (.py, .js, .ts)")
        sys.exit(0)

    print(f"[+] Found {len(files)} files")

    # 🔹 Scan (SAFE MODE: sequential)
    print("\n[+] Starting scan...\n")
    findings = scan_repo(files, llm)

    # 🔹 Summary
    print("\n=== Scan Complete ===")
    print(f"Total findings: {len(findings)}")

    # 🔹 Print findings (quick preview)
    for f in findings:
        print("\n------------------------------")
        print(f"[{f['severity']}] {f['type']}")
        print(f"File: {f['file']}")
        print(f"Line: {f['line']}")
        print(f"Reason: {f['reason']}")

    # 🔹 Save SARIF report
    output_file = "report.sarif"

    try:
        with open(output_file, "w") as f:
            f.write(generate_sarif(findings))

        print(f"\n[+] SARIF report saved to: {output_file}")

    except Exception as e:
        print(f"[ERROR] Failed to write report: {e}")


if __name__ == "__main__":
    main()
