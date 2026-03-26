import os
import json
import torch
import logging
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig


class LLMEngine:
    def __init__(self, model_path="deepseek-ai/deepseek-coder-v2-lite-instruct"):
        print(f"[LLM] Loading model from: {model_path}")

        # 🔥 Stability + memory fixes
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
        os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

        logging.getLogger("transformers").setLevel(logging.ERROR)

        # Tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_path,
            local_files_only=True,
            trust_remote_code=True
        )

        # 🔥 Quantization (fits 11GB GPU)
        quant_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4"
        )

        # Model
        self.model = AutoModelForCausalLM.from_pretrained(
            model_path,
            quantization_config=quant_config,
            device_map="auto",
            trust_remote_code=True,
            local_files_only=True
        )

    def scan_with_type(self, code, file_path, vuln_type="GENERIC"):
        """
        Used ONLY as fallback (logic bugs, IDOR, auth issues)
        """

        if vuln_type == "GENERIC":
            instruction = "Find vulnerabilities missed by static analysis like IDOR, auth bypass, business logic issues."
        else:
            instruction = f"Find {vuln_type} vulnerabilities."

        prompt = f"""
You are a strict application security scanner.

Task: {instruction}

Rules:
- Only report real vulnerabilities
- No guessing
- Must include line number
- Output JSON array only

FORMAT:
[
  {{
    "type": "IDOR",
    "line": 12,
    "reason": "User ID not validated"
  }}
]

FILE: {file_path}

CODE:
{code[:1200]}
"""

        try:
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)

            output = self.model.generate(
                **inputs,
                max_new_tokens=200,
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id
            )

            raw = self.tokenizer.decode(output[0], skip_special_tokens=True)

            return self._parse(raw, file_path)

        except Exception as e:
            print(f"[LLM ERROR] {file_path}: {e}")
            return []

    def _parse(self, text, file_path):
        try:
            data = json.loads(text)
        except:
            try:
                start = text.find("[")
                end = text.rfind("]") + 1
                data = json.loads(text[start:end])
            except:
                return []

        results = []

        for item in data:
            if not isinstance(item, dict):
                continue

            results.append({
                "type": item.get("type", "UNKNOWN"),
                "line": item.get("line", 1),
                "severity": "MEDIUM",
                "reason": item.get("reason", ""),
                "file": file_path
            })

        return results
