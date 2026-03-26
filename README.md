# DeepSAST Scanner

DeepSAST is a hybrid Static Application Security Testing (SAST) tool that combines deterministic taint analysis with LLM-assisted reasoning to identify real vulnerabilities with reduced false positives.

## Overview

DeepSAST follows a strict detection pipeline:

SOURCE → FLOW → SINK → VULNERABILITY → SEVERITY → OUTPUT

A vulnerability is reported only when user-controlled input reaches a known dangerous sink. This approach reduces noise and improves accuracy compared to pattern-based scanners.

LLM-based analysis is used selectively for logic vulnerabilities such as authorization issues and IDOR, while core detection remains rule-driven and deterministic.

## Features

- Source-to-sink taint tracking (req.query, req.body, req.params)
- Strict sink-to-vulnerability mapping
- Minimal taint propagation across variables
- Framework-aware analysis for Express.js and Django
- Detection of:
  - Remote Code Execution (RCE)
  - Command Injection
  - SSRF
  - Path Traversal
  - Cross-Site Scripting (XSS)
  - IDOR and Broken Access Control
  - Authentication Bypass
  - Hardcoded Secrets
- Deduplication of findings
- Noise reduction by skipping irrelevant files
- SARIF report generation

## Detection Philosophy

DeepSAST enforces a simple rule:

Only report a vulnerability if user input reaches a dangerous sink.

This ensures:
- Fewer false positives
- Clear and explainable findings
- Deterministic behavior

## Architecture

The scanner is composed of:

- Taint Engine  
  Tracks user-controlled input and validates flow into sinks

- Sink Mapping  
  Maps dangerous functions to vulnerability types

- Framework Analysis  
  Detects route-level issues in Express and Django

- LLM Engine  
  Used only for edge cases such as logic flaws and authorization issues

- Deduplication Layer  
  Removes duplicate findings based on file, line, and vulnerability type

## Supported Sinks

- exec → Command Injection
- eval → Remote Code Execution
- axios.get / fetch → SSRF
- fs.readFile → Path Traversal
- res.send → XSS

## Usage

```bash
python main.py
