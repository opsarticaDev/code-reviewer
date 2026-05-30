# CodeReviewer

**Static analysis and AI-assisted code review infrastructure for research pipeline validation.**

## Problem

Computational research pipelines that process large administrative datasets require systematic code quality assurance at every stage. The BVA Representation Pipeline, which extracts structured data from 1.19 million Board of Veterans' Appeals decisions across 14 processing steps, depends on Python scripts where a single uncaught exception, hardcoded credential, or silently incorrect comparison can corrupt downstream outputs or expose sensitive data. Commercial review tools (CodeRabbit, SonarQube) impose subscription costs, cloud dependencies, or heavyweight infrastructure that complicate reproducibility and institutional compliance. No existing local tool combines static analysis, security scanning, complexity measurement, and optional LLM-assisted review in a single pass suitable for research computing environments.

## What It Does

- Performs pattern-based static analysis detecting bugs, style violations, and complexity issues across Python, JavaScript, TypeScript, and 15 additional languages
- Scans for security vulnerabilities including hardcoded secrets (AWS keys, GitHub tokens, JWTs, private keys), SQL injection patterns, shell injection vectors, insecure deserialization, and eval/exec usage
- Computes per-file code metrics: cyclomatic complexity, maintainability index, lines of code, and duplication indicators
- Integrates with external linters (flake8, bandit, pylint, mypy) for deeper analysis when available
- Provides optional AI-powered semantic review via OpenAI, Anthropic, or Ollama (local), using the researcher's own API credentials
- Generates reports in Markdown, HTML, and JSON formats for documentation, sharing, and programmatic consumption
- Runs entirely on the local machine with no telemetry, no cloud dependency for core analysis, and no data leaving the workstation unless AI review is explicitly enabled

| Component | Detail |
|-----------|--------|
| Static analysis | Pattern matching for bugs, style, and code smells (mutable defaults, bare excepts, identity comparisons, star imports, debug statements) |
| Security scanning | Regex-based detection of 7 vulnerability classes and 6 secret types with severity classification |
| Complexity metrics | Cyclomatic complexity (1-50+ scale), maintainability index (0-100 scale), function argument counts |
| AI review | Optional deep analysis via OpenAI (gpt-4o-mini default), Anthropic (claude-3-haiku default), or Ollama (llama3 default) |
| External linters | Optional integration with flake8, bandit, pylint, mypy when installed |
| Report output | Markdown (.md), HTML (styled, self-contained), JSON (machine-readable) |
| GUI | Tkinter desktop application with file/folder browser, settings panel, and inline results |
| CLI | Command-line interface for scripted and batch use |

### Languages Supported

| Language | Static Analysis | Security Scan | Metrics |
|----------|-----------------|---------------|---------|
| Python | Full | Full | Full |
| JavaScript | Full | Full | Basic |
| TypeScript | Full | Full | Basic |
| Java | Basic | Secrets | Basic |
| Go | Basic | Secrets | Basic |
| Ruby | Basic | Secrets | Basic |
| PHP | Basic | Secrets | Basic |
| C/C++ | Basic | Secrets | Basic |
| Others | Secrets | Secrets | Lines |

### Severity Levels

| Level | Meaning |
|-------|---------|
| Critical | Security vulnerabilities, secrets in code |
| Error | Bugs, likely runtime errors |
| Warning | Potential issues, code smells |
| Info | Style suggestions, TODOs |

### Code Metrics Reference

**Cyclomatic Complexity** measures decision points in code: 1-10 (simple, low risk), 11-20 (moderate, consider refactoring), 21-50 (complex, high risk), 50+ (very complex, split function).

**Maintainability Index** scores from 0-100: 85-100 (highly maintainable), 65-84 (moderate), 0-64 (difficult to maintain).

## Use Cases

### BVA Pipeline Validation
Each of the 14 extraction steps in the BVA Representation Pipeline is a Python script that parses, transforms, or classifies data derived from 1.19M appellate decisions. CodeReviewer can audit these scripts for complexity creep, uncaught edge cases (bare excepts masking parse failures), and hardcoded paths or credentials before pipeline runs. Reports in JSON format enable programmatic tracking of code quality across pipeline versions.

### Pre-Commit Quality Gate
Run against changed files before committing to the research repository. Static analysis catches mutable default arguments, identity comparison errors, and debug print statements that would otherwise propagate into shared branches.

### Security Audit for Public Release
Before publishing pipeline code to a public GitHub repository (standing convention for academic work), scan for hardcoded API keys, AWS credentials, GitHub tokens, and private keys that may have entered the codebase during development. Critical findings block release until resolved.

### Codebase Onboarding
When reviewing unfamiliar contributed code or inherited scripts, generate an HTML report summarizing complexity metrics, maintainability scores, and flagged issues. This provides a structured starting point for code review and refactoring prioritization.

## Installation

### Quick Start
1. Run `START_HERE.sh` (Mac/Linux) or the equivalent batch launcher (Windows)
2. Wait for dependencies to install (first time only)
3. The tool launches automatically

Static analysis works without any API keys. AI-powered review requires an OpenAI, Anthropic, or Ollama API key (optional).

### Manual Installation
1. Install Python 3.10+ from python.org
2. Run: `pip install -r REQUIREMENTS.txt`
3. Run: `python validate_install.py`
4. Run: `python codereviewer.py`

### System Requirements
- Windows 10 / macOS 10.15 / Ubuntu 20.04
- Python 3.10 or higher
- 2 GB RAM
- 200 MB free disk space

### External Linters (Optional)

Enhance analysis with standard tools:

```bash
# Recommended
pip install flake8 bandit

# Full suite
pip install pylint flake8 bandit mypy
```

| Tool | Purpose |
|------|---------|
| flake8 | PEP8 style + pyflakes checks |
| bandit | Security vulnerability scanner |
| pylint | Comprehensive linting |
| mypy | Static type checking |

### AI Review Configuration

**OpenAI**: Obtain an API key from https://platform.openai.com/api-keys. Enter the key in the Settings tab. Select "openai" provider. Default model: gpt-4o-mini.

**Anthropic**: Obtain an API key from https://console.anthropic.com/. Enter the key in the Settings tab. Select "anthropic" provider. Default model: claude-3-haiku-20240307.

**Ollama (free, local)**: Install from https://ollama.ai/. Run `ollama pull llama3`. Select "ollama" provider (no API key needed). Default model: llama3.

## CLI Usage

```bash
# Review a single file
python codereviewer.py --file path/to/file.py

# Review a project directory
python codereviewer.py --dir path/to/project

# With AI review
python codereviewer.py --dir . --ai --provider openai --key YOUR_KEY
```

## Report Formats

**Markdown (.md)**: Clean, readable format. GitHub/GitLab compatible. Suitable for documentation and version-controlled quality records.

**HTML (.html)**: Styled, self-contained, printable report. No external dependencies. Suitable for sharing with collaborators or including in supplementary materials.

**JSON (.json)**: Machine-readable. Suitable for integration with other tools, longitudinal quality tracking, or programmatic analysis of code health across pipeline versions.

## Technical Notes

| Field | Value |
|-------|-------|
| Input | Single file or project directory (any supported language) |
| Output | Review report (Markdown, HTML, or JSON) with issue listings, severity classifications, and per-file metrics |
| Core dependencies | Python 3.10+ standard library (tkinter, ast, json, re, hashlib, subprocess, dataclasses) |
| Optional dependencies | openai >=1.0.0, anthropic >=0.18.0, requests >=2.31.0 |
| Optional external tools | flake8, bandit, pylint, mypy |
| Language | Python |
| GUI framework | Tkinter |
| Privacy model | All core analysis runs locally. No telemetry. AI review sends code to the selected provider only when explicitly enabled, using the researcher's own API key. Detected secrets are redacted in reports. |

### Directory Structure

```
CodeReviewer/
  codereviewer.py          Main application (GUI + CLI)
  validate_install.py      Dependency checker
  sample_code.py           Test input for validation
  REQUIREMENTS.txt         Python dependencies
  START_HERE.sh            Launch script
  INSTALL.txt              Installation instructions
  QUICKSTART.txt           Quick start guide
  WORKFLOW.txt             Review pipeline documentation
  EXAMPLES.txt             Usage examples
  TROUBLESHOOTING.txt      Common issues and fixes
  README.md                This file
  LICENSE                  MIT License
```

## Troubleshooting

**"No issues found" on known bad code**: Verify the file extension is supported. Enable external linters for deeper analysis. Try AI review for semantic issues.

**AI review failed**: Verify the API key is correct. Check internet connectivity. For Ollama, ensure the service is running (`ollama serve`).

**External linters not detected**: Install with pip (`pip install flake8 bandit`). Ensure they are in PATH. Restart the application.

**Large project is slow**: Disable external linters for speed. Review specific directories rather than the entire project. AI review processes only the first file.

**Python not found**: Install Python 3.10+ from https://python.org/downloads/. Check "Add Python to PATH" during install. Restart the computer.

**Permission denied**: Windows: right-click the launcher and select "Run as administrator." Mac/Linux: `chmod +x START_HERE.sh`.

## Limitations and Scope

- Static analysis is pattern-based, not flow-sensitive. It catches common anti-patterns but does not perform full data-flow or taint analysis.
- Security scanning uses regex matching. It detects known secret formats and vulnerability patterns but is not a substitute for a dedicated application security testing tool in production environments.
- Complexity metrics rely on AST parsing for Python. Other languages use line-counting heuristics and simplified pattern matching, which provide approximate rather than precise metrics.
- AI review depends on the selected LLM provider and sends source code to that provider's API. Researchers working with sensitive or restricted data should use Ollama (local inference) or disable AI review entirely.
- Full static analysis coverage (beyond secrets detection) is limited to Python, JavaScript, and TypeScript. Other languages receive basic pattern matching only.
- The tool analyzes individual files and does not perform cross-file dependency analysis, call graph construction, or project-level architectural review.
- Report generation does not include automated fix application. All remediation is manual.

## Citation

Calvin Vernon (2026). CodeReviewer: Static analysis and AI-assisted code review infrastructure for research pipeline validation.

## Author

Calvin Vernon, PsyD, CSP
Research Affiliate, Touro University Worldwide
https://orcid.org/0009-0005-9900-1613 | calvin@opsartica.com | https://github.com/opsarticaDev

## License

MIT License. See [LICENSE](LICENSE) for full text.
