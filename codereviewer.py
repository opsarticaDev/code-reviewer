#!/usr/bin/env python3
"""
Code Reviewer - Local Static Analysis & AI-Powered Code Review
Part of AI Toolkit

Features:
- Static analysis (linting, style, complexity)
- Security scanning (vulnerabilities, secrets detection)
- Code metrics (complexity, maintainability, duplication)
- AI-powered deep review (optional, BYO API key)
- Professional report generation (Markdown, HTML, JSON)
- Multi-language support (Python, JavaScript, TypeScript, more)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import queue
import os
import sys
import json
import re
import ast
import hashlib
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
import traceback

# =============================================================================
# Configuration
# =============================================================================

SUPPORTED_LANGUAGES = {
    '.py': 'python',
    '.js': 'javascript',
    '.ts': 'typescript',
    '.jsx': 'javascript',
    '.tsx': 'typescript',
    '.java': 'java',
    '.go': 'go',
    '.rb': 'ruby',
    '.php': 'php',
    '.c': 'c',
    '.cpp': 'cpp',
    '.h': 'c',
    '.hpp': 'cpp',
    '.cs': 'csharp',
    '.rs': 'rust',
    '.swift': 'swift',
    '.kt': 'kotlin',
    '.sql': 'sql',
    '.sh': 'shell',
}

IGNORE_DIRS = {
    '__pycache__', 'node_modules', '.git', '.svn', 'venv', 'env',
    '.venv', '.env', 'dist', 'build', '.idea', '.vscode', 'coverage',
    '.pytest_cache', '.mypy_cache', 'egg-info', '.tox', '.nox', '.next'
}

IGNORE_FILES = {
    '.gitignore', '.dockerignore', 'package-lock.json', 'yarn.lock',
    'poetry.lock', 'Pipfile.lock', '.DS_Store'
}


# =============================================================================
# Data Models
# =============================================================================

class Severity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class Issue:
    """Represents a code issue"""
    file: str
    line: int
    column: int
    severity: Severity
    category: str  # style, security, complexity, bug, etc.
    rule: str
    message: str
    suggestion: str = ""
    code_snippet: str = ""


@dataclass
class FileMetrics:
    """Code metrics for a file"""
    filepath: str
    lines_total: int = 0
    lines_code: int = 0
    lines_comment: int = 0
    lines_blank: int = 0
    functions: int = 0
    classes: int = 0
    complexity: float = 0.0
    maintainability: float = 0.0


@dataclass
class ReviewResult:
    """Complete review result"""
    project_path: str
    timestamp: str
    files_analyzed: int
    total_lines: int
    issues: List[Issue] = field(default_factory=list)
    metrics: List[FileMetrics] = field(default_factory=list)
    ai_summary: str = ""
    ai_suggestions: List[str] = field(default_factory=list)
    
    @property
    def issue_counts(self) -> Dict[str, int]:
        counts = defaultdict(int)
        for issue in self.issues:
            counts[issue.severity.value] += 1
        return dict(counts)
    
    @property
    def category_counts(self) -> Dict[str, int]:
        counts = defaultdict(int)
        for issue in self.issues:
            counts[issue.category] += 1
        return dict(counts)


# =============================================================================
# Static Analyzers
# =============================================================================

class PythonAnalyzer:
    """Python-specific static analysis"""
    
    SECURITY_PATTERNS = [
        (r'\beval\s*\(', 'S001', 'Use of eval() is dangerous - can execute arbitrary code', 'critical'),
        (r'\bexec\s*\(', 'S002', 'Use of exec() is dangerous - can execute arbitrary code', 'critical'),
        (r'__import__\s*\(', 'S003', 'Dynamic import can be dangerous', 'warning'),
        (r'subprocess\.call\s*\([^)]*shell\s*=\s*True', 'S004', 'shell=True in subprocess is dangerous', 'error'),
        (r'os\.system\s*\(', 'S005', 'os.system() is vulnerable to shell injection', 'error'),
        (r'pickle\.loads?\s*\(', 'S006', 'Pickle can execute arbitrary code during deserialization', 'error'),
        (r'yaml\.load\s*\([^)]*Loader\s*=\s*None', 'S007', 'Use yaml.safe_load() instead', 'error'),
        (r'yaml\.load\s*\([^)]*\)(?!.*Loader)', 'S007', 'Use yaml.safe_load() or specify Loader', 'warning'),
        (r'assert\s+\w+.*#.*security', 'S009', 'Assert statements removed with -O flag', 'warning'),
        (r'hashlib\.md5\s*\(', 'S010', 'MD5 is cryptographically weak', 'warning'),
        (r'hashlib\.sha1\s*\(', 'S011', 'SHA1 is cryptographically weak', 'warning'),
        (r'random\.[^(]+\([^)]*\)(?!.*secrets)', 'S012', 'Use secrets module for security-sensitive randomness', 'info'),
    ]
    
    SECRET_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', 'SEC001', 'Hardcoded password detected'),
        (r'(?i)(api_key|apikey|api-key)\s*=\s*["\'][^"\']{8,}["\']', 'SEC002', 'Hardcoded API key detected'),
        (r'(?i)(secret|token)\s*=\s*["\'][a-zA-Z0-9_\-]{16,}["\']', 'SEC003', 'Hardcoded secret/token detected'),
        (r'(?i)aws_access_key_id\s*=\s*["\']AKIA[A-Z0-9]{16}["\']', 'SEC004', 'AWS access key detected'),
        (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'SEC005', 'Private key in source code'),
        (r'ghp_[a-zA-Z0-9]{36}', 'SEC006', 'GitHub personal access token detected'),
        (r'sk-[a-zA-Z0-9]{32,}', 'SEC007', 'Potential OpenAI API key detected'),
        (r'xox[baprs]-[0-9]{10,}', 'SEC008', 'Slack token detected'),
    ]
    
    STYLE_PATTERNS = [
        (r'^\s*print\s*\((?!.*#\s*debug)', 'W001', 'Debug print statement found'),
        (r'#\s*TODO[:\s]', 'W002', 'TODO comment found'),
        (r'#\s*FIXME[:\s]', 'W003', 'FIXME comment found'),
        (r'#\s*HACK[:\s]', 'W004', 'HACK comment found'),
        (r'#\s*XXX[:\s]', 'W005', 'XXX comment found'),
        (r'except\s*:', 'W006', 'Bare except clause - specify exception type'),
        (r'from\s+\S+\s+import\s+\*', 'W007', 'Star import pollutes namespace'),
        (r'^\s{200,}', 'W008', 'Extremely long line'),
    ]
    
    BUG_PATTERNS = [
        (r'if\s+\w+\s*=(?!=)\s*[^=]', 'B001', 'Assignment in if condition - use == for comparison'),
        (r'except\s+\w+\s*,\s*\w+', 'B002', 'Old-style except syntax (Python 2)'),
        (r'==\s*None', 'B003', 'Use "is None" instead of "== None"'),
        (r'!=\s*None', 'B004', 'Use "is not None" instead of "!= None"'),
        (r'==\s*True\b', 'B005', 'Use "if x:" instead of "if x == True"'),
        (r'==\s*False\b', 'B006', 'Use "if not x:" instead of "if x == False"'),
        (r'\btype\s*\(\s*\w+\s*\)\s*==', 'B007', 'Use isinstance() instead of type() comparison'),
        (r'len\s*\(\s*\w+\s*\)\s*==\s*0', 'B008', 'Use "if not x:" instead of "if len(x) == 0"'),
        (r'except\s+BaseException\b', 'B009', 'Catching BaseException catches SystemExit/KeyboardInterrupt'),
        (r'\.append\s*\(\s*\)\.', 'B010', 'append() returns None, chaining will fail'),
        (r'return\s+\[\s*\]\.append', 'B011', 'append() returns None'),
    ]
    
    def analyze_file(self, filepath: str) -> Tuple[List[Issue], FileMetrics]:
        """Analyze a Python file"""
        issues = []
        metrics = FileMetrics(filepath=filepath)
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            return issues, metrics
        
        # Basic metrics
        metrics.lines_total = len(lines)
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                metrics.lines_blank += 1
            elif stripped.startswith('#'):
                metrics.lines_comment += 1
            else:
                metrics.lines_code += 1
            
            # Security checks
            for pattern, rule, message, severity in self.SECURITY_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    sev = {'critical': Severity.CRITICAL, 'error': Severity.ERROR, 
                           'warning': Severity.WARNING, 'info': Severity.INFO}[severity]
                    issues.append(Issue(
                        file=filepath, line=i, column=0,
                        severity=sev, category='security',
                        rule=rule, message=message,
                        code_snippet=line.strip()[:100]
                    ))
            
            # Secret detection
            for pattern, rule, message in self.SECRET_PATTERNS:
                if re.search(pattern, line):
                    issues.append(Issue(
                        file=filepath, line=i, column=0,
                        severity=Severity.CRITICAL, category='secret',
                        rule=rule, message=message,
                        suggestion='Move to environment variables or secrets manager',
                        code_snippet='[REDACTED]'
                    ))
            
            # Style checks
            for pattern, rule, message in self.STYLE_PATTERNS:
                if re.search(pattern, line):
                    issues.append(Issue(
                        file=filepath, line=i, column=0,
                        severity=Severity.INFO, category='style',
                        rule=rule, message=message,
                        code_snippet=line.strip()[:80]
                    ))
            
            # Bug patterns
            for pattern, rule, message in self.BUG_PATTERNS:
                if re.search(pattern, line):
                    issues.append(Issue(
                        file=filepath, line=i, column=0,
                        severity=Severity.WARNING, category='bug',
                        rule=rule, message=message,
                        code_snippet=line.strip()[:80]
                    ))
            
            # Line length check
            if len(line) > 120:
                issues.append(Issue(
                    file=filepath, line=i, column=120,
                    severity=Severity.INFO, category='style',
                    rule='E501', message=f'Line too long ({len(line)} > 120 characters)'
                ))
        
        # AST analysis
        try:
            tree = ast.parse(content)
            metrics.functions = sum(1 for node in ast.walk(tree) 
                                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
            metrics.classes = sum(1 for node in ast.walk(tree) 
                                 if isinstance(node, ast.ClassDef))
            metrics.complexity = self._calculate_complexity(tree)
            metrics.maintainability = self._calculate_maintainability(metrics)
            
            # Function-level checks
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_complexity = self._node_complexity(node)
                    if func_complexity > 10:
                        issues.append(Issue(
                            file=filepath, line=node.lineno, column=node.col_offset,
                            severity=Severity.WARNING, category='complexity',
                            rule='C001', 
                            message=f'Function "{node.name}" has high complexity ({func_complexity})',
                            suggestion='Consider breaking into smaller functions'
                        ))
                    
                    num_args = len(node.args.args) + len(node.args.kwonlyargs)
                    if num_args > 7:
                        issues.append(Issue(
                            file=filepath, line=node.lineno, column=node.col_offset,
                            severity=Severity.WARNING, category='complexity',
                            rule='C002',
                            message=f'Function "{node.name}" has too many arguments ({num_args})',
                            suggestion='Consider using a config object or dataclass'
                        ))
                    
                    # Mutable default arguments
                    for default in node.args.defaults + node.args.kw_defaults:
                        if default and isinstance(default, (ast.List, ast.Dict, ast.Set)):
                            issues.append(Issue(
                                file=filepath, line=node.lineno, column=node.col_offset,
                                severity=Severity.ERROR, category='bug',
                                rule='B012',
                                message=f'Mutable default argument in function "{node.name}"',
                                suggestion='Use None as default and initialize inside function'
                            ))
                            break
                            
        except SyntaxError as e:
            issues.append(Issue(
                file=filepath, line=e.lineno or 1, column=e.offset or 0,
                severity=Severity.CRITICAL, category='syntax',
                rule='E001', message=f'Syntax error: {e.msg}'
            ))
        except Exception:
            pass
        
        return issues, metrics
    
    def _calculate_complexity(self, tree: ast.AST) -> float:
        """Calculate average cyclomatic complexity"""
        complexities = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexities.append(self._node_complexity(node))
        return sum(complexities) / len(complexities) if complexities else 0
    
    def _node_complexity(self, node: ast.AST) -> int:
        """Calculate cyclomatic complexity for a node"""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor,
                                  ast.ExceptHandler, ast.With, ast.AsyncWith,
                                  ast.Assert, ast.comprehension)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity
    
    def _calculate_maintainability(self, metrics: FileMetrics) -> float:
        """Calculate maintainability index (0-100)"""
        if metrics.lines_code == 0:
            return 100.0
        
        import math
        loc = metrics.lines_code
        cc = max(metrics.complexity, 1)
        
        mi = 171 - 5.2 * math.log(loc + 1) - 0.23 * cc - 16.2 * math.log(loc + 1)
        mi = max(0, min(100, mi * 100 / 171))
        
        return round(mi, 1)


class JavaScriptAnalyzer:
    """JavaScript/TypeScript static analysis"""
    
    SECURITY_PATTERNS = [
        (r'\beval\s*\(', 'S001', 'Use of eval() is dangerous', 'critical'),
        (r'innerHTML\s*=', 'S002', 'innerHTML can lead to XSS vulnerabilities', 'error'),
        (r'document\.write\s*\(', 'S003', 'document.write can lead to XSS', 'error'),
        (r'\.html\s*\([^)]+\)', 'S004', 'jQuery .html() can lead to XSS', 'warning'),
        (r'dangerouslySetInnerHTML', 'S005', 'dangerouslySetInnerHTML can lead to XSS', 'warning'),
        (r'new\s+Function\s*\(', 'S006', 'new Function() is similar to eval()', 'error'),
        (r'setTimeout\s*\(\s*["\']', 'S007', 'setTimeout with string argument is like eval()', 'error'),
        (r'setInterval\s*\(\s*["\']', 'S008', 'setInterval with string argument is like eval()', 'error'),
    ]
    
    SECRET_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']', 'SEC001', 'Hardcoded password'),
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']{8,}["\']', 'SEC002', 'Hardcoded API key'),
        (r'(?i)(secret|token)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{16,}["\']', 'SEC003', 'Hardcoded secret'),
    ]
    
    STYLE_PATTERNS = [
        (r'console\.log\s*\(', 'W001', 'console.log statement found'),
        (r'\bdebugger\s*;?', 'W002', 'debugger statement found'),
        (r'//\s*TODO', 'W003', 'TODO comment found'),
        (r'//\s*FIXME', 'W004', 'FIXME comment found'),
        (r'\bvar\s+\w+', 'W005', 'Use let or const instead of var'),
    ]
    
    BUG_PATTERNS = [
        (r'if\s*\([^)]*=[^=][^)]*\)', 'B001', 'Possible assignment in condition'),
        (r'==\s*null\b', 'B002', 'Use === for strict null comparison'),
        (r'!=\s*null\b', 'B003', 'Use !== for strict null comparison'),
        (r'\btypeof\s+\w+\s*==\s*', 'B004', 'Use === with typeof'),
    ]
    
    def analyze_file(self, filepath: str) -> Tuple[List[Issue], FileMetrics]:
        """Analyze a JavaScript/TypeScript file"""
        issues = []
        metrics = FileMetrics(filepath=filepath)
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception:
            return issues, metrics
        
        metrics.lines_total = len(lines)
        in_multiline_comment = False
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if '/*' in line:
                in_multiline_comment = True
            if '*/' in line:
                in_multiline_comment = False
                metrics.lines_comment += 1
                continue
            
            if in_multiline_comment:
                metrics.lines_comment += 1
                continue
            
            if not stripped:
                metrics.lines_blank += 1
            elif stripped.startswith('//'):
                metrics.lines_comment += 1
            else:
                metrics.lines_code += 1
            
            # Security checks
            for pattern, rule, message, severity in self.SECURITY_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    sev = {'critical': Severity.CRITICAL, 'error': Severity.ERROR,
                           'warning': Severity.WARNING}[severity]
                    issues.append(Issue(
                        file=filepath, line=i, column=0,
                        severity=sev, category='security',
                        rule=rule, message=message,
                        code_snippet=line.strip()[:100]
                    ))
            
            # Secret detection
            for pattern, rule, message in self.SECRET_PATTERNS:
                if re.search(pattern, line):
                    issues.append(Issue(
                        file=filepath, line=i, column=0,
                        severity=Severity.CRITICAL, category='secret',
                        rule=rule, message=message,
                        code_snippet='[REDACTED]'
                    ))
            
            # Style checks
            for pattern, rule, message in self.STYLE_PATTERNS:
                if re.search(pattern, line):
                    issues.append(Issue(
                        file=filepath, line=i, column=0,
                        severity=Severity.INFO, category='style',
                        rule=rule, message=message
                    ))
            
            # Bug patterns
            for pattern, rule, message in self.BUG_PATTERNS:
                if re.search(pattern, line):
                    issues.append(Issue(
                        file=filepath, line=i, column=0,
                        severity=Severity.WARNING, category='bug',
                        rule=rule, message=message
                    ))
        
        # Count functions/classes
        metrics.functions = len(re.findall(r'function\s+\w+|=>\s*[{(]|\w+\s*\([^)]*\)\s*{', content))
        metrics.classes = len(re.findall(r'class\s+\w+', content))
        
        # Simplified complexity
        decision_points = (
            content.count('if ') + content.count('else ') +
            content.count('for ') + content.count('while ') +
            content.count('case ') + content.count('catch ') +
            content.count('&&') + content.count('||') + content.count('?')
        )
        metrics.complexity = decision_points / max(metrics.functions, 1)
        metrics.maintainability = max(0, min(100, 100 - metrics.complexity * 3 - metrics.lines_code / 100))
        
        return issues, metrics


class GenericAnalyzer:
    """Generic analyzer for other languages"""
    
    SECRET_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']', 'SEC001', 'Possible hardcoded password'),
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']{8,}["\']', 'SEC002', 'Possible hardcoded API key'),
        (r'(?i)(secret|token)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{16,}["\']', 'SEC003', 'Possible hardcoded secret'),
        (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'SEC004', 'Private key in code'),
    ]
    
    GENERIC_PATTERNS = [
        (r'TODO', 'W001', 'TODO comment'),
        (r'FIXME', 'W002', 'FIXME comment'),
        (r'HACK', 'W003', 'HACK comment'),
    ]
    
    def analyze_file(self, filepath: str) -> Tuple[List[Issue], FileMetrics]:
        """Basic analysis for any file"""
        issues = []
        metrics = FileMetrics(filepath=filepath)
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            return issues, metrics
        
        metrics.lines_total = len(lines)
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                metrics.lines_blank += 1
            else:
                metrics.lines_code += 1
            
            for pattern, rule, message in self.SECRET_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(Issue(
                        file=filepath, line=i, column=0,
                        severity=Severity.CRITICAL, category='secret',
                        rule=rule, message=message,
                        code_snippet='[REDACTED]'
                    ))
            
            for pattern, rule, message in self.GENERIC_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(Issue(
                        file=filepath, line=i, column=0,
                        severity=Severity.INFO, category='style',
                        rule=rule, message=message
                    ))
        
        return issues, metrics


# =============================================================================
# External Linter Integration
# =============================================================================

class ExternalLinters:
    """Run external linting tools if available"""
    
    @staticmethod
    def check_available() -> Dict[str, bool]:
        """Check which external tools are available"""
        tools = {}
        
        for tool in ['pylint', 'flake8', 'bandit', 'mypy']:
            try:
                subprocess.run([tool, '--version'], capture_output=True, timeout=5)
                tools[tool] = True
            except:
                tools[tool] = False
        
        return tools
    
    @staticmethod
    def run_flake8(filepath: str) -> List[Issue]:
        """Run flake8"""
        issues = []
        try:
            result = subprocess.run(
                ['flake8', '--format=%(row)d:%(col)d:%(code)s:%(text)s', filepath],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split('\n'):
                if line:
                    match = re.match(r'(\d+):(\d+):(\w+):(.+)', line)
                    if match:
                        row, col, code, text = match.groups()
                        severity = Severity.ERROR if code.startswith('E') else Severity.WARNING
                        issues.append(Issue(
                            file=filepath, line=int(row), column=int(col),
                            severity=severity, category='flake8',
                            rule=code, message=text.strip()
                        ))
        except:
            pass
        return issues
    
    @staticmethod
    def run_bandit(filepath: str) -> List[Issue]:
        """Run bandit security scanner"""
        issues = []
        try:
            result = subprocess.run(
                ['bandit', '-f', 'json', '-q', filepath],
                capture_output=True, text=True, timeout=30
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for item in data.get('results', []):
                    severity_map = {'LOW': Severity.INFO, 'MEDIUM': Severity.WARNING, 'HIGH': Severity.ERROR}
                    issues.append(Issue(
                        file=filepath,
                        line=item.get('line_number', 1),
                        column=0,
                        severity=severity_map.get(item.get('issue_severity', 'MEDIUM'), Severity.WARNING),
                        category='bandit',
                        rule=item.get('test_id', 'B000'),
                        message=item.get('issue_text', ''),
                        code_snippet=item.get('code', '')[:80]
                    ))
        except:
            pass
        return issues


# =============================================================================
# AI Review Engine
# =============================================================================

class AIReviewer:
    """AI-powered code review using LLM APIs"""
    
    def __init__(self, api_key: str = None, provider: str = "openai", model: str = None):
        self.api_key = api_key
        self.provider = provider
        self.model = model or self._default_model()
    
    def _default_model(self) -> str:
        defaults = {
            "openai": "gpt-4o-mini",
            "anthropic": "claude-3-haiku-20240307",
            "ollama": "llama3"
        }
        return defaults.get(self.provider, "gpt-4o-mini")
    
    def review_code(self, code: str, language: str, filename: str) -> Tuple[str, List[str]]:
        """Get AI review of code"""
        if not self.api_key and self.provider != "ollama":
            return "API key required for AI review", []
        
        # Truncate long files
        if len(code) > 12000:
            code = code[:12000] + "\n\n... [truncated]"
        
        prompt = f"""Review this {language} code for bugs, security issues, and improvements.
Be concise and specific. Focus on the most important issues.

File: {filename}

```{language}
{code}
```

Format your response as:
SUMMARY: [1-2 sentence overview]

ISSUES:
- [Specific issue with line reference if possible]

SUGGESTIONS:
- [Actionable improvement suggestion]"""
        
        try:
            if self.provider == "anthropic":
                return self._call_anthropic(prompt)
            elif self.provider == "openai":
                return self._call_openai(prompt)
            elif self.provider == "ollama":
                return self._call_ollama(prompt)
        except Exception as e:
            return f"AI review failed: {str(e)}", []
        
        return "", []
    
    def _call_anthropic(self, prompt: str) -> Tuple[str, List[str]]:
        import urllib.request
        
        data = json.dumps({
            "model": self.model,
            "max_tokens": 1500,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()
        
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01"
            }
        )
        
        with urllib.request.urlopen(req, timeout=60) as response:
            result = json.loads(response.read())
            text = result['content'][0]['text']
            return self._parse_response(text)
    
    def _call_openai(self, prompt: str) -> Tuple[str, List[str]]:
        import urllib.request
        
        data = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1500
        }).encode()
        
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
        )
        
        with urllib.request.urlopen(req, timeout=60) as response:
            result = json.loads(response.read())
            text = result['choices'][0]['message']['content']
            return self._parse_response(text)
    
    def _call_ollama(self, prompt: str) -> Tuple[str, List[str]]:
        import urllib.request
        
        data = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }).encode()
        
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=120) as response:
            result = json.loads(response.read())
            text = result.get('response', '')
            return self._parse_response(text)
    
    def _parse_response(self, text: str) -> Tuple[str, List[str]]:
        """Parse AI response"""
        summary = text
        suggestions = []
        
        if "SUMMARY:" in text:
            parts = text.split("SUMMARY:", 1)
            if len(parts) > 1:
                summary_end = text.find("ISSUES:") if "ISSUES:" in text else len(text)
                summary = text[text.find("SUMMARY:")+8:summary_end].strip()
        
        if "SUGGESTIONS:" in text:
            sugg_text = text[text.find("SUGGESTIONS:")+12:].strip()
            for line in sugg_text.split('\n'):
                line = line.strip()
                if line.startswith('- '):
                    suggestions.append(line[2:])
                elif line and not any(line.startswith(x) for x in ['SUMMARY', 'ISSUES']):
                    suggestions.append(line)
        
        return summary[:500] if len(summary) > 500 else summary, suggestions[:10]


# =============================================================================
# Report Generator
# =============================================================================

class ReportGenerator:
    """Generate review reports"""
    
    @staticmethod
    def generate_markdown(result: ReviewResult) -> str:
        """Generate markdown report"""
        lines = [
            "# Code Review Report",
            "",
            f"**Project:** `{result.project_path}`",
            f"**Date:** {result.timestamp}",
            f"**Files Analyzed:** {result.files_analyzed}",
            f"**Total Lines:** {result.total_lines:,}",
            "",
            "---",
            "",
            "## Summary",
            "",
        ]
        
        # Issue counts table
        counts = result.issue_counts
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ['critical', 'error', 'warning', 'info']:
            emoji = {'critical': '🔴', 'error': '🟠', 'warning': '🟡', 'info': '🔵'}.get(sev, '')
            lines.append(f"| {emoji} {sev.title()} | {counts.get(sev, 0)} |")
        lines.append("")
        
        # Category breakdown
        cat_counts = result.category_counts
        if cat_counts:
            lines.append("### By Category")
            lines.append("")
            for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
                lines.append(f"- **{cat}**: {count}")
            lines.append("")
        
        # AI Summary
        if result.ai_summary:
            lines.append("## AI Review")
            lines.append("")
            lines.append(result.ai_summary)
            lines.append("")
            
            if result.ai_suggestions:
                lines.append("### Suggestions")
                for sugg in result.ai_suggestions:
                    lines.append(f"- {sugg}")
                lines.append("")
        
        # Critical and Error issues
        critical_issues = [i for i in result.issues if i.severity in (Severity.CRITICAL, Severity.ERROR)]
        if critical_issues:
            lines.append("## Critical & Error Issues")
            lines.append("")
            
            for issue in critical_issues[:30]:
                lines.append(f"### `{os.path.basename(issue.file)}` line {issue.line}")
                lines.append(f"**[{issue.severity.value.upper()}]** {issue.rule}: {issue.message}")
                if issue.code_snippet and issue.code_snippet != '[REDACTED]':
                    lines.append(f"```\n{issue.code_snippet}\n```")
                if issue.suggestion:
                    lines.append(f"> 💡 {issue.suggestion}")
                lines.append("")
        
        # Warning summary
        warnings = [i for i in result.issues if i.severity == Severity.WARNING]
        if warnings:
            lines.append("## Warnings")
            lines.append("")
            lines.append(f"Found {len(warnings)} warnings:")
            lines.append("")
            for issue in warnings[:20]:
                lines.append(f"- **{os.path.basename(issue.file)}:{issue.line}** - {issue.message}")
            if len(warnings) > 20:
                lines.append(f"- ... and {len(warnings) - 20} more")
            lines.append("")
        
        # Metrics
        if result.metrics:
            lines.append("## Code Metrics")
            lines.append("")
            lines.append("| File | Lines | Complexity | Maintainability |")
            lines.append("|------|-------|------------|-----------------|")
            
            sorted_metrics = sorted(result.metrics, key=lambda x: -x.complexity)[:15]
            for m in sorted_metrics:
                name = os.path.basename(m.filepath)[:30]
                lines.append(f"| {name} | {m.lines_code} | {m.complexity:.1f} | {m.maintainability:.0f}% |")
            lines.append("")
        
        lines.append("---")
        lines.append("*Generated by Code Reviewer - AI Toolkit*")
        
        return '\n'.join(lines)
    
    @staticmethod
    def generate_html(result: ReviewResult) -> str:
        """Generate HTML report"""
        md = ReportGenerator.generate_markdown(result)
        
        # Convert markdown to HTML
        html = md
        html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
        html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
        html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)
        html = re.sub(r'^- (.+)$', r'<li>\1</li>', html, flags=re.MULTILINE)
        html = re.sub(r'^> (.+)$', r'<blockquote>\1</blockquote>', html, flags=re.MULTILINE)
        html = re.sub(r'```\n?([^`]+)```', r'<pre>\1</pre>', html, flags=re.DOTALL)
        html = re.sub(r'^---$', r'<hr>', html, flags=re.MULTILINE)
        html = html.replace('\n\n', '</p><p>')
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Code Review Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
               max-width: 900px; margin: 40px auto; padding: 20px; line-height: 1.6; color: #333; }}
        h1 {{ color: #1a1a1a; border-bottom: 3px solid #007acc; padding-bottom: 10px; }}
        h2 {{ color: #2c2c2c; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }}
        h3 {{ color: #444; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #f5f5f5; font-weight: 600; }}
        tr:nth-child(even) {{ background: #fafafa; }}
        pre {{ background: #f4f4f4; padding: 15px; overflow-x: auto; border-radius: 5px; border-left: 4px solid #007acc; }}
        code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
        blockquote {{ border-left: 4px solid #4caf50; margin: 10px 0; padding: 10px 15px; background: #f9fff9; }}
        li {{ margin: 5px 0; }}
        hr {{ border: none; border-top: 1px solid #ddd; margin: 30px 0; }}
    </style>
</head>
<body>
<p>{html}</p>
</body>
</html>"""
    
    @staticmethod
    def generate_json(result: ReviewResult) -> str:
        """Generate JSON report"""
        def serialize(obj):
            if isinstance(obj, Severity):
                return obj.value
            return str(obj)
        
        return json.dumps(asdict(result), indent=2, default=serialize)


# =============================================================================
# Main Code Reviewer
# =============================================================================

class CodeReviewer:
    """Main code review orchestrator"""
    
    def __init__(self):
        self.python_analyzer = PythonAnalyzer()
        self.js_analyzer = JavaScriptAnalyzer()
        self.generic_analyzer = GenericAnalyzer()
        self.ai_reviewer = None
    
    def set_ai_config(self, api_key: str, provider: str, model: str = None):
        """Configure AI reviewer"""
        self.ai_reviewer = AIReviewer(api_key, provider, model)
    
    def review_file(self, filepath: str, use_ai: bool = False, 
                    use_external: bool = False) -> Tuple[List[Issue], FileMetrics, str, List[str]]:
        """Review a single file"""
        ext = os.path.splitext(filepath)[1].lower()
        language = SUPPORTED_LANGUAGES.get(ext, 'generic')
        
        # Select analyzer
        if language == 'python':
            issues, metrics = self.python_analyzer.analyze_file(filepath)
            if use_external:
                issues.extend(ExternalLinters.run_flake8(filepath))
                issues.extend(ExternalLinters.run_bandit(filepath))
        elif language in ('javascript', 'typescript'):
            issues, metrics = self.js_analyzer.analyze_file(filepath)
        else:
            issues, metrics = self.generic_analyzer.analyze_file(filepath)
        
        # AI review
        ai_summary = ""
        ai_suggestions = []
        
        if use_ai and self.ai_reviewer:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                ai_summary, ai_suggestions = self.ai_reviewer.review_code(code, language, filepath)
            except Exception as e:
                ai_summary = f"AI review error: {e}"
        
        return issues, metrics, ai_summary, ai_suggestions
    
    def review_project(self, project_path: str, use_external: bool = False,
                       use_ai: bool = False, callback=None) -> ReviewResult:
        """Review entire project"""
        result = ReviewResult(
            project_path=project_path,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            files_analyzed=0,
            total_lines=0
        )
        
        # Collect files
        files_to_analyze = []
        
        if os.path.isfile(project_path):
            files_to_analyze = [project_path]
        else:
            for root, dirs, files in os.walk(project_path):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
                
                for filename in files:
                    if filename in IGNORE_FILES:
                        continue
                    
                    ext = os.path.splitext(filename)[1].lower()
                    if ext in SUPPORTED_LANGUAGES:
                        files_to_analyze.append(os.path.join(root, filename))
        
        # Analyze files
        ai_done = False
        for i, filepath in enumerate(files_to_analyze):
            if callback:
                callback(f"[{i+1}/{len(files_to_analyze)}] {os.path.basename(filepath)}")
            
            try:
                # Only do AI review on first file (for speed)
                do_ai = use_ai and not ai_done
                
                issues, metrics, ai_summary, ai_suggestions = self.review_file(
                    filepath, use_ai=do_ai, use_external=use_external
                )
                
                result.issues.extend(issues)
                result.metrics.append(metrics)
                result.total_lines += metrics.lines_total
                result.files_analyzed += 1
                
                if ai_summary and not ai_done:
                    result.ai_summary = ai_summary
                    result.ai_suggestions = ai_suggestions
                    ai_done = True
                
            except Exception as e:
                if callback:
                    callback(f"  Error: {e}")
        
        return result


# =============================================================================
# GUI Application
# =============================================================================

class CodeReviewerApp:
    """Main application window"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Code Reviewer - Static Analysis & AI Review")
        self.root.geometry("1150x800")
        
        self.reviewer = CodeReviewer()
        self.current_result: Optional[ReviewResult] = None
        self.log_queue = queue.Queue()
        self.running = False
        
        self._build_ui()
        self._process_log_queue()
        self._load_config()
    
    def _build_ui(self):
        """Build the user interface"""
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # ========== Review Tab ==========
        review_tab = ttk.Frame(notebook, padding=10)
        notebook.add(review_tab, text="Review")
        
        # Project selection
        input_frame = ttk.LabelFrame(review_tab, text="Target", padding=10)
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        path_row = ttk.Frame(input_frame)
        path_row.pack(fill=tk.X)
        
        ttk.Label(path_row, text="Path:").pack(side=tk.LEFT)
        self.path_var = tk.StringVar()
        ttk.Entry(path_row, textvariable=self.path_var, width=70).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(path_row, text="📂 Folder", command=self._browse_folder).pack(side=tk.LEFT, padx=2)
        ttk.Button(path_row, text="📄 File", command=self._browse_file).pack(side=tk.LEFT, padx=2)
        
        # Options row
        options_frame = ttk.Frame(review_tab)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.use_external_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Use external linters (flake8, bandit)",
                       variable=self.use_external_var).pack(side=tk.LEFT, padx=(0, 20))
        
        self.use_ai_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Enable AI review",
                       variable=self.use_ai_var).pack(side=tk.LEFT, padx=(0, 20))
        
        self.run_btn = ttk.Button(options_frame, text="🔍 Run Review", command=self._start_review)
        self.run_btn.pack(side=tk.LEFT)
        
        ttk.Button(options_frame, text="📊 Export", command=self._export_report).pack(side=tk.LEFT, padx=10)
        
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(options_frame, variable=self.progress_var, maximum=100, length=150).pack(side=tk.LEFT, padx=10)
        
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(options_frame, textvariable=self.status_var, foreground="gray").pack(side=tk.LEFT, padx=10)
        
        # Results paned window
        results_paned = ttk.PanedWindow(review_tab, orient=tk.HORIZONTAL)
        results_paned.pack(fill=tk.BOTH, expand=True)
        
        # Left: Issue tree
        tree_frame = ttk.LabelFrame(results_paned, text="Issues", padding=5)
        results_paned.add(tree_frame, weight=2)
        
        # Filter
        filter_frame = ttk.Frame(tree_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar(value="all")
        for sev in ["all", "critical", "error", "warning", "info"]:
            ttk.Radiobutton(filter_frame, text=sev.title(), value=sev,
                           variable=self.filter_var, command=self._filter_issues).pack(side=tk.LEFT, padx=3)
        
        # Tree
        columns = ('file', 'line', 'severity', 'category', 'message')
        self.issue_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=20)
        
        self.issue_tree.heading('file', text='File')
        self.issue_tree.heading('line', text='Line')
        self.issue_tree.heading('severity', text='Severity')
        self.issue_tree.heading('category', text='Category')
        self.issue_tree.heading('message', text='Message')
        
        self.issue_tree.column('file', width=140)
        self.issue_tree.column('line', width=45)
        self.issue_tree.column('severity', width=70)
        self.issue_tree.column('category', width=70)
        self.issue_tree.column('message', width=350)
        
        tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.issue_tree.yview)
        self.issue_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.issue_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.issue_tree.bind('<<TreeviewSelect>>', self._on_issue_select)
        
        # Right: Details
        details_frame = ttk.LabelFrame(results_paned, text="Details", padding=5)
        results_paned.add(details_frame, weight=1)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, height=25)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Summary
        summary_frame = ttk.LabelFrame(review_tab, text="Summary", padding=5)
        summary_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.summary_text = tk.Text(summary_frame, height=4, wrap=tk.WORD)
        self.summary_text.pack(fill=tk.X)
        
        # ========== Settings Tab ==========
        settings_tab = ttk.Frame(notebook, padding=10)
        notebook.add(settings_tab, text="Settings")
        
        # AI Settings
        ai_frame = ttk.LabelFrame(settings_tab, text="AI Review Settings", padding=10)
        ai_frame.pack(fill=tk.X, pady=(0, 10))
        
        provider_row = ttk.Frame(ai_frame)
        provider_row.pack(fill=tk.X, pady=5)
        ttk.Label(provider_row, text="Provider:", width=12).pack(side=tk.LEFT)
        self.provider_var = tk.StringVar(value="openai")
        ttk.Combobox(provider_row, textvariable=self.provider_var,
                     values=["openai", "anthropic", "ollama"], state="readonly", width=15).pack(side=tk.LEFT)
        
        model_row = ttk.Frame(ai_frame)
        model_row.pack(fill=tk.X, pady=5)
        ttk.Label(model_row, text="Model:", width=12).pack(side=tk.LEFT)
        self.model_var = tk.StringVar()
        ttk.Entry(model_row, textvariable=self.model_var, width=30).pack(side=tk.LEFT)
        ttk.Label(model_row, text="(blank = default)", foreground="gray").pack(side=tk.LEFT, padx=5)
        
        key_row = ttk.Frame(ai_frame)
        key_row.pack(fill=tk.X, pady=5)
        ttk.Label(key_row, text="API Key:", width=12).pack(side=tk.LEFT)
        self.api_key_var = tk.StringVar()
        ttk.Entry(key_row, textvariable=self.api_key_var, width=50, show="*").pack(side=tk.LEFT)
        
        ttk.Label(ai_frame, text="For Ollama: leave API key empty, ensure Ollama is running locally",
                  foreground="gray").pack(anchor=tk.W, pady=(5, 0))
        
        ttk.Button(ai_frame, text="💾 Save Settings", command=self._save_config).pack(anchor=tk.W, pady=(10, 0))
        
        # Tools status
        tools_frame = ttk.LabelFrame(settings_tab, text="External Tools", padding=10)
        tools_frame.pack(fill=tk.X, pady=(0, 10))
        
        tools = ExternalLinters.check_available()
        tools_text = []
        for tool, available in tools.items():
            status = "✓" if available else "○"
            tools_text.append(f"{status} {tool}")
        
        ttk.Label(tools_frame, text="  |  ".join(tools_text)).pack(anchor=tk.W)
        ttk.Label(tools_frame, text="Install with: pip install pylint flake8 bandit mypy",
                  foreground="gray").pack(anchor=tk.W)
        
        # ========== Log Tab ==========
        log_tab = ttk.Frame(notebook, padding=10)
        notebook.add(log_tab, text="Log")
        
        self.log_text = scrolledtext.ScrolledText(log_tab, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    def _browse_folder(self):
        path = filedialog.askdirectory(title="Select Project Folder")
        if path:
            self.path_var.set(path)
    
    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Select File",
            filetypes=[
                ("Code files", "*.py *.js *.ts *.jsx *.tsx *.java *.go *.rb *.php *.c *.cpp"),
                ("All files", "*.*")
            ]
        )
        if path:
            self.path_var.set(path)
    
    def _start_review(self):
        path = self.path_var.get()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Invalid Path", "Please select a valid file or folder")
            return
        
        if self.running:
            return
        
        self.running = True
        self.run_btn.config(state=tk.DISABLED)
        self.issue_tree.delete(*self.issue_tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.summary_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        
        # Configure AI
        if self.use_ai_var.get():
            self.reviewer.set_ai_config(
                self.api_key_var.get(),
                self.provider_var.get(),
                self.model_var.get() or None
            )
        
        thread = threading.Thread(target=self._review_thread, args=(path,))
        thread.daemon = True
        thread.start()
    
    def _review_thread(self, path: str):
        try:
            self._log(f"Starting review: {path}")
            self.status_var.set("Analyzing...")
            
            self.current_result = self.reviewer.review_project(
                path,
                use_external=self.use_external_var.get(),
                use_ai=self.use_ai_var.get(),
                callback=self._log
            )
            
            self.root.after(0, self._display_results)
            
            self._log(f"\n✓ Review complete: {len(self.current_result.issues)} issues found")
            self.status_var.set(f"Complete: {len(self.current_result.issues)} issues")
            self.progress_var.set(100)
            
        except Exception as e:
            self._log(f"Error: {e}")
            self.status_var.set(f"Error: {e}")
        finally:
            self.running = False
            self.root.after(0, lambda: self.run_btn.config(state=tk.NORMAL))
    
    def _display_results(self):
        if not self.current_result:
            return
        
        result = self.current_result
        
        # Populate tree
        self.issue_tree.delete(*self.issue_tree.get_children())
        
        for issue in result.issues:
            self.issue_tree.insert('', tk.END, values=(
                os.path.basename(issue.file),
                issue.line,
                issue.severity.value,
                issue.category,
                issue.message[:80]
            ), tags=(issue.severity.value,))
        
        # Color tags
        self.issue_tree.tag_configure('critical', foreground='#c62828')
        self.issue_tree.tag_configure('error', foreground='#e65100')
        self.issue_tree.tag_configure('warning', foreground='#f9a825')
        self.issue_tree.tag_configure('info', foreground='#1565c0')
        
        # Summary
        counts = result.issue_counts
        summary = f"Files: {result.files_analyzed}  |  Lines: {result.total_lines:,}  |  "
        summary += f"🔴 Critical: {counts.get('critical', 0)}  |  🟠 Error: {counts.get('error', 0)}  |  "
        summary += f"🟡 Warning: {counts.get('warning', 0)}  |  🔵 Info: {counts.get('info', 0)}"
        
        if result.ai_summary:
            summary += f"\n\nAI: {result.ai_summary[:200]}..."
        
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(tk.END, summary)
    
    def _filter_issues(self):
        if not self.current_result:
            return
        
        filter_val = self.filter_var.get()
        self.issue_tree.delete(*self.issue_tree.get_children())
        
        for issue in self.current_result.issues:
            if filter_val == 'all' or issue.severity.value == filter_val:
                self.issue_tree.insert('', tk.END, values=(
                    os.path.basename(issue.file),
                    issue.line,
                    issue.severity.value,
                    issue.category,
                    issue.message[:80]
                ), tags=(issue.severity.value,))
    
    def _on_issue_select(self, event):
        selection = self.issue_tree.selection()
        if not selection or not self.current_result:
            return
        
        item = self.issue_tree.item(selection[0])
        values = item['values']
        
        for issue in self.current_result.issues:
            if (os.path.basename(issue.file) == values[0] and
                issue.line == values[1] and
                issue.severity.value == values[2]):
                
                details = f"""File: {issue.file}
Line: {issue.line}, Column: {issue.column}
Severity: {issue.severity.value.upper()}
Category: {issue.category}
Rule: {issue.rule}

{issue.message}"""
                
                if issue.suggestion:
                    details += f"\n\n💡 Suggestion:\n{issue.suggestion}"
                
                if issue.code_snippet and issue.code_snippet != '[REDACTED]':
                    details += f"\n\nCode:\n{issue.code_snippet}"
                
                self.details_text.delete(1.0, tk.END)
                self.details_text.insert(tk.END, details)
                break
    
    def _export_report(self):
        if not self.current_result:
            messagebox.showwarning("No Results", "Run a review first")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("HTML", "*.html"), ("JSON", "*.json")],
            title="Export Report"
        )
        
        if not filepath:
            return
        
        try:
            if filepath.endswith('.html'):
                content = ReportGenerator.generate_html(self.current_result)
            elif filepath.endswith('.json'):
                content = ReportGenerator.generate_json(self.current_result)
            else:
                content = ReportGenerator.generate_markdown(self.current_result)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self._log(f"Exported: {filepath}")
            messagebox.showinfo("Exported", f"Report saved to:\n{filepath}")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _save_config(self):
        config = {
            'provider': self.provider_var.get(),
            'model': self.model_var.get(),
            'api_key': self.api_key_var.get()
        }
        
        # Folder-agnostic config path
        if '__file__' in globals():
            config_dir = os.path.dirname(os.path.abspath(__file__))
        else:
            config_dir = os.getcwd()
        config_path = os.path.join(config_dir, 'config.json')
        
        try:
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            messagebox.showinfo("Saved", f"Settings saved to {config_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config: {e}")
    
    def _load_config(self):
        # Folder-agnostic config path
        if '__file__' in globals():
            config_dir = os.path.dirname(os.path.abspath(__file__))
        else:
            config_dir = os.getcwd()
        config_path = os.path.join(config_dir, 'config.json')
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                self.provider_var.set(config.get('provider', 'openai'))
                self.model_var.set(config.get('model', ''))
                self.api_key_var.set(config.get('api_key', ''))
            except:
                pass
    
    def _log(self, message: str):
        self.log_queue.put(message)
    
    def _process_log_queue(self):
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, f"{message}\n")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        
        self.root.after(100, self._process_log_queue)


# =============================================================================
# Main
# =============================================================================

def main():
    root = tk.Tk()
    app = CodeReviewerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()