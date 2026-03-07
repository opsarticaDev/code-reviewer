#!/usr/bin/env python3
"""Installation validator for CodeReviewer"""

import sys
from pathlib import Path


def validate():
    issues = []

    if sys.version_info < (3, 10):
        issues.append(f"Python 3.10+ required, you have {sys.version_info.major}.{sys.version_info.minor}")
    else:
        print(f"  [OK] Python {sys.version_info.major}.{sys.version_info.minor}")

    # Core packages (built-in, always available)
    for mod in ['ast', 'json', 're', 'hashlib', 'tkinter']:
        try:
            __import__(mod)
            print(f"  [OK] {mod}")
        except ImportError:
            issues.append(f"Missing: {mod}")

    # Optional AI packages
    for pkg, name in [('openai', 'openai'), ('anthropic', 'anthropic')]:
        try:
            __import__(pkg)
            print(f"  [OK] {name} (AI review available)")
        except ImportError:
            print(f"  [--] {name} (optional - AI review disabled)")

    # Directory structure
    base = Path(__file__).parent.parent
    for directory in ['inputs', 'outputs']:
        dir_path = base / directory
        if dir_path.exists():
            print(f"  [OK] {directory}/ directory")
        else:
            dir_path.mkdir(exist_ok=True)
            print(f"  [OK] Created {directory}/ directory")

    print()
    if issues:
        print("VALIDATION FAILED:")
        for issue in issues:
            print(f"   - {issue}")
        return 1
    else:
        print("All checks passed - ready to use!")
        return 0


if __name__ == "__main__":
    sys.exit(validate())
