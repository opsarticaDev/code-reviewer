#!/bin/bash

echo "============================================"
echo " CodeReviewer by OpsArtica"
echo "============================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found!"
    echo ""
    echo "Install Python 3.10+:"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "  brew install python@3.12"
    else
        echo "  sudo apt install python3.12"
    fi
    exit 1
fi

# First run setup
if [ ! -f "code/.installed" ]; then
    echo "[First Time Setup]"
    echo "Installing dependencies..."
    echo ""

    python3 -m pip install --upgrade pip --quiet
    python3 -m pip install -r requirements.txt --quiet

    if [ $? -ne 0 ]; then
        echo ""
        echo "ERROR: Dependency installation failed."
        echo "Try: python3 -m pip install -r requirements.txt"
        exit 1
    fi

    touch code/.installed
    echo "Setup complete!"
    echo ""
fi

mkdir -p inputs outputs

echo "Validating setup..."
python3 code/validate_install.py
if [ $? -ne 0 ]; then
    echo ""
    echo "Setup validation failed."
    exit 1
fi

echo ""
echo "Starting CodeReviewer..."
echo ""

python3 code/codereviewer.py

chmod +x "$0"
