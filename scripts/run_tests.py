"""Automated Test Runner."""
import subprocess
import sys

def main():
    print("Running Phishing Detection Test Suite...")
    res = subprocess.run([sys.executable, "-m", "pytest", "backend/tests/", "-v"])
    sys.exit(res.returncode)

if __name__ == "__main__":
    main()
