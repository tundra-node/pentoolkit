#!/usr/bin/env python3
import os
import platform
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

def run_file(file_path):
    try:
        subprocess.run([sys.executable, file_path], check=False)
    except Exception as e:  # noqa: BLE001
        print(f"Error running the file: {e}")

def main():
    os_paths = {
        "Windows": os.path.join("windows", "main.py"),
        "Linux": os.path.join("linux", "main.py"),
        "Darwin": os.path.join("mac", "main.py")
    }

    current_os = platform.system()
    file_to_run = os_paths.get(current_os)
    full_path = os.path.join(HERE, file_to_run) if file_to_run else None

    if full_path and os.path.exists(full_path):
        print(f"Running {file_to_run} on {current_os}")
        run_file(full_path)
    else:
        print(f"Unsupported OS or file does not exist: {current_os}")

if __name__ == "__main__":
    main()
