# Imports/Defs to clean up program
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Clears screen
def clear():
    subprocess.run("clear", shell=True, check=False)

# Run .py file/run install .sh file
def run(file):
    path = os.path.join(ROOT, file)
    if file.endswith(".py"):
        subprocess.run([sys.executable, path], check=False)
    else:
        subprocess.run(["sh", path], check=False)

# Run .sh file with arg
def run_script(script_path, *args):
    subprocess.run(["sh", os.path.join(ROOT, script_path)] + [a for a in args if a], check=False)
