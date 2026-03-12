import subprocess
import sys
import os

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else input("Enter target URL (use FUZZ for injection point): ")
    vapex_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vapex.py")
    
    print(f"[*] Starting SQL Injection Deep Dive against: {target}")
    subprocess.run([sys.executable, vapex_path, "--category", "SQL Injection", "--target", target])

if __name__ == "__main__":
    main()
