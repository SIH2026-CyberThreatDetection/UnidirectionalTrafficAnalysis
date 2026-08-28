import subprocess
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def run_script(script_path):
    """Runs a Python script and outputs its logs to the terminal."""
    logging.info(f"========== Executing {script_path} ==========")
    result = subprocess.run([sys.executable, script_path], capture_output=True, text=True)
    
    # Print the standard output and standard error so you can see exactly what the scripts are doing
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip())
        
    if result.returncode != 0:
        logging.error(f"CRITICAL: Pipeline FAILED at {script_path}")
        return False
        
    return True

if __name__ == "__main__":
    logging.info("Starting Environment-Aware Feature Pipeline...")
    
    raw_dir = Path("data/raw")
    
    # Auto-Detect Logic: Check if we are processing CSVs (Training) or JSONL (Live Finals)
    if list(raw_dir.glob("*.csv")):
        logging.info("MODE DETECTED: AI Training (Historical CSV Data)")
        logging.info("Bypassing DNS/TLS extraction because CSVs already contain pre-engineered numeric features.")
        scripts_in_order = [
            "src/02_feature_dataset/clean.py",
            "src/02_feature_dataset/split.py"
        ]
    else:
        logging.info("MODE DETECTED: Live Hackathon Finals (Zeek/Suricata Telemetry)")
        logging.info("Running full Flow, DNS, and TLS threat detection extraction.")
        scripts_in_order = [
            "src/02_feature_dataset/clean.py",
            "src/02_feature_dataset/flow_features.py",
            "src/02_feature_dataset/dns_features.py",
            "src/02_feature_dataset/tls_features.py",
            "src/02_feature_dataset/split.py"
        ]
    
    for script in scripts_in_order:
        success = run_script(script)
        if not success:
            sys.exit(1)
            
    logging.info("Phase 5 Complete: Pipeline executed successfully from start to finish.")

