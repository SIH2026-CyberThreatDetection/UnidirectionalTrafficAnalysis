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
    print("===================================================")
    print("   UNIFIED M2 FEATURE PIPELINE (STRICT PARITY)     ")
    print("===================================================")
    
    # NO AUTO-DETECT VIRUS.
    # The pipeline strictly enforces that all data goes through the 
    # exact same mathematical extraction, merging, and scaling.
    
    scripts_in_order = [
        "src/02_feature_dataset/clean.py",              # 1. Enforce data types and SIH constraints
        "src/02_feature_dataset/flow_features.py",      # 2. Ratios & Rates
        "src/02_feature_dataset/dns_features.py",       # 3. DNS Entropy
        "src/02_feature_dataset/tls_features.py",       # 4. SNI Entropy & Deprecated Crypto
        "src/02_feature_dataset/merge_datasets.py",     # 5. Inject synthetic attacks BEFORE scaling
        "src/02_feature_dataset/split.py",              # 6. Time-Aware Split & Scaler Fit
        "src/02_feature_dataset/generate_reports.py"    # 7. Auto-generate Markdown for judges
    ]
    
    for script in scripts_in_order:
        success = run_script(script)
        if not success:
            sys.exit(1)
            
    logging.info("M2 Phase Complete: Data successfully standardized, engineered, merged, and scaled.")
