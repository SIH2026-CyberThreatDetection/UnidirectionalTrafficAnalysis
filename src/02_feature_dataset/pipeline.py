import subprocess
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def run_script(script_path):
    """Runs a Python script and halts the pipeline if it fails."""
    logging.info(f"========== Executing {script_path} ==========")
    
    # Use sys.executable to ensure it uses your current virtual environment
    result = subprocess.run([sys.executable, script_path], capture_output=True, text=True)
    
    # Print the output of the script to the terminal
    if result.stdout:
        print(result.stdout.strip())
        
    # If the script crashed, print the error and stop the pipeline
    if result.returncode != 0:
        logging.error(f"Pipeline FAILED at {script_path}")
        if result.stderr:
            print(result.stderr.strip())
        return False
        
    return True

if __name__ == "__main__":
    logging.info("Starting M2 Feature Engineering Pipeline...")
    
    # The exact chronological order required for M2
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
            sys.exit(1) # Stop immediately if a step fails
            
    logging.info("Phase 5 Complete: M2 Pipeline executed successfully from start to finish.")
