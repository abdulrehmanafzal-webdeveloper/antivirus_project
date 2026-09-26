# core/signatures.py
import json
from config import SIGNATURE_FILE

KNOWN_SIGNATURES = {
    "44d88612fea8a8f36de82e1278abb02f":  "EICAR Test Virus",
}

def load_signatures():
    """Load signatures from JSON file if available."""
    global KNOWN_SIGNATURES
    try: 
        with open(SIGNATURE_FILE, "r") as f:
            loaded_signatures = json.load(f)
            KNOWN_SIGNATURES.update(loaded_signatures)  # Merge with defaults
            print(f"[INFO] Loaded {len(loaded_signatures)} signatures from {SIGNATURE_FILE}")
    except FileNotFoundError: 
        print("[INFO] No external signature file found.  Using default signatures.")
    except Exception as e:
        print(f"[ERROR] Unable to load signatures: {e}")