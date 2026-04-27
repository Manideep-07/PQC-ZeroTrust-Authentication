import csv
import os
import time
from typing import Dict, Any

class LatencyLogger:
    def __init__(self, filename="handshake_metrics.csv"):
        self.filename = filename
        self.fieldnames = [
            "timestamp",
            "client_id",
            "kyber_keygen_time",
            "kyber_encap_time",
            "kyber_decap_time",
            "dilithium_sign_time",
            "dilithium_verify_time",
            "aes_encryption_time",
            "total_handshake_time"
        ]
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        file_exists = os.path.isfile(self.filename)
        if not file_exists:
            with open(self.filename, mode='w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                writer.writeheader()

    def log_metrics(self, metrics: Dict[str, Any]):
        """
        Metrics should include keys matching self.fieldnames.
        """
        metrics["timestamp"] = time.time()
        
        # Ensure all fields are present, fill with N/A if missing
        row = {field: metrics.get(field, "N/A") for field in self.fieldnames}
        
        with open(self.filename, mode='a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.fieldnames)
            writer.writerow(row)

# Decorator or context manager could also be implemented here,
# but we will just manual measure using time.time() in the logic.
