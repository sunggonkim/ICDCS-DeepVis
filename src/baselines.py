
from sklearn.ensemble import IsolationForest
import numpy as np
import pandas as pd
from typing import List, Dict
from data_gen import FileEntry

class BaselineIsolationForest:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05, random_state=42)
        
    def _to_vector(self, files: List[FileEntry]) -> np.ndarray:
        # Flatten file list into a single feature vector? 
        # No, Isolation Forest usually works on 'points'. 
        # But here we are classifying the *system state* (snapshot) as anomalous or not.
        # Naive approach: Aggregate statistics (Mean size, Max entropy, etc.)
        # This represents "Statistical Anomaly Detection".
        
        sizes = [f.size for f in files]
        ents = [f.entropy for f in files]
        perms = [f.permissions for f in files]
        
        features = [
            np.mean(sizes), np.std(sizes), np.max(sizes),
            np.mean(ents), np.std(ents), np.max(ents),
            len(files)
        ]
        return np.array(features).reshape(1, -1)
        
    def train(self, normal_snapshots: List[List[FileEntry]]):
        X = np.vstack([self._to_vector(s) for s in normal_snapshots])
        self.model.fit(X)
        
    def predict(self, snapshot: List[FileEntry]) -> int:
        # Returns -1 for anomaly, 1 for normal
        vec = self._to_vector(snapshot)
        return self.model.predict(vec)[0]

class BaselineAIDE:
    """
    Simulates AIDE (Advanced Intrusion Detection Environment).
    Logic: Snapshot baseline. Any change = Alert.
    """
    def __init__(self):
        self.baseline_hashes = set()
        
    def train(self, baseline_snapshot: List[FileEntry]):
        # AIDE memorizes the initial state
        self.baseline_hashes = { (f.filename, f.mtime, f.size, f.permissions) for f in baseline_snapshot }
        
    def predict_files(self, snapshot: List[FileEntry]) -> List[str]:
        # Returns list of changed filenames
        current_hashes = { (f.filename, f.mtime, f.size, f.permissions) for f in snapshot }
        # Changes = what is in current that wasn't in baseline
        # (Simplified: AIDE checks for any deviation)
        diff = current_hashes - self.baseline_hashes
        return [x[0] for x in diff]
