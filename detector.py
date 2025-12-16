
import os
import datetime
import numpy as np
from collections import deque
from sklearn.ensemble import IsolationForest
import time


class AdvancedAnomalyDetector:
    def __init__(
        self,
        threshold=10,
        time_window=60,
        train_interval=30,
        max_samples=1000,
        response_engine=None
    ):
        self.threshold = threshold
        self.time_window = time_window
        self.event_queue = deque()
        self.samples = deque(maxlen=max_samples)
        self.train_interval = train_interval
        self.last_trained = datetime.datetime.now()
        self.model = None
        self.response_engine = response_engine

    def _train_model(self):
        if len(self.samples) < self.threshold * 2:
            return

        feature_matrix = np.array(self.samples)
        self.model = IsolationForest(
            contamination=float(self.threshold) / len(self.samples),
            random_state=42
        )
        self.model.fit(feature_matrix)

    def add_event(self, feature_vector, path=None):
        current_time = datetime.datetime.now()

        # store event with path
        self.event_queue.append((current_time, feature_vector, path))
        self.samples.append(feature_vector)

        # remove old events outside the time window
        while self.event_queue and \
              (current_time - self.event_queue[0][0]).seconds > self.time_window:
            self.event_queue.popleft()

        # retrain periodically
        if (current_time - self.last_trained).seconds > self.train_interval:
            self._train_model()
            self.last_trained = current_time

        # anomaly detection
        is_ml_anomaly = False
        if self.model is not None:
            prediction = self.model.predict([feature_vector])
            if prediction[0] == -1:
                print("🚨 ML Anomaly detected: unusual event pattern!")
                is_ml_anomaly = True

        # burst-based detection
        is_burst = len(self.event_queue) >= self.threshold

        if is_ml_anomaly or is_burst:
            self._handle_threat(path, len(self.event_queue))

    # def _handle_threat(self, path, event_count):
    #     """
    #     Trigger prevention based on severity.
    #     """
    #     if not self.response_engine or not path:
    #         return

    #     # 🟡 MEDIUM THREAT
    #     if event_count >= self.threshold:
    #         print("[THREAT LEVEL] MEDIUM")
    #         self.response_engine.lock_file(path)

    #     # 🔴 HIGH THREAT
    #     if event_count >= self.threshold * 2:
    #         print("[THREAT LEVEL] HIGH")
    #         self.response_engine.quarantine_file(path)
    #         # clear queue after high threat to avoid repeated triggers
    #         self.event_queue.clear()
    # detector.py

    # detector.py
    def _handle_threat(self, path, event_count):
        print(f"[DEBUG] Using AdvancedAnomalyDetector from: {__file__}")

        if not self.response_engine or not path:
            print("[WARN] Threat detected but no response engine attached")
            return
    
        # Gather all recent file paths in the event queue (within window)
        affected_files = set(p for _, _, p in self.event_queue if p)
    
        # 🟡 MEDIUM THREAT: Lock all affected files
        if event_count >= self.threshold:
            print(f"[THREAT] MEDIUM – locking {len(affected_files)} files")
            for f in affected_files:
                self.response_engine.lock_file(f)
    
        # 🔴 HIGH THREAT: Quarantine all files and lock directory
        if event_count >= self.threshold * 2:
            print(f"[THREAT] HIGH – quarantining {len(affected_files)} files and locking directory")
            for f in affected_files:
                self.response_engine.quarantine_file(f)
            # Lockdown the directory
            dir_path = os.path.dirname(path)
            self.response_engine.lock_directory(dir_path)
            # Kill offending process if possible
            self.response_engine.kill_offending_process(dir_path)
            self.event_queue.clear()
    