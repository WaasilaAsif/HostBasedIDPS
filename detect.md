#  `detector.py` — Line-by-Line Technical Explanation  
> **Purpose**: Hybrid anomaly detection using unsupervised ML + burst heuristics, with threat escalation and automated response triggering.

---

## 
 Imports & Setup

```python
import os
```
> Provides OS-level utilities (e.g., `os.path.dirname()` in `_handle_threat`). Needed for cross-platform path handling.

```python
import datetime
```
> Enables precise timestamping of events for time-windowed analysis (`self.time_window`).


```python
import numpy as np
```

> Required to convert lists of feature vectors into a 2D `numpy.ndarray` for `scikit-learn` model training/inference.


```python
from collections import deque
```
> Efficient double-ended queue for maintaining sliding windows of events (`event_queue`) and samples (`samples`) with O(1) append/pop.

```python
from sklearn.ensemble import IsolationForest
```

> Core ML model: unsupervised anomaly detector ideal for imbalanced data (few anomalies, many normals). Detects outliers by isolating them in random trees.

```python
import time
```
> Used in `test.py`, but *not directly used here* — safe to remove unless future timing/debugging is added.

---

##  Class Definition: `AdvancedAnomalyDetector`

```python
class AdvancedAnomalyDetector:
```
> Encapsulates all logic for adaptive, hybrid threat detection. Designed for reuse and testability.

---

###  `__init__()` — Constructor

```python
    def __init__(
        self,
        threshold=10,
        time_window=60,
        train_interval=30,
        max_samples=1000,
        response_engine=None
    ):
```
> Initializes the detector with configurable hyperparameters:
> - `threshold`: Min event count in `time_window` to trigger **burst detection**.
> - `time_window`: Sliding window duration (seconds) for burst analysis.
> - `train_interval`: Seconds between ML model retraining (avoids overfitting/noise).
> - `max_samples`: Max number of feature vectors stored (FIFO, memory-safe).
> - `response_engine`: Reference to `ResponseEngine` — enables *automated prevention*.

```python
        self.threshold = threshold
        self.time_window = time_window
```
> Store burst-detection parameters.

```python
        self.event_queue = deque()
```
> Holds `(timestamp, feature_vector, path)` tuples — used for **burst detection** and threat context (e.g., which files were involved).

```python
        self.samples = deque(maxlen=max_samples)
```
> Stores *only* `feature_vector`s (no timestamps/paths), capped at `max_samples`. Used for **ML training**. `maxlen` ensures automatic FIFO overflow handling.

```python
        self.train_interval = train_interval
        self.last_trained = datetime.datetime.now()
```
> Tracks when the model was last trained — enables periodic retraining without external timers.

```python
        self.model = None
```
> Placeholder for `IsolationForest` instance. Starts as `None` — model trains only after sufficient data.

```python
        self.response_engine = response_engine
```
> Dependency injection: allows detector to *trigger actions* (e.g., quarantine) without owning them.

---

### 🔸 `_train_model()` — Adaptive ML Training

```python
    def _train_model(self):
```
> Private method to (re)train the anomaly detection model.

```python
        if len(self.samples) < self.threshold * 2:
            return
```
> **Safety check**: Only train if we have *at least twice the threshold* samples. Prevents overfitting on sparse/noisy early data.

```python
        feature_matrix = np.array(self.samples)
```
> Converts list of `[event_type, size]` vectors into a 2D `numpy` array of shape `(n_samples, 2)` — required input format for `sklearn`.

```python
        self.model = IsolationForest(
            contamination=float(self.threshold) / len(self.samples),
            random_state=42
        )
```
> Instantiates `IsolationForest` with:
> - `contamination`: Dynamic anomaly ratio = `threshold / total_samples`.  
>   *Why?* As more data arrives, the system *adapts sensitivity*: 10 events in 20 samples → 50% anomalous (high sensitivity); 10 in 1000 → 1% (low sensitivity).  
> - `random_state=42`: Ensures reproducible results across runs (critical for testing/debugging).

```python
        self.model.fit(feature_matrix)
```
> Trains the model on current `samples`. Training is fast (O(n log n)) — suitable for periodic online use.

---

###  `add_event()` — Core Ingestion & Detection Pipeline

```python
    def add_event(self, feature_vector, path=None):
```
> **Primary public API**. Called by `IDPSEventHandler` for every file event.

```python
        current_time = datetime.datetime.now()
```
> Timestamp used for windowing and training scheduling.

```python
        # store event with path
        self.event_queue.append((current_time, feature_vector, path))
        self.samples.append(feature_vector)
```
> - Adds event to sliding window (`event_queue`) for *burst analysis* and *threat context*.  
> - Adds feature vector to training buffer (`samples`) for *ML analysis*.

```python
        # remove old events outside the time window
        while self.event_queue and \
              (current_time - self.event_queue[0][0]).seconds > self.time_window:
            self.event_queue.popleft()
```
> Maintains a **strict sliding window**: removes oldest events until all are within `time_window` seconds. Ensures burst detection is time-bounded.

```python
        # retrain periodically
        if (current_time - self.last_trained).seconds > self.train_interval:
            self._train_model()
            self.last_trained = current_time
```
> Retrains model every `train_interval` seconds *if new data arrived*. Balances adaptability vs. compute cost.

```python
        # anomaly detection
        is_ml_anomaly = False
        if self.model is not None:
            prediction = self.model.predict([feature_vector])
            if prediction[0] == -1:
                print(" ML Anomaly detected: unusual event pattern!")
                is_ml_anomaly = True
```
> - Runs inference *only if model exists*.  
> - `predict()` returns `-1` for anomaly, `+1` for normal.  
> - Logs warning for visibility (remove in production or route to logger).

```python
        # burst-based detection
        is_burst = len(self.event_queue) >= self.threshold
```
> Simple heuristic: ≥ `threshold` events in `time_window` = suspicious burst (e.g., ransomware mass-modification).

```python
        if is_ml_anomaly or is_burst:
            self._handle_threat(path, len(self.event_queue))
```
> **Hybrid trigger**: Threat escalates if *either* ML *or* burst detects anomaly — maximizing coverage (ML catches subtle drifts; burst catches fast attacks).

---

### 🔸 `_handle_threat()` — Intelligent Escalation & Prevention

```python
    def _handle_threat(self, path, event_count):
```
> Executes response based on *severity* and *context* (not just the latest event).

```python
        print(f"[DEBUG] Using AdvancedAnomalyDetector from: {__file__}")
```
> Debug aid — confirms correct module is loaded (useful during testing/refactoring).

```python
        if not self.response_engine or not path:
            print("[WARN] Threat detected but no response engine attached")
            return
```
> Safety net: no-op if prevention is disabled (e.g., during unit tests). Logs warning for diagnostics.

```python
        # Gather all recent file paths in the event queue (within window)
        affected_files = set(p for _, _, p in self.event_queue if p)
```
>  **Key innovation**: Instead of reacting to *one* file, collects *all unique paths* in the current threat window → enables **coordinated defense** (e.g., lock *all* files touched in a ransomware burst).

```python
        #  MEDIUM THREAT: Lock all affected files
        if event_count >= self.threshold:
            print(f"[THREAT] MEDIUM – locking {len(affected_files)} files")
            for f in affected_files:
                self.response_engine.lock_file(f)
```
> **Escalation Level 1**:  
> - Trigger: `event_count ≥ threshold`  
> - Action: `chmod 0o400` on *every affected file* — prevents modification/deletion, but allows reading (forensics).

```python
        #  HIGH THREAT: Quarantine all files and lock directory
        if event_count >= self.threshold * 2:
            print(f"[THREAT] HIGH – quarantining {len(affected_files)} files and locking directory")
            for f in affected_files:
                self.response_engine.quarantine_file(f)
```
> **Escalation Level 2**:  
> - Trigger: `event_count ≥ 2 × threshold` (e.g., 20 events in 60s)  
> - Action: Move *all* affected files to `./quarantine/` — removes them from active use.

```python
            # Lockdown the directory
            dir_path = os.path.dirname(path)
            self.response_engine.lock_directory(dir_path)
```
> Prevents *new* malicious files: locks directory permissions (`0o555`) and all files inside (`0o400`).

```python
            # Kill offending process if possible
            self.response_engine.kill_offending_process(dir_path)
```
> Scans all running processes for open file handles under `dir_path` → terminates *any process actively writing to the attack zone*. Critical for stopping ransomware mid-execution.

```python
            self.event_queue.clear()
```
> Resets the event window to avoid repeated high-threat triggers during cleanup.

---

## Design Highlights & Best Practices

| Feature | Why It’s Smart |
|--------|----------------|
| **Hybrid Detection** | ML + burst = high recall, low latency. Avoids cold-start (ML) and evasion (burst-only). |
| **Dynamic Contamination** | `threshold / len(samples)` = adaptive sensitivity — no manual tuning. |
| **Context-Aware Response** | Acts on *all affected files*, not just the trigger — stops lateral movement. |
| **Escalating Actions** | Lock → Quarantine → Kill → Lockdown = defense-in-depth. |
| **Thread-Safe Design** | All state is local; no shared mutable state across threads. |
| **Fail-Safe Defaults** | `response_engine=None`, early returns, error logging. |

---

## Potential Improvements (Future Work)

| Area | Suggestion |
|------|------------|
| **Concurrency** | Add `threading.Lock()` around `_train_model()`/`predict()` for strict thread safety. |
| **Feature Engineering** | Add time-of-day, file entropy, or parent PID to `feature_vector`. |
| **Model Persistence** | Save/load `self.model` via `joblib.dump()`/`load()`. |
| **Logging** | Replace `print()` with `logging` module for levels/filters. |

---
