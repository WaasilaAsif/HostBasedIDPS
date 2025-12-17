
---

#  `idps.py` — Line-by-Line Technical Explanation  
> **Purpose**: System orchestrator — wires together file monitoring, anomaly detection, response, logging, and background system surveillance into a unified, real-time IDPS.

---

##  Imports & Dependencies

```python
import os
```
> Used for path resolution (`os.path.dirname`, `os.path.abspath`, `os.path.join`) and file existence checks.

```python
import sys
```
> Imported but *not used* — safe to remove unless future CLI/config logic is added.

```python
import time
```
> Used for `time.sleep()` in main loop and timestamp formatting (`time.strftime`).

```python
import fnmatch
```
> Enables Unix shell-style wildcard pattern matching (e.g., `*.tmp`, `*.log`) for ignore rules.

```python
import threading
```
> Required to run network/process monitors in background threads without blocking the file watcher.

```python
from watchdog.observers import Observer
```
> Entry point for `watchdog`’s file system monitoring — creates and manages the event loop.

```python
from watchdog.events import FileSystemEventHandler
```
> Base class to inherit from — defines interface for `on_created`, `on_modified`, etc.

```python
from watchdog.events import FileCreatedEvent, FileDeletedEvent, FileMovedEvent, FileModifiedEvent
```
> Concrete event types used in `_get_event_type()` for precise type checking (better than string-based `event.event_type`).

```python
from response import ResponseEngine
```
> Brings in the **prevention engine** — enables automated actions (quarantine, lock, kill).

```python
from monitor import monitor_network_connections, monitor_system_processes
```
> Imports background monitoring functions — decoupled for modularity and testability.

```python
from detector import AdvancedAnomalyDetector
```
> Core detection logic — receives events, runs ML + burst analysis, triggers responses.

```python
from idps_gui import gui_log
```
> Thread-safe logging hook to push messages to the Tkinter dashboard.

---

## Class: `IDPSEventHandler`

```python
class IDPSEventHandler(FileSystemEventHandler):
```
> Custom event handler — extends `watchdog`’s base to integrate with *your* detector and logging.

---

### 🔸 `__init__()` — Constructor

```python
    def __init__(self, ignore_patterns=None, anomaly_detector=None):
        super().__init__()
```
> Calls parent (`FileSystemEventHandler`) constructor — required for `watchdog` compatibility.

```python
        self.ignore_patterns = ignore_patterns or []
```
> Stores ignore list (e.g., `["*.tmp", "*.log"]`). Defaults to empty list if `None`.

```python
        self.anomaly_detector = anomaly_detector
```
> Dependency injection: holds reference to `AdvancedAnomalyDetector` — enables event forwarding.

---

### 🔸 `_get_event_type()` — Event Normalization

```python
    def _get_event_type(self, event):
```
> Converts `watchdog` event objects → compact integer codes for ML efficiency.

```python
        if isinstance(event, FileCreatedEvent):
            return 0
        elif isinstance(event, FileDeletedEvent):
            return 1
        elif isinstance(event, FileMovedEvent):
            return 2
        elif isinstance(event, FileModifiedEvent):
            return 3
        else:
            return -1
```
>  **Why integers?**  
> - Smaller memory footprint than strings  
> - Faster array operations in `numpy`  
> - Clear mapping: `[create=0, delete=1, move=2, modify=3]`  
> - `-1` = unknown → safely ignored later.

>  Note: `FileMovedEvent` has *both* `src_path` and `dest_path` — handled correctly in `on_moved`.

---

###  `_get_event_vector()` — Feature Extraction

```python
    def _get_event_vector(self, event):
```
> Constructs the **2D feature vector** `[event_type, file_size]` used by `IsolationForest`.

```python
        event_type = self._get_event_type(event)
        if event_type == -1:
            return None
```
> Skip unknown/unhandled events early.

```python
        file_size = 0
        if os.path.exists(event.src_path):
            file_size = os.path.getsize(event.src_path)
```
>  **Robustness**:  
> - `file_size = 0` if path missing (e.g., `on_deleted` may race with filesystem)  
> - Uses `event.src_path` (source path) — correct for *all* events (including `FileMovedEvent`, where `src_path` is original location).

```python
        return [event_type, file_size]
```
> Final output: e.g., `[3, 1024]` = modified 1KB file.  
> This minimal vector captures *what happened* and *how much changed* — surprisingly effective for burst + ML detection.

---

###  `should_ignore()` — Path Filtering

```python
    def should_ignore(self, path):
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False
```
> Uses `fnmatch.fnmatch()` (not `glob`) — supports `*`, `?`, `[seq]` wildcards.  
> Example: `fnmatch.fnmatch("/tmp/foo.log", "*.log") → True`.

> **Why filter early?**  
> Avoids useless feature extraction, logging, and detector load for temp/logs.

---

###  `log_event()` — Persistent File Logging

```python
    def log_event(self, event_type, path):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
```
> UTC timestamp (via `gmtime()`) — avoids timezone confusion in logs.

```python
        with open("./logs/file_log.txt", "a") as log_file:
            log_file.write(f"{timestamp} - {event_type} - {path}\n")
```
> **Best practices**:  
> - Appends (`"a"`) → safe for concurrent writes  
> - Simple format → easy to parse later (e.g., `awk`, `grep`)  
> - Logs to `./logs/` — assumed to exist (created by `ResponseEngine` or `test.py`).


---

###  Event Handlers (`on_created`, `on_deleted`, etc.)

All event handlers follow the **same 5-step pipeline**:

1. **Ignore check**  
2. **Feature extraction**  
3. **Send to detector**  
4. **Log to console & GUI**  
5. **Log to file**

Let’s walk through `on_created` — others are analogous.

```python
    def on_created(self, event):
        if self.should_ignore(event.src_path):
            return
```
> Early exit if ignored (e.g., `file.tmp`).

```python
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector, event.src_path)
```
> Forward to detector — note: `event.src_path` is the *new* file path (correct for create).

```python
        print(f"Alert! {event.src_path} has been created.")
```
> Console alert — useful for CLI debugging.

```python
        gui_log(f"File created: {event.src_path}")
```

```python
        self.log_event("created", event.src_path)
```
> Persistent log entry.

---

#### Special Case: `on_moved()`

```python
    def on_moved(self, event):
        if self.should_ignore(event.src_path) and self.should_ignore(event.dest_path):
            return
```
> Only ignore if *both* source and destination match patterns — e.g., moving `a.log → b.log` should still be ignored.

```python
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector, event.src_path)
```
> Uses `event.src_path` as context — correct: the *original* file is what’s being acted upon.

```python
        print(f"Alert! {event.src_path} has been moved to {event.dest_path}.")
        gui_log(f"File moved: {event.src_path} -> {event.dest_path}")
        self.log_event("moved", f"{event.src_path} -> {event.dest_path}")
```
> Clear logging of full move path.

---

##   `main()` — System Orchestration

```python
def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    idps_test_path = os.path.join(base_dir, "idps_test")
```
> Resolves absolute path to `idps_test/` — avoids issues with relative paths when run from elsewhere.

```python
    ignore_patterns = ["*.tmp", "*.log"]
```
> Default ignore list — easily configurable later (e.g., via config file).

```python
    response_engine = ResponseEngine(
        quarantine_dir="./quarantine",
        dry_run=False  
    )
```
>  **Critical**: `dry_run=False` → *real prevention enabled*.  
>  **Warning**: Students should *always* test with `dry_run=True` first.

```python
    anomaly_detector = AdvancedAnomalyDetector(
        threshold=10,
        time_window=60,
        response_engine=response_engine
    )
```
> Instantiates detector with shared `response_engine` — enables tight feedback loop.

```python
    event_handler = IDPSEventHandler(
        ignore_patterns=ignore_patterns,
        anomaly_detector=anomaly_detector
    )
```
> Links detector → handler. Single source of truth.

```python
    observer = Observer()
    observer.schedule(event_handler, idps_test_path, recursive=True)
    observer.start()
```
> Starts `watchdog` file monitoring:  
> - `recursive=True` → watches subdirectories  
> - Runs in a daemon thread — non-blocking.

```python
    threading.Thread(target=monitor_network_connections, daemon=True).start()
    threading.Thread(target=monitor_system_processes, daemon=True).start()
```
> Launches *two background monitors*:  
> - Network: logs new connections to `./logs/network_connections_log.txt`  
> - Processes: logs high-CPU/MEM processes to `./logs/processes_log.txt`  
>  
> `daemon=True` → threads auto-terminate when main thread exits.

```python
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
```
> Keeps main thread alive. `Ctrl+C` → graceful shutdown.

```python
    observer.join()
```
> Waits for observer thread to finish cleanup (e.g., releasing file handles).

---

## Entry Point

```python
if __name__ == "__main__":
    main()
```
> Standard Python idiom — allows `import idps` without side effects.

---

## Architectural Strengths

| Feature | Why It’s Smart |
|--------|----------------|
| **Single Responsibility** | Each module does one thing: `monitor.py` logs, `detector.py` decides, `response.py` acts. |
| **Dependency Injection** | `anomaly_detector` and `response_engine` passed in → easy to mock for testing. |
| **Decoupled GUI Logging** | `gui_log()` is a simple function hook — no direct Tkinter dependency. |
| **Cross-Module Consistency** | Same `event_vector = [type, size]` used everywhere — no format drift. |
| **Safe Defaults** | `dry_run=False` is *explicit* — no hidden surprises. |

---

##  Integration Diagram (Text)

```plaintext
File Event (watchdog)
       ↓
IDPSEventHandler
       ├──→ should_ignore()? → [skip]
       └──→ _get_event_vector() → [type, size]
               ↓
       AdvancedAnomalyDetector.add_event()
               ├──→ burst check? → _handle_threat()
               └──→ ML check?   → _handle_threat()
                       ↓
               ResponseEngine → quarantine/lock/kill
                       ↓
               gui_log() → Tkinter dashboard
               log_event() → ./logs/file_log.txt
```

---
