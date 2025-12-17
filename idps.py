import os
import sys
#not used was gonna add cli config later but no time
import time
import fnmatch
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from watchdog.events import FileCreatedEvent, FileDeletedEvent, FileMovedEvent, FileModifiedEvent
from response import ResponseEngine
from monitor import monitor_network_connections, monitor_system_processes
from detector import AdvancedAnomalyDetector
from idps_gui import gui_log

class IDPSEventHandler(FileSystemEventHandler):
    def __init__(self, ignore_patterns=None, anomaly_detector=None):
        super().__init__()
        self.ignore_patterns = ignore_patterns or []
        self.anomaly_detector = anomaly_detector


    def _get_event_type(self, event):
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

    def _get_event_vector(self, event):
        event_type = self._get_event_type(event)
        if event_type == -1:
            return None

        file_size = 0
        if os.path.exists(event.src_path):
            file_size = os.path.getsize(event.src_path)

        return [event_type, file_size]

    def should_ignore(self, path):
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False
    
    def log_event(self, event_type, path):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        log_path = "./logs"
        os.makedirs(log_path, exist_ok=True)
       # with open("./logs/file_log.txt", "a") as log_file:
        with open(os.path.join(log_path, "file_log.txt"), "a") as log_file:
            log_file.write(f"{timestamp} - {event_type} - {path}\n")

    def on_created(self, event):
        if self.should_ignore(event.src_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector, event.src_path)
        print(f"Alert! {event.src_path} has been created.")
        gui_log(f"File created: {event.src_path}")
        self.log_event("created", event.src_path)

    def on_deleted(self, event):
        if self.should_ignore(event.src_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector, event.src_path)
        print(f"Alert! {event.src_path} has been deleted.")
        gui_log(f"File deleted: {event.src_path}")
        self.log_event("deleted", event.src_path)

    def on_moved(self, event):
        if self.should_ignore(event.src_path) and self.should_ignore(event.dest_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector, event.src_path)
        print(f"Alert! {event.src_path} has been moved to {event.dest_path}.")
        gui_log(f"File moved: {event.src_path} -> {event.dest_path}")
        self.log_event("moved", f"{event.src_path} -> {event.dest_path}")

    def on_modified(self, event):
        if self.should_ignore(event.src_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector, event.src_path)
        print(f"Alert! {event.src_path} has been modified.")
        gui_log(f"File modified: {event.src_path}")
        self.log_event("modified", event.src_path)

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    idps_test_path = os.path.join(base_dir, "idps_test")

    ignore_patterns = ["*.tmp", "*.log"]

    response_engine = ResponseEngine(
        quarantine_di
    )

    anomaly_detector = AdvancedAnomalyDetector(
        threshold=10,
        time_window=60,
        response_engine=response_engine
    )

    event_handler = IDPSEventHandler(
        ignore_patterns=ignore_patterns,
        anomaly_detector=anomaly_detector
    )

    observer = Observer()
    observer.schedule(event_handler, idps_test_path, recursive=True)
    observer.start()

    threading.Thread(target=monitor_network_connections, daemon=True).start()
    threading.Thread(target=monitor_system_processes, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()


if __name__ == "__main__":
    main()