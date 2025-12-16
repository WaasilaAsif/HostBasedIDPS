import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue
import time

# This queue will receive logs/events from IDPS
log_queue = queue.Queue()

# ---- Helper logging function (thread-safe) ----
def gui_log(message):
    timestamp = time.strftime("%H:%M:%S")
    log_queue.put(f"[{timestamp}] {message}")


# ---- GUI Application ----
class IDPSGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("AI-IDPS Monitor")
        self.geometry("800x500")
        self.configure(bg="#1e1e1e")

        self._build_ui()
        self.after(200, self._poll_logs)

    def _build_ui(self):
        # Title
        title = tk.Label(
            self,
            text="AI-Powered IDPS – Live Monitor",
            font=("Segoe UI", 16, "bold"),
            fg="#00ffcc",
            bg="#1e1e1e"
        )
        title.pack(pady=10)

        # Status Frame
        status_frame = ttk.Frame(self)
        status_frame.pack(fill="x", padx=10)

        self.status_label = tk.Label(
            status_frame,
            text="Status: RUNNING",
            fg="green",
            font=("Segoe UI", 10, "bold")
        )
        self.status_label.pack(side="left")

        # Log Output
        self.log_box = scrolledtext.ScrolledText(
            self,
            height=20,
            bg="#111",
            fg="#e6e6e6",
            insertbackground="white",
            font=("Consolas", 10)
        )
        self.log_box.pack(fill="both", expand=True, padx=10, pady=10)

        # Control Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="Clear Logs", command=self._clear_logs).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Exit", command=self._shutdown).pack(side="left", padx=5)

    def _poll_logs(self):
        while not log_queue.empty():
            msg = log_queue.get()
            self.log_box.insert(tk.END, msg + "\n")
            self.log_box.see(tk.END)
        self.after(200, self._poll_logs)

    def _clear_logs(self):
        self.log_box.delete("1.0", tk.END)

    def _shutdown(self):
        self.status_label.config(text="Status: STOPPED", fg="red")
        self.after(500, self.destroy)


# ---- Example hook (used by IDPS core) ----
def start_gui():
    app = IDPSGUI()
    gui_log("IDPS GUI started")
    app.mainloop()


if __name__ == "__main__":
    start_gui()