import threading
from idps_gui import start_gui
import idps

# Run IDPS core in background
threading.Thread(target=idps.main, daemon=True).start()

# Run GUI in main thread
start_gui()
